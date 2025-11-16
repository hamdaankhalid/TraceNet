using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

# region Protocol Implementation

/* UDP Hole punching client
Technique to enable direct communication between two clients behind NATs by using a third-party server to coordinate the connection.
1. 2 clients A and B want to communicate.
2. Both clients connect to a public server S and send their external IP and port. They need to use a STUN server to discover this.
3. Server S shares A's external IP/port with B and B's external IP/port with A
4. Both clients send UDP packets to each other's external IP/port
5. NATs create mappings for these outbound packets, allowing direct communication
6. Clients A and B can now communicate directly via UDP

NAT will only let through packets from IP:ports that the client has sent packets to. This protects against random unsolicited packets from attackers etc

NAT Types:
- Full Cone NAT: Maps internal IP:port to same external IP:port for all destinations (easiest for hole punching)
- Restricted Cone NAT: Reuses mapping but only accepts packets from IPs the client has sent to
- Port Restricted Cone NAT: Like Restricted Cone but also checks source port
- Symmetric NAT: Creates different external port for each destination (hardest - hole punching often fails)

Note: Success depends on NAT types; symmetric NATs typically block this technique.

Both clients open ephemeral ports acting as clients making outbound connections.
NAT thinks both peers are "replying" to outbound connections.
and thus without any listening sockets you have peer to peer communication.
*/

enum HolePunchingState
{
  // move to RegisteredWithServer by contacting STUN server and registering with registration server
  Initial = 0,
  // check if peer has also registered, if not retry till max retries reached, then move to ReceivedPeerInfo. If max retries reached move to Closed
  RegisteredWithServer,
  // try to do hole punching by sending packets to peer's external IP:port, move to EstablishedConnection on success else refetch peer info and retry (move back to RegisteredWithServer)
  // if max retries reached move to Closed
  ReceivedPeerInfo,
  // connection established, can now use the UDP socket for communication, if Next() is called again, move to Closed
  EstablishedConnection,
  // perform cleanup of resources and deregister from server, then move back to Initial for potential future connections
  Closed,
}

internal class HolePunchingStateMachine : IAsyncDisposable
{
  // STUN is used as a way to get public IP and port mapping from NAT
  private static readonly string[] STUN_SERVERS = new string[]
  {
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun3.l.google.com:19302",
    "stun4.l.google.com:19302",
  };

  private readonly static byte[] PUNCH_PACKET = System.Text.Encoding.UTF8.GetBytes("HolePunching: Punch Packet");

  // Session lifetime for registration with server, after these minutes the server will evict our registration
  // this will not impact active connections but will require re-registration for future connections
  private const int SESSION_LIFETIME_MINS = 10;
  private const int TIMEOUT_SECS = 10;

  // Non-static fields
  private readonly IConnectionMultiplexer _connectionMultiplexer;
  private readonly string _selfId;
  private readonly byte[] _internalBuffer = new byte[1024];
  private readonly int _maxRetryCount;
  private readonly ILogger? _logger;

  // State - Mutable fields 
  private int _registrationRetryCount;
  private int _sendPunchRetryCount;
  private IPAddress? _peerIp;
  private string? _peerId;
  private int _peerPort;
  private IPEndPoint? _peerEndPoint;
  private Socket? _udpSocket;

  // IDisposable support
  private bool _isDisposed;

  private HolePunchingState CurrentState { get; set; } = HolePunchingState.Initial;

  // This is the primary inteface to get the hole punched socket once connection is established
  // The user should not dispose this socket, it will be disposed when the state machine is disposed
  public Socket HolePunchedSocket
  {
    get
    {
      if (CurrentState != HolePunchingState.EstablishedConnection)
      {
        throw new InvalidOperationException("Connection not yet established.");
      }
      Debug.Assert(_udpSocket != null);
      return _udpSocket;
    }
  }

  public HolePunchingStateMachine(string selfId, string registrationServerAddr, int maxRetryCount = 5, ILogger? logger = null)
  {
    ArgumentOutOfRangeException.ThrowIfNegative(maxRetryCount);

    ConfigurationOptions options = ConfigurationOptions.Parse(registrationServerAddr);
    options.Password = options.Password; // Preserve password from connection string if provided
    options.ConnectRetry = maxRetryCount;
    options.ConnectTimeout = 5000; // 5 seconds
    options.SyncTimeout = 5000; // 5 seconds
    options.KeepAlive = 60; // seconds
    _connectionMultiplexer = ConnectionMultiplexer.Connect(options);

    _selfId = selfId;
    _maxRetryCount = maxRetryCount;
    _logger = logger;
  }

  public async Task<bool> ConnectAsync(string peerId)
  {
    if (CurrentState != HolePunchingState.Initial)
    {
      throw new InvalidOperationException($"Connection process already started. {CurrentState}");
    }

    _peerId = peerId;

    // Main loop to progress through states till connection is established or failed (went all the way back to initial)
    HolePunchingState currentState = CurrentState;
    HolePunchingState nextState;
    do
    {
      nextState = await Next();
      _logger?.LogDebug("HolePunching State Transition: {CurrentState} => state {NextState}, retry count {RegistrationRetryCount}, send punch retry count {SendPunchRetryCount}",
        currentState, nextState, _registrationRetryCount, _sendPunchRetryCount);
    }
    while (nextState != HolePunchingState.EstablishedConnection && nextState != HolePunchingState.Initial);

    // Connection established or failed
    return CurrentState != HolePunchingState.EstablishedConnection;
  }

  public async Task CloseAsync()
  {
    // Connection should have already been in EstablishedConnection state for close to be viable
    if (CurrentState != HolePunchingState.EstablishedConnection)
    {
      throw new InvalidOperationException("Connection not yet established.");
    }

    HolePunchingState currentState = CurrentState;
    await Next(); // Move to Closed state and cleanup
    _logger?.LogDebug("HolePunching State Transition: {CurrentState} => state {NextState}, retry count {RegistrationRetryCount}, send punch retry count {SendPunchRetryCount}", 
      currentState, CurrentState, _registrationRetryCount, _sendPunchRetryCount);
  }

  // Advance the state machine to the next state returning the new state
  private async Task<HolePunchingState> Next()
  {
    switch (CurrentState)
    {
      case HolePunchingState.Initial: // At this stage we don't have an active UDP socket yet and have not registered our ephemeral port with server since we don't know it yet
        Debug.Assert(_peerId != null, "Invariant Violation: Set by ConnectAsync before calling Next()");
        Debug.Assert(_udpSocket == null, "Invariant Violation: No UDP socket should exist in initial state");
        Debug.Assert(_peerIp == null, "Invariant Violation: if we have not yet received peer info from server this should still be null");
        Debug.Assert(_peerPort == 0, "Invariant Violation: Will be set once we get peer info from server so currenty should be 0");
        Debug.Assert(_peerEndPoint == null, "Invariant Violation: Will be set once we get peer info from server so currenty should be null");
        Debug.Assert(_registrationRetryCount == 0, "Invariant Violation: Retry count should be 0 in initial state");
        Debug.Assert(_sendPunchRetryCount == 0, "Invariant Violation: Send punch retry count should be 0 in initial state");

        _logger?.LogDebug("HolePunching: Initializing UDP socket and registering with server");

        // Initialize UDP socket and register self and port with server
        _udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

        // Make sure we are not behing a NAT that is symmetric otherwise hole punching will likely fail
        bool isSymmetricNat = await MinimalStunClient.IsSymmetricNat(_udpSocket, new string[] { "stun1.l.google.com:19302", "stun2.l.google.com:19302" });
        if (isSymmetricNat)
        {
          _logger?.LogError("HolePunching: Symmetric NAT detected, hole punching will fail");
          CurrentState = HolePunchingState.Closed;
          break;
        }

        _logger?.LogDebug("HolePunching: NAT is not symmetric, proceeding with hole punching");

        // get which is the port the above socket is bound to externally via NAT using STUN
        (IPAddress publicIp, int ephemeralPort) = await MinimalStunClient.GetStunPortAsync(_udpSocket, STUN_SERVERS);

        await RegisterWithServerAsync(publicIp, ephemeralPort); // Let any failure in registration propagate up, redis stack exchange client should have already retried internally if needed

        CurrentState = HolePunchingState.RegisteredWithServer;
        break;
      case HolePunchingState.RegisteredWithServer:
        Debug.Assert(_udpSocket != null, "Invariant Violation: UDP socket should have been created in previous state Initial");
        Debug.Assert(_peerId != null, "Invariant Violation: Set by ConnectAsync before calling Next() this should still hold");
        Debug.Assert(_peerIp == null, "Invariant Violation: if we have not yet received peer info from server this should still be null");
        Debug.Assert(_peerPort == 0, "Invariant Violation: Will be set once we get peer info from server so currenty should be 0");
        Debug.Assert(_peerEndPoint == null, "Invariant Violation: Will be set once we get peer info from server so currenty should be null");

        if (_registrationRetryCount >= _maxRetryCount)
        {
          // Exceeded max retries, mark as failed
          CurrentState = HolePunchingState.Closed;
          break;
        }

        _logger?.LogDebug("HolePunching: Waiting for peer info from server");

        // Wait for peer info from server
        IDatabase db = _connectionMultiplexer.GetDatabase();
        string? peerInfo = await db.StringGetAsync(_peerId); // Any stackexchange issues will throw exceptions and propagate up and that is okay.
        if (peerInfo == null)
        {
          _registrationRetryCount++;
          // Peer info not yet available
          _logger?.LogDebug("HolePunching: Peer info not yet available, retrying... {RegistrationRetryCount}/{MaxRetryCount}",
            _registrationRetryCount, _maxRetryCount);
          await Task.Delay(2_000); // Wait and let the next next() invocation retry
          break;
        }

        // peer we want to connect to has also registered, parse their info
        _registrationRetryCount = 0;
        string[] peerParts = peerInfo.Split(':');
        _peerIp = IPAddress.Parse(peerParts[0]);
        _peerPort = int.Parse(peerParts[1]);
        _peerEndPoint = new IPEndPoint(_peerIp, _peerPort);
        _logger?.LogDebug("HolePunching: Received peer info: {PeerInfo}", peerInfo);
        CurrentState = HolePunchingState.ReceivedPeerInfo;
        break;

      case HolePunchingState.ReceivedPeerInfo:
        Debug.Assert(_udpSocket != null, "Invariant Violation: UDP socket should have been created in previous state Initial");
        Debug.Assert(_peerIp != null, "Invariant Violation: Set by ConnectAsync before calling Next() this should still hold");
        Debug.Assert(_peerId != null, "Invariant Violation: Set by ConnectAsync before calling Next() this should still hold");
        Debug.Assert(_peerPort >= 0, "Invariant Violation: Should have been received from server in previous state RegisteredWithServer");
        Debug.Assert(_peerEndPoint != null, "Invariant Violation: Should have been created in previous state RegisteredWithServer");

        if (_sendPunchRetryCount >= _maxRetryCount)
        {
          // Exceeded max retries, mark as failed
          CurrentState = HolePunchingState.Closed;
          _logger?.LogDebug("HolePunching: Exceeded max retries, marking as failed");
          break;
        }

        // CORE LOGIC OF HOLE PUNCHING
        _logger?.LogDebug("HolePunching: Sending punch packet to peer");

        int receiveResult = 0;
        int maxAttempts = TIMEOUT_SECS * 4;
        EndPoint tempEndPoint = _peerEndPoint; // only need to do this so I can pass it by ref
        for (int i = 0; i < maxAttempts; i++)
        {
          _udpSocket.SendTo(PUNCH_PACKET, SocketFlags.None, _peerEndPoint);

          if (i % 10 == 0 && i != 0)
          {
            _logger?.LogDebug("HolePunching: Sent {PacketCount} punch packets to peer, waiting for response...", i);
          }

          // Poll to see if data is available (increased poll time to 250ms for better timing)
          if (_udpSocket.Poll(250_000, SelectMode.SelectRead)) // microseconds - 250ms between sends
          {
            receiveResult = _udpSocket.ReceiveFrom(_internalBuffer, SocketFlags.None, ref tempEndPoint);
            _logger?.LogDebug("HolePunching: Received {ByteCount} bytes from peer!", receiveResult);
            break; // Got response!
          }
        }

        if (receiveResult <= 0)
        {
          _sendPunchRetryCount++;
          // Peer may not have registered yet
          // retry sending punch packet by moving one level back on state where we will reget Peer's info and resend punch packet incase the first was not received
          CurrentState = HolePunchingState.RegisteredWithServer;
          _logger?.LogDebug("HolePunching: Did not receive response from peer, retrying...");
          break;
        }

        // Successfully received response from peer
        _sendPunchRetryCount = 0;
        CurrentState = HolePunchingState.EstablishedConnection;
        break;

      case HolePunchingState.EstablishedConnection:
        Debug.Assert(_udpSocket != null, "Invariant Violation: UDP socket should have been created in previous state Initial");
        Debug.Assert(_peerId != null, "Invariant Violation: Set by ConnectAsync before calling Next() this should still hold");
        Debug.Assert(_peerIp != null, "Invariant Violation: Set by ConnectAsync before calling Next() this should still hold");
        Debug.Assert(_peerPort >= 0, "Invariant Violation: Should have been received from server in previous state RegisteredWithServer");
        Debug.Assert(_peerEndPoint != null, "Invariant Violation: Should have been created in previous state RegisteredWithServer");

        CurrentState = HolePunchingState.Closed;
        break;

      case HolePunchingState.Closed:
        Debug.Assert(_udpSocket != null, "Invariant Violation: UDP socket should have been created in previous state Initial");

        // If next was called on this state, then the want is to close the connection.
        // if state was past RegisteredWithServer we need to deregister from server as a best effort way otherwise TTL will expire our registration in worst case!
        if (CurrentState != HolePunchingState.Initial)
        {
          await DeregisterFromServerAsync();
        }

        if (_udpSocket != null)
        {
          _udpSocket.Dispose();
          _udpSocket = null;
        }


        _registrationRetryCount = 0;
        _sendPunchRetryCount = 0;
        _peerId = null;
        _peerIp = null;
        _peerPort = 0;
        _peerEndPoint = null!;

        CurrentState = HolePunchingState.Initial;
        break;
    }

    return CurrentState;
  }

  private Task RegisterWithServerAsync(IPAddress publicIp, int externalPort)
  {
    IDatabase db = _connectionMultiplexer.GetDatabase();
    return db.StringSetAsync(_selfId, $"{publicIp}:{externalPort}", expiry: TimeSpan.FromMinutes(SESSION_LIFETIME_MINS)); // Sessions are 10 minutes long...
  }

  private Task DeregisterFromServerAsync()
  {
    IDatabase db = _connectionMultiplexer.GetDatabase();
    return db.KeyDeleteAsync(_selfId);
  }

  public async ValueTask DisposeAsync()
  {
    if (!_isDisposed)
    {
      // Close the connection if it's established (deregister from server, cleanup socket)
      if (CurrentState == HolePunchingState.EstablishedConnection)
      {
        try
        {
          await CloseAsync();
        }
        catch
        {
          // Best effort - continue with disposal even if close fails
        }
      }
      
      // Dispose any remaining resources
      _udpSocket?.Dispose();
      await _connectionMultiplexer.CloseAsync();
      _connectionMultiplexer.Dispose();
      _isDisposed = true;
    }
  }
}

#endregion

// This is a minimal STUN client implementation to get public IP and port mapping from NAT
// I don't need anything else so I'm not even parsing full messages, just give me the bytes I need damn it
static class MinimalStunClient
{
  public static async Task<bool> IsSymmetricNat(Socket udpSocket, string[] stunServers)
  {
    int randomIdx = Random.Shared.Next(stunServers.Length);
    string stunServer1 = stunServers[randomIdx];
    int randomIdx2 = (randomIdx + 1) % stunServers.Length;
    string stunServer2 = stunServers[randomIdx2];

    // Run sequentially, not in parallel!
    (IPAddress publicIp, int publicPort) result1 = await GetStunPortAsync(udpSocket, new string[] { stunServer1 });
    (IPAddress publicIp, int publicPort) result2 = await GetStunPortAsync(udpSocket, new string[] { stunServer2 });

    return result1.publicPort != result2.publicPort;
  }

  public static async Task<(IPAddress publicIp, int publicPort)> GetStunPortAsync(Socket udpSocket, string[] stunServers)
  {
    // try each STUN server until we get a valid response
    // start from a random server to distribute load although this is really not a concern lol
    int startingStun = Random.Shared.Next(stunServers.Length);
    for (int k = 0; k < stunServers.Length; k++)
    {
      string server = stunServers[(k + startingStun) % stunServers.Length];
      string[] parts = server.Split(':');
      string host = parts[0];
      int port = int.Parse(parts[1]);

      IPEndPoint serverEndPoint = new IPEndPoint(Dns.GetHostAddresses(host)[0], port);

      // Build and send STUN binding request
      byte[] request = new byte[20];
      request[0] = 0x00; // Binding Request
      request[1] = 0x01;

      await udpSocket.SendToAsync(request, SocketFlags.None, serverEndPoint);

      // Receive response
      byte[] buffer = new byte[512];
      SocketReceiveFromResult result = await udpSocket.ReceiveFromAsync(buffer, SocketFlags.None, serverEndPoint);

      if (result.ReceivedBytes > 0)
      {
        // Parse response to extract public IP and port
        // This is a simplified parser assuming the response is well-formed.....
        // HK TODO: I need to make this slightly more robust in case of malformed responses
        for (int i = 20; i < result.ReceivedBytes;)
        {
          ushort type = (ushort)((buffer[i] << 8) | buffer[i + 1]);
          ushort length = (ushort)((buffer[i + 2] << 8) | buffer[i + 3]);
          if (type == 0x0001) // MAPPED-ADDRESS
          {
            byte family = buffer[i + 5];
            ushort publicFacingExternalPort = (ushort)((buffer[i + 6] << 8) | buffer[i + 7]);
            byte[] addrBytes = new byte[4];
            Array.Copy(buffer, i + 8, addrBytes, 0, 4);
            IPAddress publicIp = new IPAddress(addrBytes);
            return (publicIp, publicFacingExternalPort);
          }
          i += 4 + length;
        }
      }
    }

    throw new Exception("Failed to get public IP and port from STUN servers.");
  }
}

public sealed class HOPPeer : IAsyncDisposable
{
  private readonly Object _socketLock = new Object();
  private readonly HolePunchingStateMachine _stateMachine;

  public HOPPeer(string discoverableId, string registrationServerAddr, ILogger? logger = null)
  {
    _stateMachine = new HolePunchingStateMachine(discoverableId, registrationServerAddr, maxRetryCount: 5, logger: logger);
  }

  public async Task<bool> ConnectAsync(string peerId)
  {
    return await _stateMachine.ConnectAsync(peerId); // use await here to propagate exceptions showing connection failure explicitly here
  }

  public int Send(ReadOnlySpan<byte> data)
  {
    lock (_socketLock)
    {
      return _stateMachine.HolePunchedSocket.Send(data);
    }
  }

  public int Receive(Span<byte> buffer, int receiveTimeoutMs = 250)
  {
    lock (_socketLock)
    {
      if (_stateMachine.HolePunchedSocket.Poll(receiveTimeoutMs * 1_000, SelectMode.SelectRead) == false)
      {
        return 0; // timeout
      }
      return _stateMachine.HolePunchedSocket.Receive(buffer);
    }
  }

  public async Task CloseAsync() => await _stateMachine.CloseAsync();

  public ValueTask DisposeAsync() => _stateMachine.DisposeAsync();
}

// Sample program showing how to use the above Hole Punched Peer class to establish a hole punched connection and send/receive data
internal class Program
{
  // args[0] = peer identifier to connect to
  // args[1] = registration server address [Garnet Connection String]
  // args[2] = self identification string

  private static async Task Main(string[] args)
  {
    string registrationServerAddr = args[1];
    string selfIdentification = args[2];

    using ILoggerFactory loggerFactory = LoggerFactory.Create(builder =>
    {
      builder.AddConsole();
      builder.SetMinimumLevel(LogLevel.Debug);
    });

    ILogger logger = loggerFactory.CreateLogger<Program>();

    await using HOPPeer peer = new HOPPeer(selfIdentification, registrationServerAddr, logger);

    Console.WriteLine("Press enter to start connection to peer...");

    Console.ReadLine();

    Console.WriteLine($"Connecting to peer {args[0]}...");

    if (!await peer.ConnectAsync(args[0]))
    {
      Console.WriteLine("Failed to establish connection.");
      return;
    }

    // once established create 2 separate execution flows for sending and receiving data
    Console.WriteLine("Connection established!");
    Console.WriteLine("Press Enter to send a ping message to peer");

    using CancellationTokenSource cts = new CancellationTokenSource();

    string indentationOfReadMessages = new string('\t', 4);
    // one thread for receiving pings
    Task receivingTask = Task.Run(async () =>
    {
      try
      {
        byte[] receiveBuffer = new byte[1024];
        while (!cts.IsCancellationRequested)
        {
          int receivedBytes = peer.Receive(receiveBuffer, 250);
          if (receivedBytes > 0)
          {
            string message = System.Text.Encoding.UTF8.GetString(receiveBuffer, 0, receivedBytes);
            Console.WriteLine($"Received{indentationOfReadMessages}{message}");
          }
          await Task.Delay(250, cts.Token); // slight delay to avoid busy loop
        }
      }
      catch (OperationCanceledException)
      {
      }
    }, cts.Token);

    while (true)
    {
      string? userInput = Console.ReadLine();
      if (string.IsNullOrEmpty(userInput))
      {
        break; // exit on empty input
      }

      byte[] dataToSend = System.Text.Encoding.UTF8.GetBytes(userInput);
      peer.Send(dataToSend);
      Console.WriteLine($"Sent => {userInput}");
    }

    cts.Cancel();

    await receivingTask;
  }
}