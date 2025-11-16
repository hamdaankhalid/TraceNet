
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

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
enum HolePunchingStates
{
  Initial = 0,
  RegisteredWithServer,
  ReceivedPeerInfo,
  SentPunchPacket,
  EstablishedConnection,
  Failed
}

// Protocol state machine for hole punching process
internal class HolePunchingStateMachine : IDisposable
{
  private readonly IConnectionMultiplexer _connectionMultiplexer;
  private readonly string _selfId;
  private readonly byte[] _internalBuffer = new byte[1024];
  private readonly int _maxRetryCount;
  private readonly ILogger? _logger;
  // STUN is used as a way to get public IP and port mapping from NAT
  private readonly string[] _stunServers = new string[]
  {
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun3.l.google.com:19302",
    "stun4.l.google.com:19302",
  };

  // Session lifetime for registration with server, after these minutes the server will evict our registration
  // this will not impact active connections but will require re-registration for future connections
  private readonly int SESSION_LIFETIME_MINS = 10;

  // State variables
  private int _registrationRetryCount = 0;
  private int _sendPunchRetryCount = 0;
  private int _waitForPeerResponseRetryCount = 0;
  private IPAddress? _peerIp;
  private string? _peerId;
  private int _peerPort;
  private IPEndPoint? _peerEndPoint;
  private Socket? _udpSocket;

  // IDisposable support
  private bool disposedValue;

  private HolePunchingStates CurrentState { get; set; } = HolePunchingStates.Initial;

  // This is the primary inteface to get the hole punched socket once connection is established
  // The user should not dispose this socket, it will be disposed when the state machine is disposed
  public Socket HolePunchedSocket
  {
    get
    {
      if (CurrentState != HolePunchingStates.EstablishedConnection)
      {
        throw new InvalidOperationException("Connection not yet established.");
      }
      Debug.Assert(_udpSocket != null);
      return _udpSocket;
    }
  }

  public HolePunchingStateMachine(string selfId, string registrationServerAddr, int maxRetryCount = 5, ILogger? logger = null)
  {
    if (maxRetryCount < 0)
    {
      throw new ArgumentOutOfRangeException(nameof(maxRetryCount));
    }

    ConfigurationOptions option = ConfigurationOptions.Parse(registrationServerAddr);
    option.ConnectRetry = maxRetryCount;
    option.ConnectTimeout = 5000; // 5 seconds
    option.SyncTimeout = 5000; // 5 seconds
    option.KeepAlive = 60; // seconds

    _connectionMultiplexer = ConnectionMultiplexer.Connect(option);

    _selfId = selfId;
    _maxRetryCount = maxRetryCount;
    _logger = logger;
  }

  public async Task<bool> ConnectAsync(string peerId)
  {
    // Can only connect on initial or failed state
    if (CurrentState != HolePunchingStates.Initial && CurrentState != HolePunchingStates.Failed)
    {
      throw new InvalidOperationException($"Connection process already started. {CurrentState}");
    }

    _peerId = peerId;

    // Main loop to progress through states till connection is established or failed
    while (CurrentState != HolePunchingStates.EstablishedConnection && CurrentState != HolePunchingStates.Failed)
    {
      _logger?.LogDebug($"HolePunching: Current state {CurrentState}, retry count {_registrationRetryCount}, " +
        $"send punch retry count {_sendPunchRetryCount}, wait for peer response retry count {_waitForPeerResponseRetryCount}");
      await Next();
      await Task.Delay(100); // slight delay to avoid busy loop
    }

    // Connection established or failed
    return CurrentState == HolePunchingStates.EstablishedConnection;
  }

  private async Task Next()
  {
    switch (CurrentState)
    {
      case HolePunchingStates.Initial: // At this stage we don't have an active UDP socket yet and have not registered our ephemeral port with server since we don't know it yet
        Debug.Assert(_peerId != null, "Invariant Violation: Set by ConnectAsync before calling Next()");
        Debug.Assert(_udpSocket == null, "Invariant Violation: No UDP socket should exist in initial state");
        Debug.Assert(_peerIp == null, "Invariant Violation: if we have not yet received peer info from server this should still be null");
        Debug.Assert(_peerPort == 0, "Invariant Violation: Will be set once we get peer info from server so currenty should be 0");
        Debug.Assert(_peerEndPoint == null, "Invariant Violation: Will be set once we get peer info from server so currenty should be null");
        Debug.Assert(_registrationRetryCount == 0, "Invariant Violation: Retry count should be 0 in initial state");
        Debug.Assert(_sendPunchRetryCount == 0, "Invariant Violation: Send punch retry count should be 0 in initial state");
        Debug.Assert(_waitForPeerResponseRetryCount == 0, "Invariant Violation: Wait for peer response retry count should be 0 in initial state");

        _logger?.LogDebug("HolePunching: Initializing UDP socket and registering with server");

        // Initialize UDP socket and register self and port with server
        _udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        // get which is the port the above socket is bound to externally via NAT using STUN
        (IPAddress publicIp, int ephemeralPort) = await StunRequestAsync();
        await RegisterWithServerAsync(publicIp, ephemeralPort); // Let any failure in registration propagate up, redis stack exchange client should have already retried internally if needed

        _logger?.LogDebug("HolePunching: Registered with server"); 
        CurrentState = HolePunchingStates.RegisteredWithServer;
        break;
      case HolePunchingStates.RegisteredWithServer:
        Debug.Assert(_udpSocket != null, "Invariant Violation: UDP socket should have been created in previous state Initial");
        Debug.Assert(_peerId != null, "Invariant Violation: Set by ConnectAsync before calling Next() this should still hold");
        Debug.Assert(_peerIp == null, "Invariant Violation: if we have not yet received peer info from server this should still be null");
        Debug.Assert(_peerPort == 0, "Invariant Violation: Will be set once we get peer info from server so currenty should be 0");
        Debug.Assert(_peerEndPoint == null, "Invariant Violation: Will be set once we get peer info from server so currenty should be null");

        if (_registrationRetryCount >= _maxRetryCount)
        {
          // Exceeded max retries, mark as failed
          CurrentState = HolePunchingStates.Failed;
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
          _logger?.LogDebug($"HolePunching: Peer info not yet available, retrying... {_registrationRetryCount}/{_maxRetryCount}");
          await Task.Delay(500); // Wait and let the next next() invocation retry
          break;
        }

        // peer we want to connect to has also registered, parse their info
        _registrationRetryCount = 0;
        string[] peerParts = peerInfo.Split(':');
        _peerIp = IPAddress.Parse(peerParts[0]);
        _peerPort = int.Parse(peerParts[1]);
        _peerEndPoint = new IPEndPoint(_peerIp, _peerPort);
        _logger?.LogDebug($"HolePunching: Received peer info: {peerInfo}");
        CurrentState = HolePunchingStates.ReceivedPeerInfo;
        break;
      case HolePunchingStates.ReceivedPeerInfo:
        Debug.Assert(_udpSocket != null, "Invariant Violation: UDP socket should have been created in previous state Initial");
        Debug.Assert(_peerIp != null, "Invariant Violation: Set by ConnectAsync before calling Next() this should still hold");
        Debug.Assert(_peerId != null, "Invariant Violation: Set by ConnectAsync before calling Next() this should still hold");
        Debug.Assert(_peerPort >= 0, "Invariant Violation: Should have been received from server in previous state RegisteredWithServer");
        Debug.Assert(_peerEndPoint != null, "Invariant Violation: Should have been created in previous state RegisteredWithServer");

        if (_sendPunchRetryCount >= _maxRetryCount)
        {
          // Exceeded max retries, mark as failed
          CurrentState = HolePunchingStates.Failed;
          _logger?.LogDebug("HolePunching: Exceeded max retries, marking as failed");
          break;
        }

        _logger?.LogDebug("HolePunching: Sending punch packet to peer");
        // Send punch packet to peer
        byte[] punchPacket = System.Text.Encoding.UTF8.GetBytes("Punch");
        try
        {
          _udpSocket.SendTimeout= 3000; // 3 seconds
          _udpSocket.SendTo(punchPacket, SocketFlags.None, _peerEndPoint);
          _udpSocket.SendTimeout= 0; // reset timeout
        }
        catch (SocketException)
        {
          // Retry from RegisteredWithServer state
          _sendPunchRetryCount++;
          CurrentState = HolePunchingStates.RegisteredWithServer;
          _peerIp = null;
          _peerPort = 0; // reset the state so RegisteredWithServer can re-fetch peer info from server
          _peerEndPoint = null;
          await Task.Delay(500); // Wait before retrying
          break;
        }
  
        // Successfully sent punch packet
        _sendPunchRetryCount = 0;
        CurrentState = HolePunchingStates.SentPunchPacket;
        _logger?.LogDebug("HolePunching: Sent punch packet to peer");
        break;
      case HolePunchingStates.SentPunchPacket:
        Debug.Assert(_udpSocket != null, "Invariant Violation: UDP socket should have been created in previous state Initial");
        Debug.Assert(_peerIp != null, "Invariant Violation: Set by ConnectAsync before calling Next() this should still hold");
        Debug.Assert(_peerId != null, "Invariant Violation: Set by ConnectAsync before calling Next() this should still hold");
        Debug.Assert(_peerPort >= 0, "Invariant Violation: Should have been received from server in previous state RegisteredWithServer");
        Debug.Assert(_peerEndPoint != null, "Invariant Violation: Should have been created in previous state RegisteredWithServer");

        if (_waitForPeerResponseRetryCount >= _maxRetryCount)
        {
          // Exceeded max retries, mark as failed
          CurrentState = HolePunchingStates.Failed;
          _logger?.LogDebug("HolePunching: Exceeded max retries, marking as failed");
          break;
        }

        // Wait for response from peer
        _logger?.LogDebug("HolePunching: Waiting for response from peer");
      
        bool failed = false;
        int receiveResult = 0;
        try
        {
          _udpSocket.ReceiveTimeout = 3000; // 3 seconds
          EndPoint tempEndPoint = _peerEndPoint;
          receiveResult = _udpSocket.ReceiveFrom(_internalBuffer, SocketFlags.None, ref tempEndPoint);
          _udpSocket.ReceiveTimeout = 0; // reset timeout
        }
        catch (SocketException ex)
        {
          _logger?.LogError(ex, "HolePunching: Failed to receive response from peer due to socket exception");
          failed = true;
        }

        if (failed || receiveResult <= 0)
        {
          _waitForPeerResponseRetryCount++;
          // Peer may not have registered yet
          // retry sending punch packet by moving one level back on state where we will resend punch packet incase the first was not received
          CurrentState = HolePunchingStates.ReceivedPeerInfo;
          _logger?.LogDebug("HolePunching: Did not receive response from peer, retrying...");
          await Task.Delay(500); // Wait before retrying
          break;
        }

        // Successfully received response from peer
        _waitForPeerResponseRetryCount = 0;
        CurrentState = HolePunchingStates.EstablishedConnection;
        _logger?.LogDebug("HolePunching: Established connection with peer!");
        break;
      case HolePunchingStates.EstablishedConnection:
        Debug.Assert(_udpSocket != null, "Invariant Violation: UDP socket should have been created in previous state Initial");
        Debug.Assert(_peerId != null, "Invariant Violation: Set by ConnectAsync before calling Next() this should still hold");
        Debug.Assert(_peerIp != null, "Invariant Violation: Set by ConnectAsync before calling Next() this should still hold");
        Debug.Assert(_peerPort >= 0, "Invariant Violation: Should have been received from server in previous state RegisteredWithServer");
        Debug.Assert(_peerEndPoint != null, "Invariant Violation: Should have been created in previous state RegisteredWithServer");

        _logger?.LogDebug("HolePunching: Closing established connection with peer");

        // If next was called on this state, then the want is to close the connection.
        await ResetForFutureConnections(); // Happy path closing!
      
        _logger?.LogDebug("HolePunching: Closed established connection with peer");
        break;

      case HolePunchingStates.Failed:
        Debug.Assert(_udpSocket != null, "Invariant Violation: UDP socket should have been created in previous state Initial");

        _logger?.LogDebug("HolePunching: Connection failed");

        // If someone calls connect again on a failed connection we can restart from initial
        await ResetForFutureConnections();

        _logger?.LogDebug("HolePunching: Reset for future connections after failure");
        break;
    }
  }

  private async Task ResetForFutureConnections()
  {
    if (_udpSocket != null)
    {
      _udpSocket.Dispose();
      _udpSocket = null;
    }

    // if state was past RegisteredWithServer we need to deregister from server as a best effort way otherwise TTL will expire our registration in worst case!
    if (CurrentState != HolePunchingStates.Initial)
    {
      await DeregisterFromServerAsync();
    }

    _registrationRetryCount = 0;
    _sendPunchRetryCount = 0;
    _waitForPeerResponseRetryCount = 0;
    _peerId = null;
    _peerIp = null;
    _peerPort = 0;
    _peerEndPoint = null!;

    CurrentState = HolePunchingStates.Initial; // Reset to initial for potential future connections
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

  private Task<(IPAddress publicIp, int publicPort)> StunRequestAsync()
  {
    Debug.Assert(_udpSocket != null, "Invariant Violation: UDP socket should have been created in previous state Initial before calling this method");
    return MinimalStunClient.GetStunPortAsync(_udpSocket, _stunServers);
  }

  protected virtual void Dispose(bool disposing)
  {
    if (!disposedValue)
    {
      if (disposing)
      {
        _udpSocket?.Dispose();
        _connectionMultiplexer.Dispose();
      }

      disposedValue = true;
    }
  }

  public void Dispose()
  {
    // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
    Dispose(disposing: true);
    GC.SuppressFinalize(this);
  }
}

// This is a minimal STUN client implementation to get public IP and port mapping from NAT
// I don't need anything else so I'm not even parsing full messages, just give me the bytes I need damn it
static class MinimalStunClient
{
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
      var buffer = new byte[512];
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

public sealed class HOPPeer : IDisposable
{
  private readonly HolePunchingStateMachine _stateMachine;

  public HOPPeer(string discoverableId, string registrationServerAddr, ILogger? logger = null)
  {
    _stateMachine = new HolePunchingStateMachine(discoverableId, registrationServerAddr, logger: logger);
  }

  public async Task<bool> ConnectAsync(string peerId)
  {
    return await _stateMachine.ConnectAsync(peerId); // use await here to propagate exceptions showing connection failure explicitly here
  }

  public int Send(ReadOnlySpan<byte> data) => _stateMachine.HolePunchedSocket.Send(data);

  public int Receive(Span<byte> buffer) => _stateMachine.HolePunchedSocket.Receive(buffer);

  public void Close() => throw new NotImplementedException();

  public void Dispose() => _stateMachine.Dispose();
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

    using ILoggerFactory loggerFactory = LoggerFactory.Create(builder => {
      builder.AddConsole(); 
      builder.SetMinimumLevel(LogLevel.Debug);
    });

    ILogger logger = loggerFactory.CreateLogger<Program>();

    using HOPPeer peer = new HOPPeer(selfIdentification, registrationServerAddr, logger);

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
          int receivedBytes = peer.Receive(receiveBuffer);
          string message = System.Text.Encoding.UTF8.GetString(receiveBuffer, 0, receivedBytes);
          Console.WriteLine($"Received{indentationOfReadMessages}{message}");
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