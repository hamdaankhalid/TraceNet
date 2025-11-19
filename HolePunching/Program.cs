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


# region Handshake State Machine
// State machine to manage the handshake for hole punching over UDP.
// It uses Garnet/Redis as the reliable delivery mechanism to exchange control messages between peers to coordinate the hole punching process
// once it is clear that both peers have an open state, we know that connection has been established!
// We basically use UDP only for keep-alive bullets to maintain NAT mappings
// We need something that gives us ATLEAST once delivery semantics. De-dupe will make it exactly once.
// The core problem is that we need to be able to say I see your messages, and the peer needs to be able to say I see your messages too.
// Only when both sides can confirm can we move to a fully established state

enum ProtocolState : byte
{
  INITIAL, // we have not yet seen any peer state
  SEEN_PEER_STATE, // this is reached when it sees peer's udp messages get in via UDP. It then publishes to state store that it sees peer at this session
  ESTABLISHED_CONNECTION
}

class HandshakeStateMachine
{
  private const int MAX_ATTEMPTS = 5;
  private static string STATE_STORE_KEY_PREFIX = "HolePunching:SynAckStateMachine:";

  // borrowed socket from HolePunchingStateMachine. DO NOT DISPOSE
  private readonly Socket _udpSocket;
  private readonly int _mySessionId;

  // borrowed conn mux, DO NOT DISPOSE
  private readonly IConnectionMultiplexer _connectionMultiplexer;
  private readonly string _mySessionStateStoreKey;
  private readonly string _peerSessionStateStoreKey;
  private readonly EndPoint _peerEndPoint;
  private readonly ILogger? _logger;
  private readonly byte[] _internalRecvBuffer = new byte[6 * 10]; // 1 byte type + 4 bytes sessionId + 1 byte seq = 6 bytes per packet, buffer holds 6 packets
  private readonly byte[] _internalSendBuffer = new byte[6]; // 1 byte type + 4 bytes sessionId + 1 byte seq
  private readonly bool _isA;

  // Non-readonly fields
  private ProtocolState _currentState = ProtocolState.INITIAL;
  private int _attemptCount = 0;

  // Sequence numbers for detecting duplicates and old packets (de-dupe and ordering)
  private int _peerSessionId = 0; // peer session id is mutable since if peer session id changes we need to rollback our state machine to match with theirs
  private byte _mySeq;
  private byte _peerSeq;

  public ProtocolState CurrentState => _currentState;

  public HandshakeStateMachine(string selfId, string peerId, int sessionId, Socket udpSocket, EndPoint peerEndPoint, ILogger? logger, IConnectionMultiplexer connectionMultiplexer)
  {
    _udpSocket = udpSocket;
    _peerEndPoint = peerEndPoint;
    _logger = logger;
    _mySessionId = sessionId;
    _connectionMultiplexer = connectionMultiplexer;
    _isA = selfId.CompareTo(peerId) < 0; // just a way to deterministically decide roles and

    // create and store the strings so as to not have to create per calll
    _mySessionStateStoreKey = $"{STATE_STORE_KEY_PREFIX}/{selfId}/{peerId}"; // I can ONLY write to this
    _peerSessionStateStoreKey = $"{STATE_STORE_KEY_PREFIX}/{peerId}/{selfId}"; // I can ONLY read from this. This read write separation means no concurrent write data races can occur
  }

  // As long as the state machine is kept active we actually want to keep sending bullets
  public void Next()
  {
    ShootNatPenetrationBullets(1); // 3 bullets per state call to keep NAT mappings alive
    PublishViewToPeer();
    ShootNatPenetrationBullets(1); // 3 bullets per state call to keep NAT mappings alive
    // UDP is only kept for hole punching keep-alive bullets, only once the established state is reached should UDP be used for actual data transfer
    bool gotNewPeerBullets = TryReadNatPenetrationBullets();
    ShootNatPenetrationBullets(1); // 3 bullets per state call to keep NAT mappings alive
    // read penetration bullets that could have been sent by peer. This will be used to make sure
    bool readPeerView = TryReadPeerView(out int peerSessionId, out int ourSessionIdViewedByPeer);

    // we have seen peer's udp messages get in via UDP. It then publishes to state store that it sees peer at this session
    _logger?.LogDebug("HandshakeStateMachine: Publishing {isA} view to peer {mySessionId} {peerSessionId}", _isA ? "A" : "B", _mySessionId, _peerSessionId);


    _logger?.LogDebug("HandshakeStateMachine: Read peer view from state store PeerSessionId: {PeerSessionId}, {PeersViewOfOurSessionId}",
      peerSessionId, ourSessionIdViewedByPeer);

    switch (_currentState)
    {
      case ProtocolState.INITIAL:
        {
          if (_attemptCount >= MAX_ATTEMPTS)
          {
            throw new TimeoutException("Max retries reached");
          }

          if (!gotNewPeerBullets)
          {
            _logger?.LogDebug("HandshakeStateMachine: No valid UDP bullets received from peer");
            // have not yet seen any peer state
            _attemptCount++;
            break;
          }

          _currentState = ProtocolState.SEEN_PEER_STATE;

          break;
        }
      case ProtocolState.SEEN_PEER_STATE:
        {
          // if the recvd bullets are from the same session who has posted state, that same session must be live right now, and if the live session can confirm that it sees us!
          // we can establish that a bidirectionally viewable UDP channel has been established.
          if (gotNewPeerBullets && readPeerView)
          {

            if (peerSessionId == _peerSessionId && ourSessionIdViewedByPeer == _mySessionId)
            {
              _currentState = ProtocolState.ESTABLISHED_CONNECTION;
              return;
            }
            else
            {
              _logger?.LogDebug(
                "HandshakeStateMachine: PeerSessionId: {PeerSessionId}, OurViewOfPeerSession: {OurViewOfPeerSession}, PeerViewOfOurSeesionId: {PeerViewOfOurSeesionId} OurSessionId: {OurSessionId}",
                  peerSessionId, ourSessionIdViewedByPeer, ourSessionIdViewedByPeer, _mySessionId);
            }
          }
          else
          {
            _logger?.LogDebug("HandshakeStateMachine: {reason}", gotNewPeerBullets ? "Failed to read peer view from state store" : "No valid UDP bullets received from peer");
          }

          _attemptCount++;
          _currentState = ProtocolState.INITIAL;
          break;
        }
      case ProtocolState.ESTABLISHED_CONNECTION:
        // nothing to do here, connection is established
        // if we are in established connection state, we should drop the bullets
        break;
    }
  }

  // send reliable state delivery to peer over common infra
  private void PublishViewToPeer()
  {
    // what is my session id, what is the session Id I saw of peers
    // A writes their session ID high (upper 32 bits), B writes their session ID low (lower 32 bits)
    long view;
    if (_isA)
    {
      view = ((long)_mySessionId << 32) | (uint)_peerSessionId;
    }
    else
    {
      view = ((long)_peerSessionId << 32) | (uint)_mySessionId;
    }

    IDatabase db = _connectionMultiplexer.GetDatabase();
    db.Execute("SET", _mySessionStateStoreKey, view, "EX", 30); // expire after 60 seconds to avoid stale state
  }

  private bool TryReadPeerView(out int peerSessionId, out int ourSessionIdViewedByPeer)
  {
    peerSessionId = 0;
    ourSessionIdViewedByPeer = 0;
    IDatabase db = _connectionMultiplexer.GetDatabase();
    RedisResult res = db.Execute("GET", _peerSessionStateStoreKey);
    if (res.IsNull)
    {
      return false;
    }
    long stateLong = (long)res;
    if (_isA)
    {
      ourSessionIdViewedByPeer = (int)((stateLong >> 32) & 0xFFFFFFFF);
      peerSessionId = (int)(stateLong & 0xFFFFFFFF);
    }
    // low bits belong to peerB
    else
    {
      peerSessionId = (int)((stateLong >> 32) & 0xFFFFFFFF);
      ourSessionIdViewedByPeer = (int)(stateLong & 0xFFFFFFFF);
    }

    return true;
  }

  private void ShootNatPenetrationBullets(int numBullets)
  {
    _mySeq++;
    _internalSendBuffer[0] = (byte)1; // 1 represents bullet
    // Pack int sessionId into 4 bytes (big-endian)
    _internalSendBuffer[1] = (byte)(_mySessionId >> 24);
    _internalSendBuffer[2] = (byte)(_mySessionId >> 16);
    _internalSendBuffer[3] = (byte)(_mySessionId >> 8);
    _internalSendBuffer[4] = (byte)_mySessionId;
    _internalSendBuffer[5] = _mySeq; // used to make sure when read a buffer we can find the latest udp message!
    for (int i = 0; i < numBullets; i++)
    {
      _udpSocket.SendTo(_internalSendBuffer, SocketFlags.None, _peerEndPoint);
    }
  }

  // reads and updates state for what it sees from peer
  private bool TryReadNatPenetrationBullets()
  {
    if (!_udpSocket.Poll(250_000, SelectMode.SelectRead))
    {
      // timed out, did not receive any bullets
      _logger?.LogDebug("HandshakeStateMachine: No UDP bullets received from peer within timeout");
      _peerSessionId = 0; // semantically this means we don't see any valid peer bullets
      return false;
    }

    EndPoint remoteEP = new IPEndPoint(IPAddress.Any, 0);
    int receivedBytes = _udpSocket.ReceiveFrom(_internalRecvBuffer, ref remoteEP);
    if (receivedBytes % 6 != 0)
    {
      // invalid packet
      _logger?.LogError("HandshakeStateMachine: Invalid UDP bullet packet received with size not multiple of 6");
      return false;
    }

    if (receivedBytes < 6)
    {
      // invalid packet
      _logger?.LogError("HandshakeStateMachine: Invalid UDP bullet packet received with size less than 6 bytes");
      return false;
    }

    bool gotSomeValidInfo = false;
    for (int i = 0; i < receivedBytes; i += 6)
    {
      byte packetType = _internalRecvBuffer[i];
      // Unpack int sessionId from 4 bytes (big-endian)
      int sessionId = (_internalRecvBuffer[i + 1] << 24) |
                      (_internalRecvBuffer[i + 2] << 16) |
                      (_internalRecvBuffer[i + 3] << 8) |
                      _internalRecvBuffer[i + 4];
      byte seqNum = _internalRecvBuffer[i + 5];

      if (packetType != 1 || seqNum <= _peerSeq)
      {
        continue;
      }

      // new bullet packet. If this says that the session has changed we need to tell the state store that we see B at this session Id now!
      _logger?.LogDebug("HandshakeStateMachine: Received UDP bullet packet - Type: {PacketType}, SessionId: {SessionId}, SeqNum: {SeqNum}",
        packetType, sessionId, seqNum);

      _peerSessionId = sessionId;
      _peerSeq = seqNum; // update that we see this new sequence number
      gotSomeValidInfo = true;
    }

    return gotSomeValidInfo;
  }
}

#endregion

#region HolePunching State Machine

enum HolePunchingState
{
  // move to RegisteredWithServer by contacting STUN server and registering with registration server
  INITIAL = 0,
  // check if peer has also registered, if not retry till max retries reached, then move to ReceivedPeerInfo. If max retries reached move to Closed
  REGISTRATION_WITH_SERVER,
  // try to do hole punching by sending packets to peer's external IP:port, move to EstablishedConnection on success else refetch peer info and retry (move back to RegisteredWithServer)
  // if max retries reached move to Closed
  RECEIVED_PEER_INFO,
  // connection established, can now use the UDP socket for communication, if Next() is called again, move to Closed
  ESTABLISHED_CONNECTION,
  // perform cleanup of resources and deregister from server, then move back to Initial for potential future connections
  CLOSED,
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

  // Session lifetime for registration with server, after these minutes the server will evict our registration
  // this will not impact active connections but will require re-registration for future connections
  private const int SESSION_LIFETIME_MINS = 10;

  // Non-static fields
  private readonly IConnectionMultiplexer _connectionMultiplexer;
  private readonly string _selfId;
  private readonly int _maxRetryCount;
  private readonly ILogger? _logger;


  // State - Mutable fields 
  private int _registrationRetryCount;
  private int _handshakeRetryCount;
  private IPAddress? _peerIp;
  private string? _peerId;
  private int _peerPort;
  // used to handle synchronization when 2 peers are in 2 different states in the SynAck state machine
  private int _sessionId;
  internal IPEndPoint? _peerEndPoint;
  private Socket? _udpSocket;

  // IDisposable support
  private bool _isDisposed;

  private HolePunchingState CurrentState { get; set; } = HolePunchingState.INITIAL;

  // This is the primary inteface to get the hole punched socket once connection is established
  // The user should not dispose this socket, it will be disposed when the state machine is disposed
  public Socket HolePunchedSocket
  {
    get
    {
      if (CurrentState != HolePunchingState.ESTABLISHED_CONNECTION)
      {
        throw new InvalidOperationException("Connection not yet established.");
      }
      Debug.Assert(_udpSocket != null);
      return _udpSocket;
    }
  }

  public HolePunchingStateMachine(string selfId, string registrationServerAddr, int maxRetryCount = 60, ILogger? logger = null)
  {
    ArgumentOutOfRangeException.ThrowIfNegative(maxRetryCount);

    ConfigurationOptions options = ConfigurationOptions.Parse(registrationServerAddr);

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
    if (CurrentState != HolePunchingState.INITIAL)
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
        currentState, nextState, _registrationRetryCount, _handshakeRetryCount);
    }
    while (nextState != HolePunchingState.ESTABLISHED_CONNECTION && nextState != HolePunchingState.INITIAL);

    return CurrentState == HolePunchingState.ESTABLISHED_CONNECTION;
  }

  public async Task CloseAsync()
  {
    // Connection should have already been in EstablishedConnection state for close to be viable
    if (CurrentState != HolePunchingState.ESTABLISHED_CONNECTION)
    {
      throw new InvalidOperationException("Connection not yet established.");
    }

    HolePunchingState currentState = CurrentState;
    await Next(); // Move to Closed state and cleanup
    _logger?.LogDebug("HolePunching State Transition: {CurrentState} => state {NextState}, retry count {RegistrationRetryCount}, send punch retry count {SendPunchRetryCount}",
      currentState, CurrentState, _registrationRetryCount, _handshakeRetryCount);
  }

  // Advance the state machine to the next state returning the new state
  private async Task<HolePunchingState> Next()
  {
    switch (CurrentState)
    {
      case HolePunchingState.INITIAL: // At this stage we don't have an active UDP socket yet and have not registered our ephemeral port with server since we don't know it yet
        Debug.Assert(_peerId != null, "Invariant Violation: Set by ConnectAsync before calling Next()");
        Debug.Assert(_udpSocket == null, "Invariant Violation: No UDP socket should exist in initial state");
        Debug.Assert(_peerIp == null, "Invariant Violation: if we have not yet received peer info from server this should still be null");
        Debug.Assert(_peerPort == 0, "Invariant Violation: Will be set once we get peer info from server so currenty should be 0");
        Debug.Assert(_peerEndPoint == null, "Invariant Violation: Will be set once we get peer info from server so currenty should be null");
        Debug.Assert(_registrationRetryCount == 0, "Invariant Violation: Retry count should be 0 in initial state");
        Debug.Assert(_handshakeRetryCount == 0, "Invariant Violation: Send punch retry count should be 0 in initial state");

        _logger?.LogDebug("HolePunching: Initializing UDP socket and registering with server");

        // Initialize UDP socket and register self and port with server
        _sessionId = Random.Shared.Next();
        _udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

        // Make sure we are not behing a NAT that is symmetric otherwise hole punching will likely fail
        if (await MinimalStunClient.IsSymmetricNatAsync(_udpSocket, STUN_SERVERS))
        {
          _logger?.LogError("HolePunching: Symmetric NAT detected, hole punching will fail");
          CurrentState = HolePunchingState.CLOSED;
          break;
        }

        // get which is the port the above socket is bound to externally via NAT using STUN
        (IPAddress publicIp, int ephemeralPort) = await MinimalStunClient.GetStunPortAsync(_udpSocket, STUN_SERVERS);

        _logger?.LogDebug("HolePunching: Discovered public IP {PublicIP} and port {PublicPort} via STUN", publicIp, ephemeralPort);
        await RegisterWithServerAsync(publicIp, ephemeralPort); // Let any failure in registration propagate up, redis stack exchange client should have already retried internally if needed

        CurrentState = HolePunchingState.REGISTRATION_WITH_SERVER;
        break;
      case HolePunchingState.REGISTRATION_WITH_SERVER:
        Debug.Assert(_udpSocket != null, "Invariant Violation: UDP socket should have been created in previous state Initial");
        Debug.Assert(_peerId != null, "Invariant Violation: Set by ConnectAsync before calling Next() this should still hold");
        Debug.Assert(_peerIp == null, "Invariant Violation: if we have not yet received peer info from server this should still be null");
        Debug.Assert(_peerPort == 0, "Invariant Violation: Will be set once we get peer info from server so currenty should be 0");
        Debug.Assert(_peerEndPoint == null, "Invariant Violation: Will be set once we get peer info from server so currenty should be null");

        if (_registrationRetryCount >= _maxRetryCount)
        {
          // Exceeded max retries, mark as failed
          CurrentState = HolePunchingState.CLOSED;
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
        CurrentState = HolePunchingState.RECEIVED_PEER_INFO;
        break;

      case HolePunchingState.RECEIVED_PEER_INFO:
        Debug.Assert(_udpSocket != null, "Invariant Violation: UDP socket should have been created in previous state Initial");
        Debug.Assert(_peerIp != null, "Invariant Violation: Set by ConnectAsync before calling Next() this should still hold");
        Debug.Assert(_peerId != null, "Invariant Violation: Set by ConnectAsync before calling Next() this should still hold");
        Debug.Assert(_peerPort >= 0, "Invariant Violation: Should have been received from server in previous state RegisteredWithServer");
        Debug.Assert(_peerEndPoint != null, "Invariant Violation: Should have been created in previous state RegisteredWithServer");

        if (_handshakeRetryCount >= _maxRetryCount)
        {
          // Exceeded max retries, mark as failed
          CurrentState = HolePunchingState.CLOSED;
          _logger?.LogDebug("HolePunching: Exceeded max retries, marking as failed");
          break;
        }

        _logger?.LogDebug("HolePunching: Attempting hole punching synchronization with peer at {PeerEndPoint}", _peerEndPoint);

        bool connected = false;
        try
        {
          // Based on role assignemnt create appropriate state machine
          HandshakeStateMachine stateMachine = new HandshakeStateMachine(_selfId, _peerId, _sessionId, _udpSocket, _peerEndPoint, _logger, _connectionMultiplexer);

          while (stateMachine.CurrentState != ProtocolState.ESTABLISHED_CONNECTION)
          {
            stateMachine.Next();
            await Task.Delay(Random.Shared.Next(100, 150)); // small delay to avoid tight loop
          }
          connected = true;
        }
        catch (TimeoutException)
        {
        }

        if (!connected)
        {
          _sessionId++; // increment session id for next attempt
          _handshakeRetryCount++;
          // Peer may not have registered yet
          // retry sending punch packet by moving one level back on state where we will reget Peer's info and resend punch packet incase the first was not received
          _peerEndPoint = null!; // reset peer endpoint to force re-creation
          _peerIp = null;
          _peerPort = 0;
          CurrentState = HolePunchingState.REGISTRATION_WITH_SERVER;
          _logger?.LogDebug("HolePunching: Did not receive response from peer, retrying...");
          break;
        }

        // Successfully received response from peer
        _handshakeRetryCount = 0;
        CurrentState = HolePunchingState.ESTABLISHED_CONNECTION;
        break;

      case HolePunchingState.ESTABLISHED_CONNECTION:
        Debug.Assert(_udpSocket != null, "Invariant Violation: UDP socket should have been created in previous state Initial");
        Debug.Assert(_peerId != null, "Invariant Violation: Set by ConnectAsync before calling Next() this should still hold");
        Debug.Assert(_peerIp != null, "Invariant Violation: Set by ConnectAsync before calling Next() this should still hold");
        Debug.Assert(_peerPort >= 0, "Invariant Violation: Should have been received from server in previous state RegisteredWithServer");
        Debug.Assert(_peerEndPoint != null, "Invariant Violation: Should have been created in previous state RegisteredWithServer");

        CurrentState = HolePunchingState.CLOSED;
        break;

      case HolePunchingState.CLOSED:
        Debug.Assert(_udpSocket != null, "Invariant Violation: UDP socket should have been created in previous state Initial");

        // If next was called on this state, then the want is to close the connection.
        // if state was past RegisteredWithServer we need to deregister from server as a best effort way otherwise TTL will expire our registration in worst case!
        if (CurrentState != HolePunchingState.INITIAL)
        {
          await DeregisterFromServerAsync();
        }

        if (_udpSocket != null)
        {
          _udpSocket.Dispose();
          _udpSocket = null;
        }

        _registrationRetryCount = 0;
        _handshakeRetryCount = 0;
        _peerId = null;
        _peerIp = null;
        _peerPort = 0;
        _peerEndPoint = null!;

        CurrentState = HolePunchingState.INITIAL;
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
      if (CurrentState == HolePunchingState.ESTABLISHED_CONNECTION)
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
  public static async Task<bool> IsSymmetricNatAsync(Socket udpSocket, string[] stunServers)
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

      IPAddress ipAddress = Dns.GetHostAddresses(host).First((x) => x.AddressFamily == AddressFamily.InterNetwork);
      IPEndPoint serverEndPoint = new IPEndPoint(ipAddress, port);

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
    _stateMachine = new HolePunchingStateMachine(discoverableId, registrationServerAddr, maxRetryCount: 200, logger: logger);
  }

  public async Task<bool> ConnectAsync(string peerId)
  {
    return await _stateMachine.ConnectAsync(peerId); // use await here to propagate exceptions showing connection failure explicitly here
  }

  public int Send(ReadOnlySpan<byte> data)
  {
    lock (_socketLock)
    {
      return _stateMachine.HolePunchedSocket.SendTo(data, SocketFlags.None, _stateMachine._peerEndPoint!);
    }
  }

  public int Receive(Span<byte> buffer, int receiveTimeoutMs = 250)
  {
    lock (_socketLock)
    {
      if (!_stateMachine.HolePunchedSocket.Poll(receiveTimeoutMs * 1_000, SelectMode.SelectRead))
        return 0;

      EndPoint tempEndPoint = _stateMachine._peerEndPoint!;
      return _stateMachine.HolePunchedSocket.ReceiveFrom(buffer, SocketFlags.None, ref tempEndPoint);
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

    string indentationOfReadMessages = new string('\t', 2);
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