import eris, taps
import std/asyncfutures, std/deques, std/net, std/options

const
  standardPort* = 2021
  erisStandardPort* = Port(2021)

proc erisTransport(): TransportProperties =
  ## A TCP transport profile
  result = newTransportProperties()
  result.require("congestion-control")
  result.require("preserve-order")
  result.require("reliability")

proc receiveMsg(conn: Connection) {.inline.} =
  ## Receive a message that is between 32B and 32KiB.
  conn.receive(32, 32 shl 10)

type
  Peer = ref object
    ## Peer broker object
    conn: Connection
    ready: Future[void]

  Get = object
    ## Get operation state
    f: Future[seq[byte]]
    r: Reference
    p: Peer

  ErisBroker* = ref ErisBrokerObj
  ErisBrokerObj = object of ErisStoreObj
    ## Networked block broker object
    store: ErisStore
    listener: Listener
    ready: Future[void]
    gets: Deque[Get]
      # Pending operations
    peers: seq[Peer]
      # Known peers

using
  broker: ErisBroker
  peer: Peer

proc brokerPut(s: ErisStore; r: Reference; blk: seq[byte]): Future[void] =
  var s = ErisBroker(s)
  s.store.put(r, blk)

proc brokerGet(s: ErisStore; r: Reference): Future[seq[byte]] =
  var
    s = ErisBroker(s)
    rf = newFuture[seq[byte]]("brokerGet")
  s.store.get(r).addCallback do (lf: Future[seq[byte]]):
    if not lf.failed:
      let blk = lf.read()
      rf.complete(blk)
    else:
      if s.peers.len > 0:
        let peer = s.peers[0]
        echo "got a peer, wait for ready callback"
        peer.ready.addCallback do ():
          echo "peer is ready, request ", r
          s.gets.addLast Get(f: rf, r: r, p: peer)
          peer.conn.send(s.gets.peekLast.r.bytes)
      else:
        rf.fail(newException(IOError, "no peers to request data from"))
  rf

proc initializeConnection(broker; conn: Connection; serving: bool) =
  ## Initialize a ``Broker`` ``Connection``.
  conn.onSent do (ctx: MessageContext):
    conn.receiveMsg()
      # alternate between sending and receiving datagrams
  conn.onReceived do (data: seq[byte]; ctx: MessageContext):
    # Dispatch a received datagram
    echo "received a ", data.len, " byte message from peer"
    case data.len
    of sizeof(Reference):
      var r: Reference
      copyMem(r.bytes[0].addr, data[0].unsafeAddr, r.bytes.len)
      if serving:
        broker.store.get(r).addCallback do (fut: Future[seq[byte]]):
          if fut.failed:
            conn.send(r.bytes, ctx)
              # failed: send the reference back
          else:
            conn.send(fut.read, ctx)
              # success: send the block back
      else:
        # peer will not send the block
        for i in 0..<broker.gets.len:
          if broker.gets.peekFirst.r == r:
            let getOp = broker.gets.popFirst()
            getOp.f.fail(newException(KeyError, "ERIS block not held by peer"))
          else:
            broker.gets.addLast(broker.gets.popFirst())
    of 1 shl 10, 32 shl 10:
      # A block was sent, complete any pending get
      # requests with it
      var r = reference(data)
      for i in 0..<broker.gets.len:
        if broker.gets.peekFirst.r == r:
          let getOp = broker.gets.popFirst()
          broker.store.put(r, data).addCallback do (f: Future[void]):
            # Complete the request after the
            # block is put into the local store
            if f.failed:
              getOp.f.fail(f.error)
            else:
              getOp.f.complete(data)
          break
        else:
          broker.gets.addLast(broker.gets.popFirst())
            # resend? timeout?
    else:
      conn.abort()

proc newErisBroker*(store: ErisStore; lp: LocalSpecifier): ErisBroker =
  # Create a new ERIS network broker.
  var
    preconn = newPreconnection(local = some(lp), transport = some(erisTransport()))
    broker = ErisBroker(
        store: store,
        listener: preconn.listen(),
        ready: newFuture[void]("newErisClient"),
        gets: initDeque[Get](),
        putImpl: brokerPut,
        getImpl: brokerGet)
  broker.listener.onConnectionReceived do (conn: Connection):
    initializeConnection(broker, conn, serving = true)
    conn.receiveMsg()
  broker

proc newErisBroker*(store: ErisStore; hostName: string): ErisBroker =
  var ep = newLocalEndpoint()
  ep.withHostname hostName
  ep.with Port(standardPort)
  newErisBroker(store, ep)

proc newErisBroker*(store: ErisStore; address: IpAddress): ErisBroker =
  var ep = newLocalEndpoint()
  ep.with address
  ep.with Port(standardPort)
  newErisBroker(store, ep)

proc addPeer*(broker; remote: RemoteSpecifier) =
  # TODO: check if the peer is already stored
  var
    preconn = newPreconnection(
        remote = some remote,
        transport = some erisTransport())
    peer = Peer(conn: preconn.initiate(), ready: newFuture[void]("addPeer"))
  echo "connection intiated with ", remote
  peer.conn.onReady do ():
    echo "connection ready"
    peer.ready.complete()
  initializeConnection(broker, peer.conn, serving = false)
  broker.peers.add(peer)

proc addPeer*(broker; address: IpAddress) =
  var ep = newRemoteEndpoint()
  ep.with address
  ep.with Port(standardPort)
  broker.addPeer(ep)

proc close*(broker) =
  ## Shutdown ``broker``.
  assert(not broker.listener.isNil)
  stop(broker.listener)
  for peer in broker.peers:
    close(peer.conn)
  reset(broker.peers)
