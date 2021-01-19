import eris, taps
import std/asyncfutures, std/deques, std/net, std/options

const standardPort* = 2021

proc erisTransport(): TransportProperties =
  ## A UDP transport profile
  result = newTransportProperties()
  result.ignore("reliability")
  result.ignore("congestion-control")
  result.ignore("preserve-order")

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
  ErisBrokerObj = object of StoreObj
    ## Networked block broker object
    store: Store
    listener: Listener
    ready: Future[void]
    gets: Deque[Get]
      # Pending operations
    peers: seq[Peer]
      # Known peers

using
  broker: ErisBroker
  peer: Peer

proc brokerPut(s: Store; r: Reference; blk: seq[byte]): Future[void] =
  var s = ErisBroker(s)
  s.store.put(r, blk)

proc brokerGet(s: Store; r: Reference): Future[seq[byte]] =
  var
    s = ErisBroker(s)
    rf = newFuture[seq[byte]]("brokerGet")
  s.store.get(r).addCallback do (lf: Future[seq[byte]]):
    if not lf.failed:
      rf.complete(lf.read())
    else:
      assert(s.peers.len > 0)
      let peer = s.peers[0]
      peer.ready.addCallback do ():
        s.gets.addLast Get(f: rf, r: r, p: peer)
        peer.conn.send(s.gets.peekLast.r.bytes)
  rf

proc initializeConnection(broker; conn: Connection; serving: bool) =
  ## Initialize a ``Broker`` ``Connection``.
  conn.onSent do (ctx: MessageContext):
    conn.receiveMsg()
      # alternate between sending and receiving datagrams
  conn.onReceived do (data: seq[byte]; ctx: MessageContext):
    # Dispatch a received datagram
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

proc newErisBroker*(store: Store; lp: LocalSpecifier): ErisBroker =
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

proc newErisBroker*(store: Store; hostName: string): ErisBroker =
  var ep = newLocalEndpoint()
  ep.withHostname hostName
  ep.with Port(standardPort)
  newErisBroker(store, ep)

proc newErisBroker*(store: Store; address: IpAddress): ErisBroker =
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
  peer.conn.onReady do ():
    peer.ready.complete()
  initializeConnection(broker, peer.conn, serving = false)
  broker.peers.add(peer)

proc addPeer*(broker; address: IpAddress) =
  var ep = newRemoteEndpoint()
  ep.with address
  ep.with Port(standardPort)
  broker.addPeer(ep)
