import eris, taps
import std/asyncfutures, std/deques, std/net, std/options

const standardPort* = 8332

proc erisTransport(): TransportProperties =
  result = newTransportProperties()
  result.prohibit("reliability")
  result.ignore("congestion-control")
  result.ignore("preserve-order")

type ErisServer* = ref object
  store: Store
  listener: Listener
  putRef, getRef: Reference

proc newErisServer*(store: Store; lp: LocalSpecifier): ErisServer =
  var
    preconn = newPreconnection(local = some(lp), transport = some(erisTransport()))
    server = ErisServer(store: store, listener: preconn.listen())
  server.listener.onConnectionReceived do (conn: Connection):
    conn.receive(32, 32 shl 10)
    conn.onReceived do (data: seq[byte]; ctx: MessageContext):
      case data.len
      of sizeOf(Reference):
        copyMem(server.getRef.bytes[0].unsafeAddr, data[0].unsafeAddr, sizeOf(Reference))
        let fut = server.store.get(0, server.getRef)
        fut.addCallback do ():
          if fut.failed:
            echo "block not found, server does not reply?"
          else:
            let blk = fut.read
            conn.send(blk, ctx)
      of 1 shl 10, 32 shl 10:
        server.putRef = reference(data)
        let putFut = server.store.put(server.putRef, data)
        putFut.addCallback do:
          conn.send(server.putRef.bytes, ctx)
      else:
        debugecho "server received strange message size ", data.len
      conn.onSent do (ctx: MessageContext):
        conn.receive(32, 32 shl 10)
          # don't request more data until it's known
          # that the putRef buffer has been copied
  server

proc newErisServer*(store: Store; hostName: string): ErisServer =
  var ep = newLocalEndpoint()
  ep.withHostname hostName
  ep.with Port(standardPort)
  newErisServer(store, ep)

proc newErisServer*(store: Store; address: IpAddress): ErisServer =
  var ep = newLocalEndpoint()
  ep.with address
  ep.with Port(standardPort)
  newErisServer(store, ep)

type
  Put = object
    f: Future[void]
    r: Reference
    b: seq[byte]
  Get = object
    f: Future[seq[byte]]
    r: Reference
  ErisClient* = ref ErisClientObj
  ErisClientObj = object of StoreObj
    conn: Connection
    ready: Future[void]
    puts: Deque[Put]
    gets: Deque[Get]

proc clientGet(s: Store; r: Reference): Future[seq[byte]] =
  var
    s = ErisClient(s)
    fut = newFuture[seq[byte]]("clientGet")
  s.gets.addLast Get(f: fut, r: r)
  callSoon:
    s.conn.send(r.bytes)
  fut

proc clientPut(s: Store; r: Reference; blk: seq[byte]): Future[void] =
  var
    s = ErisClient(s)
    fut = newFuture[void]("clientPut")
  s.puts.addLast Put(f: fut, r: r, b: blk)
  s.ready.addCallback do:
    s.conn.send(r.bytes, endOfMessage = false)
    s.conn.send(blk, endOfMessage = true)
  fut

proc newErisClient*(remote: RemoteSpecifier): ErisClient =
  var preconn = newPreconnection(
    remote = some remote,
    transport = some erisTransport())

  var client = ErisClient(
      conn: preconn.initiate(),
      ready: newFuture[void]("newErisClient"),
      puts: initDeque[Put](),
      gets: initDeque[Get]())
  client.conn.onReady do ():
    client.ready.complete()
  client.conn.onSent do (ctx: MessageContext):
    client.conn.receive(32, 32 shl 10)
  client.conn.onReceived do (data: seq[byte]; ctx: MessageContext):
    case data.len
    of 1 shl 10, 32 shl 10:
      var r = reference(data)
      for i in 0..<client.gets.len:
        if client.gets.peekFirst.r == r:
          client.gets.popFirst.f.complete(data)
          break
        else:
          client.gets.addLast client.gets.popFirst
            # resend? timeout?
    of sizeOf(Reference):
      var r: Reference
      copyMem(r.bytes[0].addr, data[0].unsafeAddr, r.bytes.len)
      for i in 0..<client.puts.len:
        if client.puts.peekFirst.r == r:
          client.puts.popFirst.f.complete()
          break
        else:
          client.puts.addLast client.puts.popFirst
            # resend? timeout?
    else:
      debugecho "server received strange server message size ", data.len
      client.conn.send("")

  result = client
  result.putImpl = clientPut
  result.getImpl = clientGet

proc newErisClient*(hostName: string): ErisClient =
  var ep = newRemoteEndpoint()
  ep.withHostname hostName
  ep.with Port(standardPort)
  newErisClient(ep)

proc newErisClient*(address: IpAddress): ErisClient =
  var ep = newRemoteEndpoint()
  ep.with address
  ep.with Port(standardPort)
  newErisClient(ep)
