# SPDX-FileCopyrightText: 2020 Emery Hemingway
#
# SPDX-License-Identifier: ISC

import base32, eris/private/chacha20/src/chacha20, eris/private/blake2/blake2

import asyncdispatch, asyncfutures, math, streams, strutils

const erisCborTag* = 276

type
  Reference* = object
    bytes*: array[32, byte]
  Key* = object
    bytes*: array[32, byte]
  Secret* = object
    bytes*: array[32, byte]
  Pair {.packed.} = object
    r*: Reference
    k*: Key
  Cap* = object
    pair*: Pair
    level*: int
    blockSize*: int

using
  key: Key
  secret: Secret
  pair: Pair
  cap: Cap

assert(sizeOf(Pair) == 64)

proc `$`*(x: Reference|Key|Secret): string =
  base32.encode(cast[array[32, char]](x.bytes), pad = false)

proc `==`*(x, y: Cap): bool = x.pair.r.bytes == y.pair.r.bytes

proc reference*(data: openarray[byte]): Reference =
  assert(data.len in {1 shl 10, 32 shl 10})
  var ctx: Blake2b
  ctx.init(32)
  ctx.update(data)
  ctx.final(result.bytes)

proc toBase32*(cap): string =
  var tmp = newSeqOfCap[byte](1+1+32+32)
  let bs =
    case cap.blockSize
    of 1 shl 10: 0x00'u8
    of 32 shl 10: 0x01'u8
    else: raiseAssert "invalid block size"
  tmp.add bs
  tmp.add cap.level.uint8
  tmp.add cap.pair.r.bytes
  tmp.add cap.pair.k.bytes
  base32.encode(cast[seq[char]](tmp), pad = false)

proc `$`*(cap): string =
  "urn:erisx2:" & cap.toBase32

proc parseSecret*(s: string): Secret =
  var buf = base32.decode(s)
  if buf.len != result.bytes.len:
    raise newException(Defect, "invalid convergence-secret")
  copyMem(result.bytes[0].addr, buf[0].addr, result.bytes.len)

proc parseCap*(bin: openArray[char]): Cap =
  assert(bin.len == 66)
  result.blockSize =
    case bin[0].byte
    of 0x00: 1 shl 10
    of 0x01: 32 shl 10
    else: raise newException(Defect, "invalid ERIS block size")
  result.level = int(bin[1])
  if result.level < 0 or 255 < result.level:
    raise newException(Defect, "invalid ERIS root level")
  copyMem(addr result.pair.r.bytes[0], unsafeAddr bin[2], 32)
  copyMem(addr result.pair.k.bytes[0], unsafeAddr bin[34], 32)

proc parseErisUrn*(urn: string|TaintedString): Cap =
  let parts = urn.split(':')
  if 3 <= parts.len:
    if parts[0] == "urn":
      if parts[1] == "erisx2":
        if parts[2].len >= 106:
          let bin = base32.decode(parts[2][0..105])
          return parseCap(bin)
  raise newException(Defect, "invalid ERIS URN encoding")

proc encryptBlock(secret; blk: seq[byte]): tuple[pair: Pair; blk: seq[byte]] =
  var
    ctx: Blake2b
    nonce: Nonce
  result[1] = newSeq[byte](blk.len)
  ctx.init(32, secret.bytes)
  ctx.update(blk)
  ctx.final(result[0].k.bytes)
  discard chacha20(result[0].k.bytes, nonce, 0, blk, result[1])
  ctx.init(32)
  ctx.update(result[1])
  ctx.final(result[0].r.bytes)

proc decryptBlock(secret; key; result: var seq[byte]) =
  var
    ctx: Blake2b
    nonce: Nonce
  discard chacha20(key.bytes, nonce, 0, result, result)
  ctx.init(32, secret.bytes)
  ctx.update(result)
  let digest = ctx.final()
  if digest != key.bytes:
    raise newException(IOError, "ERIS block failed verification")

proc unpad(blk: seq[byte]): seq[byte] =
  assert(blk.len in {1 shl 10, 32 shl 10})
  for i in countdown(blk.high, blk.low):
    case blk[i]
    of 0x00: discard
    of 0x80: return blk[0..pred(i)]
    else: break
  raise newException(IOError, "invalid ERIS block padding")

type
  ErisStore* = ref ErisStoreObj
  ErisStoreObj* = object of RootObj
    getImpl*: proc (s: ErisStore; r: Reference): Future[seq[byte]] {.nimcall, gcsafe.}
    putImpl*: proc (s: ErisStore; r: Reference; b: seq[byte]): Future[void] {.
        nimcall, gcsafe.}

using store: ErisStore

proc discardPut(store; r: Reference; b: seq[byte]): Future[void] =
  result = newFuture[void]("discardPut")
  result.complete()

proc discardGet(store; r: Reference): Future[seq[byte]] =
  result = newFuture[seq[byte]]("discardGet")
  result.fail(newException(KeyError, "ERIS reference not found"))

proc newDiscardStore*(): ErisStore =
  new(result)
  result.putImpl = discardPut
  result.getImpl = discardGet

proc put*(store; r: Reference; b: seq[byte]): Future[void] =
  assert(not store.putImpl.isNil)
  store.putImpl(store, r, b)

proc put*(store; blk: seq[byte]; secret = Secret()): Future[Pair] {.async.} =
  let (pair, buf) = encryptBlock(secret, blk)
  await store.put(pair.r, buf)
  return pair

proc get*(store; r: Reference): Future[seq[byte]] =
  assert(not store.getImpl.isNil)
  store.getImpl(store, r)

proc get*(store; blockSize: Natural; pair; secret = Secret()):
    Future[seq[byte]] {.async.} =
  var blk = await get(store, pair.r)
  assert(blk.len == blockSize)
  decryptBlock(secret, pair.k, blk)
  return blk

proc get*(store; cap): Future[seq[byte]] = get(store, cap.pair.r)

proc splitContent(store; blockSize: Natural; secret; content: Stream):
    Future[seq[Pair]] {.async.} =
  var
    pairs = newSeq[Pair]()
    blk = newSeq[byte](blockSize)
    padded = false
  var count = 0
  while not content.atEnd:
    blk.setLen content.readData(blk[0].addr, blk.len)
    assert(blk.len <= blockSize)
    if unlikely(blk.len < blockSize):
      let i = blk.len
      inc count
      blk.setLen(blockSize)
      blk[i] = 0x80
      padded = true
    pairs.add(await store.put(blk, secret))
  if not padded:
    blk.setLen(1) # zero all but the first byte
    blk[0] = 0x80
    blk.setLen(blockSize)
    pairs.add(await store.put(blk, secret))
  return pairs

proc collectRkPairs(store; blockSize: Natural; secret; pairs: seq[Pair]):
    Future[seq[Pair]] {.async.} =
  let arity = blockSize div 64
  var
    next = newSeqOfCap[Pair](pairs.len div 2)
    blk = newSeq[byte](blockSize)
  for i in countup(0, pairs.high, arity):
    let
      pairCount = min(arity, pairs.len - i)
      byteCount = pairCount * sizeof(Pair)
    blk.setLen(byteCount)
    copyMem(blk[0].addr, pairs[i].unsafeAddr, byteCount)
    blk.setLen(blockSize)
    var (pair, buf) = encryptBlock(secret, blk)
    await store.put(pair.r, buf)
    next.add(pair)
  assert(next.len > 0)
  return next

proc encode*(store; blockSize: Natural; content: Stream; secret = Secret()):
    Future[Cap] {.async.} =
  var
    cap = Cap(blockSize: blockSize)
    pairs = await splitContent(store, blockSize, secret, content)
  while pairs.len > 1:
    pairs = await collectRkPairs(store, blockSize, secret, pairs)
    inc(cap.level)
  cap.pair = pairs[0]
  return cap

proc encode*(store; blockSize: Natural; content: string; secret = Secret()): Future[Cap] =
  encode(store, blockSize, newStringStream(content), secret)

proc erisCap*(blockSize: Natural; secret; content: string): Cap =
  var store = newDiscardStore()
  waitFor encode(store, blockSize, newStringStream(content), secret)
    # DiscardStore will complete this immediately

iterator rk(blk: openarray[byte]): Pair =
  let buf = cast[ptr UncheckedArray[Pair]](blk[0].unsafeAddr)
  block loop:
    for i in countup(0, blk.high, 64):
      block EndCheck:
        for j in i..(i + 63):
          if blk[j] != 0: break EndCheck
        break loop
      yield buf[i div 64]

proc decodeRecursive(store; blockSize: Natural; secret; level: Natural; pair;
    buf: var seq[byte]): Future[void] {.async.} =
  var blk = await store.get(blockSize, pair, secret)
  if level == 0:
    buf.add(blk)
  else:
    for pair in blk.rk:
      await decodeRecursive(store, blockSize, secret, level.pred, pair, buf)

proc decode*(store; cap; secret = Secret()): Future[seq[byte]] {.async.} =
  var buf = newSeq[byte]()
  await decodeRecursive(store, cap.blockSize, secret, cap.level, cap.pair, buf)
  return unpad(buf)

type
  ErisStream* = ref ErisStreamObj
  ErisStreamObj = object
    store: ErisStore
    pos: BiggestInt
    leaves: seq[Pair]
    secret: Secret
    cap: Cap

proc init(s: ErisStream) {.async.} =
  if s.cap.level == 0:
    s.leaves = @[s.cap.pair]
  else:
    let
      arity = s.cap.blockSize div sizeof(Pair)
      maxLeaves = arity ^ s.cap.level
    s.leaves = newSeqOfCap[Pair]((maxLeaves div 4) * 3)
      # TODO: math?
    proc expand(level: Natural; pair: Pair) {.async.} =
      # Expand on the stack
      let blk = await s.store.get(s.cap.blockSize, pair, s.secret)
      if level == 1:
        for p in blk.rk:
          s.leaves.add(p)
      else:
        for p in blk.rk:
          await expand(level.pred, p)
    await expand(s.cap.level, s.cap.pair)

proc close*(s: ErisStream) =
  reset s.store
  reset s.pos
  reset s.leaves

proc atEnd*(s: ErisStream): bool =
  s.leaves.len * s.cap.blockSize < s.pos
    # TODO: padding?

proc setPosition*(s: ErisStream; pos: BiggestInt) =
  s.pos = pos

proc getPosition*(s: ErisStream): BiggestInt =
  s.pos

proc length*(s: ErisStream): Future[BiggestInt] =
  ## Estimate the length of stream ``s``.
  ## The result is the length of ``s`` rounded up to the next block boundary.
  let fut = newFuture[BiggestInt]("ErisStream.length")
  init(s).addCallback do ():
    fut.complete(s.leaves.len.BiggestInt * s.cap.blockSize.BiggestInt)
  fut

proc readBuffer*(s: ErisStream; buffer: pointer; bufLen: int): Future[int] {.async.} =
  if s.leaves == @[]: await init(s)
  var
    bNum = s.pos div s.cap.blockSize
    buf = cast[ptr UncheckedArray[byte]](buffer)
    bufOff: int
  while bufOff < bufLen and bNum < s.leaves.len:
    var
      blk = await s.store.get(s.cap.blockSize, s.leaves[bNum], s.secret)
      blkOff = s.pos.int and s.cap.blockSize.pred
    if bNum == s.leaves.high:
      blk = unpad(blk)
      if (blk.len - blkOff) == 0: break
    let n = min(bufLen - blkOff, blk.len - blkOff)
    copyMem(unsafeAddr(buf[bufOff]), unsafeAddr(blk[blkOff]), n)
    inc(bNum)
    inc(bufOff, n)
    inc(s.pos, n)
  return bufOff

proc read*(s: ErisStream; size: int): Future[seq[byte]] {.async.} =
  var buf = newSeq[byte](size)
  let n = await s.readBuffer(buf[0].addr, buf.len)
  buf.setLen(n)
  return buf

proc readLine*(s: ErisStream): Future[TaintedString] {.async.} =
  # TODO: buffer a block?
  if s.leaves == @[]: await init(s)
  var
    line = ""
    bNum = s.pos div s.cap.blockSize
  line.setLen(0)
  while true:
    var
      blk = await s.store.get(s.cap.blockSize, s.leaves[bNum], s.secret)
      blkOff = line.len and s.cap.blockSize.pred
    if bNum == s.leaves.high:
      blk = unpad(blk)
    for i in blkOff..blk.high:
      let c = blk[i].char
      if c in Newlines:
        return line
      line.add(c)
    inc(bNum)
    if blk.len < s.cap.blockSize:
      return line

proc readDataStr*(s: ErisStream; buffer: var string; slice: Slice[int]): Future[int] =
  readBuffer(s, addr(buffer[slice.a]), slice.b - slice.a)

proc readAll*(s: ErisStream): Future[string] {.async.} =
  ## Reads all data from the specified file.
  while true:
    let data = await read(s, s.cap.blockSize)
    if data.len == 0:
      return
    result.add(cast[string](data))

proc newErisStream*(store; cap; secret = Secret()): owned ErisStream =
  ## Open a new stream for reading ERIS data.
  result = ErisStream(
    store: store,
    secret: secret,
    cap: cap)
