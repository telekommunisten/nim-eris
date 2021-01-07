# SPDX-FileCopyrightText: 2020 Emery Hemingway
#
# SPDX-License-Identifier: ISC

import base32, eris/private/chacha20/src/chacha20, eris/private/blake2/blake2

import math, streams, strutils

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

assert(sizeOf(Pair) == 64)

proc `$`*(x: Reference|Key|Secret): string =
  base32.encode(cast[array[32, char]](x.bytes), pad = false)

proc `==`*(x, y: Cap): bool = x.pair.r.bytes == y.pair.r.bytes

proc toBase32*(cap: Cap): string =
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

proc `$`*(cap: Cap): string =
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

proc parseErisUrn*(urn: string): Cap =
  let parts = urn.split(':')
  if 3 <= parts.len:
    if parts[0] == "urn":
      if parts[1] == "erisx2":
        if parts[2].len >= 106:
          let bin = base32.decode(parts[2][0..105])
          return parseCap(bin)
  raise newException(Defect, "invalid ERIS URN encoding")

proc encryptBlock(secret: Secret; blk: var openarray[byte]): Pair =
  var
    ctx: Blake2b
    nonce: Nonce
  ctx.init(32, secret.bytes)
  ctx.update(blk)
  ctx.final(result.k.bytes)
  discard chacha20(result.k.bytes, nonce, 0, blk, blk)
  ctx.init(32)
  ctx.update(blk)
  ctx.final(result.r.bytes)

proc decryptBlock(secret: Secret; key: Key; blk: var seq[byte]) =
  var
    ctx: Blake2b
    nonce: Nonce
  discard chacha20(key.bytes, nonce, 0, blk, blk)
  ctx.init(32, secret.bytes)
  ctx.update(blk)
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
  Store* = ref StoreObj
  StoreObj* = object of RootObj
    getImpl*: proc (s: Store; r: Reference): seq[byte]
      {.nimcall, raises: [Defect, IOError, OSError], tags: [ReadIOEffect], gcsafe.}
    putImpl*: proc (s: Store; r: Reference; b: openarray[byte])
      {.nimcall, raises: [Defect, IOError, OSError], tags: [WriteIOEffect], gcsafe.}

proc discardPut(s: Store; r: Reference; b: openarray[byte]) =
  discard

proc discardGet(s: Store; r: Reference): seq[byte] =
  raise newException(Defect, "cannot retrieve data from dummy ERIS store")

proc newDiscardStore*(): Store =
  new(result)
  result.putImpl = discardPut
  result.getImpl = discardGet

proc get*(store: Store; blockSize: Natural; r: Reference; ): seq[byte] =
  # TODO:
  #   - async
  #   - caller decrypts a store buffer to a private buffer
  assert(not store.getImpl.isNil)
  result = store.getImpl(store, r)
  if result.len != blockSize:
    raise newException(Defect, "ERIS block size mismatch")

proc get*(store: Store; blockSize: Natural; secret: Secret; pair: Pair): seq[byte] =
  result = get(store, blockSize, pair.r)
  decryptBlock(secret, pair.k, result)

proc put*(store: Store; r: Reference; b: openarray[byte]) =
  # TODO:
  #   - async
  #   - caller encrypts a private buffer to a store buffer
  assert(not store.putImpl.isNil)
  store.putImpl(store, r, b)

proc put*(store: Store; secret: Secret; blk: var openarray[byte]): Pair =
  result = encryptBlock(secret, blk)
  store.put(result.r, blk)

proc splitContent(store: Store; blockSize: Natural; secret: Secret; content: Stream): seq[Pair] =
  result = newSeq[Pair]()
  var
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
    result.add(store.put(secret, blk))
  if not padded:
    blk.setLen(1) # zero all but the first byte
    blk[0] = 0x80
    blk.setLen(blockSize)
    result.add(store.put(secret, blk))

proc collectRkPairs(store: Store; blockSize: Natural; secret: Secret; pairs: seq[Pair]): seq[Pair] =
  let arity = blockSize div 64
  result = newSeqOfCap[Pair](pairs.len div 2)
  var blk = newSeq[byte](blockSize)
  for i in countup(0, pairs.high, arity):
    let
      pairCount = min(arity, pairs.len - i)
      byteCount = pairCount * sizeof(Pair)
    blk.setLen(byteCount)
    copyMem(blk[0].addr, pairs[i].unsafeAddr, byteCount)
    blk.setLen(blockSize)
    var pair = encryptBlock(secret, blk)
    store.put(pair.r, blk)
    result.add(pair)

proc encode*(store: Store; blockSize: Natural; secret: Secret; content: Stream): Cap =
  var pairs = splitContent(store, blockSize, secret, content)
  while pairs.len > 1:
    pairs = collectRkPairs(store, blockSize, secret, pairs)
    inc(result.level)
  result.pair = pairs[0]
  result.blockSize = blockSize

proc encode*(store: Store; blockSize: Natural; secret: Secret;
    content: string): Cap =
  encode(store, blockSize, secret, newStringStream(content))

proc erisCap*(blockSize: Natural; secret: Secret; content: string): Cap =
  var store = newDiscardStore()
  encode(store, blockSize, secret, newStringStream(content))

iterator rk(blk: openarray[byte]): Pair =
  let buf = cast[ptr UncheckedArray[Pair]](blk[0].unsafeAddr)
  block loop:
    for i in countup(0, blk.high, 64):
      block EndCheck:
        for j in i..(i + 63):
          if blk[j] != 0: break EndCheck
        break loop
      yield buf[i div 64]

proc decodeRecursive(store: Store; blockSize: Natural; secret: Secret; level: Natural; pair: Pair; result: var seq[byte]) =
  var blk = store.get(blockSize, secret, pair)
  if level == 0:
    result.add(blk)
  else:
    for pair in blk.rk:
      decodeRecursive(store, blockSize, secret, level.pred, pair, result)

proc decode*(store: Store; secret: Secret; cap: Cap): seq[byte] =
  result = newSeq[byte]()
  decodeRecursive(store, cap.blockSize, secret, cap.level, cap.pair, result)
  result = unpad(result)

type
  ErisStream* = ref ErisStreamObj
  ErisStreamObj = object of StreamObj
    store: Store
    pos: BiggestInt
    leaves: seq[Pair]
    secret: Secret
    cap: Cap

proc esClose(s: Stream) =
  var s = ErisStream(s)
  reset s.store
  reset s.pos
  reset s.leaves

proc esAtEnd(s: Stream): bool =
  var s = ErisStream(s)
  s.leaves.len * s.cap.blockSize < s.pos
    # TODO: padding?

proc esSetPosition(s: Stream; pos: int) =
  var s = ErisStream(s)
  s.pos = pos

proc esGetPosition(s: Stream): int =
  ErisStream(s).pos.int

proc esReadLine(s: Stream; line: var TaintedString): bool =
  # TODO: buffer a block?
  var
    s = ErisStream(s)
    bNum = s.pos div s.cap.blockSize
  line.setLen(0)
  while true:
    var
      blk = s.store.get(s.cap.blockSize, s.secret, s.leaves[bNum])
      blkOff = line.len and s.cap.blockSize.pred
    if bNum == s.leaves.high:
      blk = unpad(blk)
    for i in blkOff..blk.high:
      let c = blk[i].char
      if c in Newlines:
        return true
      line.add(c)
    inc(bNum)
    if blk.len < s.cap.blockSize:
      return false

proc esPeekData(s: Stream; buffer: pointer; bufLen: int): int =
  # TODO: only reads a single block at a time
  var
    s = ErisStream(s)
    buf = cast[ptr UncheckedArray[byte]](buffer)
    bNum = s.pos div s.cap.blockSize
  while result < bufLen and bNum < s.leaves.len:
    var
      blk = s.store.get(s.cap.blockSize, s.secret, s.leaves[bNum])
      blkOff = int(s.pos + result) and s.cap.blockSize.pred
    if bNum == s.leaves.high:
      blk = unpad(blk)
      if blk.len == 0: break
    let count = min(bufLen - result, blk.len - blkOff)
    copyMem(unsafeAddr(buf[result]), unsafeAddr(blk[blkOff]), count)
    inc(result, count)
    inc(bNum)

proc esReadData(s: Stream; buffer: pointer; bufLen: int): int =
  var s = ErisStream(s)
  result = esPeekData(s, buffer, bufLen)
  inc(s.pos, result)

proc esReadDataStr(s: Stream; buffer: var string; slice: Slice[int]): int =
  esReadData(s, addr(buffer[slice.a]), slice.b - slice.a)

proc esWriteData(s: Stream; buffer: pointer; bufLen: int) =
  raise newException(IOError, "ERIS streams are read-only")

proc esFlush(s: Stream) = discard

proc newErisStream*(store: Store; secret: Secret; cap: Cap): owned ErisStream =
  ## Open a new stream for reading ERIS data
  result = ErisStream(
    store: store,
    secret: secret,
    cap: cap,
    closeImpl: esClose,
    atEndImpl: esAtEnd,
    setPositionImpl: esSetPosition,
    getPositionImpl: esGetPosition,
    readDataStrImpl: esReadDataStr,
    readLineImpl: esReadLine,
    readDataImpl: esReadData,
    peekDataImpl: esPeekData,
    writeDataImpl: esWriteData,
    flushImpl: esFlush)
  if cap.level == 0:
    result.leaves = @[cap.pair]
  else:
    let
      arity = cap.blockSize div sizeof(Pair)
      maxLeaves = arity ^ cap.level
    var leaves = newSeqOfCap[Pair]((maxLeaves div 4) * 3)
      # TODO: math?
    proc expand(level: Natural; pair: Pair) =
      # Expand on the stack
      let blk = store.get(cap.blockSize, secret, pair)
      if level == 1:
        for p in blk.rk:
          leaves.add(p)
      else:
        for p in blk.rk:
          expand(level.pred, p)
    expand(cap.level, cap.pair)
    result.leaves = leaves
