# SPDX-FileCopyrightText: 2020 Emery Hemingway
#
# SPDX-License-Identifier: ISC

import base32, eris/private/chacha20/src/chacha20, eris/private/blake2/blake2

import streams, strutils

type
  Reference* = object
    bytes*: array[32, byte]
  Key* = object
    bytes*: array[32, byte]
  Secret* = object
    bytes*: array[32, byte]
  Pair {.packed.} = object
    r: Reference
    k: Key
  ReadCap* = object
    pair*: Pair
    level*: int
    blockSize*: int

assert(sizeOf(Pair) == 64)

proc `$`*(x: Reference|Key|Secret): string =
  base32.encode(cast[array[32, char]](x.bytes), pad=false)

proc `$`*(cap: ReadCap): string =
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
  "urn:erisx2:" & base32.encode(cast[seq[char]](tmp), pad = false)

proc parseSecret*(s: string): Secret =
  var buf = base32.decode(s)
  if buf.len != result.bytes.len:
    raise newException(ValueError, "invalid convergence-secret")
  copyMem(result.bytes[0].addr, buf[0].addr, result.bytes.len)

proc parseReadCap*(bin: openArray[char]): ReadCap =
  assert(bin.len == 66)
  result.blockSize =
    case bin[0].byte
    of 0x00: 1 shl 10
    of 0x01: 32 shl 10
    else: raise newException(ValueError, "invalid ERIS block size")
  result.level = int(bin[1])
  if result.level < 0 or 255 < result.level:
    raise newException(ValueError, "invalid ERIS root level")
  copyMem(addr result.pair.r.bytes[0], unsafeAddr bin[2], 32)
  copyMem(addr result.pair.k.bytes[0], unsafeAddr bin[34], 32)

proc parseErisUrn*(urn: string): ReadCap =
  let parts = urn.split(':')
  if 3 <= parts.len:
    if parts[0] == "urn":
      if parts[1] == "erisx2":
        if parts[2].len >= 106:
          let bin = base32.decode(parts[2][0..105])
          return parseReadCap(bin)
  raise newException(ValueError, "invalid ERIS URN encoding")

proc readCap*(str: Stream): ReadCap =
  discard

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
    raise newException(ValueError, "ERIS block failed verification")

type
  Store* = ref StoreObj
  StoreObj* = object of RootObj
    getImpl*: proc (s: Store; r: Reference): seq[byte]
      {.nimcall, gcsafe.}
    putImpl*: proc (s: Store; r: Reference; b: openarray[byte])
      {.nimcall, raises: [Defect, IOError, OSError], tags: [], gcsafe.}

proc get*(store: Store; r: Reference; blockSize: Natural): seq[byte] =
  # TODO:
  #   - async
  #   - caller decrypts a store buffer to a private buffer
  assert(not store.getImpl.isNil)
  result = store.getImpl(store, r)
  if result.len != blockSize:
    raise newException(ValueError, "ERIS block size mismatch")

proc get*(store: Store; blockSize: Natural; secret: Secret; pair: Pair): seq[byte] =
  result = get(store, pair.r, blockSize)
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

proc encode*(store: Store; blockSize: Natural; secret: Secret; content: Stream): ReadCap =
  var pairs = splitContent(store, blockSize, secret, content)
  while pairs.len > 1:
    pairs = collectRkPairs(store, blockSize, secret, pairs)
    inc(result.level)
  result.pair = pairs[0]
  result.blockSize = blockSize

proc encode*(store: Store; blockSize: Natural; secret: Secret; content: string): ReadCap =
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

proc unpad(blk: var seq[byte]) =
  var i = blk.high
  while 0 < i:
    case blk[i]
    of 0x00: dec(i)
    of 0x80:
      blk.setLen(i)
      return
    else: break
  raise newException(ValueError, "invalid ERIS block padding")

proc decode*(store: Store; secret: Secret; cap: ReadCap): seq[byte] =
  result = newSeq[byte]()
  decodeRecursive(store, cap.blockSize, secret, cap.level, cap.pair, result)
  unpad(result)
