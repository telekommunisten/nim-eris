import eris

import endians, math

const
  b = 256      ## Number of bits in an ERIS reference
  h = 32       ## Number of bits in a sub-hash
  k = 8        ## Number of sub-hashes in an ERIS reference
  m = 1 shl 10 ## Number of bits in a Bloom filter

assert(k*h <= b)
assert(h <= 64)
assert(2^h > m)
assert(m mod 64 == 0)

type Filter* = object
  ## Bloom filter of ERIS block references
  bits: array[m div 32, uint32]

assert(sizeof(Filter) == m div 8)
assert(sizeof(uint32) * 8 == h)

func incl*(bf: var Filter; r: Reference) =
  ## Include an ERIS reference within a filter.
  for i in 0..<k:
    var subhash: uint32
    bigEndian32(addr subhash, unsafeAddr r.bytes[i*4])
    let
      bitIndex = subhash mod m
      j = bitIndex shr 5
    bf.bits[j] = bf.bits[j] or (1'u32 shl (bitIndex and 31))

func incl*(bf: var Filter; cap: Cap) =
  ## Include an ERIS capability within a filter.
  incl(bf, cap.pair.r)

func contains*(bf: Filter; r: Reference): bool =
  ## Check if a filter possibly contains an ERIS reference.
  for i in 0..<k:
    var subhash: uint32
    bigEndian32(addr subhash, unsafeAddr r.bytes[i*4])
    let
      bitIndex = subhash mod m
      j = bitIndex shr 5
    if (bf.bits[j] and (1'u32 shl (bitIndex and 31))) != 0:
      return true

func contains*(bf: Filter; cap: Cap): bool =
  ## Check if a filter possibly contains an ERIS capability.
  contains(bf, cap.pair.r)

when isMainModule:
  var
    filter: Filter
    x = erisCap(1 shl 10, Secret(), "x")
    y = erisCap(1 shl 10, Secret(), "y")
    z = erisCap(1 shl 10, Secret(), "z")
  filter.incl(x)
  assert(x in filter)
  assert(not (y in filter))
  assert(not (z in filter))

  filter.incl(y)
  assert(x in filter)
  assert(y in filter)
  assert(not (z in filter))

  filter.incl(z)
  assert(x in filter)
  assert(y in filter)
  assert(z in filter)
