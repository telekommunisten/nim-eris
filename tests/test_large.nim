import eris, eris/private/chacha20/src/chacha20, eris/private/blake2/blake2
import asyncdispatch, streams, unittest

suite "streaming":

  type
    TestStream = ref TestStreamObj
    TestStreamObj = object of StreamObj
      key: array[32, byte]
      nonce: Nonce
      counter: Counter
      pos: uint64
      len: uint64

  proc testAtEnd(s: Stream): bool =
    var test = TestStream(s)
    test.len <= test.pos

  proc testReadData(s: Stream; buffer: pointer; bufLen: int): int =
    assert(bufLen mod chacha20.BlockSize == 0)
    var test = TestStream(s)
    zeroMem(buffer, bufLen)
    test.counter = chacha20(test.key, test.nonce, test.counter, buffer, buffer, bufLen)
    test.pos.inc(bufLen)
    bufLen

  proc newTestStream(name: string; contentSize: uint64): TestStream =
    new(result)
    var ctx: Blake2b
    ctx.init(32)
    ctx.update(name)
    ctx.final(result.key)
    result.len = contentSize
    result.atEndImpl = testAtEnd
    result.readDataImpl = testReadData

  let tests = [
    ("100MiB (block size 1KiB)", 100'u64 shl 20, 1 shl 10,
        "urn:erisx2:AACXPZNDNXFLO4IOMF6VIV2ZETGUJEUU7GN4AHPWNKEN6KJMCNP6YNUMVW2SCGZUJ4L3FHIXVECRZQ3QSBOTYPGXHN2WRBMB27NXDTAP24"),
    ("1GiB (block size 32KiB)", 1'u64 shl 30, 32 shl 10,
        "urn:erisx2:AEBFG37LU5BM5N3LXNPNMGAOQPZ5QTJAV22XEMX3EMSAMTP7EWOSD2I7AGEEQCTEKDQX7WCKGM6KQ5ALY5XJC4LMOYQPB2ZAFTBNDB6FAA"),
    ("256GiB (block size 32KiB)", 256'u64 shl 30, 32 shl 10,
        "AEBZHI55XJYINGLXWKJKZHBIXN6RSNDU233CY3ELFSTQNSVITBSVXGVGBKBCS4P4M5VSAUOZSMVAEC2VDFQTI5SEYVX4DN53FTJENWX4KU"),
    ]

  var
    secret: Secret
    store = newDiscardStore()
  for i, t in tests:
    test $i:
      echo "This could take a long time…"
      checkpoint t[0]
      var
        str = newTestStream(t[0], t[1])
        cap = waitFor store.encode(t[2], secret, str)
      check($cap == t[3])
