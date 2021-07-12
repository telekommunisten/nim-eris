import std/[asyncdispatch, json, unittest, strutils]
import syndicate
import eris, eris/[actors, stores]

import vectors

proc test(store: ErisStore; v: TestVector) {.async.} =
  test v:
    let cap = await store.encode(v.cap.blockSize, v.data, v.secret)
    check($cap == v.urn)
    let
      stream = newErisStream(store, v.cap, v.secret)
      buf = await stream.readAll()
    check(buf.len == v.data.len)
    check(buf.toHex == v.data.toHex)
    assert(buf == v.data, "decode mismatch")

let eve = newMemoryStore()
  # The evesdropping store.

syndicate testActors:
  boot replicator(eve)

  let alice = newStoreActor(getCurrentFacet())
    # The thin store

  for v in testVectors():
    asyncCheck test(alice, v) # check that alice is functional

for v in testVectors():
  waitFor test(eve, v) # check that eve replicated alice
