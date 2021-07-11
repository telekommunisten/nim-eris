import std/[asyncdispatch, json, unittest, strutils]
import eris, ./jsonstores

import vectors

suite "encode":
  for v in testVectors():
    test v:
      let
        store = newDiscardStore()
        testCap = waitFor store.encode(v.cap.blockSize, v.data, v.secret)
      check($testCap == v.urn)

suite "decode":
  for v in testVectors():
    test v:
      let
        store = newJsonStore(v.js)
        stream = newErisStream(store, v.cap, v.secret)
        streamLength = waitFor stream.length()
      check((streamLength - v.data.len) <= v.cap.blockSize)
      let a = waitFor stream.readAll()
      check(a.len == v.data.len)
      check(a.toHex == v.data.toHex)
      assert(a == v.data, "decode mismatch")
