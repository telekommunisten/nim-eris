import eris, eris/lmdb_backend
import base32
import asyncdispatch, json, net, os, unittest

suite "lmdb":
  let store = newLmdbStore("tests/db")
  for path in walkPattern("eris/test-vectors/*.json"):
    let js = parseFile(path)
    test $js["id"].getInt:
      checkpoint js["name"].getStr
      checkpoint js["description"].getStr
      let urn = js["urn"].getStr
      checkpoint urn
      let
        cap = parseErisUrn(urn)
        secret = parseSecret(js["convergence-secret"].getStr)
        data = base32.decode(js["content"].getStr)
      let testCap = waitFor store.encode(cap.blockSize, data, secret)
      check($testCap == urn)
      let
        stream = newErisStream(store, cap, secret)
        a = waitFor stream.readAll()
        b = base32.decode(js["content"].getStr)
      check(a.len == b.len)
      assert(a == b, "decode mismatch")
  close(store)
