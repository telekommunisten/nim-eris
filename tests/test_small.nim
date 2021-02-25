import eris, ./jsonstores
import base32
import asyncdispatch, json, os, unittest, strutils

suite "encode":
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
        store = newDiscardStore()

      let testCap = waitFor store.encode(cap.blockSize, secret, data)
      check($testCap == urn)

suite "decode":
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
        b = base32.decode(js["content"].getStr)
        store = newJsonStore(js)
        stream = newErisStream(store, secret, cap)
        streamLength = waitFor stream.length()
      check((streamLength - b.len) <= cap.blockSize)
      let a = waitFor stream.readAll()
      check(a.len == b.len)
      check(a.toHex == b.toHex)
      assert(a == b, "decode mismatch")
