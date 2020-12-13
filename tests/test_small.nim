import eris, ./stores
import base32
import json, os, unittest

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

      let testCap = store.encode(cap.blockSize, secret, data)
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
        data = cast[seq[byte]](base32.decode(js["content"].getStr))
        store = newJsonStore(js)
      let testData = store.decode(secret, cap)
      check(testData == data)
