import eris, eris/networking, ./stores
import base32
import asyncdispatch, json, net, os, unittest

let
  server = newErisServer(newMemoryStore(), parseIpAddress"127.0.0.1")
  client = newErisClient(parseIpAddress"127.0.0.1")

suite "network":
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
      let testCap = waitFor client.encode(cap.blockSize, secret, data)
      check($testCap == urn)
      let
        stream = newErisStream(client, secret, cap)
        a = waitFor stream.readAll()
        b = base32.decode(js["content"].getStr)
      check(a.len == b.len)
      assert(a == b, "decode mismatch")
