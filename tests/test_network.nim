import eris, eris/networking, eris/stores
import base32, taps
import asyncdispatch, json, net, os, random, unittest

from std/net import Port

randomize()

proc randomPort(): Port =
  while result.uint < 1024: # Fuck UNIX
    result = Port(rand(1 shl 16))

let
  ipAddr = parseIpAddress"::1"
  alicePort = randomPort()
  bobPort = randomPort()
  carolPort = randomPort()
var
  aliceLocal = newLocalEndpoint()
  carolLocal = newLocalEndpoint()
  bobLocal = newLocalEndpoint()
  bobRemote = newRemoteEndpoint()

aliceLocal.with ipAddr
bobLocal.with ipAddr
carolLocal.with ipAddr

aliceLocal.with alicePort
bobLocal.with bobPort
carolLocal.with carolPort

bobRemote.with bobPort

var
  alice = newErisBroker(newMemoryStore(), aliceLocal)
  bob = newErisBroker(alice, bobLocal)
  carol = newErisBroker(newMemoryStore(), carolLocal)
carol.addPeer(bobRemote)

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
      let testCap = waitFor alice.encode(cap.blockSize, data, secret)
      check($testCap == urn)
      let
        stream = newErisStream(carol, cap, secret)
        a = waitFor stream.readAll()
        b = base32.decode(js["content"].getStr)
      check(a.len == b.len)
      assert(a == b, "decode mismatch")
