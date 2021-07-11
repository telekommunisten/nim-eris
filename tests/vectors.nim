import std/[json, os, strutils, unittest]
import base32
import eris

type TestVector* = tuple[js: JsonNode, urn: string, cap: Cap, secret: Secret, data: string]

template test*(v: TestVector; body: untyped): untyped =
  test(intToStr(v.js["id"].getInt, 2) & ": " & v.js["name"].getStr):
    checkpoint v.js["description"].getStr

iterator testVectors*(): TestVector =
  for path in walkPattern("eris/test-vectors/*.json"):
    let
      js = parseFile(path)
      urn = js["urn"].getStr
      cap = parseErisUrn(urn)
      secret = parseSecret(js["convergence-secret"].getStr)
      data = base32.decode(js["content"].getStr)
    yield (js, urn, cap, secret, data)
