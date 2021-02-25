import eris
import base32
import std/json

import asyncdispatch, asyncfutures

type
  JsonStore = ref JsonStoreObj
  JsonStoreObj = object of ErisStoreObj
    js: JsonNode

proc jsonGet(s: ErisStore; r: Reference): Future[seq[byte]] =
  var s = JsonStore(s)
  result = newFuture[seq[byte]]("jsonGet")
  try:
    result.complete(cast[seq[byte]](base32.decode(s.js["blocks"][$r].getStr)))
  except:
    result.fail(newException(IOError, $r & " not found"))

proc newJsonStore*(js: JsonNode): JsonStore =
  new(result)
  result.js = js
  result.getImpl = jsonGet
