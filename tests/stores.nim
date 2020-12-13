import eris
import base32
import json

type
  # TODO: async storage

  DiscardStore = ref DiscardStoreObj
  DiscardStoreObj = object of StoreObj

  JsonStore = ref JsonStoreObj
  JsonStoreObj = object of StoreObj
    js: JsonNode

proc discardPut(s: Store; r: Reference; b: openarray[byte]) =
  discard

proc newDiscardStore*(): DiscardStore =
  new(result)
  result.putImpl = discardPut

proc jsonGet(s: Store; r: Reference): seq[byte] {.gcsafe.} =
  var s = JsonStore(s)
  cast[seq[byte]](base32.decode(s.js["blocks"][$r].getStr))

proc newJsonStore*(js: JsonNode): JsonStore =
  new(result)
  result.js = js
  result.getImpl = jsonGet
