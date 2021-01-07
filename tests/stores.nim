import eris
import base32
import json

type
  # TODO: async storage

  JsonStore = ref JsonStoreObj
  JsonStoreObj = object of StoreObj
    js: JsonNode

proc jsonGet(s: Store; r: Reference): seq[byte] =
  var s = JsonStore(s)
  try:
    cast[seq[byte]](base32.decode(s.js["blocks"][$r].getStr))
  except:
    raise newException(IOError, $r & " not found")

proc newJsonStore*(js: JsonNode): JsonStore =
  new(result)
  result.js = js
  result.getImpl = jsonGet
