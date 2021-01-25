import eris
import base32
import std/json, std/hashes, std/tables

import asyncdispatch, asyncfutures

type
  JsonStore = ref JsonStoreObj
  JsonStoreObj = object of StoreObj
    js: JsonNode

proc jsonGet(s: Store; r: Reference): Future[seq[byte]] =
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

proc hash(r: Reference): Hash = hash(r.bytes)

type
  MemoryStore = ref MemoryStoreObj
  MemoryStoreObj = object of StoreObj
    table: Table[Reference, seq[byte]]

proc memoryPut(s: Store; r: Reference; b: seq[byte]): Future[void] =
  var s = MemoryStore(s)
  s.table[r] = b
  result = newFuture[void]("memoryPut")
  result.complete()

proc memoryGet(s: Store; r: Reference): Future[seq[byte]] =
  var s = MemoryStore(s)
  result = newFuture[seq[byte]]("memoryGet")
  try:
    result.complete(s.table[r])
  except:
    result.fail(newException(IOError, $r & " not found"))

proc newMemoryStore*(): MemoryStore =
  MemoryStore(
    table: initTable[Reference, seq[byte]](),
    putImpl: memoryPut,
    getImpl: memoryGet)
