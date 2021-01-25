import eris

import lmdb

import std/asyncfutures

type
  LmdbStore* = ref LmdbStoreObj
  LmdbStoreObj = object of StoreObj
    db: LMDBEnv
    txn: LMDBTxn
    dbi: Dbi

proc lmdbPut(s: Store; r: Reference; blk: seq[byte]): Future[void] =
  var
    s = LmdbStore(s)
    key = Val(mvSize: r.bytes.len.uint, mvData: r.bytes[0].unsafeAddr)
    val = Val(mvSize: blk.len.uint, mvData: blk[0].unsafeAddr)
  let err = put(s.txn, s.dbi, key.addr, val.addr, 0)
  result = newFuture[void]("ldbmPut")
  if err == 0:
    # s.txn.commit()
    result.complete()
  else:
    result.fail(newException(Exception, $strerror(err)))

proc lmdbGet(s: Store; r: Reference): Future[seq[byte]] =
  var
    s = LmdbStore(s)
    key = Val(mvSize: r.bytes.len.uint, mvData: r.bytes[0].unsafeAddr)
    val: Val
  let err = get(s.txn, s.dbi, key.addr, val.addr)
  result = newFuture[seq[byte]]("ldbmGet")
  if err == 0:
    var blk = newSeq[byte](val.mvSize)
    copyMem(blk[0].addr, val.mvData, blk.len)
    result.complete(blk)
  else:
    result.fail(newException(Exception, $strerror(err)))

proc newLmdbStore*(filePath: string; mapSize = 1 shl 30): LmdbStore =
  result = LmdbStore(
      db: newLMDBEnv(filePath, openflags = CREATE),
      putImpl: lmdbPut,
      getImpl: lmdbGet)
  discard result.db.envSetMapsize(mapSize)
  result.txn = result.db.newTxn()
  result.dbi = result.txn.dbiOpen(cast[string](nil), 0)

proc close*(s: LmdbStore) =
  close(s.db, s.dbi)
  envClose(s.db)
