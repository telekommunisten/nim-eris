# SPDX-License-Identifier: ISC

## Module for using Syndicate dataspaces as an ERIS transmission medium.
##
## See https://syndicate-lang.org/

import std/asyncfutures
import preserves, preserves/records
import syndicate
import eris

proc fromPreserveHook*(result: var Reference; prs: Preserve) =
  if prs.kind == pkByteString and prs.bytes.len == result.bytes.len:
    for i in 0..<result.bytes.len: result.bytes[i] = prs.bytes[i]
  else:
    raise newException(ValueError, "not a preserved ERIS Reference: " & $prs)

const
  Block = RecordClass(label: symbol"erisx2block", arity: 2)
    ## Assertion class for moving block in and out of dataspace.
  Cache = RecordClass(label: symbol"erisx2cache", arity: 1)
    ## Message class for announcing cached blocks.

proc replicator*(store: ErisStore): BootProc =
  ## Spawn a Syndicate actor that replicates ERIS blocks to and from a dataspace.
  runnableExamples:
    import syndicate, eris/stores
    syndicate replicatorExample:
      boot replicator(newMemoryStore())

  proc bootProc(f: Facet) =
    withFacet f:
      spawn "replicator":
        during(Observe % Block.init(`?*`, `?_`)) do (blkRef: Reference):
          let facet = getCurrentFacet()
          facet.beginExternalTask()
          store.get(blkRef).addCallback do (f: Future[seq[byte]]):
            facet.endExternalTask()
            react: assert: Block.init(blkRef.bytes, f.read)

        onAsserted(Block.init(`?*`, `?*`)) do (blkRef: Reference; blkBuf: seq[byte]):
          let facet = getCurrentFacet()
          facet.beginExternalTask()
          store.put(blkRef, blkBuf).addCallback do (f: Future[void]):
            facet.endExternalTask()
            f.read()
            send(Cache % blkRef.bytes)

  bootProc

type
  StoreActor = ref StoreActorObj
  StoreActorObj = object of ErisStoreObj
    facet: Facet

proc newStoreActor*(facet: Facet): StoreActor =
  ## Create a new ``ErisStore`` backed by a Syndicate dataspace.
  ## Requires a replication actor.
  runnableExamples:
    import syndicate
    syndicate storeExample:
      let store = newStoreActor(getCurrentFacet())

  proc actorPut(s: ErisStore; blkRef: Reference; blkBuf: seq[byte]): Future[void] =
    assert(blkBuf.len in {1 shl 10, 32 shl 10})
    let fut = newFuture[void]("actorPut")
    withFacet StoreActor(s).facet:
      react:
        assert: Block.init(blkRef.bytes, blkBuf)
        onMessage(Cache % blkRef.bytes):
          stop: fut.complete()
    fut

  proc actorGet(s: ErisStore; blkRef: Reference): Future[seq[byte]] =
    let fut = newFuture[seq[byte]]("actorGet")
    withFacet StoreActor(s).facet:
      react:
        onAsserted(Block.init(blkRef.bytes, `?*`)) do (blkBuf: seq[byte]):
          stop:
            if blkRef == blkBuf.reference:
              fut.complete(blkBuf)
            else:
              fut.fail newException(IOError, "false assertion of an ERIS block in dataspace")
    fut

  StoreActor(
      putImpl: actorPut,
      getImpl: actorGet,
      facet: facet)
