# ERIS

See http://purl.org/eris

## Test

```
nimble develop https://git.sr.ht/~ehmry/eris
cd eris
git submodule init
git submodule update

nim c -d:release -r test/test_small
nim c -d:release -r test/test_large
```
