# ERIS

See http://purl.org/eris

## Test

```
git clone --recursive https://git.sr.ht/~ehmry/eris
cd eris

nim c -d:release -r tests/test_small
nim c -d:release -r tests/test_large
```

## Todo
* Optimise the Chacha20 and BLAKE2 implementations
* Asynchronise the API for block storage
* Block size selection helpers
