# CTHASH (Compile Time Hash)

`const fn` implementation of SHA-1 SHA-2, SHA-3, Keccak, MD4, MD5 hash functions.

This crate allows you to use hash functions as constant expressions in Rust. For all other usages, the [RustCrypto/hashes/](https://github.com/RustCrypto/hashes/) repo includes more optimized implementations of these hash functions.

## Supported hash functions

* MD4 (`md4`)
* MD5 (`md5`)

* SHA-1 (`sha1`)

* SHA-224 (`sha2_224`)
* SHA-256 (`sha2_256`)
* SHA-384 (`sha2_384`)
* SHA-512 (`sha2_512`)

* SHA3-224 (`sha3_224`)
* SHA3-256 (`sha3_256`)
* SHA3-384 (`sha3_384`)
* SHA3-512 (`sha3_512`)

* pre-NISE Keccak-224 (`keccak_256`)
* pre-NISE Keccak-256 (`keccak_256`)
* pre-NISE Keccak-384 (`keccak_384`)
* pre-NISE Keccak-512 (`keccak_512`)

## Implementation note

There is no allocation at all, no std, no unsafe, no panics, no proc macros, no nightly.

## Compiler support

MSRV = 1.88

## Related projects

* [hanickadot/cthash](https://github.com/hanickadot/cthash)
* [rylev/const-sha1](https://github.com/rylev/const-sha1)
* [saleemrashid/sha2-const](https://github.com/saleemrashid/sha2-const)
