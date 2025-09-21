#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! `const fn` implementation of hash functions.
//!
//! This crate allows you to use hash functions as constant expressions in Rust.
//! For all other usages, the [`RustCrypto/hashes/`] repo includes more
//! optimized implementations of these hash functions.
//!
//! [`RustCrypto/hashes/`]: https://github.com/RustCrypto/hashes/
//!
//! # Examples
//! ```
//! use cthash::*;
//!
//! const H_MD4: [u8; 16] = md4(b"data");
//! const H_MD5: [u8; 16] = md5(b"data");
//! const H_SHA1: [u8; 20] = sha1(b"data");
//! const H_SHA2_224: [u8; 28] = sha2_224(b"data");
//! const H_SHA2_256: [u8; 32] = sha2_256(b"data");
//! const H_SHA2_384: [u8; 48] = sha2_384(b"data");
//! const H_SHA2_512: [u8; 64] = sha2_512(b"data");
//! const H_SHA3_224: [u8; 28] = sha3_224(b"data");
//! const H_SHA3_256: [u8; 32] = sha3_256(b"data");
//! const H_SHA3_384: [u8; 48] = sha3_384(b"data");
//! const H_SHA3_512: [u8; 64] = sha3_512(b"data");
//! const H_KECCAK_224: [u8; 28] = keccak_224(b"data");
//! const H_KECCAK_256: [u8; 32] = keccak_256(b"data");
//! const H_KECCAK_384: [u8; 48] = keccak_384(b"data");
//! const H_KECCAK_512: [u8; 64] = keccak_512(b"data");
//!
//! ```

mod block_api;

mod md4;
mod md5;
mod sha1;
mod sha2;
mod sha3;

pub use md4::md4;
pub use md5::md5;
pub use sha1::sha1;
pub use sha2::sha2_224;
pub use sha2::sha2_256;
pub use sha2::sha2_384;
pub use sha2::sha2_512;
pub use sha3::keccak_224;
pub use sha3::keccak_256;
pub use sha3::keccak_384;
pub use sha3::keccak_512;
pub use sha3::sha3_224;
pub use sha3::sha3_256;
pub use sha3::sha3_384;
pub use sha3::sha3_512;
