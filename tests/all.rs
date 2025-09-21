// Tests for all hash functions in the `cthash` crate, comparing their outputs
// against reference implementations from the `RustCrypto` crates.
fn cmp_fn_results<const N: usize>(data: &[u8], cthash_fn: fn(&[u8]) -> [u8; N], reference_impl_fn: fn(&[u8]) -> [u8; N]) {
    let cthash_res = cthash_fn(data);
    let reference_res = reference_impl_fn(data);
    assert_eq!(cthash_res, reference_res);
}

const TEST_DATA: [&[u8]; 7] = [
    b"",
    b"abc",
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", // 448 bits
    b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", // 896 bits
    b"The quick brown fox jumps over the lazy dog",
    b"The quick brown fox jumps over the lazy cog",
    &[b'a'; 1_000_000],
];

// Reference implementations of digest fns using the `RustCrypto` crates
mod reference_impls {
    pub fn sha1(data: &[u8]) -> [u8; 20] {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    pub fn sha224(data: &[u8]) -> [u8; 28] {
        use sha2::{Digest, Sha224};
        let mut hasher = Sha224::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    pub fn sha256(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    pub fn sha384(data: &[u8]) -> [u8; 48] {
        use sha2::{Digest, Sha384};
        let mut hasher = Sha384::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    pub fn sha512(data: &[u8]) -> [u8; 64] {
        use sha2::{Digest, Sha512};
        let mut hasher = Sha512::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    pub fn sha3_224(data: &[u8]) -> [u8; 28] {
        use sha3::{Digest, Sha3_224};
        let mut hasher = Sha3_224::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    pub fn sha3_256(data: &[u8]) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    pub fn sha3_384(data: &[u8]) -> [u8; 48] {
        use sha3::{Digest, Sha3_384};
        let mut hasher = Sha3_384::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    pub fn sha3_512(data: &[u8]) -> [u8; 64] {
        use sha3::{Digest, Sha3_512};
        let mut hasher = Sha3_512::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    pub fn keccak_224(data: &[u8]) -> [u8; 28] {
        use sha3::{Digest, Keccak224};
        let mut hasher = Keccak224::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    pub fn keccak_256(data: &[u8]) -> [u8; 32] {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    pub fn keccak_384(data: &[u8]) -> [u8; 48] {
        use sha3::{Digest, Keccak384};
        let mut hasher = Keccak384::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    pub fn keccak_512(data: &[u8]) -> [u8; 64] {
        use sha3::{Digest, Keccak512};
        let mut hasher = Keccak512::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    pub fn md4(data: &[u8]) -> [u8; 16] {
        use md4::{Digest, Md4};
        let mut hasher = Md4::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    pub fn md5(data: &[u8]) -> [u8; 16] {
        use md5::{Digest, Md5};
        let mut hasher = Md5::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }
}

#[test]
fn sha1() {
    for data in TEST_DATA.iter() {
        cmp_fn_results(data, cthash::sha1, reference_impls::sha1);
    }
}

#[test]
fn sha224() {
    for data in TEST_DATA.iter() {
        cmp_fn_results(data, cthash::sha2_224, reference_impls::sha224);
    }
}

#[test]
fn sha256() {
    for data in TEST_DATA.iter() {
        cmp_fn_results(data, cthash::sha2_256, reference_impls::sha256);
    }
}

#[test]
fn sha384() {
    for data in TEST_DATA.iter() {
        cmp_fn_results(data, cthash::sha2_384, reference_impls::sha384);
    }
}

#[test]
fn sha512() {
    for data in TEST_DATA.iter() {
        cmp_fn_results(data, cthash::sha2_512, reference_impls::sha512);
    }
}

#[test]
fn sha3_224() {
    for data in TEST_DATA.iter() {
        cmp_fn_results(data, cthash::sha3_224, reference_impls::sha3_224);
    }
}

#[test]
fn sha3_256() {
    for data in TEST_DATA.iter() {
        cmp_fn_results(data, cthash::sha3_256, reference_impls::sha3_256);
    }
}

#[test]
fn sha3_384() {
    for data in TEST_DATA.iter() {
        cmp_fn_results(data, cthash::sha3_384, reference_impls::sha3_384);
    }
}

#[test]
fn sha3_512() {
    for data in TEST_DATA.iter() {
        cmp_fn_results(data, cthash::sha3_512, reference_impls::sha3_512);
    }
}

#[test]
fn keccak_224() {
    for data in TEST_DATA.iter() {
        cmp_fn_results(data, cthash::keccak_224, reference_impls::keccak_224);
    }
}

#[test]
fn keccak_256() {
    for data in TEST_DATA.iter() {
        cmp_fn_results(data, cthash::keccak_256, reference_impls::keccak_256);
    }
}

#[test]
fn keccak_384() {
    for data in TEST_DATA.iter() {
        cmp_fn_results(data, cthash::keccak_384, reference_impls::keccak_384);
    }
}

#[test]
fn keccak_512() {
    for data in TEST_DATA.iter() {
        cmp_fn_results(data, cthash::keccak_512, reference_impls::keccak_512);
    }
}

#[test]
fn md4() {
    for data in TEST_DATA.iter() {
        cmp_fn_results(data, cthash::md4, reference_impls::md4);
    }
}

#[test]
fn md5() {
    for data in TEST_DATA.iter() {
        cmp_fn_results(data, cthash::md5, reference_impls::md5);
    }
}
