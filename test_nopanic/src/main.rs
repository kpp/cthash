use no_panic::no_panic;

#[no_panic]
#[unsafe(no_mangle)]
fn check_ct_sha1(s: &[u8]) -> [u8; 20] {
    cthash::sha1(s)
}

#[no_panic]
#[unsafe(no_mangle)]
fn check_ct_sha2_224(s: &[u8]) -> [u8; 28] {
    cthash::sha2_224(s)
}

#[no_panic]
#[unsafe(no_mangle)]
fn check_ct_sha2_256(s: &[u8]) -> [u8; 32] {
    cthash::sha2_256(s)
}

#[no_panic]
#[unsafe(no_mangle)]
fn check_ct_sha2_384(s: &[u8]) -> [u8; 48] {
    cthash::sha2_384(s)
}

#[no_panic]
#[unsafe(no_mangle)]
fn check_ct_sha2_512(s: &[u8]) -> [u8; 64] {
    cthash::sha2_512(s)
}

#[no_panic]
#[unsafe(no_mangle)]
fn check_ct_sha3_512(s: &[u8]) -> [u8; 64] {
    cthash::sha3_512(s)
}

#[no_panic]
#[unsafe(no_mangle)]
fn check_ct_md4(s: &[u8]) -> [u8; 16] {
    cthash::md4(s)
}

#[no_panic]
#[unsafe(no_mangle)]
fn check_ct_md5(s: &[u8]) -> [u8; 16] {
    cthash::md5(s)
}

fn main() {
    let _ = check_ct_sha1(&[]);
    let _ = check_ct_sha2_224(&[]);
    let _ = check_ct_sha2_256(&[]);
    let _ = check_ct_sha2_384(&[]);
    let _ = check_ct_sha2_512(&[]);
    let _ = check_ct_sha3_512(&[]);

    let _ = check_ct_md4(&[]);
    let _ = check_ct_md5(&[]);
}
