/// Example of usage all hash functions on empty string.
/// Actually DATA can be changed to any other value.
/// The results are formatted as hex strings at compile time too.
use const_hex::const_encode as hex;
use cthash::*;

const DATA: &[u8] = b"";
const WITH_PREFIX: bool = true;

const H_MD4: &str = hex::<16, WITH_PREFIX>(&md4(DATA)).as_str();

const H_MD5: &str = hex::<16, WITH_PREFIX>(&md5(DATA)).as_str();

const H_SHA1: &str = hex::<20, WITH_PREFIX>(&sha1(DATA)).as_str();

const H_SHA2_224: &str = hex::<28, WITH_PREFIX>(&sha2_224(DATA)).as_str();
const H_SHA2_256: &str = hex::<32, WITH_PREFIX>(&sha2_256(DATA)).as_str();
const H_SHA2_384: &str = hex::<48, WITH_PREFIX>(&sha2_384(DATA)).as_str();
const H_SHA2_512: &str = hex::<64, WITH_PREFIX>(&sha2_512(DATA)).as_str();

const H_SHA3_224: &str = hex::<28, WITH_PREFIX>(&sha3_224(DATA)).as_str();
const H_SHA3_256: &str = hex::<32, WITH_PREFIX>(&sha3_256(DATA)).as_str();
const H_SHA3_384: &str = hex::<48, WITH_PREFIX>(&sha3_384(DATA)).as_str();
const H_SHA3_512: &str = hex::<64, WITH_PREFIX>(&sha3_512(DATA)).as_str();

const H_KECCAK_224: &str = hex::<28, WITH_PREFIX>(&keccak_224(DATA)).as_str();
const H_KECCAK_256: &str = hex::<32, WITH_PREFIX>(&keccak_256(DATA)).as_str();
const H_KECCAK_384: &str = hex::<48, WITH_PREFIX>(&keccak_384(DATA)).as_str();
const H_KECCAK_512: &str = hex::<64, WITH_PREFIX>(&keccak_512(DATA)).as_str();

fn main() {
    println!("\n\nHashes of empty string:\n");
    println!("MD4:        {H_MD4}");
    println!("MD5:        {H_MD5}");
    println!("SHA1:       {H_SHA1}");
    println!("SHA2-224:   {H_SHA2_224}");
    println!("SHA2-256:   {H_SHA2_256}");
    println!("SHA2-384:   {H_SHA2_384}");
    println!("SHA2-512:   {H_SHA2_512}");
    println!("SHA3-224:   {H_SHA3_224}");
    println!("SHA3-256:   {H_SHA3_256}");
    println!("SHA3-384:   {H_SHA3_384}");
    println!("SHA3-512:   {H_SHA3_512}");
    println!("KECCAK-224: {H_KECCAK_224}");
    println!("KECCAK-256: {H_KECCAK_256}");
    println!("KECCAK-384: {H_KECCAK_384}");
    println!("KECCAK-512: {H_KECCAK_512}");
}
