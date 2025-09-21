/// Compute SHA3-224 digest.
/// # Examples
/// ```
/// use cthash::sha3_224;
/// const H: [u8; 28] = sha3_224(b"data");
/// ```
pub const fn sha3_224(input: &[u8]) -> [u8; 28] {
    keccak::<28, 144>(input, 0x06)
}

/// Compute SHA3-256 digest.
/// # Examples
/// ```
/// use cthash::sha3_256;
/// const H: [u8; 32] = sha3_256(b"data");
/// ```
pub const fn sha3_256(input: &[u8]) -> [u8; 32] {
    keccak::<32, 136>(input, 0x06)
}

/// Compute SHA3-384 digest.
/// # Examples
/// ```
/// use cthash::sha3_384;
/// const H: [u8; 48] = sha3_384(b"data");
/// ```
pub const fn sha3_384(input: &[u8]) -> [u8; 48] {
    keccak::<48, 104>(input, 0x06)
}

/// Compute SHA3-512 digest.
/// # Examples
/// ```
/// use cthash::sha3_512;
/// const H: [u8; 64] = sha3_512(b"data");
/// ```
pub const fn sha3_512(input: &[u8]) -> [u8; 64] {
    keccak::<64, 72>(input, 0x06)
}

/// Compute pre-NISE Keccak-224 digest.
/// # Examples
/// ```
/// use cthash::keccak_224;
/// const H: [u8; 28] = keccak_224(b"data");
/// ```
pub const fn keccak_224(input: &[u8]) -> [u8; 28] {
    keccak::<28, 144>(input, 0x01)
}

/// Compute pre-NISE Keccak-256 digest.
/// # Examples
/// ```
/// use cthash::keccak_256;
/// const H: [u8; 32] = keccak_256(b"data");
/// ```
pub const fn keccak_256(input: &[u8]) -> [u8; 32] {
    keccak::<32, 136>(input, 0x01)
}

/// Compute pre-NISE Keccak-384 digest.
/// # Examples
/// ```
/// use cthash::keccak_384;
/// const H: [u8; 48] = keccak_384(b"data");
/// ```
pub const fn keccak_384(input: &[u8]) -> [u8; 48] {
    keccak::<48, 104>(input, 0x01)
}

/// Compute pre-NISE Keccak-512 digest.
/// # Examples
/// ```
/// use cthash::keccak_512;
/// const H: [u8; 64] = keccak_512(b"data");
/// ```
pub const fn keccak_512(input: &[u8]) -> [u8; 64] {
    keccak::<64, 72>(input, 0x01)
}

const fn keccak<const OUT: usize, const RATE: usize>(input: &[u8], domain: u8) -> [u8; OUT] {
    let mut state = [0u64; 25];

    let (blocks, rem) = input.as_chunks();

    // Absorb full blocks
    let mut i = 0usize;
    while i < blocks.len() {
        absorb_block::<RATE>(&mut state, &blocks[i]);
        keccak_f1600(&mut state);
        i += 1;
    }

    // Last block with padding
    let mut block = [0u8; RATE];

    // copy remainder
    block.split_at_mut(rem.len()).0.copy_from_slice(rem);

    block[rem.len()] ^= domain;
    block[RATE - 1] ^= 0x80;

    absorb_block::<RATE>(&mut state, &block);
    keccak_f1600(&mut state);

    // Squeeze

    // This check should be optimized out at compile time
    // If OUT is bigger, the squeezing phase would need one or more permutations
    // which is not implemented here.
    assert!(OUT <= 25 * 8, "output length must be less than state size");

    let mut out = [0u8; OUT];
    let (out_chunks, out_rem) = out.as_chunks_mut();

    let mut i = 0;
    while i < out_chunks.len() {
        out_chunks[i] = state[i].to_le_bytes();
        i += 1;
    }
    if !out_rem.is_empty() {
        let last_state = state[i].to_le_bytes();
        let (last_state, _) = last_state.split_at(out_rem.len());
        out_rem.copy_from_slice(last_state);
    }

    out
}

#[inline(always)]
const fn absorb_block<const RATE: usize>(s: &mut [u64; 25], block: &[u8; RATE]) {
    let (chunks, rem) = block.as_chunks();
    let mut k = 0usize;
    while k < chunks.len() {
        s[k] ^= u64::from_le_bytes(chunks[k]);
        k += 1;
    }

    // This check should be optimized out at compile time
    assert!(rem.is_empty(), "block length must be multiple of 8");
}

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const RHO: [u32; 25] = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

const fn keccak_f1600(a: &mut [u64; 25]) {
    let mut round = 0;
    while round < 24 {
        let c = [
            a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20],
            a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21],
            a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22],
            a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23],
            a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24],
        ];

        let d = [
            c[4] ^ c[1].rotate_left(1),
            c[0] ^ c[2].rotate_left(1),
            c[1] ^ c[3].rotate_left(1),
            c[2] ^ c[4].rotate_left(1),
            c[3] ^ c[0].rotate_left(1),
        ];

        let b = [
            (a[0] ^ d[0]).rotate_left(RHO[0]),
            (a[6] ^ d[1]).rotate_left(RHO[6]),
            (a[12] ^ d[2]).rotate_left(RHO[12]),
            (a[18] ^ d[3]).rotate_left(RHO[18]),
            (a[24] ^ d[4]).rotate_left(RHO[24]),
            (a[3] ^ d[3]).rotate_left(RHO[3]),
            (a[9] ^ d[4]).rotate_left(RHO[9]),
            (a[10] ^ d[0]).rotate_left(RHO[10]),
            (a[16] ^ d[1]).rotate_left(RHO[16]),
            (a[22] ^ d[2]).rotate_left(RHO[22]),
            (a[1] ^ d[1]).rotate_left(RHO[1]),
            (a[7] ^ d[2]).rotate_left(RHO[7]),
            (a[13] ^ d[3]).rotate_left(RHO[13]),
            (a[19] ^ d[4]).rotate_left(RHO[19]),
            (a[20] ^ d[0]).rotate_left(RHO[20]),
            (a[4] ^ d[4]).rotate_left(RHO[4]),
            (a[5] ^ d[0]).rotate_left(RHO[5]),
            (a[11] ^ d[1]).rotate_left(RHO[11]),
            (a[17] ^ d[2]).rotate_left(RHO[17]),
            (a[23] ^ d[3]).rotate_left(RHO[23]),
            (a[2] ^ d[2]).rotate_left(RHO[2]),
            (a[8] ^ d[3]).rotate_left(RHO[8]),
            (a[14] ^ d[4]).rotate_left(RHO[14]),
            (a[15] ^ d[0]).rotate_left(RHO[15]),
            (a[21] ^ d[1]).rotate_left(RHO[21]),
        ];

        *a = [
            b[0] ^ !b[1] & b[2] ^ RC[round],
            b[1] ^ !b[2] & b[3],
            b[2] ^ !b[3] & b[4],
            b[3] ^ !b[4] & b[0],
            b[4] ^ !b[0] & b[1],
            b[5] ^ !b[6] & b[7],
            b[6] ^ !b[7] & b[8],
            b[7] ^ !b[8] & b[9],
            b[8] ^ !b[9] & b[5],
            b[9] ^ !b[5] & b[6],
            b[10] ^ !b[11] & b[12],
            b[11] ^ !b[12] & b[13],
            b[12] ^ !b[13] & b[14],
            b[13] ^ !b[14] & b[10],
            b[14] ^ !b[10] & b[11],
            b[15] ^ !b[16] & b[17],
            b[16] ^ !b[17] & b[18],
            b[17] ^ !b[18] & b[19],
            b[18] ^ !b[19] & b[15],
            b[19] ^ !b[15] & b[16],
            b[20] ^ !b[21] & b[22],
            b[21] ^ !b[22] & b[23],
            b[22] ^ !b[23] & b[24],
            b[23] ^ !b[24] & b[20],
            b[24] ^ !b[20] & b[21],
        ];

        round += 1;
    }
}
