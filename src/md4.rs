use crate::block_api::eager_split_pad;

/// Compute MD4 digest.
/// # Examples
/// ```
/// use cthash::md4;
/// const H: [u8; 16] = md4(b"data");
/// ```
pub const fn md4(input: &[u8]) -> [u8; 16] {
    let mut state = [0x67452301u32, 0xefcdab89, 0x98badcfe, 0x10325476];

    md4_pad_and_run(input, &mut state);

    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 4 {
        out.as_chunks_mut().0[i] = state[i].to_le_bytes();
        i += 1;
    }
    out
}

#[inline(always)]
const fn md4_pad_and_run(input: &[u8], state: &mut [u32; 4]) {
    let mut b0 = [0; _];
    let mut b1 = [0; _];
    let bit_len = ((input.len() as u64) * 8).to_le_bytes();
    let (blocks, pad_two_blocks) = eager_split_pad(input, &bit_len, 0x80, &mut b0, &mut b1);

    let mut i = 0;
    while i < blocks.len() {
        compress(state, &blocks[i]);
        i += 1;
    }

    if pad_two_blocks {
        compress(state, &b0);
        compress(state, &b1);
    } else {
        compress(state, &b0);
    }
}

const fn compress(h: &mut [u32; 4], block: &[u8; 64]) {
    const K1: u32 = 0x5a827999;
    const K2: u32 = 0x6ed9eba1;

    #[inline(always)]
    const fn round1(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
        let t = a.wrapping_add(b & c | !b & d).wrapping_add(k);
        t.rotate_left(s)
    }
    #[inline(always)]
    const fn round2(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
        let t = a.wrapping_add(b & c | b & d | c & d).wrapping_add(k).wrapping_add(K1);
        t.rotate_left(s)
    }
    #[inline(always)]
    const fn round3(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
        let t = a.wrapping_add(b ^ c ^ d).wrapping_add(k).wrapping_add(K2);
        t.rotate_left(s)
    }

    let mut data = [0u32; 16];
    let mut i = 0;
    let (w_words, _rem) = block.as_chunks();
    while i < 16 {
        data[i] = u32::from_le_bytes(w_words[i]);
        i += 1;
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];

    // Round 1
    a = round1(a, b, c, d, data[0], 3);
    d = round1(d, a, b, c, data[1], 7);
    c = round1(c, d, a, b, data[2], 11);
    b = round1(b, c, d, a, data[3], 19);
    a = round1(a, b, c, d, data[4], 3);
    d = round1(d, a, b, c, data[5], 7);
    c = round1(c, d, a, b, data[6], 11);
    b = round1(b, c, d, a, data[7], 19);
    a = round1(a, b, c, d, data[8], 3);
    d = round1(d, a, b, c, data[9], 7);
    c = round1(c, d, a, b, data[10], 11);
    b = round1(b, c, d, a, data[11], 19);
    a = round1(a, b, c, d, data[12], 3);
    d = round1(d, a, b, c, data[13], 7);
    c = round1(c, d, a, b, data[14], 11);
    b = round1(b, c, d, a, data[15], 19);

    // Round 2
    a = round2(a, b, c, d, data[0], 3);
    d = round2(d, a, b, c, data[4], 5);
    c = round2(c, d, a, b, data[8], 9);
    b = round2(b, c, d, a, data[12], 13);
    a = round2(a, b, c, d, data[1], 3);
    d = round2(d, a, b, c, data[5], 5);
    c = round2(c, d, a, b, data[9], 9);
    b = round2(b, c, d, a, data[13], 13);
    a = round2(a, b, c, d, data[2], 3);
    d = round2(d, a, b, c, data[6], 5);
    c = round2(c, d, a, b, data[10], 9);
    b = round2(b, c, d, a, data[14], 13);
    a = round2(a, b, c, d, data[3], 3);
    d = round2(d, a, b, c, data[7], 5);
    c = round2(c, d, a, b, data[11], 9);
    b = round2(b, c, d, a, data[15], 13);

    // Round 3
    a = round3(a, b, c, d, data[0], 3);
    d = round3(d, a, b, c, data[8], 9);
    c = round3(c, d, a, b, data[4], 11);
    b = round3(b, c, d, a, data[12], 15);
    a = round3(a, b, c, d, data[2], 3);
    d = round3(d, a, b, c, data[10], 9);
    c = round3(c, d, a, b, data[6], 11);
    b = round3(b, c, d, a, data[14], 15);
    a = round3(a, b, c, d, data[1], 3);
    d = round3(d, a, b, c, data[9], 9);
    c = round3(c, d, a, b, data[5], 11);
    b = round3(b, c, d, a, data[13], 15);
    a = round3(a, b, c, d, data[3], 3);
    d = round3(d, a, b, c, data[11], 9);
    c = round3(c, d, a, b, data[7], 11);
    b = round3(b, c, d, a, data[15], 15);

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
}
