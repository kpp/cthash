use crate::block_api::eager_split_pad;

/// Compute MD5 digest.
/// # Examples
/// ```
/// use cthash::md5;
/// const H: [u8; 16] = md5(b"data");
/// ```
pub const fn md5(input: &[u8]) -> [u8; 16] {
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

const MD5_K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1,
    0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453,
    0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942,
    0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
    0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

#[inline(always)]
const fn f(w: u32, x: u32, y: u32, z: u32, m: u32, c: u32, s: u32) -> u32 {
    ((x & y) | (!x & z))
        .wrapping_add(w)
        .wrapping_add(m)
        .wrapping_add(c)
        .rotate_left(s)
        .wrapping_add(x)
}

#[inline(always)]
const fn g(w: u32, x: u32, y: u32, z: u32, m: u32, c: u32, s: u32) -> u32 {
    ((x & z) | (y & !z))
        .wrapping_add(w)
        .wrapping_add(m)
        .wrapping_add(c)
        .rotate_left(s)
        .wrapping_add(x)
}

#[inline(always)]
const fn h(w: u32, x: u32, y: u32, z: u32, m: u32, c: u32, s: u32) -> u32 {
    (x ^ y ^ z)
        .wrapping_add(w)
        .wrapping_add(m)
        .wrapping_add(c)
        .rotate_left(s)
        .wrapping_add(x)
}

#[inline(always)]
const fn i(w: u32, x: u32, y: u32, z: u32, m: u32, c: u32, s: u32) -> u32 {
    (y ^ (x | !z))
        .wrapping_add(w)
        .wrapping_add(m)
        .wrapping_add(c)
        .rotate_left(s)
        .wrapping_add(x)
}

const fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
    let mut data = [0u32; 16];
    let mut t = 0;
    let (w_words, _rem) = block.as_chunks();
    while t < 16 {
        data[t] = u32::from_le_bytes(w_words[t]);
        t += 1;
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    // round 1
    a = f(a, b, c, d, data[0], MD5_K[0], 7);
    d = f(d, a, b, c, data[1], MD5_K[1], 12);
    c = f(c, d, a, b, data[2], MD5_K[2], 17);
    b = f(b, c, d, a, data[3], MD5_K[3], 22);

    a = f(a, b, c, d, data[4], MD5_K[4], 7);
    d = f(d, a, b, c, data[5], MD5_K[5], 12);
    c = f(c, d, a, b, data[6], MD5_K[6], 17);
    b = f(b, c, d, a, data[7], MD5_K[7], 22);

    a = f(a, b, c, d, data[8], MD5_K[8], 7);
    d = f(d, a, b, c, data[9], MD5_K[9], 12);
    c = f(c, d, a, b, data[10], MD5_K[10], 17);
    b = f(b, c, d, a, data[11], MD5_K[11], 22);

    a = f(a, b, c, d, data[12], MD5_K[12], 7);
    d = f(d, a, b, c, data[13], MD5_K[13], 12);
    c = f(c, d, a, b, data[14], MD5_K[14], 17);
    b = f(b, c, d, a, data[15], MD5_K[15], 22);

    // round 2
    a = g(a, b, c, d, data[1], MD5_K[16], 5);
    d = g(d, a, b, c, data[6], MD5_K[17], 9);
    c = g(c, d, a, b, data[11], MD5_K[18], 14);
    b = g(b, c, d, a, data[0], MD5_K[19], 20);

    a = g(a, b, c, d, data[5], MD5_K[20], 5);
    d = g(d, a, b, c, data[10], MD5_K[21], 9);
    c = g(c, d, a, b, data[15], MD5_K[22], 14);
    b = g(b, c, d, a, data[4], MD5_K[23], 20);

    a = g(a, b, c, d, data[9], MD5_K[24], 5);
    d = g(d, a, b, c, data[14], MD5_K[25], 9);
    c = g(c, d, a, b, data[3], MD5_K[26], 14);
    b = g(b, c, d, a, data[8], MD5_K[27], 20);

    a = g(a, b, c, d, data[13], MD5_K[28], 5);
    d = g(d, a, b, c, data[2], MD5_K[29], 9);
    c = g(c, d, a, b, data[7], MD5_K[30], 14);
    b = g(b, c, d, a, data[12], MD5_K[31], 20);

    // round 3
    a = h(a, b, c, d, data[5], MD5_K[32], 4);
    d = h(d, a, b, c, data[8], MD5_K[33], 11);
    c = h(c, d, a, b, data[11], MD5_K[34], 16);
    b = h(b, c, d, a, data[14], MD5_K[35], 23);

    a = h(a, b, c, d, data[1], MD5_K[36], 4);
    d = h(d, a, b, c, data[4], MD5_K[37], 11);
    c = h(c, d, a, b, data[7], MD5_K[38], 16);
    b = h(b, c, d, a, data[10], MD5_K[39], 23);

    a = h(a, b, c, d, data[13], MD5_K[40], 4);
    d = h(d, a, b, c, data[0], MD5_K[41], 11);
    c = h(c, d, a, b, data[3], MD5_K[42], 16);
    b = h(b, c, d, a, data[6], MD5_K[43], 23);

    a = h(a, b, c, d, data[9], MD5_K[44], 4);
    d = h(d, a, b, c, data[12], MD5_K[45], 11);
    c = h(c, d, a, b, data[15], MD5_K[46], 16);
    b = h(b, c, d, a, data[2], MD5_K[47], 23);

    // round 4
    a = i(a, b, c, d, data[0], MD5_K[48], 6);
    d = i(d, a, b, c, data[7], MD5_K[49], 10);
    c = i(c, d, a, b, data[14], MD5_K[50], 15);
    b = i(b, c, d, a, data[5], MD5_K[51], 21);

    a = i(a, b, c, d, data[12], MD5_K[52], 6);
    d = i(d, a, b, c, data[3], MD5_K[53], 10);
    c = i(c, d, a, b, data[10], MD5_K[54], 15);
    b = i(b, c, d, a, data[1], MD5_K[55], 21);

    a = i(a, b, c, d, data[8], MD5_K[56], 6);
    d = i(d, a, b, c, data[15], MD5_K[57], 10);
    c = i(c, d, a, b, data[6], MD5_K[58], 15);
    b = i(b, c, d, a, data[13], MD5_K[59], 21);

    a = i(a, b, c, d, data[4], MD5_K[60], 6);
    d = i(d, a, b, c, data[11], MD5_K[61], 10);
    c = i(c, d, a, b, data[2], MD5_K[62], 15);
    b = i(b, c, d, a, data[9], MD5_K[63], 21);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}
