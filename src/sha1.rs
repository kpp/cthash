use crate::block_api::eager_split_pad;

const K: [u32; 4] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];

/// Compute SHA-1 digest.
/// # Examples
/// ```
/// use cthash::sha1;
/// const H: [u8; 20] = sha1(b"data");
/// ```
pub const fn sha1(input: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    sha1_pad_and_run(input, &mut state);

    let mut out = [0u8; 20];
    let mut i = 0;
    while i < 5 {
        out.as_chunks_mut().0[i] = state[i].to_be_bytes();
        i += 1;
    }
    out
}

#[inline(always)]
const fn sha1_pad_and_run(input: &[u8], state: &mut [u32; 5]) {
    let mut b0 = [0; _];
    let mut b1 = [0; _];
    let bit_len = ((input.len() as u64) * 8).to_be_bytes();
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

const fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    let mut t = 0;

    let (w_words, _rem) = block.as_chunks();
    while t < 16 {
        w[t] = u32::from_be_bytes(w_words[t]);
        t += 1;
    }

    while t < 80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
        t += 1;
    }

    let mut state_cpy = *state;

    t = 0;
    while t < 80 {
        let [a, b, c, d, e] = state_cpy;

        let f = match t {
            0..=19 => b & c | !b & d,
            20..=39 => b ^ c ^ d,
            40..=59 => b & c | b & d | c & d,
            60.. => b ^ c ^ d,
        };

        let k = K[t / 20];

        let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[t]);

        state_cpy = [temp, a, b.rotate_left(30), c, d];

        t += 1;
    }

    let [n_a, n_b, n_c, n_d, n_e] = state_cpy;
    let [a, b, c, d, e] = state;

    *a = a.wrapping_add(n_a);
    *b = b.wrapping_add(n_b);
    *c = c.wrapping_add(n_c);
    *d = d.wrapping_add(n_d);
    *e = e.wrapping_add(n_e);
}
