/// Split input into blocks, apply padding, delim, zeroes and suffix.
#[inline(always)]
pub(crate) const fn eager_split_pad<'a, const BLOCK_SIZE: usize, const SFX_LEN: usize>(
    input: &'a [u8],
    suffix: &[u8; SFX_LEN],
    delim: u8,
    b0: &mut [u8; BLOCK_SIZE], // final block with padding
    b1: &mut [u8; BLOCK_SIZE], // optional second final block if needed
) -> (
    &'a [[u8; BLOCK_SIZE]], // blocks
    bool,                   // true if two blocks is necessary for padding
) {
    let (blocks, rem) = input.as_chunks();

    let pad_two_blocks = rem.len() > BLOCK_SIZE - 1 - SFX_LEN;

    b0.split_at_mut(rem.len()).0.copy_from_slice(rem);
    b0[rem.len()] = delim;

    if SFX_LEN > 0 {
        if pad_two_blocks {
            b1.as_chunks_mut::<SFX_LEN>().0[7].copy_from_slice(suffix);
        } else {
            b0.as_chunks_mut::<SFX_LEN>().0[7].copy_from_slice(suffix);
        }
    }

    (blocks, pad_two_blocks)
}
