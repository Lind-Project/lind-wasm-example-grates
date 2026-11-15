//! The byte streams the grate hands out: one ChaCha20 keystream per cage.
//!
//! The key holds the declared seed, the nonce is the cage id and the block counter is the
//! position in that cage's stream, so every byte follows from (seed, cage, position) alone and
//! the grate keeps no generator state. This is the original ChaCha20, with a 64-bit counter and
//! a 64-bit nonce.

/// Fills the 24 key bytes after the seed, and separates these streams from other uses of ChaCha20
/// with the same seed.
const LABEL: &[u8; 24] = b"seeded-random-grate v1\0\0";

fn key(seed: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..8].copy_from_slice(&seed.to_le_bytes());
    k[8..].copy_from_slice(LABEL);
    k
}

fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn block(key: &[u8; 32], counter: u64, nonce: u64) -> [u8; 64] {
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for i in 0..8 {
        init[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    init[12] = counter as u32;
    init[13] = (counter >> 32) as u32;
    init[14] = nonce as u32;
    init[15] = (nonce >> 32) as u32;

    let mut s = init;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
    out
}

/// Writes the bytes at `pos..pos + out.len()` of the stream of `cage` under `seed`.
pub fn fill(seed: u64, cage: u64, pos: u64, out: &mut [u8]) {
    let key = key(seed);
    let mut counter = pos / 64;
    let mut skip = (pos % 64) as usize;
    let mut done = 0;
    while done < out.len() {
        let b = block(&key, counter, cage);
        let n = (64 - skip).min(out.len() - done);
        out[done..done + n].copy_from_slice(&b[skip..skip + n]);
        done += n;
        skip = 0;
        counter = counter.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8439, section 2.3.2. Its 32-bit counter and 96-bit nonce fill the same four state
    // words as the 64-bit counter and nonce here.
    #[test]
    fn block_matches_rfc_8439() {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        let expected = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        assert_eq!(block(&k, 0x0900_0000_0000_0001, 0x4a00_0000), expected);
    }

    // The first bytes for seed 42 and cage 7, as OpenSSL's chacha20 gives them for the same key,
    // counter and nonce (the test program test/random_test.c checks the same construction).
    #[test]
    fn stream_matches_openssl() {
        let mut out = [0u8; 16];
        fill(42, 7, 0, &mut out);
        assert_eq!(out, SEED_42_CAGE_7);
    }

    #[test]
    fn reads_join_into_one_stream() {
        let mut whole = [0u8; 300];
        fill(1, 2, 0, &mut whole);
        for split in [0, 1, 63, 64, 65, 128, 299, 300] {
            let mut parts = [0u8; 300];
            let (a, b) = parts.split_at_mut(split);
            fill(1, 2, 0, a);
            fill(1, 2, split as u64, b);
            assert_eq!(parts, whole, "split at {split}");
        }
    }

    #[test]
    fn cages_and_seeds_have_their_own_streams() {
        let read = |seed, cage| {
            let mut out = [0u8; 32];
            fill(seed, cage, 0, &mut out);
            out
        };
        assert_ne!(read(1, 2), read(1, 3));
        assert_ne!(read(1, 2), read(2, 2));
        assert_eq!(read(1, 2), read(1, 2));
    }

    const SEED_42_CAGE_7: [u8; 16] = [
        0x2e, 0x0d, 0x19, 0x69, 0xf9, 0xa0, 0x18, 0xc4, 0x28, 0xe2, 0x20, 0x32, 0x66, 0xb9, 0x3e,
        0xb8,
    ];
}
