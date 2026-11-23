pub const MAGIC: [u8; 4] = *b"LCRY";
pub const VERSION: u16 = 1;

pub const FILE_ID_LEN: usize = 16;
pub const HEADER_LEN: u64 = 24;

pub const BLOCK_SIZE: u64 = 4096;
pub const NONCE_LEN: u64 = 12;
pub const TAG_LEN: u64 = 16;
pub const BLOCK_OVERHEAD: u64 = NONCE_LEN + TAG_LEN;
pub const CIPHER_BLOCK_SIZE: u64 = BLOCK_SIZE + BLOCK_OVERHEAD;

/// Largest logical size we accept, so physical offsets always fit in an i64.
pub const MAX_LOGICAL_SIZE: u64 = 1 << 60;

pub type FileId = [u8; FILE_ID_LEN];

/// Plaintext size of a file whose ciphertext is `physical` bytes long.
///
/// A trailing fragment too short to hold a sealed block (a torn write) is
/// ignored here; reading it fails authentication instead.
pub fn logical_size(physical: u64) -> u64 {
    if physical <= HEADER_LEN {
        return 0;
    }
    let body = physical - HEADER_LEN;
    let full = body / CIPHER_BLOCK_SIZE;
    let rem = body % CIPHER_BLOCK_SIZE;
    full * BLOCK_SIZE + rem.saturating_sub(BLOCK_OVERHEAD)
}

/// Ciphertext size of a file holding `logical` plaintext bytes.
pub fn physical_size(logical: u64) -> u64 {
    if logical == 0 {
        return 0;
    }
    let full = logical / BLOCK_SIZE;
    let rem = logical % BLOCK_SIZE;
    let tail = if rem == 0 { 0 } else { rem + BLOCK_OVERHEAD };
    HEADER_LEN + full * CIPHER_BLOCK_SIZE + tail
}

/// Physical offset of sealed block `block`.
pub fn block_offset(block: u64) -> u64 {
    HEADER_LEN + block * CIPHER_BLOCK_SIZE
}

pub fn encode_header(file_id: &FileId) -> [u8; HEADER_LEN as usize] {
    let mut h = [0u8; HEADER_LEN as usize];
    h[0..4].copy_from_slice(&MAGIC);
    h[4..6].copy_from_slice(&VERSION.to_le_bytes());
    h[8..24].copy_from_slice(file_id);
    h
}

/// Returns the file id, or `None` if this is not a version-1 header.
pub fn decode_header(h: &[u8]) -> Option<FileId> {
    if h.len() < HEADER_LEN as usize || h[0..4] != MAGIC {
        return None;
    }
    if u16::from_le_bytes([h[4], h[5]]) != VERSION {
        return None;
    }
    let mut id = [0u8; FILE_ID_LEN];
    id.copy_from_slice(&h[8..24]);
    Some(id)
}
