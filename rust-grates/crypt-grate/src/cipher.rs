use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::format::{FILE_ID_LEN, FileId, NONCE_LEN};

/// HKDF `info` for the content key. Changing it changes every derived key.
const CONTENT_KEY_INFO: &[u8] = b"lind crypt-grate v1 content key";

pub struct ContentCipher {
    aead: Aes256Gcm,
}

impl ContentCipher {
    /// Derives the content key from the 32-byte master key with HKDF-SHA256, so
    /// the master key itself is never used directly for encryption.
    pub fn from_master_key(master: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, master);
        let mut key = [0u8; 32];
        hk.expand(CONTENT_KEY_INFO, &mut key)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        let aead = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        key.fill(0);
        Self { aead }
    }

    /// Appends `nonce | ciphertext | tag` for `plain` to `out`.
    pub fn seal_block(
        &self,
        file_id: &FileId,
        block: u64,
        nonce: &[u8; NONCE_LEN as usize],
        plain: &[u8],
        out: &mut Vec<u8>,
    ) {
        let aad = aad(file_id, block);
        let ct = self
            .aead
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plain,
                    aad: &aad,
                },
            )
            .expect("AES-GCM encryption of a <= 4 KiB block cannot fail");
        out.extend_from_slice(nonce);
        out.extend_from_slice(&ct);
    }

    /// Opens a sealed block. Fails if it was modified, moved to another block
    /// number, copied from another file, or sealed under another key.
    #[allow(clippy::result_unit_err)]
    pub fn open_block(&self, file_id: &FileId, block: u64, sealed: &[u8]) -> Result<Vec<u8>, ()> {
        let n = NONCE_LEN as usize;
        if sealed.len() < n {
            return Err(());
        }
        let aad = aad(file_id, block);
        self.aead
            .decrypt(
                Nonce::from_slice(&sealed[..n]),
                Payload {
                    msg: &sealed[n..],
                    aad: &aad,
                },
            )
            .map_err(|_| ())
    }
}

fn aad(file_id: &FileId, block: u64) -> [u8; FILE_ID_LEN + 8] {
    let mut a = [0u8; FILE_ID_LEN + 8];
    a[..FILE_ID_LEN].copy_from_slice(file_id);
    a[FILE_ID_LEN..].copy_from_slice(&block.to_le_bytes());
    a
}

/// Parses a key file: exactly 32 raw bytes, or 64 hex digits (surrounding
/// whitespace allowed, e.g. the output of `openssl rand -hex 32`).
pub fn parse_key_file(contents: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    if contents.len() == 32 {
        key.copy_from_slice(contents);
        return Ok(key);
    }
    let text = std::str::from_utf8(contents)
        .map_err(|_| {
            format!(
                "key file must be 32 raw bytes or 64 hex digits (got {} bytes)",
                contents.len()
            )
        })?
        .trim();
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "key file must be 32 raw bytes or 64 hex digits (got {} bytes)",
            contents.len()
        ));
    }
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
    }
    Ok(key)
}
