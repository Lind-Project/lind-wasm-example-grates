use crate::cipher::ContentCipher;
use crate::errno::{EFBIG, EINVAL, EIO};
use crate::format::{
    BLOCK_OVERHEAD, BLOCK_SIZE, CIPHER_BLOCK_SIZE, FileId, HEADER_LEN, MAX_LOGICAL_SIZE, NONCE_LEN,
    block_offset, decode_header, encode_header, logical_size, physical_size,
};

/// Positioned access to the ciphertext. Errors are positive errno values.
pub trait BlockIo {
    /// Reads at `offset`; returns 0 at end of file.
    fn pread(&mut self, buf: &mut [u8], offset: u64) -> Result<usize, i32>;
    fn pwrite(&mut self, buf: &[u8], offset: u64) -> Result<usize, i32>;
    /// Physical (ciphertext) size in bytes.
    fn size(&mut self) -> Result<u64, i32>;
    fn set_size(&mut self, size: u64) -> Result<(), i32>;
}

/// Blocks handled per ciphertext I/O, bounding the grate's buffers (256 KiB of
/// plaintext). The grate's linear memory is capped at 64 MiB.
pub const CHUNK_BLOCKS: u64 = 64;
pub const CHUNK_BYTES: u64 = CHUNK_BLOCKS * BLOCK_SIZE;

pub struct CryptFile<'a, I: BlockIo> {
    io: &'a mut I,
    cipher: &'a ContentCipher,
    random: &'a mut dyn FnMut(&mut [u8]),
}

#[allow(clippy::len_without_is_empty)]
impl<'a, I: BlockIo> CryptFile<'a, I> {
    /// `random` must fill its buffer with cryptographically secure bytes; it
    /// supplies file ids and per-block nonces.
    pub fn new(
        io: &'a mut I,
        cipher: &'a ContentCipher,
        random: &'a mut dyn FnMut(&mut [u8]),
    ) -> Self {
        Self { io, cipher, random }
    }

    /// Plaintext size.
    pub fn len(&mut self) -> Result<u64, i32> {
        Ok(logical_size(self.io.size()?))
    }

    /// Reads plaintext at `offset` into `buf`; returns the bytes read (0 at EOF).
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, i32> {
        // Check the header even when there is nothing to read, so a file that
        // was never encrypted fails loudly instead of reading as empty.
        let Some(file_id) = self.load_header()? else {
            return Ok(0);
        };
        let size = self.len()?;
        if buf.is_empty() || offset >= size {
            return Ok(0);
        }
        let end = size.min(offset.saturating_add(buf.len() as u64));

        let mut pos = offset;
        while pos < end {
            let first = pos / BLOCK_SIZE;
            let last = ((end - 1) / BLOCK_SIZE).min(first + CHUNK_BLOCKS - 1);
            let phys_start = block_offset(first);
            let phys_end = block_offset(last) + sealed_len(last, size);
            let mut sealed = vec![0u8; (phys_end - phys_start) as usize];
            read_exact_at(self.io, &mut sealed, phys_start)?;

            for block in first..=last {
                let rel = ((block - first) * CIPHER_BLOCK_SIZE) as usize;
                let chunk = &sealed[rel..rel + sealed_len(block, size) as usize];
                let plain = self
                    .cipher
                    .open_block(&file_id, block, chunk)
                    .map_err(|_| EIO)?;
                let block_start = block * BLOCK_SIZE;
                let lo = pos.max(block_start) - block_start;
                let hi = end.min(block_start + BLOCK_SIZE) - block_start;
                let dst = (block_start + lo - offset) as usize;
                buf[dst..dst + (hi - lo) as usize]
                    .copy_from_slice(&plain[lo as usize..hi as usize]);
            }
            pos = end.min((last + 1) * BLOCK_SIZE);
        }
        Ok((end - offset) as usize)
    }

    /// Writes plaintext at `offset`, zero-filling any gap past the current end.
    /// Returns `data.len()`.
    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<usize, i32> {
        if data.is_empty() {
            return Ok(0);
        }
        let end = offset.checked_add(data.len() as u64).ok_or(EFBIG)?;
        if end > MAX_LOGICAL_SIZE {
            return Err(EFBIG);
        }
        let mut size = self.len()?;
        let file_id = self.ensure_header()?;
        if offset > size {
            self.zero_fill(&file_id, offset, &mut size)?;
        }
        self.write_span(&file_id, offset, data, &mut size)?;
        Ok(data.len())
    }

    /// Sets the plaintext size, like `ftruncate`: shrinking drops data,
    /// growing appends zeros.
    pub fn set_len(&mut self, new_size: u64) -> Result<(), i32> {
        if new_size > MAX_LOGICAL_SIZE {
            return Err(EFBIG);
        }
        let mut size = self.len()?;
        if new_size == 0 {
            return self.io.set_size(0);
        }
        if new_size > size {
            let file_id = self.ensure_header()?;
            return self.zero_fill(&file_id, new_size, &mut size);
        }
        if new_size < size {
            let file_id = self.load_header()?.ok_or(EIO)?;
            let block = new_size / BLOCK_SIZE;
            let keep = (new_size % BLOCK_SIZE) as usize;
            if keep != 0 {
                // The new last block is partial: re-seal its shortened plaintext.
                let mut plain = self.read_block(&file_id, block, size)?;
                plain.truncate(keep);
                let mut out = Vec::with_capacity(keep + BLOCK_OVERHEAD as usize);
                self.seal(&file_id, block, &plain, &mut out);
                write_all_at(self.io, &out, block_offset(block))?;
            }
        }
        // Also trims any torn tail left behind when new_size == size.
        self.io.set_size(physical_size(new_size))
    }

    /// Writes `data` at `offset` in chunks of at most CHUNK_BLOCKS blocks.
    /// Requires `offset <= *size`.
    fn write_span(
        &mut self,
        file_id: &FileId,
        offset: u64,
        data: &[u8],
        size: &mut u64,
    ) -> Result<(), i32> {
        let end = offset + data.len() as u64;
        let mut pos = offset;
        while pos < end {
            let chunk_end = end.min((pos / BLOCK_SIZE + CHUNK_BLOCKS) * BLOCK_SIZE);
            let src = &data[(pos - offset) as usize..(chunk_end - offset) as usize];
            self.write_blocks(file_id, pos, src, *size)?;
            *size = (*size).max(chunk_end);
            pos = chunk_end;
        }
        Ok(())
    }

    /// Extends the file with zeros from `*size` up to `to`.
    fn zero_fill(&mut self, file_id: &FileId, to: u64, size: &mut u64) -> Result<(), i32> {
        let zeros = vec![0u8; CHUNK_BYTES.min(to - *size) as usize];
        while *size < to {
            let n = (to - *size).min(zeros.len() as u64) as usize;
            let at = *size;
            self.write_span(file_id, at, &zeros[..n], size)?;
        }
        Ok(())
    }

    /// Re-seals the blocks covering `[offset, offset + data.len())` (at most
    /// CHUNK_BLOCKS of them) and writes them with one positioned write.
    /// Partially covered blocks that already hold data are read and merged.
    fn write_blocks(
        &mut self,
        file_id: &FileId,
        offset: u64,
        data: &[u8],
        size: u64,
    ) -> Result<(), i32> {
        let end = offset + data.len() as u64;
        let first = offset / BLOCK_SIZE;
        let last = (end - 1) / BLOCK_SIZE;
        let mut out = Vec::with_capacity(((last - first + 1) * CIPHER_BLOCK_SIZE) as usize);

        for block in first..=last {
            let block_start = block * BLOCK_SIZE;
            let lo = (offset.max(block_start) - block_start) as usize;
            let hi = (end.min(block_start + BLOCK_SIZE) - block_start) as usize;
            let existing = size.saturating_sub(block_start).min(BLOCK_SIZE) as usize;
            let src = &data[(block_start + lo as u64 - offset) as usize
                ..(block_start + hi as u64 - offset) as usize];

            let plain = if lo == 0 && hi >= existing {
                // The write covers everything this block holds: no read needed.
                src.to_vec()
            } else {
                let mut p = if existing > 0 {
                    self.read_block(file_id, block, size)?
                } else {
                    Vec::new()
                };
                if p.len() < hi {
                    p.resize(hi, 0);
                }
                p[lo..hi].copy_from_slice(src);
                p
            };
            self.seal(file_id, block, &plain, &mut out);
        }
        write_all_at(self.io, &out, block_offset(first))
    }

    fn read_block(&mut self, file_id: &FileId, block: u64, size: u64) -> Result<Vec<u8>, i32> {
        let mut sealed = vec![0u8; sealed_len(block, size) as usize];
        read_exact_at(self.io, &mut sealed, block_offset(block))?;
        self.cipher
            .open_block(file_id, block, &sealed)
            .map_err(|_| EIO)
    }

    fn seal(&mut self, file_id: &FileId, block: u64, plain: &[u8], out: &mut Vec<u8>) {
        let mut nonce = [0u8; NONCE_LEN as usize];
        (self.random)(&mut nonce);
        self.cipher.seal_block(file_id, block, &nonce, plain, out);
    }

    /// The file id, `None` for an empty file, `EIO` if the header is missing
    /// or damaged (for example, a plaintext file that was never encrypted).
    fn load_header(&mut self) -> Result<Option<FileId>, i32> {
        let physical = self.io.size()?;
        if physical == 0 {
            return Ok(None);
        }
        if physical < HEADER_LEN {
            return Err(EIO);
        }
        let mut h = [0u8; HEADER_LEN as usize];
        read_exact_at(self.io, &mut h, 0)?;
        decode_header(&h).map(Some).ok_or(EIO)
    }

    /// The file id, writing a fresh header first if the file is empty.
    fn ensure_header(&mut self) -> Result<FileId, i32> {
        if let Some(id) = self.load_header()? {
            return Ok(id);
        }
        let mut id: FileId = Default::default();
        (self.random)(&mut id);
        write_all_at(self.io, &encode_header(&id), 0)?;
        Ok(id)
    }
}

/// Sealed length of `block` in a file of plaintext size `size`.
fn sealed_len(block: u64, size: u64) -> u64 {
    let plain = (size - block * BLOCK_SIZE).min(BLOCK_SIZE);
    plain + BLOCK_OVERHEAD
}

fn read_exact_at<I: BlockIo>(io: &mut I, buf: &mut [u8], offset: u64) -> Result<(), i32> {
    let mut done = 0;
    while done < buf.len() {
        match io.pread(&mut buf[done..], offset + done as u64)? {
            0 => return Err(EIO), // ciphertext shorter than its size claims
            n => done += n,
        }
    }
    Ok(())
}

fn write_all_at<I: BlockIo>(io: &mut I, buf: &[u8], offset: u64) -> Result<(), i32> {
    let mut done = 0;
    while done < buf.len() {
        match io.pwrite(&buf[done..], offset + done as u64)? {
            0 => return Err(EIO),
            n => done += n,
        }
    }
    Ok(())
}

/// Validates a seek target coming from the cage.
pub fn checked_offset(offset: i64) -> Result<u64, i32> {
    if offset < 0 {
        Err(EINVAL)
    } else {
        Ok(offset as u64)
    }
}
