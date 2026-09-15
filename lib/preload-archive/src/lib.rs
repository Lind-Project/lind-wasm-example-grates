//! Preload archive: a list of files packed into one contiguous block of memory.
//!
//! The archive is how files reach the IMFS grate without IMFS ever touching
//! the host filesystem tree. Whoever builds it (the IMFS grate itself from its
//! `PRELOADS` list, or the native `mkpreload` tool ahead of time) ends up with
//! one buffer; IMFS is then given that buffer as a `(pointer, size)` pair and
//! creates its nodes straight from the bytes.
//!
//! The producer and the consumer sit on opposite sides of a trust boundary
//! (an untrusted runtime packs, an enclave or grate stages), so the format is
//! built to be checked, not trusted: every length is bounds-checked, the
//! header carries a SHA-256 of the payload, and a consumer can additionally
//! demand a specific digest it obtained through a trusted channel. See
//! [`verify_archive`].
//!
//! Feature `lind` (on by default) adds the [`host`] module: cage-side helpers
//! that read host files through 3i. Feature `native` adds the [`pack`]
//! module: the untrusted-side packer built on `std::fs`, for `mkpreload` and
//! ocall handlers. The format itself has no dependencies beyond `sha2`.
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! header  magic "LINDPRLD" (8), version u32 (2), entry count u32,
//!         payload_len u64, sha256(payload) [u8; 32]           = 56 bytes
//! payload entries back to back:
//!         path_len u32, mode u32, data_len u64, path bytes, data bytes
//! ```
//!
//! Entries are stored in list order. Staging the same IMFS path twice keeps
//! the last entry's contents, matching the PRELOADS semantics.

#[cfg(feature = "lind")]
pub mod host;
#[cfg(feature = "native")]
pub mod pack;

use std::fmt;

use sha2::{Digest as _, Sha256};

pub const MAGIC: [u8; 8] = *b"LINDPRLD";
pub const VERSION: u32 = 2;
pub const HEADER_LEN: usize = 56;
pub const ENTRY_HEADER_LEN: usize = 16;
pub const DIGEST_LEN: usize = 32;

/// SHA-256 of an archive's payload, as stored in its header.
pub type ArchiveDigest = [u8; DIGEST_LEN];

const OFF_VERSION: usize = 8;
const OFF_COUNT: usize = 12;
const OFF_PAYLOAD_LEN: usize = 16;
const OFF_DIGEST: usize = 24;

// =========================================================================
//  Building
// =========================================================================

/// Accumulates preload entries into one contiguous buffer.
pub struct ArchiveBuilder {
    buf: Vec<u8>,
    count: u32,
}

impl Default for ArchiveBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveBuilder {
    pub fn new() -> Self {
        // Header fields other than magic/version are patched in by finish().
        let mut buf = vec![0u8; HEADER_LEN];
        buf[..MAGIC.len()].copy_from_slice(&MAGIC);
        buf[OFF_VERSION..OFF_COUNT].copy_from_slice(&VERSION.to_le_bytes());
        ArchiveBuilder { buf, count: 0 }
    }

    /// Append one file: its IMFS path, permission bits, and full contents.
    pub fn push(&mut self, path: &str, mode: u32, data: &[u8]) {
        self.buf
            .extend_from_slice(&(path.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(&mode.to_le_bytes());
        self.buf
            .extend_from_slice(&(data.len() as u64).to_le_bytes());
        self.buf.extend_from_slice(path.as_bytes());
        self.buf.extend_from_slice(data);
        self.count += 1;
    }

    pub fn entries(&self) -> u32 {
        self.count
    }

    /// Finalize the header (entry count, payload length, payload digest) and
    /// hand back the buffer. Its `as_ptr()` and `len()` are what IMFS consumes.
    pub fn finish(mut self) -> Vec<u8> {
        let payload_len = (self.buf.len() - HEADER_LEN) as u64;
        let digest = Sha256::digest(&self.buf[HEADER_LEN..]);
        self.buf[OFF_COUNT..OFF_PAYLOAD_LEN].copy_from_slice(&self.count.to_le_bytes());
        self.buf[OFF_PAYLOAD_LEN..OFF_DIGEST].copy_from_slice(&payload_len.to_le_bytes());
        self.buf[OFF_DIGEST..HEADER_LEN].copy_from_slice(&digest);
        self.buf
    }
}

// =========================================================================
//  Parsing
// =========================================================================

/// Why an archive could not be parsed or verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveError {
    BadMagic,
    UnsupportedVersion(u32),
    /// The archive ended before the named field was complete.
    Truncated(&'static str),
    /// An entry path is not valid UTF-8.
    BadPath,
    TrailingBytes(usize),
    /// The header's payload length does not match the bytes that follow it.
    BadPayloadLength {
        header: u64,
        actual: usize,
    },
    /// The payload does not hash to the digest recorded in the header.
    DigestMismatch,
    /// The archive's digest is not the one the consumer was told to expect.
    UnexpectedDigest,
    /// The archive is larger than the consumer is willing to accept.
    TooLarge {
        len: usize,
        max: usize,
    },
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArchiveError::BadMagic => write!(f, "not a preload archive (bad magic)"),
            ArchiveError::UnsupportedVersion(v) => {
                write!(f, "unsupported preload archive version {}", v)
            }
            ArchiveError::Truncated(what) => write!(f, "preload archive truncated in {}", what),
            ArchiveError::BadPath => write!(f, "preload archive entry path is not UTF-8"),
            ArchiveError::TrailingBytes(n) => {
                write!(f, "preload archive has {} trailing bytes", n)
            }
            ArchiveError::BadPayloadLength { header, actual } => write!(
                f,
                "preload archive header claims {} payload bytes but {} follow",
                header, actual
            ),
            ArchiveError::DigestMismatch => {
                write!(f, "preload archive payload does not match its digest")
            }
            ArchiveError::UnexpectedDigest => {
                write!(f, "preload archive digest is not the expected one")
            }
            ArchiveError::TooLarge { len, max } => write!(
                f,
                "preload archive is {} bytes, more than the {} allowed",
                len, max
            ),
        }
    }
}

impl std::error::Error for ArchiveError {}

/// One decoded entry, borrowing from the archive.
#[derive(Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub path: &'a str,
    pub mode: u32,
    pub data: &'a [u8],
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], ArchiveError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.bytes.len())
            .ok_or(ArchiveError::Truncated(what))?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u32(&mut self, what: &'static str) -> Result<u32, ArchiveError> {
        let b = self.take(4, what)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self, what: &'static str) -> Result<u64, ArchiveError> {
        let b = self.take(8, what)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
}

/// The header of an archive, checked against the bytes that follow it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveInfo {
    pub entries: u32,
    pub payload_len: u64,
    pub digest: ArchiveDigest,
}

/// Parse and check the header: magic, version, that exactly `payload_len`
/// bytes follow, and that they hash to the recorded digest. Entries are not
/// decoded. This is the cheap integrity check to run on a blob that crossed
/// a trust boundary, before anything else looks at it.
pub fn read_header(bytes: &[u8]) -> Result<ArchiveInfo, ArchiveError> {
    let mut r = Reader { bytes, pos: 0 };

    if r.take(MAGIC.len(), "header")? != MAGIC {
        return Err(ArchiveError::BadMagic);
    }
    let version = r.u32("header")?;
    if version != VERSION {
        return Err(ArchiveError::UnsupportedVersion(version));
    }
    let entries = r.u32("header")?;
    let payload_len = r.u64("header")?;
    let mut digest = [0u8; DIGEST_LEN];
    digest.copy_from_slice(r.take(DIGEST_LEN, "header")?);

    let payload = &bytes[HEADER_LEN..];
    if payload_len != payload.len() as u64 {
        return Err(ArchiveError::BadPayloadLength {
            header: payload_len,
            actual: payload.len(),
        });
    }
    if Sha256::digest(payload).as_slice() != digest {
        return Err(ArchiveError::DigestMismatch);
    }

    Ok(ArchiveInfo {
        entries,
        payload_len,
        digest,
    })
}

/// Everything a consumer should check before staging a blob it did not build
/// itself: a size cap, the header and payload digest, and optionally that the
/// digest is the one it was told to expect through a trusted channel.
///
/// Call this on a copy the consumer owns. A blob still sitting in memory the
/// producer can write to could change after the check.
pub fn verify_archive(
    bytes: &[u8],
    max_len: usize,
    expected: Option<&ArchiveDigest>,
) -> Result<ArchiveInfo, ArchiveError> {
    if bytes.len() > max_len {
        return Err(ArchiveError::TooLarge {
            len: bytes.len(),
            max: max_len,
        });
    }
    let info = read_header(bytes)?;
    if let Some(expected) = expected {
        if *expected != info.digest {
            return Err(ArchiveError::UnexpectedDigest);
        }
    }
    Ok(info)
}

/// Decode an archive into its entries without copying any file data. The
/// header and digest are checked first, and every entry length is
/// bounds-checked, so a corrupt, truncated or tampered buffer is rejected
/// rather than read past its end.
pub fn parse_archive(bytes: &[u8]) -> Result<Vec<Entry<'_>>, ArchiveError> {
    let info = read_header(bytes)?;
    let count = info.entries;
    let mut r = Reader {
        bytes,
        pos: HEADER_LEN,
    };

    let mut entries = Vec::with_capacity(count.min(1024) as usize);
    for _ in 0..count {
        let path_len = r.u32("entry header")? as usize;
        let mode = r.u32("entry header")?;
        let data_len = r.u64("entry header")?;
        let data_len =
            usize::try_from(data_len).map_err(|_| ArchiveError::Truncated("entry data"))?;
        let path = std::str::from_utf8(r.take(path_len, "entry path")?)
            .map_err(|_| ArchiveError::BadPath)?;
        let data = r.take(data_len, "entry data")?;
        entries.push(Entry { path, mode, data });
    }

    if r.pos != bytes.len() {
        return Err(ArchiveError::TrailingBytes(bytes.len() - r.pos));
    }
    Ok(entries)
}

/// Lower-case hex of a digest, as `mkpreload` prints it.
pub fn digest_to_hex(digest: &ArchiveDigest) -> String {
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Parse the 64-character hex form of a digest.
pub fn parse_digest_hex(hex: &str) -> Option<ArchiveDigest> {
    let hex = hex.trim();
    if hex.len() != DIGEST_LEN * 2 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0u8; DIGEST_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Split one PRELOADS entry into `(imfs_path, host_path)`.
///
/// A bare path maps onto itself; `imfs_path=host_path` maps the host file to
/// a different IMFS path. Returns None for entries that cannot name a file on
/// both sides: the empty entry, `=host_path`, and `imfs_path=`.
pub fn parse_preload_entry(entry: &str) -> Option<(&str, &str)> {
    match entry.split_once('=') {
        Some((imfs_path, host_path)) if !imfs_path.is_empty() && !host_path.is_empty() => {
            Some((imfs_path, host_path))
        }
        None if !entry.is_empty() => Some((entry, entry)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 7 + 3) & 0xff) as u8).collect()
    }

    fn archive(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
        let mut b = ArchiveBuilder::new();
        for (path, mode, data) in entries {
            b.push(path, *mode, data);
        }
        b.finish()
    }

    #[test]
    fn builder_and_parser_roundtrip() {
        let bytes = archive(&[
            ("/a.txt", 0o644, b"hello"),
            ("dir/b.bin", 0o600, &pattern(3000)),
            ("/empty", 0o444, b""),
        ]);
        let entries = parse_archive(&bytes).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0],
            Entry {
                path: "/a.txt",
                mode: 0o644,
                data: b"hello"
            }
        );
        assert_eq!(entries[1].path, "dir/b.bin");
        assert_eq!(entries[1].mode, 0o600);
        assert_eq!(entries[1].data, pattern(3000));
        assert_eq!(entries[2].data, b"");
        assert_eq!(
            bytes.len(),
            HEADER_LEN
                + (ENTRY_HEADER_LEN + 6 + 5)
                + (ENTRY_HEADER_LEN + 9 + 3000)
                + (ENTRY_HEADER_LEN + 6)
        );
    }

    #[test]
    fn empty_archive_has_no_entries() {
        let bytes = ArchiveBuilder::new().finish();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert!(parse_archive(&bytes).unwrap().is_empty());
        assert_eq!(read_header(&bytes).unwrap().entries, 0);
    }

    #[test]
    fn corrupt_archives_are_rejected() {
        let good = archive(&[("/a", 0o644, b"abc")]);
        let err = |bytes: &[u8]| parse_archive(bytes).map(|_| ());

        assert_eq!(err(&[]), Err(ArchiveError::Truncated("header")));

        let mut bad = good.clone();
        bad[0] = b'X';
        assert_eq!(err(&bad), Err(ArchiveError::BadMagic));

        let mut bad = good.clone();
        bad[OFF_VERSION..OFF_COUNT].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(err(&bad), Err(ArchiveError::UnsupportedVersion(7)));

        // Any change to the payload is caught by the digest before decoding.
        assert!(matches!(
            err(&good[..good.len() - 1]),
            Err(ArchiveError::BadPayloadLength { .. })
        ));
        let mut bad = good.clone();
        bad.push(0);
        assert!(matches!(
            err(&bad),
            Err(ArchiveError::BadPayloadLength { .. })
        ));
        let mut bad = good.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(err(&bad), Err(ArchiveError::DigestMismatch));

        // A header that lies about its payload is caught too: count, length
        // and digest edited together so the digest check passes, then the
        // entry decoding must still refuse to read past the end.
        let reseal = |bytes: &mut Vec<u8>| {
            let payload_len = (bytes.len() - HEADER_LEN) as u64;
            let digest = Sha256::digest(&bytes[HEADER_LEN..]);
            bytes[OFF_PAYLOAD_LEN..OFF_DIGEST].copy_from_slice(&payload_len.to_le_bytes());
            bytes[OFF_DIGEST..HEADER_LEN].copy_from_slice(&digest);
        };

        // Entry count says two, but only one follows.
        let mut bad = good.clone();
        bad[OFF_COUNT..OFF_PAYLOAD_LEN].copy_from_slice(&2u32.to_le_bytes());
        reseal(&mut bad);
        assert_eq!(err(&bad), Err(ArchiveError::Truncated("entry header")));

        // A data length that cannot fit is caught before any slicing.
        let mut bad = good.clone();
        bad[HEADER_LEN + 8..HEADER_LEN + 16].copy_from_slice(&u64::MAX.to_le_bytes());
        reseal(&mut bad);
        assert!(matches!(err(&bad), Err(ArchiveError::Truncated(_))));

        let mut bad = good.clone();
        bad[HEADER_LEN + ENTRY_HEADER_LEN] = 0xff; // first path byte
        reseal(&mut bad);
        assert_eq!(err(&bad), Err(ArchiveError::BadPath));

        // Payload truncated but resealed: the last entry runs off the end.
        let mut bad = good.clone();
        bad.pop();
        reseal(&mut bad);
        assert_eq!(err(&bad), Err(ArchiveError::Truncated("entry data")));
    }

    #[test]
    fn verify_checks_size_cap_and_expected_digest() {
        let good = archive(&[("/a", 0o644, b"abc")]);
        let info = read_header(&good).unwrap();
        assert_eq!(info.entries, 1);
        assert_eq!(info.payload_len as usize, good.len() - HEADER_LEN);
        assert_eq!(
            info.digest.as_slice(),
            Sha256::digest(&good[HEADER_LEN..]).as_slice()
        );

        assert_eq!(verify_archive(&good, good.len(), None), Ok(info));
        assert_eq!(
            verify_archive(&good, good.len(), Some(&info.digest)),
            Ok(info)
        );
        assert_eq!(
            verify_archive(&good, good.len() - 1, None),
            Err(ArchiveError::TooLarge {
                len: good.len(),
                max: good.len() - 1
            })
        );
        let other = [0x5au8; DIGEST_LEN];
        assert_eq!(
            verify_archive(&good, good.len(), Some(&other)),
            Err(ArchiveError::UnexpectedDigest)
        );

        // Same contents always produce the same digest; a different mode does not.
        assert_eq!(archive(&[("/a", 0o644, b"abc")]), good);
        assert_ne!(
            read_header(&archive(&[("/a", 0o600, b"abc")]))
                .unwrap()
                .digest,
            info.digest
        );
    }

    #[test]
    fn digest_hex_roundtrips() {
        let digest: ArchiveDigest = core::array::from_fn(|i| (i * 8 + 1) as u8);
        let hex = digest_to_hex(&digest);
        assert_eq!(hex.len(), 64);
        assert_eq!(parse_digest_hex(&hex), Some(digest));
        assert_eq!(parse_digest_hex(&hex.to_uppercase()), Some(digest));
        assert_eq!(parse_digest_hex(&format!("  {}\n", hex)), Some(digest));
        assert_eq!(parse_digest_hex(&hex[..63]), None);
        assert_eq!(parse_digest_hex(&format!("{}0", hex)), None);
        assert_eq!(parse_digest_hex(&hex.replace('1', "g")), None);
    }

    fn parse_preloads(preloads: &str) -> Vec<(&str, &str)> {
        preloads
            .split(':')
            .filter_map(parse_preload_entry)
            .collect()
    }

    #[test]
    fn bare_entry_maps_a_path_onto_itself() {
        assert_eq!(
            parse_preload_entry("/hello.c"),
            Some(("/hello.c", "/hello.c"))
        );
    }

    #[test]
    fn mapped_entry_splits_imfs_path_from_host_path() {
        assert_eq!(
            parse_preload_entry("/hello.c=/host/hello.c"),
            Some(("/hello.c", "/host/hello.c"))
        );
    }

    #[test]
    fn malformed_entries_are_skipped() {
        assert_eq!(parse_preload_entry(""), None);
        assert_eq!(parse_preload_entry("="), None);
        assert_eq!(parse_preload_entry("=/host/hello.c"), None);
        assert_eq!(parse_preload_entry("/hello.c="), None);
    }

    #[test]
    fn malformed_entries_do_not_drop_the_entries_around_them() {
        assert_eq!(
            parse_preloads("/a.txt=a.txt::=b.txt:c.txt=:/d.txt=d.txt"),
            vec![("/a.txt", "a.txt"), ("/d.txt", "d.txt")]
        );
    }
}
