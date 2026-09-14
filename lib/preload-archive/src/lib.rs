//! Preload archive: a list of files packed into one contiguous block of memory.
//!
//! The archive is how files reach the IMFS grate without IMFS ever touching
//! the host filesystem tree. Whoever builds it (the IMFS grate itself from its
//! `PRELOADS` list, or the native `mkpreload` tool ahead of time) ends up with
//! one buffer; IMFS is then given that buffer as a `(pointer, size)` pair and
//! creates its nodes straight from the bytes.
//!
//! The format has no dependencies, so a native program can produce it. The
//! `host` module (feature `lind`, on by default) adds the helpers that only
//! make sense inside a Lind cage.
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! header  magic "LINDPRLD" (8), version u32, entry count u32
//! entry   path_len u32, mode u32, data_len u64, path bytes, data bytes
//! ```
//!
//! Entries are stored in list order. Staging the same IMFS path twice keeps
//! the last entry's contents, matching the PRELOADS semantics.

#[cfg(feature = "lind")]
pub mod host;

use std::fmt;

pub const MAGIC: [u8; 8] = *b"LINDPRLD";
pub const VERSION: u32 = 1;
pub const HEADER_LEN: usize = 16;
pub const ENTRY_HEADER_LEN: usize = 16;

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
        let mut buf = Vec::with_capacity(HEADER_LEN);
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // entry count, patched by finish()
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

    /// Finalize the header and hand back the buffer. Its `as_ptr()` and
    /// `len()` are what IMFS consumes.
    pub fn finish(mut self) -> Vec<u8> {
        self.buf[12..16].copy_from_slice(&self.count.to_le_bytes());
        self.buf
    }
}

// =========================================================================
//  Parsing
// =========================================================================

/// Why an archive could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveError {
    BadMagic,
    UnsupportedVersion(u32),
    /// The archive ended before the named field was complete.
    Truncated(&'static str),
    /// An entry path is not valid UTF-8.
    BadPath,
    TrailingBytes(usize),
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

/// Decode an archive into its entries without copying any file data. Every
/// length is bounds-checked, so a corrupt or truncated buffer is rejected
/// rather than read past its end.
pub fn parse_archive(bytes: &[u8]) -> Result<Vec<Entry<'_>>, ArchiveError> {
    let mut r = Reader { bytes, pos: 0 };

    if r.take(MAGIC.len(), "header")? != MAGIC {
        return Err(ArchiveError::BadMagic);
    }
    let version = r.u32("header")?;
    if version != VERSION {
        return Err(ArchiveError::UnsupportedVersion(version));
    }
    let count = r.u32("header")?;

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
        bad[8..12].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(err(&bad), Err(ArchiveError::UnsupportedVersion(7)));

        assert_eq!(
            err(&good[..good.len() - 1]),
            Err(ArchiveError::Truncated("entry data"))
        );

        // Entry count says two, but only one follows.
        let mut bad = good.clone();
        bad[12..16].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(err(&bad), Err(ArchiveError::Truncated("entry header")));

        // A data length that cannot fit is caught before any slicing.
        let mut bad = good.clone();
        bad[HEADER_LEN + 8..HEADER_LEN + 16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(err(&bad), Err(ArchiveError::Truncated(_))));

        let mut bad = good.clone();
        bad[HEADER_LEN + ENTRY_HEADER_LEN] = 0xff; // first path byte
        assert_eq!(err(&bad), Err(ArchiveError::BadPath));

        let mut bad = good.clone();
        bad.push(0);
        assert_eq!(err(&bad), Err(ArchiveError::TrailingBytes(1)));
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
