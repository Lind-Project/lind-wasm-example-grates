//! Reading a preload archive out of another cage and describing it as an
//! in-toto statement.
//!
//! The archive is streamed: the header and each entry's header and path are
//! read on their own, and file data in chunks, so the grate never holds a
//! second copy of a compiler pipeline. Every file is hashed, and the whole
//! payload is hashed too and must match the digest in the archive header, so
//! the statement describes exactly the bytes IMFS checked and staged.

use preload_archive::attest::{PREDICATE_TYPE, STATEMENT_TYPE};
use preload_archive::{DIGEST_LEN, ENTRY_HEADER_LEN, HEADER_LEN, MAGIC, VERSION};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::sign::hex;

/// Bytes read per call when hashing file data.
const CHUNK: usize = 1 << 20;
/// Longest entry path accepted.
const MAX_PATH: usize = 4096;

/// Random access to the archive bytes (another cage's memory in the grate,
/// a slice in tests).
pub trait Source {
    fn len(&self) -> u64;
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), String>;
}

impl Source for &[u8] {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), String> {
        let start = usize::try_from(offset).map_err(|_| "offset too large")?;
        let end = start.checked_add(buf.len()).ok_or("offset too large")?;
        buf.copy_from_slice(self.get(start..end).ok_or("read past the end")?);
        Ok(())
    }
}

/// One file of the archive and its SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub name: String,
    pub sha256: String,
}

/// What an archive holds, as hashed by the grate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveSummary {
    pub subjects: Vec<Subject>,
    /// SHA-256 of the payload (equal to the digest in the header).
    pub payload_sha256: String,
    pub bytes: u64,
}

struct Cursor<'a, S: Source> {
    source: &'a mut S,
    pos: u64,
    payload: Sha256,
}

impl<S: Source> Cursor<'_, S> {
    /// Read the next `buf.len()` bytes; payload bytes are also hashed.
    fn take(&mut self, buf: &mut [u8]) -> Result<(), String> {
        let end = self
            .pos
            .checked_add(buf.len() as u64)
            .filter(|&end| end <= self.source.len())
            .ok_or("archive truncated")?;
        self.source.read_at(self.pos, buf)?;
        if self.pos >= HEADER_LEN as u64 {
            self.payload.update(&buf[..]);
        }
        self.pos = end;
        Ok(())
    }
}

/// Hash every file of the archive in `source`.
pub fn summarize<S: Source>(source: &mut S) -> Result<ArchiveSummary, String> {
    let total = source.len();
    let mut cursor = Cursor {
        source,
        pos: 0,
        payload: Sha256::new(),
    };

    let mut header = [0u8; HEADER_LEN];
    cursor.take(&mut header)?;
    if header[..MAGIC.len()] != MAGIC {
        return Err("not a preload archive".to_string());
    }
    let u32_at = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    let u64_at = |b: &[u8], at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    if u32_at(&header, 8) != VERSION {
        return Err("unsupported preload archive version".to_string());
    }
    let count = u32_at(&header, 12);
    let payload_len = u64_at(&header, 16);
    let digest = &header[24..24 + DIGEST_LEN];
    if Some(total) != payload_len.checked_add(HEADER_LEN as u64) {
        return Err("archive length does not match its header".to_string());
    }

    let mut subjects = Vec::with_capacity(count.min(65536) as usize);
    let mut chunk = vec![0u8; CHUNK];
    for _ in 0..count {
        let mut entry = [0u8; ENTRY_HEADER_LEN];
        cursor.take(&mut entry)?;
        let path_len = u32_at(&entry, 0) as usize;
        let data_len = u64_at(&entry, 8);
        if path_len == 0 || path_len > MAX_PATH {
            return Err("bad entry path length".to_string());
        }
        let mut path = vec![0u8; path_len];
        cursor.take(&mut path)?;
        let name = String::from_utf8(path).map_err(|_| "entry path is not UTF-8")?;

        let mut file = Sha256::new();
        let mut left = data_len;
        while left > 0 {
            let n = left.min(CHUNK as u64) as usize;
            cursor.take(&mut chunk[..n])?;
            file.update(&chunk[..n]);
            left -= n as u64;
        }
        subjects.push(Subject {
            name,
            sha256: hex(&file.finalize()),
        });
    }

    if cursor.pos != total {
        return Err("trailing bytes after the last entry".to_string());
    }
    let payload = cursor.payload.finalize();
    if payload[..] != *digest {
        return Err("archive payload does not match its digest".to_string());
    }
    Ok(ArchiveSummary {
        subjects,
        payload_sha256: hex(&payload),
        bytes: total,
    })
}

/// The in-toto statement for archive number `index` of a run, named `step`.
/// `previous` is the SHA-256 of the envelope of the archive before it, which
/// chains the attestations of one run together.
pub fn statement(
    summary: &ArchiveSummary,
    step: &str,
    index: u64,
    previous: Option<&str>,
    keyid: &str,
) -> Value {
    let subjects: Vec<Value> = summary
        .subjects
        .iter()
        .map(|s| json!({ "name": s.name, "digest": { "sha256": s.sha256 } }))
        .collect();
    let mut predicate = json!({
        "step": step,
        "index": index,
        "archive": {
            "sha256": summary.payload_sha256,
            "entries": summary.subjects.len(),
            "bytes": summary.bytes,
        },
        "signer": { "keyid": keyid },
    });
    if let Some(previous) = previous {
        predicate["previous"] = json!({ "sha256": previous });
    }
    json!({
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use preload_archive::ArchiveBuilder;

    fn archive() -> Vec<u8> {
        let mut b = ArchiveBuilder::new();
        b.push("/bin/cc", 0o755, b"compiler");
        b.push("/big", 0o644, &vec![7u8; CHUNK + 5]);
        b.push("/empty", 0o644, b"");
        b.finish()
    }

    #[test]
    fn summarizes_every_file() {
        let bytes = archive();
        let summary = summarize(&mut &bytes[..]).unwrap();
        assert_eq!(summary.subjects.len(), 3);
        assert_eq!(summary.subjects[0].name, "/bin/cc");
        assert_eq!(
            summary.subjects[0].sha256,
            hex(&Sha256::digest(b"compiler"))
        );
        assert_eq!(
            summary.subjects[1].sha256,
            hex(&Sha256::digest(vec![7u8; CHUNK + 5]))
        );
        assert_eq!(summary.subjects[2].sha256, hex(&Sha256::digest(b"")));
        let info = preload_archive::read_header(&bytes).unwrap();
        assert_eq!(summary.payload_sha256, hex(&info.digest));
        assert_eq!(summary.bytes, bytes.len() as u64);
    }

    #[test]
    fn rejects_tampered_or_truncated_archives() {
        let bytes = archive();
        // Flip a byte of /big's data (the last entry, /empty, has none).
        let mut bad = bytes.clone();
        let at = bytes.len() - 30;
        bad[at] ^= 1;
        assert!(summarize(&mut &bad[..]).is_err());
        assert!(summarize(&mut &bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(summarize(&mut &longer[..]).is_err());
        assert!(
            summarize(&mut &b"not an archive at all, not at all, not at all, not at all"[..])
                .is_err()
        );
    }

    #[test]
    fn statement_lists_subjects_and_chains_to_the_previous_one() {
        let bytes = archive();
        let summary = summarize(&mut &bytes[..]).unwrap();
        let st = statement(&summary, "pipeline", 1, None, "abc");
        assert_eq!(st["_type"], STATEMENT_TYPE);
        assert_eq!(st["predicateType"], PREDICATE_TYPE);
        assert_eq!(st["subject"][0]["name"], "/bin/cc");
        assert_eq!(st["predicate"]["step"], "pipeline");
        assert_eq!(st["predicate"]["archive"]["entries"], 3);
        assert!(st["predicate"].get("previous").is_none());
        let st = statement(&summary, "sources", 2, Some("ff"), "abc");
        assert_eq!(st["predicate"]["previous"]["sha256"], "ff");
    }
}
