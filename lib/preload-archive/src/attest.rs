//! The attestation request IMFS sends after staging a preload archive.
//!
//! IMFS stops after staging an archive (the compiler pipeline, then the
//! source files) and issues [`SYS_INTOTO_ATTEST`] on itself. The call is
//! routed by 3i to the in-toto grate that runs IMFS as its child. That grate
//! reads the archive straight out of IMFS's memory, hashes every file, signs
//! an in-toto statement over them and writes the DSSE envelope back into a
//! buffer IMFS provides. IMFS then resumes.
//!
//! Arguments, in order (pointers are IMFS addresses, passed with
//! `GRATE_MEMORY_FLAG`):
//!
//! | arg | [`OP_ATTEST`] | [`OP_PUBLIC_KEY`] |
//! |---|---|---|
//! | 1 | `OP_ATTEST` | `OP_PUBLIC_KEY` |
//! | 2 | archive pointer | 0 |
//! | 3 | archive length | 0 |
//! | 4 | output buffer pointer | output buffer pointer |
//! | 5 | output buffer capacity | output buffer capacity |
//! | 6 | step name (NUL-terminated, at most [`MAX_STEP_NAME`] bytes) | 0 |
//!
//! The return value is the number of bytes written to the output buffer, or
//! a negative errno: `-ENOSPC` if the buffer is too small, `-EPERM` if the
//! caller is not the grate's child, `-EINVAL` for a malformed request or
//! archive.

/// Syscall number of an attestation request. It is not a Linux syscall; only
/// the in-toto grate handles it.
pub const SYS_INTOTO_ATTEST: u64 = 2101;

/// Attest a preload archive: the output is a DSSE envelope.
pub const OP_ATTEST: u64 = 0;
/// Return the signer's public key: the output is a key JSON object.
pub const OP_PUBLIC_KEY: u64 = 1;

/// Longest step name accepted, including the NUL terminator.
pub const MAX_STEP_NAME: usize = 64;

/// `predicateType` of the statements the in-toto grate signs.
pub const PREDICATE_TYPE: &str = "https://lind-project.org/attestation/imfs-preload/v1";

/// in-toto statement `_type`.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// DSSE `payloadType` of an in-toto statement.
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
