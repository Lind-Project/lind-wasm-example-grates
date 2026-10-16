//! The attestation requests IMFS sends to the in-toto grate (the recorder).
//!
//! IMFS stops after staging an archive (the compiler pipeline, then the
//! source files) and issues [`SYS_INTOTO_ATTEST`] on itself. The call is
//! routed by 3i to the in-toto grate that runs IMFS as its child. That grate
//! reads the archive straight out of IMFS's memory, hashes every file, signs
//! an in-toto statement over them and writes the DSSE envelope back into a
//! buffer IMFS provides. IMFS then resumes.
//!
//! When the program has exited, IMFS packs the files it is to dump into an
//! archive and asks for [`OP_PRODUCTS`]: the recorder signs a statement over
//! them, the last link of its chain. Then [`OP_EVIDENCE`] closes the chain:
//! the recorder hands its public key and the hash of the last link to the
//! runtime (`LIND_EVIDENCE`, see `shm::evidence`), which signs `run-end`
//! naming both with the key its TEE attestation binds, and the recorder
//! answers with the whole evidence, assembled from its own state: its key,
//! every envelope of the chain, and what the runtime answered. IMFS dumps
//! that as [`EVIDENCE_PATH`] next to the outputs.
//!
//! Arguments, in order (pointers are IMFS addresses, passed with
//! `GRATE_MEMORY_FLAG`):
//!
//! | arg | [`OP_ATTEST`] | [`OP_PUBLIC_KEY`] | [`OP_PRODUCTS`] | [`OP_EVIDENCE`] |
//! |---|---|---|---|---|
//! | 1 | `OP_ATTEST` | `OP_PUBLIC_KEY` | `OP_PRODUCTS` | `OP_EVIDENCE` |
//! | 2 | archive pointer | 0 | archive pointer | 0 |
//! | 3 | archive length | 0 | archive length | 0 |
//! | 4 | output buffer pointer | output buffer pointer | output buffer pointer | output buffer pointer |
//! | 5 | output buffer capacity | output buffer capacity | output buffer capacity | output buffer capacity |
//! | 6 | step name (NUL-terminated, at most [`MAX_STEP_NAME`] bytes) | 0 | the program's exit status (`u64::MAX`: unknown) | 0 |
//!
//! The return value is the number of bytes written to the output buffer, or
//! a negative errno: `-ENOSPC` if the buffer is too small, `-EPERM` if the
//! caller is not the grate's child or the chain is closed, `-EINVAL` for a
//! malformed request or archive.

/// Syscall number of an attestation request. It is not a Linux syscall; only
/// the in-toto grate handles it.
pub const SYS_INTOTO_ATTEST: u64 = 2101;

/// Attest a preload archive: the output is a DSSE envelope.
pub const OP_ATTEST: u64 = 0;
/// Return the signer's public key: the output is a key JSON object.
pub const OP_PUBLIC_KEY: u64 = 1;
/// Attest the archive of the files to be dumped: the output is a DSSE
/// envelope, the last link of the chain.
pub const OP_PRODUCTS: u64 = 2;
/// Close the chain, have the runtime sign run-end over it, and return the
/// evidence: a JSON object (see `intoto-grate`).
pub const OP_EVIDENCE: u64 = 3;

/// Longest step name accepted, including the NUL terminator.
pub const MAX_STEP_NAME: usize = 64;

/// `predicateType` of the statements the in-toto grate signs.
pub const PREDICATE_TYPE: &str = "https://lind-project.org/attestation/imfs-preload/v1";

/// `predicateType` of the statement over the files dumped at the end.
pub const PRODUCTS_PREDICATE_TYPE: &str = "https://lind-project.org/attestation/imfs-products/v1";

/// Path of the evidence in the dump archive.
pub const EVIDENCE_PATH: &str = "evidence/evidence.json";

/// in-toto statement `_type`.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// DSSE `payloadType` of an in-toto statement.
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
