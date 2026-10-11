# intoto-grate

Signs in-toto statements over the preload archives the IMFS grate stages, so
that a run can show which compiler pipeline and which sources it was given.

```text
intoto-grate imfs-grate.cwasm --preload-shm --attest [--dump-shm] [imfs options] <program> [args...]
```

The grate runs the IMFS grate as its child and handles one syscall for it,
`SYS_INTOTO_ATTEST` (2101, see `lib/preload-archive/src/attest.rs`). With
`--preload-shm --attest`, IMFS stages its preload bundle one archive at a
time and, after each, stops and issues that call:

1. IMFS copies the compiler pipeline out of shared memory and stages it.
2. IMFS stops and requests an attestation. This grate reads the archive
   straight out of IMFS's memory (in 1 MiB pieces, so it never holds a copy),
   hashes every file and the whole payload (which must match the archive's
   digest), and signs an in-toto statement whose subjects are the files and
   their SHA-256. The DSSE envelope is written back into a buffer IMFS
   provides, and IMFS keeps it as `/attest/1-pipeline.intoto.json`.
3. IMFS resumes with the source files and stops again: `/attest/2-sources.intoto.json`.
   Each statement after the first records the SHA-256 of the previous
   envelope, so the attestations of a run form a chain.

The statement:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "/usr/local/bin/gcc", "digest": { "sha256": "..." } }, ...],
  "predicateType": "https://lind-project.org/attestation/imfs-preload/v1",
  "predicate": {
    "step": "pipeline", "index": 1,
    "archive": { "sha256": "<payload digest>", "entries": 143, "bytes": 344301089 },
    "signer": { "keyid": "..." },
    "previous": { "sha256": "<envelope of step index - 1>" }
  }
}
```

## Key

The grate makes an ECDSA P-256 key when it starts, from `getrandom` (inside a
TriSeal keep that is the enclave's own randomness; the private key never
leaves the enclave). IMFS asks for the public key once and keeps it as
`/attest/signer.pub.json`, in the securesystemslib / in-toto format
(`ecdsa-sha2-nistp256`, PEM SubjectPublicKeyInfo, keyid = SHA-256 of the key's
canonical JSON). Signatures are DER-encoded ECDSA over SHA-256 of the DSSE
pre-authentication encoding.

Only the grate's own child (the IMFS cage) is served; any other caller gets
`-EPERM`.

## Build and test

```bash
cargo lind_compile --release      # the grate
cargo +nightly test               # signing, statements, archive hashing (native)
```
