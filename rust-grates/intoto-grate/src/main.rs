//! in-toto grate — signs in-toto statements over the preload archives the
//! IMFS grate stages.
//!
//! Usage: intoto-grate imfs-grate.cwasm --preload-shm --attest [imfs options] <program> [args...]
//!
//! The grate runs the IMFS grate as its child and handles one syscall for it,
//! `SYS_INTOTO_ATTEST` (see `preload_archive::attest`). IMFS issues it after
//! staging each archive of its preload bundle (the compiler pipeline, then
//! the source files); this grate reads the archive straight out of IMFS's
//! memory, hashes every file, signs an in-toto statement over them with a
//! P-256 key it made at startup, and writes the DSSE envelope back into a
//! buffer IMFS provided. Each statement after the first records the SHA-256
//! of the envelope before it, so the attestations of a run form a chain.
//!
//! When the program has exited, IMFS hands over the archive of the files it
//! dumps, and the grate signs a products statement over them: the last link.
//! IMFS then asks for the evidence. The grate closes the chain, hands its
//! public key and the hash of the last link to the runtime (`LIND_EVIDENCE`;
//! only the first cage of a run, this grate, may), which signs `run-end`
//! naming both with the key its TEE attestation binds, and answers IMFS with
//! the evidence, assembled from what the grate itself kept:
//!
//! ```json
//! { "recorder": { "publicKey": <key> },
//!   "chain": [ <envelope>, ... ],        // the exact bytes, as strings
//!   "runtime": { "runId", "identityKey", "report", "runStart", "runEnd" } }
//! ```
//!
//! (`runtime` is null if the runtime signs nothing.) A verifier checks the
//! report binds the identity key, that key signed run-start and run-end,
//! run-end names this grate's key and the hash of the last envelope, and each
//! envelope is signed by this grate's key and names the one before.
//!
//! The key is drawn from `getrandom` when the grate starts; inside a TriSeal
//! keep that is the enclave's own randomness, and the key never leaves the
//! enclave.

mod sign;
mod statement;

use std::ffi::c_void;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use grate_rs::constants::lind::GRATE_MEMORY_FLAG;
use grate_rs::{GrateBuilder, GrateError, copy_data_between_cages, getcageid};
use preload_archive::attest::{
    MAX_STEP_NAME, OP_ATTEST, OP_EVIDENCE, OP_PRODUCTS, OP_PUBLIC_KEY, PAYLOAD_TYPE,
    SYS_INTOTO_ATTEST,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use sign::{Signer, hex};
use statement::{Source, products_statement, statement, summarize};

const EINVAL: i32 = 22;
const ENOSPC: i32 = 28;
const EPERM: i32 = 1;
const EIO: i32 = 5;

unsafe extern "C" {
    fn getrandom(buf: *mut c_void, buflen: usize, flags: u32) -> isize;
}

/// The signer, made in main() before the child starts.
static SIGNER: Mutex<Option<Signer>> = Mutex::new(None);
/// The IMFS cage: the only caller whose requests are served.
static CHILD: AtomicU64 = AtomicU64::new(u64::MAX);
/// The envelopes signed in this run, in order, as handed out; whether the
/// products statement is among them; and the evidence, once the chain is
/// closed. Nothing is added after the products statement.
struct Chain {
    envelopes: Vec<String>,
    products: bool,
    evidence: Option<String>,
}

impl Chain {
    /// SHA-256 of the last envelope.
    fn head(&self) -> Option<String> {
        self.envelopes
            .last()
            .map(|e| hex(&Sha256::digest(e.as_bytes())))
    }

    /// Whether a link may still be added.
    fn open(&self) -> bool {
        !self.products && self.evidence.is_none()
    }
}

static CHAIN: Mutex<Chain> = Mutex::new(Chain {
    envelopes: Vec::new(),
    products: false,
    evidence: None,
});

/// Room for the runtime's answer to `LIND_EVIDENCE`.
const RUNTIME_ANSWER_CAPACITY: usize = 1 << 20;

/// What the grate hands the runtime: its key and the end of its chain.
fn evidence_request(public_key: &Value, chain: &Chain) -> Value {
    json!({
        "recorder": { "publicKey": public_key },
        "chain": { "head": { "sha256": chain.head() }, "links": chain.envelopes.len() },
    })
}

/// The evidence of the run (see the crate documentation).
fn evidence(public_key: &Value, chain: &Chain, runtime: Value) -> Value {
    json!({
        "recorder": { "publicKey": public_key },
        "chain": chain.envelopes,
        "runtime": runtime,
    })
}

fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    let mut done = 0;
    while done < buf.len() {
        let rest = &mut buf[done..];
        let n = unsafe { getrandom(rest.as_mut_ptr() as *mut c_void, rest.len(), 0) };
        if n <= 0 {
            return Err(format!("getrandom failed: {}", n));
        }
        done += n as usize;
    }
    Ok(())
}

/// The calling cage's memory, read through 3i.
struct CageMemory {
    cage: u64,
    addr: u64,
    len: u64,
}

impl Source for CageMemory {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), String> {
        if buf.is_empty() {
            return Ok(());
        }
        let this_cage = getcageid();
        copy_data_between_cages(
            this_cage,
            self.cage,
            self.addr + offset,
            self.cage,
            buf.as_mut_ptr() as u64,
            this_cage,
            buf.len() as u64,
            0,
        )
        .map(|_| ())
        .map_err(|e| format!("cannot read the archive: {:?}", e))
    }
}

/// Copy `bytes` into the caller's buffer; returns their length or -ENOSPC.
fn write_back(cage: u64, addr: u64, capacity: u64, bytes: &[u8]) -> i32 {
    if bytes.len() as u64 > capacity || bytes.len() > i32::MAX as usize {
        return -ENOSPC;
    }
    let this_cage = getcageid();
    match copy_data_between_cages(
        this_cage,
        cage,
        bytes.as_ptr() as u64,
        this_cage,
        addr,
        cage,
        bytes.len() as u64,
        0,
    ) {
        Ok(_) => bytes.len() as i32,
        Err(_) => -EIO,
    }
}

/// Read the NUL-terminated step name from the caller.
fn read_step(cage: u64, addr: u64) -> Option<String> {
    let mut buf = [0u8; MAX_STEP_NAME];
    let this_cage = getcageid();
    copy_data_between_cages(
        this_cage,
        cage,
        addr,
        cage,
        buf.as_mut_ptr() as u64,
        this_cage,
        MAX_STEP_NAME as u64,
        1, // strncpy: stops at the NUL
    )
    .ok()?;
    let end = buf.iter().position(|&b| b == 0)?;
    let name = std::str::from_utf8(&buf[..end]).ok()?;
    let ok = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    ok.then(|| name.to_string())
}

/// Handler for `SYS_INTOTO_ATTEST`, called by 3i on behalf of IMFS.
pub extern "C" fn attest_handler(
    _cageid: u64,
    op: u64,
    op_cage: u64,
    archive_addr: u64,
    archive_cage: u64,
    archive_len: u64,
    _arg3cage: u64,
    out_addr: u64,
    out_cage: u64,
    out_capacity: u64,
    _arg5cage: u64,
    step_addr: u64,
    step_cage: u64,
) -> i32 {
    let caller = op_cage & !GRATE_MEMORY_FLAG;
    if caller != CHILD.load(Ordering::SeqCst) {
        return -EPERM;
    }
    let out_cage = out_cage & !GRATE_MEMORY_FLAG;
    if out_cage != caller {
        return -EPERM;
    }

    let signer = SIGNER.lock().unwrap();
    let signer = match signer.as_ref() {
        Some(signer) => signer,
        None => return -EIO,
    };

    match op {
        OP_PUBLIC_KEY => {
            let key = signer.public_key_json().to_string();
            write_back(caller, out_addr, out_capacity, key.as_bytes())
        }
        OP_ATTEST => {
            let archive_cage = archive_cage & !GRATE_MEMORY_FLAG;
            let step_cage = step_cage & !GRATE_MEMORY_FLAG;
            if archive_cage != caller || step_cage != caller {
                return -EPERM;
            }
            let step = match read_step(caller, step_addr) {
                Some(step) => step,
                None => return -EINVAL,
            };

            // Read and hash the archive straight out of IMFS's memory.
            let mut memory = CageMemory {
                cage: caller,
                addr: archive_addr,
                len: archive_len,
            };
            let summary = match summarize(&mut memory) {
                Ok(summary) => summary,
                Err(e) => {
                    eprintln!("[intoto-grate] {}: {}", step, e);
                    return -EINVAL;
                }
            };

            let mut chain = CHAIN.lock().unwrap();
            if !chain.open() {
                return -EPERM;
            }
            let index = chain.envelopes.len() as u64 + 1;
            let head = chain.head();
            let st = statement(&summary, &step, index, head.as_deref(), signer.keyid());
            let envelope = signer.envelope(PAYLOAD_TYPE, st.to_string().as_bytes());
            let envelope = envelope.to_string();

            let ret = write_back(caller, out_addr, out_capacity, envelope.as_bytes());
            if ret > 0 {
                chain.envelopes.push(envelope);
                eprintln!(
                    "[intoto-grate] attested {} ({}): {} files, sha256 {}",
                    index,
                    step,
                    summary.subjects.len(),
                    summary.payload_sha256
                );
            }
            ret
        }
        OP_PRODUCTS => {
            // `step_addr` carries the program's exit status here.
            let archive_cage = archive_cage & !GRATE_MEMORY_FLAG;
            if archive_cage != caller {
                return -EPERM;
            }
            let exit_status = (step_addr != u64::MAX).then_some(step_addr as i64);
            let mut memory = CageMemory {
                cage: caller,
                addr: archive_addr,
                len: archive_len,
            };
            let summary = match summarize(&mut memory) {
                Ok(summary) => summary,
                Err(e) => {
                    eprintln!("[intoto-grate] products: {}", e);
                    return -EINVAL;
                }
            };

            let mut chain = CHAIN.lock().unwrap();
            if !chain.open() {
                return -EPERM;
            }
            let index = chain.envelopes.len() as u64 + 1;
            let head = chain.head();
            let st = products_statement(&summary, index, head.as_deref(), signer.keyid(), exit_status);
            let envelope = signer.envelope(PAYLOAD_TYPE, st.to_string().as_bytes());
            let envelope = envelope.to_string();

            let ret = write_back(caller, out_addr, out_capacity, envelope.as_bytes());
            if ret > 0 {
                chain.envelopes.push(envelope);
                chain.products = true;
                eprintln!(
                    "[intoto-grate] attested {} (products): {} files, sha256 {}",
                    index,
                    summary.subjects.len(),
                    summary.payload_sha256
                );
            }
            ret
        }
        OP_EVIDENCE => {
            let mut chain = CHAIN.lock().unwrap();
            if chain.evidence.is_none() {
                if chain.envelopes.is_empty() {
                    return -EINVAL;
                }
                // Close the chain and have the runtime sign run-end over it.
                let public_key = signer.public_key_json();
                let request = evidence_request(&public_key, &chain).to_string();
                let mut answer = vec![0u8; RUNTIME_ANSWER_CAPACITY];
                let runtime = match preload_archive::shm::evidence(request.as_bytes(), &mut answer)
                {
                    Ok(n) => match serde_json::from_slice::<Value>(&answer[..n]) {
                        Ok(runtime) => runtime,
                        Err(e) => {
                            eprintln!("[intoto-grate] the runtime's answer is not JSON: {}", e);
                            Value::Null
                        }
                    },
                    Err(e) => {
                        eprintln!("[intoto-grate] the runtime signed no run-end (error {})", e);
                        Value::Null
                    }
                };
                eprintln!(
                    "[intoto-grate] evidence: {} links, head {}, run-end {}",
                    chain.envelopes.len(),
                    chain.head().unwrap_or_default(),
                    if runtime.is_null() { "missing" } else { "signed by the runtime" }
                );
                chain.evidence = Some(evidence(&public_key, &chain, runtime).to_string());
            }
            // Asking again returns the same evidence (say, with a larger buffer).
            let evidence = chain.evidence.as_deref().unwrap_or_default();
            write_back(caller, out_addr, out_capacity, evidence.as_bytes())
        }
        _ => -EINVAL,
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    match Signer::generate(fill_random) {
        Ok(signer) => {
            eprintln!("[intoto-grate] signing key {}", signer.keyid());
            *SIGNER.lock().unwrap() = Some(signer);
        }
        Err(e) => {
            eprintln!("[intoto-grate] cannot make a signing key: {}", e);
            std::process::exit(1);
        }
    }

    GrateBuilder::new()
        .register(SYS_INTOTO_ATTEST, attest_handler)
        .preexec(|cageid: i32| {
            CHILD.store(cageid as u64, Ordering::SeqCst);
        })
        .teardown(|result: Result<i32, GrateError>| {
            if let Err(e) = result {
                eprintln!("[intoto-grate] cannot run the child: {:?}", e);
            }
        })
        .run(argv);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(envelopes: &[&str]) -> Chain {
        Chain {
            envelopes: envelopes.iter().map(|e| e.to_string()).collect(),
            products: false,
            evidence: None,
        }
    }

    #[test]
    fn request_names_the_key_and_the_last_link() {
        let key = json!({ "keyid": "k" });
        let c = chain(&["first", "second"]);
        let r = evidence_request(&key, &c);
        assert_eq!(r["recorder"]["publicKey"], key);
        assert_eq!(r["chain"]["links"], 2);
        assert_eq!(r["chain"]["head"]["sha256"], hex(&Sha256::digest(b"second")));
    }

    #[test]
    fn evidence_keeps_the_exact_envelopes() {
        let key = json!({ "keyid": "k" });
        let c = chain(&["{\"a\": 1}", "{\"b\":2}"]);
        let e = evidence(&key, &c, json!({ "runEnd": "x" }));
        let back: Value = serde_json::from_str(&e.to_string()).unwrap();
        assert_eq!(back["chain"][0], "{\"a\": 1}");
        assert_eq!(back["chain"][1], "{\"b\":2}");
        assert_eq!(back["runtime"]["runEnd"], "x");
        assert_eq!(back["recorder"]["publicKey"], key);
    }

    #[test]
    fn chain_closes_after_products_or_evidence() {
        let mut c = chain(&["one"]);
        assert!(c.open());
        c.products = true;
        assert!(!c.open());
        let mut c = chain(&["one"]);
        c.evidence = Some(String::new());
        assert!(!c.open());
    }
}
