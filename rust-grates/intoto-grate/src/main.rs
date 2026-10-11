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
//! buffer IMFS provided. The second statement records the SHA-256 of the
//! first envelope, so the attestations of a run form a chain. IMFS also asks
//! once for the public key, and keeps it with the envelopes in /attest.
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
    MAX_STEP_NAME, OP_ATTEST, OP_PUBLIC_KEY, PAYLOAD_TYPE, SYS_INTOTO_ATTEST,
};
use sha2::{Digest as _, Sha256};

use sign::{Signer, hex};
use statement::{Source, statement, summarize};

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
/// Attestations made so far, and the SHA-256 of the last envelope.
static CHAIN: Mutex<(u64, Option<String>)> = Mutex::new((0, None));

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
            let index = chain.0 + 1;
            let st = statement(&summary, &step, index, chain.1.as_deref(), signer.keyid());
            let envelope = signer.envelope(PAYLOAD_TYPE, st.to_string().as_bytes());
            let envelope = envelope.to_string();

            let ret = write_back(caller, out_addr, out_capacity, envelope.as_bytes());
            if ret > 0 {
                *chain = (index, Some(hex(&Sha256::digest(envelope.as_bytes()))));
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
