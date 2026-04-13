use std::{ffi::{CString, c_int}, process::exit};
use grate_rs::{constants::mman::{MAP_ANON, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE}, ffi::{execv, fork, mmap, sem_init, sem_post, sem_t, sem_wait, waitpid}, getcageid};
use std::ffi::c_char;

mod tee;
mod handlers;
mod utils;

use crate::{handlers::{register_lifecycle_handlers, register_target_handlers}, tee::{TEE_STATE, TeeState, with_tee},};

#[derive(Debug)]
struct Parsed {
    primary: Vec<String>,
    secondary: Vec<String>,
    target: Vec<String>,
}

fn to_exec_argv(args: &[String]) -> (Vec<CString>, Vec<*const c_char>) {
    let cstrings: Vec<CString> = args
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();

    let mut argv: Vec<*const c_char> =
        cstrings.iter().map(|s| s.as_ptr()).collect();

    argv.push(std::ptr::null());

    (cstrings, argv)
}

fn parse_block(args: &[String], i: &mut usize) -> Result<Vec<String>, String> {
    if args.get(*i).map(String::as_str) != Some("%{") {
        return Err(format!("expected %{{ at argv[{i}]"));
    }
    *i += 1;

    let mut items = Vec::new();

    while let Some(tok) = args.get(*i) {
        items.push(tok.clone());
        *i += 1;

        if tok == "%}" {
            // *i += 1;
            return Ok(items);
        }
    }

    Err("unterminated %{ block".into())
}

fn parse_rest(args: &[String], i: &mut usize) -> Result<Vec<String>, String> {
    let mut items = Vec::new();

    while let Some(tok) = args.get(*i) {
        items.push(tok.clone());
        *i += 1;
    }

    if items.is_empty() {
        return Err("missing target args".into());
    }

    Ok(items)
}

fn parse_args(args: &[String]) -> Result<Parsed, String> {
    let mut i = 0;

    let primary = parse_block(args, &mut i)?;
    let secondary = parse_block(args, &mut i)?;
    let target = parse_rest(args, &mut i)?;

    Ok(Parsed {
        primary,
        secondary,
        target,
    })
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    let parsed = parse_args(&argv).unwrap();
    
    println!("[t-grate] Parsed= {:?}", parsed);

    let tee_cage_id = getcageid();
    *TEE_STATE.lock().unwrap() = Some(TeeState::new(tee_cage_id));

    let stackone = unsafe { fork() };
    if stackone == 0 {
        let cage_id = getcageid();
        println!("[t-grate] primary_grateid={} primary= {:?}", cage_id, parsed.primary);

        let cage_id = getcageid();
        
        // sem wait
        register_lifecycle_handlers(cage_id);
        
        // execv
        let (_storage, argv) = to_exec_argv(&parsed.primary);
        let exec_ret = unsafe { execv(argv[0], argv.as_ptr())};
        println!("[primary] exec_ret... {}", exec_ret);

        exit(0);
    } 
    // register lifecycle handlers for primary

    loop {
        let primary_stackd = with_tee(|s| {
            match s.primary_target_cage {
                Some(_) => return true, 
                None => return false,
            }  
        });

        if primary_stackd { break; }
    }

    let stacktwo = unsafe { fork() }; 
    if stacktwo == 0 {
        let cage_id = getcageid();
        println!("[t-grate] secondary_grateid={} secondary= {:?}", cage_id, parsed.secondary);

        // sem wait 
        register_lifecycle_handlers(cage_id);

        // execv
        let (_storage, argv) = to_exec_argv(&parsed.secondary);
        let exec_ret = unsafe { execv(argv[0], argv.as_ptr()) };
        println!("[secondary] exec_ret... {}", exec_ret);
        
        exit(0);
    }
    // register lifecycle handlers for secondary

    println!("[t-grate] waiting for primary and secondary stacks to be initialized...");
    loop {
        let initd_stacks = with_tee(|s| {
            if s.primary_target_cage.is_some() && s.secondary_target_cage.is_some() {
                return true;
            }
            return false;
        });
        
        if initd_stacks {
            break;    
        }
    }

    println!("[t-grate] 2 stacks initialized, running target cages...");
    println!("[t-grate] Parsed= {:?}", parsed);

    let sem: *mut sem_t = unsafe {
        let ptr = mmap(
            std::ptr::null_mut(),
            std::mem::size_of::<sem_t>(),
            PROT_READ| PROT_WRITE,
            MAP_SHARED | MAP_ANON,
            -1, 0,
        );
        if ptr == MAP_FAILED {
            eprintln!("[tee-grate] mmap failed");
            std::process::exit(-1);
        }
        ptr as *mut sem_t
    };

    if unsafe { sem_init(sem, 1, 0) } < 0 {
        eprintln!("[tee-grate] sem_init failed");
        std::process::exit(-1);
    }

    let targetstack = unsafe { fork() };
    if targetstack == 0 {
        let cage_id = getcageid();
        println!("[t-grate] target, parsed= {:?}", parsed);
        println!("[t-grate] target_stackid={} target_stack= {:?}", cage_id, parsed.target);
        // sem wait
        unsafe { sem_wait(sem) };
        // register_target_handlers(cage_id);
        
        // execv
        let (_storage, argv) = to_exec_argv(&parsed.target);
        let exec_ret = unsafe { execv(argv[0], argv.as_ptr()) };
        println!("[target] exec_ret... {}", exec_ret);

        exit(0);
    }

    with_tee(|s| s.set_target_cage_id(targetstack as u64));
    register_target_handlers(targetstack as u64);
    
    unsafe { sem_post(sem) };

    loop {
        let mut status: i32 = 0;
        // println!("[t-grate] Waiting...");
        let ret = unsafe { waitpid(-1, &mut status as *mut i32 as *mut c_int, 0) };
        // println!("[t-grate] Wait ret={}", ret);
        if ret <= 0 { break; }
        println!("[t-grate] child {} exited with status {}", ret, status);
    }

    println!("[t-grate] All children exited. Exiting.");

}

