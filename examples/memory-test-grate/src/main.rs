//! Memory management stress test grate.
//!
//! Runs the same battery of tests in main() and in a handler, then compares.
//! If something passes in main but fails in a handler, we know the execution
//! context matters.

use grate_rs::constants::*;
use grate_rs::{GrateBuilder, GrateError, getcageid, make_threei_call};
use std::collections::HashMap;

fn test_vec_alloc() -> bool {
    eprintln!("  [vec-alloc] allocating 200 vecs of 4096 bytes...");
    let mut vecs: Vec<Vec<u8>> = Vec::new();
    for i in 0..200 {
        let mut v = vec![0xABu8; 4096];
        if v.iter().any(|&b| b != 0xAB) {
            eprintln!("  [vec-alloc] FAIL: corruption at vec {}", i);
            return false;
        }
        v[0] = i as u8;
        vecs.push(v);
    }
    for (i, v) in vecs.iter().enumerate() {
        if v[0] != i as u8 || v[1] != 0xAB {
            eprintln!("  [vec-alloc] FAIL: readback corruption at vec {}", i);
            return false;
        }
    }
    drop(vecs);
    eprintln!("  [vec-alloc] PASS");
    true
}

fn test_string_ops() -> bool {
    eprintln!("  [string-ops] building and manipulating strings...");
    let mut strings: Vec<String> = Vec::new();
    for i in 0..100 {
        let s = format!("test string number {} with padding {:0>100}", i, i);
        strings.push(s);
    }
    for (i, s) in strings.iter().enumerate() {
        if !s.contains(&format!("number {}", i)) {
            eprintln!("  [string-ops] FAIL: string {} corrupted", i);
            return false;
        }
    }
    let joined = strings.join("|");
    if !joined.contains("number 99") {
        eprintln!("  [string-ops] FAIL: join corrupted");
        return false;
    }
    drop(strings);
    drop(joined);
    eprintln!("  [string-ops] PASS");
    true
}

fn test_hashmap() -> bool {
    eprintln!("  [hashmap] inserting 1000 entries...");
    let mut map: HashMap<u64, Vec<u8>> = HashMap::new();
    for i in 0..1000u64 {
        map.insert(i, vec![(i & 0xFF) as u8; 256]);
    }
    for i in 0..1000u64 {
        match map.get(&i) {
            Some(v) => {
                if v.len() != 256 || v[0] != (i & 0xFF) as u8 {
                    eprintln!("  [hashmap] FAIL: corruption at key {}", i);
                    return false;
                }
            }
            None => {
                eprintln!("  [hashmap] FAIL: key {} missing", i);
                return false;
            }
        }
    }
    drop(map);
    eprintln!("  [hashmap] PASS");
    true
}

fn test_box_trait_objects() -> bool {
    eprintln!("  [trait-obj] creating boxed trait objects...");

    trait Animal {
        fn speak(&self) -> &str;
        fn id(&self) -> u64;
    }

    struct Dog { id: u64 }
    struct Cat { id: u64 }

    impl Animal for Dog {
        fn speak(&self) -> &str { "woof" }
        fn id(&self) -> u64 { self.id }
    }
    impl Animal for Cat {
        fn speak(&self) -> &str { "meow" }
        fn id(&self) -> u64 { self.id }
    }

    let mut animals: Vec<Box<dyn Animal>> = Vec::new();
    for i in 0..200u64 {
        if i % 2 == 0 {
            animals.push(Box::new(Dog { id: i }));
        } else {
            animals.push(Box::new(Cat { id: i }));
        }
    }

    for (i, a) in animals.iter().enumerate() {
        let i = i as u64;
        if a.id() != i {
            eprintln!("  [trait-obj] FAIL: id mismatch at {}", i);
            return false;
        }
        let expected = if i % 2 == 0 { "woof" } else { "meow" };
        if a.speak() != expected {
            eprintln!("  [trait-obj] FAIL: vtable dispatch wrong at {}", i);
            return false;
        }
    }
    drop(animals);
    eprintln!("  [trait-obj] PASS");
    true
}

fn test_large_alloc() -> bool {
    eprintln!("  [large-alloc] allocating 1MB...");
    let mut big = vec![0xEFu8; 1024 * 1024];
    if big[0] != 0xEF || big[1024 * 1024 - 1] != 0xEF {
        eprintln!("  [large-alloc] FAIL: initial fill wrong");
        return false;
    }
    for i in 0..big.len() {
        big[i] = (i & 0xFF) as u8;
    }
    for i in 0..big.len() {
        if big[i] != (i & 0xFF) as u8 {
            eprintln!("  [large-alloc] FAIL: readback wrong at offset {}", i);
            return false;
        }
    }
    drop(big);
    eprintln!("  [large-alloc] PASS");
    true
}

fn test_nested_alloc() -> bool {
    eprintln!("  [nested] deeply nested data structures...");
    let mut outer: Vec<Vec<HashMap<String, Vec<u8>>>> = Vec::new();
    for i in 0..10 {
        let mut mid: Vec<HashMap<String, Vec<u8>>> = Vec::new();
        for j in 0..10 {
            let mut map: HashMap<String, Vec<u8>> = HashMap::new();
            for k in 0..10 {
                let key = format!("{}-{}-{}", i, j, k);
                let val = vec![(i * 100 + j * 10 + k) as u8; 64];
                map.insert(key, val);
            }
            mid.push(map);
        }
        outer.push(mid);
    }
    // Verify
    for i in 0..10 {
        for j in 0..10 {
            for k in 0..10 {
                let key = format!("{}-{}-{}", i, j, k);
                let expected = (i * 100 + j * 10 + k) as u8;
                match outer[i][j].get(&key) {
                    Some(v) if v[0] == expected => {}
                    Some(v) => {
                        eprintln!("  [nested] FAIL: wrong value at {}: got {} expected {}", key, v[0], expected);
                        return false;
                    }
                    None => {
                        eprintln!("  [nested] FAIL: key {} missing", key);
                        return false;
                    }
                }
            }
        }
    }
    drop(outer);
    eprintln!("  [nested] PASS");
    true
}

fn run_all_tests(label: &str) -> bool {
    eprintln!("=== {} ===", label);
    let mut all_pass = true;
    all_pass &= test_vec_alloc();
    all_pass &= test_string_ops();
    all_pass &= test_hashmap();
    all_pass &= test_box_trait_objects();
    all_pass &= test_large_alloc();
    all_pass &= test_nested_alloc();
    eprintln!("=== {} RESULT: {} ===\n", label, if all_pass { "ALL PASS" } else { "FAIL" });
    all_pass
}

// Handler: run the same tests when cage triggers a write to fd > 2
pub extern "C" fn write_handler(
    _cageid: u64,
    fd: u64, fd_cage: u64,
    buf: u64, buf_cage: u64,
    count: u64, count_cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    if fd > 2 {
        run_all_tests("HANDLER CONTEXT");
    }

    let grate_cage = getcageid();
    match make_threei_call(
        SYS_WRITE as u32, 0, grate_cage, fd_cage,
        fd, fd_cage, buf, buf_cage, count, count_cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage, 0,
    ) {
        Ok(r) => r,
        Err(_) => -1,
    }
}

fn main() {
    // Run tests in main context first
    run_all_tests("MAIN CONTEXT");

    let argv: Vec<String> = std::env::args().skip(1).collect();

    GrateBuilder::new()
        .register(SYS_WRITE, write_handler)
        .teardown(|result: Result<i32, GrateError>| {
            if let Err(e) = result {
                eprintln!("[memory-test] error: {:?}", e);
            }
        })
        .run(argv);
}
