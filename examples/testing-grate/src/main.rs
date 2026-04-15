use grate_rs::{GrateBuilder, GrateError, make_threei_call};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

static RULES: OnceLock<Mutex<HashMap<u64, RuleAction>>> = OnceLock::new();

#[derive(Clone, Copy)]
enum RuleAction {
    ReturnConst(i32),
    PassThrough,
}

fn usage(bin: &str) -> String {
    format!(
        "Usage: {bin} -s <rules> <cage> [cage args...]\n\
         Rules: <syscall>:<constant> or <syscall>: (empty means passthrough)\n\
         Example: {bin} -s 2:10,4:,233:7 ./app.wasm"
    )
}

fn parse_rules(spec: &str) -> Result<HashMap<u64, RuleAction>, String> {
    let mut rules = HashMap::new();

    for raw in spec.split(',') {
        let token = raw.trim();
        if token.is_empty() || token == "..." {
            continue;
        }

        let (syscall_raw, value_raw) = token
            .split_once(':')
            .ok_or_else(|| format!("Invalid rule '{token}'; expected <syscall>:<constant|empty>"))?;

        let syscall_nr = syscall_raw
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("Invalid syscall number in rule '{token}'"))?;

        let action = if value_raw.trim().is_empty() {
            RuleAction::PassThrough
        } else {
            let value = value_raw
                .trim()
                .parse::<i32>()
                .map_err(|_| format!("Invalid constant return value in rule '{token}'"))?;
            RuleAction::ReturnConst(value)
        };

        if rules.contains_key(&syscall_nr) {
            return Err(format!("Duplicate syscall rule for {syscall_nr}"));
        }
        rules.insert(syscall_nr, action);
    }

    if rules.is_empty() {
        return Err("No syscall rules provided".to_string());
    }

    Ok(rules)
}

fn dispatch_handler(
    syscall_nr: u64,
    cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let action = RULES
        .get()
        .and_then(|rules| rules.lock().ok().and_then(|map| map.get(&syscall_nr).copied()));

    match action {
        Some(RuleAction::ReturnConst(v)) => v,
        Some(RuleAction::PassThrough) => match make_threei_call(
            syscall_nr as u32,
            0,
            cageid,
            arg1cage,
            arg1,
            arg1cage,
            arg2,
            arg2cage,
            arg3,
            arg3cage,
            arg4,
            arg4cage,
            arg5,
            arg5cage,
            arg6,
            arg6cage,
            0,
        ) {
            Ok(ret) => ret,
            Err(e) => {
                eprintln!(
                    "[testing-grate] make_threei_call failed for syscall {}: {:?}",
                    syscall_nr, e
                );
                -1
            }
        },
        None => {
            eprintln!("[testing-grate] no rule found for syscall {}", syscall_nr);
            -1
        }
    }
}

include!(concat!(env!("OUT_DIR"), "/generated_handlers.rs"));

fn main() {
    let all_args = std::env::args().collect::<Vec<_>>();
    let bin = all_args
        .first()
        .cloned()
        .unwrap_or_else(|| "testing-grate".to_string());
    let args = all_args.iter().skip(1).cloned().collect::<Vec<_>>();

    if args.len() < 3 || args[0] != "-s" {
        eprintln!("{}", usage(&bin));
        std::process::exit(2);
    }

    let rules = match parse_rules(&args[1]) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[testing-grate] {e}");
            eprintln!("{}", usage(&bin));
            std::process::exit(2);
        }
    };

    let cage_argv = args.into_iter().skip(2).collect::<Vec<_>>();
    if cage_argv.is_empty() {
        eprintln!("{}", usage(&bin));
        std::process::exit(2);
    }

    let mut grate = GrateBuilder::new();
    let mut installed = HashMap::new();
    for (syscall_nr, action) in rules {
        let handler = match handler_for(syscall_nr) {
            Some(h) => h,
            None => {
                eprintln!(
                    "[testing-grate] syscall {} out of supported generated range (0..=1024)",
                    syscall_nr
                );
                std::process::exit(2);
            }
        };
        installed.insert(syscall_nr, action);
        grate = grate.register(syscall_nr, handler);
    }

    if RULES.set(Mutex::new(installed)).is_err() {
        eprintln!("[testing-grate] internal error while initializing syscall rules");
        std::process::exit(2);
    }

    grate
        .teardown(|result: Result<i32, GrateError>| {
            println!("[testing-grate] result: {:#?}", result);
        })
        .run(cage_argv);
}
