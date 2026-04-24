use std::env;
use std::fs;
use std::path::PathBuf;

const MAX_SYSCALL: usize = 1024;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let out_file = out_dir.join("generated_handlers.rs");

    let mut generated = String::new();

    for n in 0..=MAX_SYSCALL {
        generated.push_str(&format!(
            "extern \"C\" fn syscall_handler_{n}(\n\
                 cageid: u64,\n\
                 arg1: u64,\n\
                 arg1cage: u64,\n\
                 arg2: u64,\n\
                 arg2cage: u64,\n\
                 arg3: u64,\n\
                 arg3cage: u64,\n\
                 arg4: u64,\n\
                 arg4cage: u64,\n\
                 arg5: u64,\n\
                 arg5cage: u64,\n\
                 arg6: u64,\n\
                 arg6cage: u64,\n\
             ) -> i32 {{\n\
                 dispatch_handler(\n\
                     {n}, cageid, arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,\n\
                     arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,\n\
                 )\n\
             }}\n\n"
        ));
    }

    generated.push_str("const HANDLERS: [grate_rs::SyscallHandler; ");
    generated.push_str(&(MAX_SYSCALL + 1).to_string());
    generated.push_str("] = [\n");
    for n in 0..=MAX_SYSCALL {
        generated.push_str(&format!("    syscall_handler_{n},\n"));
    }
    generated.push_str("];\n\n");
    generated.push_str(
        "fn handler_for(syscall_nr: u64) -> Option<grate_rs::SyscallHandler> {\n\
             HANDLERS.get(syscall_nr as usize).copied()\n\
         }\n",
    );

    fs::write(out_file, generated).expect("failed to write generated handlers");
}
