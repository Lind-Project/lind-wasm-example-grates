use grate_rs::{copy_data_between_cages, getcageid};

pub enum Arg {
    Int(u64),
    CString { addr: u64, cage: u64 },
}

// function to facilitate argument parsing
pub fn parse_arg(arg: Arg) -> String {
    match arg {
        Arg::Int(v) => format!("{v}"),
        Arg::CString { addr, cage } => {
            copy_string_from_cage(cage, addr, 256)
                .map(|s| format!("{:?}", s))
                .unwrap_or("<bad_ptr>".into())
        }
    }
}

// helper function to copy string from the cage
fn copy_string_from_cage (
    srccage: u64,
    srcaddr: u64,
    max_len: usize
) -> Option<String> {
    let thiscage = getcageid();
    let mut buf = vec![0u8; max_len as usize];

    copy_data_between_cages(
        thiscage,
        srccage,
        srcaddr,
        srccage,
        buf.as_mut_ptr() as u64,
        thiscage,
        max_len as u64,
        1
    ).ok()?;

    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..len]).into_owned())
}

// macro to dynamically create syscall handlers
#[macro_export]
macro_rules! define_syscall_handler {
    (
        $name:ident,
        $num:expr,
        [ $( $arg_type:ident ),* ]
    ) => {
        extern "C" fn $name(
            cageid: u64,
            arg1: u64, arg1cage: u64,
            arg2: u64, arg2cage: u64,
            arg3: u64, arg3cage: u64,
            arg4: u64, arg4cage: u64,
            arg5: u64, arg5cage: u64,
            arg6: u64, arg6cage: u64
        ) -> i32 {
            let ret = match make_threei_call(
                $num,
                cageid,
                arg1cage,
                arg1, arg1cage,
                arg2, arg2cage,
                arg3, arg3cage,
                arg4, arg4cage,
                arg5, arg5cage,
                arg6, arg6cage,
                0
            ) {
                Ok(val) => val,
                Err(_) => -1
            };

            let mut args = Vec::new();
            let all_vals = [
                (arg1, arg1cage),
                (arg2, arg2cage),
                (arg3, arg3cage),
                (arg4, arg4cage),
                (arg5, arg5cage),
                (arg6, arg6cage),
            ];
            
            // compile-time argument processing
            let mut _arg_index = 0;     // prefixed to supress warning
            $(
                let (val, cage) = all_vals[_arg_index];
                let arg = match stringify!($arg_type) {
                    "Int" => Arg::Int(val),
                    "CString" => Arg::CString { addr: val, cage },
                    _ => unreachable!(),
                };
                args.push(arg);
                _arg_index += 1;
            )*

            let parsed: Vec<String> = args.into_iter().map(parse_arg).collect();
            
            // printing syscall name, args and ret value
            println!(
                "{}({}) = {:?}",
                stringify!($name),
                parsed.join(", "),
                ret
            );
            ret
        }
    };
}
