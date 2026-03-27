//! Linux-compatible Filesystem constants.
//!
//! For cages written in Rust, the program should import these through `use
//! grate_rs::constants::fs;` instead of using `use libc;` equivalents since libc supplies
//! constants that are WASI compliant instead.

pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_RDWR: i32 = 2;
pub const O_ACCMODE: i32 = 3;
pub const O_CREAT: i32 = 0o100;
pub const O_EXCL: i32 = 0o200;
pub const O_TRUNC: i32 = 0o1000;
pub const O_APPEND: i32 = 0o2000;
pub const O_DIRECTORY: i32 = 0o200000;

pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

pub const F_GETFL: i32 = 3;

pub const S_IRUSR: u32 = 0o400;
pub const S_IWUSR: u32 = 0o200;

pub const S_IFDIR: u32 = 0o4_0000;
