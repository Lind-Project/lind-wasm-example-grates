//! Linux-compatible <sys/mman.h> constants.
//!
//! For grates written in Rust, the program should import these through `use
//! grate_rs::constants::mman;` along with mman functions in `grate_rs::ffi` for mman functions
//! that are not exposed in WASI.

pub const PROT_READ: i32 = 0x1; // pages may be read
pub const PROT_WRITE: i32 = 0x2; // pages may be written

pub const MAP_SHARED: i32 = 0x01; // share mapping with other processes
pub const MAP_ANON: i32 = 0x20; // mapping is not backed by a file (same as MAP_ANONYMOUS)
pub const MAP_FAILED: *mut core::ffi::c_void = (-1isize) as *mut core::ffi::c_void;
