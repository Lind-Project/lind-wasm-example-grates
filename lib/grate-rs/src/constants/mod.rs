pub mod fs;

pub mod mman;

pub mod net;

pub mod process;

pub mod lind {
    pub const ELINDAPIABORTED: u64 = 0xE001_0001;

    /// Flag to mark an argcageid as pointing into the grate's own linear memory
    /// rather than the calling cage's memory. OR this with the cageid when passing
    /// a pointer that lives in the grate's address space.
    ///
    /// Example: `arg2cage = my_cageid | GRATE_MEMORY_FLAG`
    pub const GRATE_MEMORY_FLAG: u64 = 1u64 << 63;
}

pub mod syscall_numbers;
pub use syscall_numbers::*;

pub mod error;
