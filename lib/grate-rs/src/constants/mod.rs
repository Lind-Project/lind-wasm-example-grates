pub mod fs;

pub mod mman;

pub mod net;

pub mod process;

pub mod lind {
    pub const ELINDAPIABORTED: u64 = 0xE001_0001;
}

pub mod syscall_numbers;
pub use syscall_numbers::*;

pub mod error;
