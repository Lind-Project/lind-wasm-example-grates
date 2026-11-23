pub mod cipher;
pub mod cryptfile;
pub mod format;

/// Errno values returned by the core. Handlers negate them for the cage.
pub mod errno {
    pub const EIO: i32 = 5;
    pub const EINVAL: i32 = 22;
    pub const EFBIG: i32 = 27;
}
