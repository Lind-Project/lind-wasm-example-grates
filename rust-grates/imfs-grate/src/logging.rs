use std::sync::atomic::{AtomicBool, Ordering};

static LOGGING_ENABLED: AtomicBool = AtomicBool::new(false);

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        if $crate::logging::logging_enabled() {
            $crate::logging::raw_line(&format!("[imfs-grate] {}\n", format_args!($($arg)*)));
        }
    };
}

/// Raw write(2): no stdout lock, no panic on a failed print.
pub fn raw_line(s: &str) {
    let mut rest = s.as_bytes();
    while !rest.is_empty() {
        let n = unsafe { libc::write(1, rest.as_ptr() as *const _, rest.len()) };
        if n <= 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if n < 0 && errno == libc::EINTR {
                continue;
            }
            return;
        }
        rest = &rest[n as usize..];
    }
}

pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("[imfs-grate] PANIC: {}\n", info);
        unsafe {
            libc::write(2, msg.as_ptr() as *const _, msg.len());
        }
    }));
}

pub fn init(logging_enabled: bool) {
    LOGGING_ENABLED.store(logging_enabled, Ordering::Relaxed);
}

pub fn logging_enabled() -> bool {
    LOGGING_ENABLED.load(Ordering::Relaxed)
}
