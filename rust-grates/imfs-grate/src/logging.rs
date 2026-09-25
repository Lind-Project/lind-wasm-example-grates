use std::sync::atomic::{AtomicBool, Ordering};

static LOGGING_ENABLED: AtomicBool = AtomicBool::new(false);

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        if $crate::logging::logging_enabled() {
            println!("[imfs-grate] {}", format_args!($($arg)*));
        }
    };
}

pub fn init(logging_enabled: bool) {
    LOGGING_ENABLED.store(logging_enabled, Ordering::Relaxed);
}

pub fn logging_enabled() -> bool {
    LOGGING_ENABLED.load(Ordering::Relaxed)
}
