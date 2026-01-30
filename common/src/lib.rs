pub mod error;

pub use error::{CommonError, Result};

use std::time::{SystemTime, UNIX_EPOCH};

pub fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub fn generate_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    
    let timestamp = current_timestamp();
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("{}-{}", timestamp, counter)
}
