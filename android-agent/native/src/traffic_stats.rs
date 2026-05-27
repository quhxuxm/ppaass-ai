use std::sync::atomic::{AtomicU64, Ordering};

static VPN_DOWNLOAD_BYTES: AtomicU64 = AtomicU64::new(0);
static VPN_UPLOAD_BYTES: AtomicU64 = AtomicU64::new(0);

pub fn record_download(bytes: usize) {
    VPN_DOWNLOAD_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
}

pub fn record_upload(bytes: usize) {
    VPN_UPLOAD_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
}

pub fn download_bytes() -> u64 {
    VPN_DOWNLOAD_BYTES.load(Ordering::Relaxed)
}

pub fn upload_bytes() -> u64 {
    VPN_UPLOAD_BYTES.load(Ordering::Relaxed)
}
