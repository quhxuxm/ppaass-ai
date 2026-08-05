#[cfg(target_os = "android")]
fn write_log(priority: libc::c_int, message: impl AsRef<str>) {
    use std::ffi::CString;

    let text = message.as_ref().replace('\0', " ");
    let Ok(tag) = CString::new("PPAASS-Native") else {
        return;
    };
    let Ok(text) = CString::new(text) else {
        return;
    };
    unsafe {
        __android_log_write(priority, tag.as_ptr(), text.as_ptr());
    }
}

#[cfg(target_os = "android")]
struct AndroidTracingWriter {
    bytes: Vec<u8>,
    priority: libc::c_int,
}

#[cfg(target_os = "android")]
impl AndroidTracingWriter {
    fn new(priority: libc::c_int) -> Self {
        Self {
            bytes: Vec::new(),
            priority,
        }
    }
}

#[cfg(target_os = "android")]
impl Write for AndroidTracingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "android")]
impl Drop for AndroidTracingWriter {
    fn drop(&mut self) {
        if !self.bytes.is_empty() {
            write_log(self.priority, String::from_utf8_lossy(&self.bytes));
        }
    }
}

#[cfg(target_os = "android")]
#[derive(Clone, Copy)]
struct AndroidTracingMakeWriter;

#[cfg(target_os = "android")]
impl<'writer> MakeWriter<'writer> for AndroidTracingMakeWriter {
    type Writer = AndroidTracingWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        AndroidTracingWriter::new(4)
    }

    fn make_writer_for(&'writer self, metadata: &tracing::Metadata<'_>) -> Self::Writer {
        let priority = match *metadata.level() {
            tracing::Level::TRACE => 2,
            tracing::Level::DEBUG => 3,
            tracing::Level::INFO => 4,
            tracing::Level::WARN => 5,
            tracing::Level::ERROR => 6,
        };
        AndroidTracingWriter::new(priority)
    }
}

#[cfg(target_os = "android")]
pub(crate) fn install_tracing() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let filter = if cfg!(debug_assertions) {
            EnvFilter::new("debug,netstack_smoltcp=off")
        } else {
            EnvFilter::new("info,netstack_smoltcp=off")
        };
        let _ = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_env_filter(filter)
            .with_target(true)
            .with_writer(AndroidTracingMakeWriter)
            .try_init();
    });
}

#[cfg(not(target_os = "android"))]
pub(crate) fn install_tracing() {}

#[cfg(target_os = "android")]
#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(
        prio: libc::c_int,
        tag: *const libc::c_char,
        text: *const libc::c_char,
    ) -> libc::c_int;
}
#[cfg(target_os = "android")]
use std::io::Write;
#[cfg(target_os = "android")]
use std::sync::OnceLock;
#[cfg(target_os = "android")]
use tracing_subscriber::EnvFilter;
#[cfg(target_os = "android")]
use tracing_subscriber::fmt::MakeWriter;
