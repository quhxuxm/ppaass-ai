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

#[cfg(not(target_os = "android"))]
fn write_log(_priority: libc::c_int, message: impl AsRef<str>) {
    let _ = message;
}

pub(crate) fn info(message: impl AsRef<str>) {
    write_log(4, message);
}

pub(crate) fn warn(message: impl AsRef<str>) {
    write_log(5, message);
}

pub(crate) fn error(message: impl AsRef<str>) {
    write_log(6, message);
}

#[cfg(target_os = "android")]
#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(
        prio: libc::c_int,
        tag: *const libc::c_char,
        text: *const libc::c_char,
    ) -> libc::c_int;
}
