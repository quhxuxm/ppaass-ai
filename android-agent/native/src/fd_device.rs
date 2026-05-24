#[cfg(unix)]
mod imp {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    use tokio::io::unix::AsyncFd;

    pub struct AndroidTunDevice {
        fd: AsyncFd<OwnedFd>,
    }

    impl AndroidTunDevice {
        pub fn from_raw_fd(fd: RawFd) -> io::Result<Self> {
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            set_nonblocking(fd.as_raw_fd())?;
            Ok(Self {
                fd: AsyncFd::new(fd)?,
            })
        }

        pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            loop {
                let mut guard = self.fd.readable().await?;
                match guard.try_io(|inner| read_fd(inner.get_ref().as_raw_fd(), buf)) {
                    Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(result) => return result,
                    Err(_would_block) => continue,
                }
            }
        }

        pub async fn send(&self, packet: &[u8]) -> io::Result<()> {
            let mut written = 0;
            while written < packet.len() {
                let mut guard = self.fd.writable().await?;
                match guard
                    .try_io(|inner| write_fd(inner.get_ref().as_raw_fd(), &packet[written..]))
                {
                    Ok(Ok(0)) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "zero-length write to VPN fd",
                        ));
                    }
                    Ok(Ok(n)) => written += n,
                    Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => continue,
                }
            }
            Ok(())
        }
    }

    fn set_nonblocking(fd: RawFd) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
        let result = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }

    fn write_fd(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
        let result = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }

    pub type PlatformRawFd = RawFd;
}

#[cfg(not(unix))]
mod imp {
    use std::io;

    pub type PlatformRawFd = i32;

    pub struct AndroidTunDevice;

    impl AndroidTunDevice {
        pub fn from_raw_fd(_fd: PlatformRawFd) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Android VPN fd is only supported on Unix-like targets",
            ))
        }

        pub async fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Android VPN fd is only supported on Unix-like targets",
            ))
        }

        pub async fn send(&self, _packet: &[u8]) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Android VPN fd is only supported on Unix-like targets",
            ))
        }
    }
}

pub use imp::{AndroidTunDevice, PlatformRawFd as RawFd};
