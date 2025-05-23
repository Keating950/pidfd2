//! Provides a safe interface for working with Linux pidfds.

#![warn(clippy::pedantic)]
use nix::{libc, sys::signal::Signal, unistd::Pid};
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

#[derive(Debug)]
pub struct PidFd {
    fd: OwnedFd,
}

impl PidFd {
    const FLAGS: libc::c_uint = 0;
    /// Open a pidfd for the running process with the given PID.
    ///
    /// # Errors
    ///
    /// Returns an error if the `pidfd_open` syscall fails. See the [man
    /// page](https://man7.org/linux/man-pages/man2/pidfd_open.2.html#ERRORS) for details.
    #[expect(clippy::missing_panics_doc)]
    pub fn open(pid: Pid) -> io::Result<PidFd> {
        match unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), PidFd::FLAGS) } {
            -1 => Err(io::Error::last_os_error()),
            n => {
                let Ok(fd) = n.try_into() else {
                    panic!("Return value of pidfd_open syscall was greater than i32::MAX: {n}")
                };
                unsafe {
                    Ok(PidFd {
                        fd: OwnedFd::from_raw_fd(fd),
                    })
                }
            }
        }
    }

    /// Convenience wrapper over [`PidFd::open`] for working with spawned processes.
    #[expect(clippy::missing_panics_doc, clippy::missing_errors_doc)]
    pub fn from_child(child: &std::process::Child) -> io::Result<PidFd> {
        let id = child.id();
        let Ok(pid) = id.try_into() else {
            panic!("std::process::Child::id returned PID value outside range of libc::pid_t: {id}");
        };
        PidFd::open(Pid::from_raw(pid))
    }

    /// Send a signal to the process associated with this [`PidFd`].
    ///
    /// # Errors
    ///
    /// Some situations that can cause this function to fail are:
    ///
    ///  - The underlying process has exited and been waited on
    ///  - The caller does not have permission to send signals to the process
    ///  - [Others](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html#ERRORS)
    ///
    pub fn send_signal(&self, signal: Signal) -> io::Result<()> {
        unsafe {
            if libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.fd.as_raw_fd(),
                signal as libc::c_int,
                std::ptr::null::<libc::c_void>(),
                PidFd::FLAGS,
            ) == 0
            {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }
}

impl AsRawFd for PidFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl FromRawFd for PidFd {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        PidFd {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;
    use std::{
        path::PathBuf,
        process::{Child, Command, ExitStatus, Stdio},
        time::{Duration, Instant},
    };

    fn run_sleep_cmd() -> Child {
        Command::new("sleep")
            .arg("24h")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    fn wait_timeout(mut child: Child, timeout: Duration) -> io::Result<Option<ExitStatus>> {
        std::mem::drop(child.stdin.take());
        let start = Instant::now();
        let stop_at = start + timeout;
        loop {
            let status = child.try_wait().unwrap();
            if status.is_some() {
                return Ok(status);
            }
            if Instant::now() >= stop_at {
                return Ok(None);
            }
        }
    }

    #[test]
    fn test_from_child() {
        let mut child = run_sleep_cmd();
        let res = PidFd::from_child(&child);
        child.kill().unwrap();
        assert!(res.is_ok(), "{res:?}");
    }

    #[test]
    fn test_send_signal() {
        let child = run_sleep_cmd();
        let fd = PidFd::from_child(&child).unwrap();
        fd.send_signal(Signal::SIGTERM).unwrap();
        assert!(
            wait_timeout(child, Duration::from_secs(5))
                .unwrap()
                .is_some(),
            "Process failed to exit after receiving SIGTERM"
        );
    }

    #[test]
    fn test_invalid_pid_fails() {
        let mut rng = rand::rng();
        let pid_dir = PathBuf::from("/proc");
        assert!(pid_dir.exists());
        // There's a race condition here, since a process with an id equal to `val` could be
        // started after the !pid_path.exists() check. This should be replaced with a more robust
        // solution if possible.
        let invalid_pid = loop {
            let val: nix::libc::pid_t = rng.random();
            let pid_path = pid_dir.join(val.to_string());
            if !pid_path.exists() {
                break Pid::from_raw(val);
            }
        };
        let res = PidFd::open(invalid_pid);
        assert!(res.is_err(), "{res:?}");
    }
}
