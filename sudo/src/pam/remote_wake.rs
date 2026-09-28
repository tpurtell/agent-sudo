//! agent-sudo: lets a pending remote decision interrupt the password prompt.
//!
//! While armed, the password reader polls the hostd socket alongside the terminal.
//! When the socket becomes readable the read is aborted with a marker error, PAM
//! fails the conversation, and the caller inspects the remote decision.

use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

static FD: AtomicI32 = AtomicI32::new(-1);
static WOKEN: AtomicBool = AtomicBool::new(false);

pub(crate) fn arm(fd: RawFd) {
    WOKEN.store(false, Ordering::SeqCst);
    FD.store(fd, Ordering::SeqCst);
}

/// Disarm and report whether the remote side interrupted the prompt.
pub(crate) fn disarm() -> bool {
    FD.store(-1, Ordering::SeqCst);
    WOKEN.swap(false, Ordering::SeqCst)
}

pub(crate) enum Wait {
    /// The input fd is readable (or the hook is not armed).
    Ready,
    /// The remote decision arrived first.
    Woken,
    TimedOut,
}

/// Poll the input fd together with the armed remote fd.
pub(crate) fn wait(
    input: RawFd,
    events: libc::c_short,
    timeout_ms: libc::c_int,
) -> io::Result<Wait> {
    let remote = FD.load(Ordering::SeqCst);
    if remote < 0 {
        return Ok(Wait::Ready);
    }
    let mut fds = [
        libc::pollfd {
            fd: input,
            events,
            revents: 0,
        },
        libc::pollfd {
            fd: remote,
            events: libc::POLLIN | libc::POLLRDHUP,
            revents: 0,
        },
    ];
    // SAFETY: `fds` is an initialized array and its length is passed alongside it.
    let ret = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    if fds[1].revents != 0 {
        WOKEN.store(true, Ordering::SeqCst);
        return Ok(Wait::Woken);
    }
    if ret == 0 {
        return Ok(Wait::TimedOut);
    }
    Ok(Wait::Ready)
}

pub(crate) fn woken_error() -> io::Error {
    io::Error::other("remote approval decision arrived")
}

/// Poll a single fd for readability. Returns false on timeout.
pub(crate) fn poll_readable(fd: RawFd, timeout_ms: libc::c_int) -> io::Result<bool> {
    let mut fds = [libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLRDHUP,
        revents: 0,
    }];
    // SAFETY: `fds` is an initialized array and its length is passed alongside it.
    let ret = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ret > 0)
}
