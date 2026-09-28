//! Connection to `agent-sudo-hostd` over its root-only unix socket.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use super::wire::{Line, RequestBlock};

/// Longest line we accept from hostd; anything larger is a protocol error.
const MAX_LINE: usize = 16 * 1024;

pub(crate) struct Connection {
    stream: UnixStream,
    buf: Vec<u8>,
}

/// Returns the uid of the process on the other end of the socket.
fn peer_uid(stream: &UnixStream) -> io::Result<libc::uid_t> {
    crate::system::audit::get_peer_credentials(stream).map(|cred| cred.uid)
}

/// Wait until `fd` is readable or the deadline passes. Returns false on timeout.
pub(crate) fn wait_readable(fd: RawFd, deadline: Option<Instant>) -> io::Result<bool> {
    loop {
        let timeout = match deadline {
            Some(deadline) => {
                let now = Instant::now();
                if now >= deadline {
                    return Ok(false);
                }
                (deadline - now).as_millis().min(i32::MAX as u128) as i32
            }
            None => -1,
        };
        match crate::pam::remote_wake::poll_readable(fd, timeout) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

impl Connection {
    pub(crate) fn connect(path: &Path) -> io::Result<Connection> {
        let stream = UnixStream::connect(path)?;
        // Only a root-owned hostd may answer on behalf of the approval service.
        let uid = peer_uid(&stream)?;
        if uid != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} is served by uid {uid}, not root", path.display()),
            ));
        }
        Ok(Connection {
            stream,
            buf: Vec::new(),
        })
    }

    pub(crate) fn fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    pub(crate) fn send(&mut self, request: RequestBlock) -> io::Result<()> {
        self.stream.write_all(request.finish().as_bytes())?;
        self.stream.flush()
    }

    pub(crate) fn send_line(&mut self, line: &str) -> io::Result<()> {
        self.stream.write_all(line.as_bytes())?;
        self.stream.write_all(b"\n")
    }

    /// Read one event line. `Ok(None)` means the deadline passed first.
    pub(crate) fn read_line(&mut self, deadline: Option<Instant>) -> io::Result<Option<Line>> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let raw: Vec<u8> = self.buf.drain(..=pos).collect();
                let text = std::str::from_utf8(&raw)
                    .map_err(|_| io::Error::other("hostd sent a non-ASCII line"))?;
                return Line::parse(text)
                    .map(Some)
                    .ok_or_else(|| io::Error::other("hostd sent a malformed line"));
            }
            if self.buf.len() > MAX_LINE {
                return Err(io::Error::other("hostd sent an overlong line"));
            }
            if !wait_readable(self.fd(), deadline)? {
                return Ok(None);
            }
            let mut chunk = [0u8; 1024];
            let n = match self.stream.read(&mut chunk) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "agent-sudo-hostd closed the connection",
                ));
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    pub(crate) fn read_line_within(&mut self, within: Duration) -> io::Result<Option<Line>> {
        self.read_line(Some(Instant::now() + within))
    }
}
