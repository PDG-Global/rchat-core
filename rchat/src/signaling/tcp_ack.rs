//! How much of a connection's TCP stream its peer has acknowledged
//! (Task 8 review M1). Held copies are released only once the bytes of
//! their frame are acknowledged by the client's TCP stack, not on a timing
//! heuristic.
//!
//! The relay counts every byte the kernel accepts from it on the raw TCP
//! socket (`CountingIo`, below TLS, so TLS records and the handshake are
//! counted too) and asks the kernel how many of those it still holds:
//! bytes in the send queue are either not sent yet or sent and not yet
//! acknowledged, because TCP keeps data in the send buffer until the peer
//! acknowledges it. So `acknowledged = written - still_queued`.
//!
//! - Linux and Android: `ioctl(SIOCOUTQ)` (= `TIOCOUTQ`), which for TCP is
//!   `write_seq - snd_una`.
//! - FreeBSD (the production relay): `ioctl(FIONWRITE)`, which returns
//!   `sbavail(&so->so_snd)` (sys/kern/sys_socket.c, releng/15.0); TCP drops
//!   data from `so_snd` only when it is acknowledged (`sbcut_locked` in
//!   tcp_input). FreeBSD's `TCP_INFO` has `tcpi_snd_nxt` but no `snd_una`,
//!   so it cannot give this.
//! - macOS and iOS (development): `getsockopt(SO_NWRITE)`, the bytes in the
//!   send buffer.
//! - Elsewhere, or when the call fails: unknown, and held copies fall back
//!   to the timing guard (`held::HOLD_GUARD`).
//!
//! **A dead connection is never "all acknowledged"** (Task 8 re-review H1).
//! When TCP drops a connection (a peer RST, a retransmission or keepalive
//! timeout), FreeBSD's `tcp_close` empties the send buffer
//! (`soisdisconnected` → `sbdrop_locked`), so `FIONWRITE` then reads 0 and
//! everything would look acknowledged. So after reading the queue the relay
//! reads the connection's state (`TCP_INFO`, `tcpi_state`, queue first, then
//! state: `tcp_close` sets CLOSED before it drops the buffer, under the lock
//! `TCP_INFO` takes) and reports unknown unless the connection is still
//! synchronized; a failed `TCP_INFO` (a dropped connection answers
//! ECONNRESET) is unknown too. Once unknown on a dead connection it stays
//! unknown. Unknown at teardown releases nothing, so every copy still held
//! is re-queued (at worst a duplicate the core drops). Linux applies the
//! same state check (its `SIOCOUTQ` is believed unaffected); macOS was
//! verified unaffected (`SO_NWRITE` keeps its value after an RST). The
//! reported value also never goes backwards (a high-water mark).
//!
//! The counter is read before the queue, so a write racing the two reads
//! can only make the result smaller (a copy kept a little longer), never
//! larger.

use std::io::IoSlice;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// What the kernel says the client's TCP stack has acknowledged (Task 8
/// re-review round 2, R2-M1: "no source" and "dead connection" are not the
/// same answer and must never be handled the same way).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ack {
    /// Bytes of the stream the peer has acknowledged (a lower bound).
    Acked(u64),
    /// This platform has no acknowledgement source at all: held copies use
    /// the timing guard on client frames.
    NoSource,
    /// The platform has a source but gave no trustworthy answer: the
    /// connection was dropped (its send queue may have been emptied) or the
    /// call failed. Nothing is released; the copies are re-queued at
    /// teardown.
    Unknown,
}

/// Where held copies learn what the client's TCP stack has acknowledged.
pub(crate) trait AckSource: Send + Sync {
    /// Bytes of this connection's TCP stream the kernel has accepted from
    /// the relay so far (the offset a frame ends at once it is flushed).
    fn written(&self) -> u64;
    /// What the peer has acknowledged.
    fn acked(&self) -> Ack;
    /// This connection joined a video lane: keep little unsent data in the
    /// kernel, so the writer blocks and frames wait in the relay's queue,
    /// where the video age cap drops stale ones (instead of seconds of video
    /// queued in a deep send buffer towards a weak receiver). Best effort.
    fn bound_send_queue(&self) {}
}

/// Unsent bytes a video call connection's socket may hold (Linux
/// `TCP_NOTSENT_LOWAT`).
#[cfg(any(target_os = "linux", target_os = "android"))]
const VIDEO_NOTSENT_LOWAT: libc::c_int = 16 * 1024;
/// Send buffer of a video call connection where there is no
/// `TCP_NOTSENT_LOWAT` (FreeBSD 15) or it does not bound writes (macOS).
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const VIDEO_SNDBUF: libc::c_int = 32 * 1024;

/// `bound_send_queue` on a raw socket: returns whether it took.
fn bound_send_queue(fd: std::os::fd::RawFd) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let (level, opt, v) = (
        libc::IPPROTO_TCP,
        libc::TCP_NOTSENT_LOWAT,
        VIDEO_NOTSENT_LOWAT,
    );
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let (level, opt, v) = (libc::SOL_SOCKET, libc::SO_SNDBUF, VIDEO_SNDBUF);
    // SAFETY: an fd the connection task keeps open while it calls this (see
    // `KernelAck`), and a pointer to a c_int of the size passed.
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &v as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    r == 0
}

/// Whether this platform has a kernel acknowledgement source.
pub(crate) const HAS_SOURCE: bool = cfg!(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "ios"
));

/// A raw TCP stream that counts the bytes the kernel accepts from it.
pub(crate) struct CountingIo<S> {
    inner: S,
    written: Arc<AtomicU64>,
}

impl<S> CountingIo<S> {
    pub(crate) fn new(inner: S, written: Arc<AtomicU64>) -> Self {
        Self { inner, written }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = res {
            self.written.fetch_add(n as u64, Ordering::AcqRel);
        }
        res
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = res {
            self.written.fetch_add(n as u64, Ordering::AcqRel);
        }
        res
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The kernel's view of one TCP socket.
///
/// Contract: `acked` is called only while the connection's stream (which
/// owns `fd`) is alive. The connection task calls it from its read loop and
/// once right after it, while it still owns the stream's read half, so the
/// descriptor can never have been closed and reused.
pub(crate) struct KernelAck {
    fd: std::os::fd::RawFd,
    written: Arc<AtomicU64>,
    /// The highest value reported so far: `acked` never goes backwards.
    high_water: AtomicU64,
    /// The connection was seen dropped: unknown from then on.
    dead: std::sync::atomic::AtomicBool,
}

impl KernelAck {
    pub(crate) fn new(fd: std::os::fd::RawFd, written: Arc<AtomicU64>) -> Self {
        Self {
            fd,
            written,
            high_water: AtomicU64::new(0),
            dead: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl AckSource for KernelAck {
    fn bound_send_queue(&self) {
        if !bound_send_queue(self.fd) {
            tracing::debug!("Could not bound a video call connection's send queue");
        }
    }

    fn written(&self) -> u64 {
        self.written.load(Ordering::Acquire)
    }

    fn acked(&self) -> Ack {
        if !HAS_SOURCE {
            return Ack::NoSource;
        }
        if self.dead.load(Ordering::Acquire) {
            return Ack::Unknown;
        }
        // Counter first, then the queue, then the state: see the module note.
        let written = self.written.load(Ordering::Acquire);
        let Some(queued) = unacked_bytes(self.fd) else {
            return Ack::Unknown;
        };
        if !connection_open(self.fd) {
            self.dead.store(true, Ordering::Release);
            return Ack::Unknown;
        }
        let acked = written.saturating_sub(queued);
        let before = self.high_water.fetch_max(acked, Ordering::AcqRel);
        Ack::Acked(before.max(acked))
    }
}

/// Bytes in `fd`'s send queue: not yet sent, or sent and not yet
/// acknowledged. None when the platform has no such call or it fails.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn unacked_bytes(fd: std::os::fd::RawFd) -> Option<u64> {
    let mut queued: libc::c_int = 0;
    // SAFETY: SIOCOUTQ (TIOCOUTQ) writes one c_int through the pointer,
    // which points at a live local. It does not block. A closed descriptor
    // fails with EBADF; the caller's contract keeps `fd` open.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCOUTQ, &mut queued as *mut libc::c_int) };
    (rc == 0 && queued >= 0).then_some(queued as u64)
}

#[cfg(target_os = "freebsd")]
pub(crate) fn unacked_bytes(fd: std::os::fd::RawFd) -> Option<u64> {
    let mut queued: libc::c_int = 0;
    // SAFETY: FIONWRITE writes one int through the pointer, which points
    // at a live local; it is an unlocked read of the send buffer's byte
    // count and does not block. A closed descriptor fails with EBADF; the
    // caller's contract keeps `fd` open.
    let rc = unsafe { libc::ioctl(fd, libc::FIONWRITE, &mut queued as *mut libc::c_int) };
    (rc == 0 && queued >= 0).then_some(queued as u64)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) fn unacked_bytes(fd: std::os::fd::RawFd) -> Option<u64> {
    let mut queued: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: SO_NWRITE writes at most `len` bytes (one c_int) into a live
    // local and updates `len`; it does not block. A closed descriptor fails
    // with EBADF; the caller's contract keeps `fd` open.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_NWRITE,
            &mut queued as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0 && queued >= 0).then_some(queued as u64)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "ios"
)))]
pub(crate) fn unacked_bytes(_fd: std::os::fd::RawFd) -> Option<u64> {
    None
}

/// Whether `fd`'s TCP connection is still synchronized, so its send queue
/// still holds every unacknowledged byte (re-review H1). Read after the
/// queue. False when the state cannot be read: a dropped connection fails.
#[cfg(target_os = "freebsd")]
pub(crate) fn connection_open(fd: std::os::fd::RawFd) -> bool {
    // netinet/tcp_fsm.h: ESTABLISHED 4, CLOSE_WAIT 5, FIN_WAIT_1 6,
    // CLOSING 7, LAST_ACK 8, FIN_WAIT_2 9, TIME_WAIT 10. In FIN_WAIT_2 and
    // TIME_WAIT our FIN, and so every byte before it, is acknowledged.
    // CLOSED (0) is a dropped connection, whose buffer was emptied.
    tcp_state(fd).is_some_and(|state| (4..=10).contains(&state))
}

/// Linux: netinet/tcp.h `TCP_ESTABLISHED` 1, `TCP_FIN_WAIT1` 4,
/// `TCP_FIN_WAIT2` 5, `TCP_TIME_WAIT` 6, `TCP_CLOSE_WAIT` 8,
/// `TCP_LAST_ACK` 9, `TCP_CLOSING` 11; `TCP_CLOSE` (7) is gone.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn connection_open(fd: std::os::fd::RawFd) -> bool {
    tcp_state(fd).is_some_and(|state| matches!(state, 1 | 4 | 5 | 6 | 8 | 9 | 11))
}

/// macOS and iOS: `SO_NWRITE` keeps the unacknowledged count after a reset
/// (verified), so no state check is needed.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) fn connection_open(_fd: std::os::fd::RawFd) -> bool {
    true
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "ios"
)))]
pub(crate) fn connection_open(_fd: std::os::fd::RawFd) -> bool {
    false
}

/// `tcpi_state`, the first byte of `struct tcp_info` on FreeBSD and Linux.
/// The kernel copies at most the length given, so a short buffer is fine.
#[cfg(any(target_os = "freebsd", target_os = "linux", target_os = "android"))]
fn tcp_state(fd: std::os::fd::RawFd) -> Option<u8> {
    let mut info = [0u8; 8];
    let mut len = info.len() as libc::socklen_t;
    // SAFETY: TCP_INFO writes at most `len` bytes into `info`, a live local
    // of that size, and updates `len`; it does not block. A dropped
    // connection fails (ECONNRESET on FreeBSD), which is the answer wanted.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            info.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0 && len >= 1).then_some(info[0])
}

/// A source the tests control: everything acknowledged, nothing, or
/// unknown, over a counter the test can also move.
#[cfg(test)]
pub(crate) struct FakeAck {
    pub(crate) written: AtomicU64,
    /// `NO_SOURCE` and `DEAD` stand for those answers; anything else is the
    /// acknowledged offset.
    pub(crate) acked: AtomicU64,
}

#[cfg(test)]
impl FakeAck {
    /// `Ack::NoSource`.
    pub(crate) const NO_SOURCE: u64 = u64::MAX;
    /// `Ack::Unknown` (a dropped connection).
    pub(crate) const DEAD: u64 = u64::MAX - 1;
    /// Everything acknowledged.
    pub(crate) const ALL: u64 = u64::MAX - 2;

    /// Starts with one byte written, so a copy held before the test moves
    /// the counter ends past an `acked` of 0.
    pub(crate) fn new(acked: u64) -> Arc<Self> {
        Arc::new(Self {
            written: AtomicU64::new(1),
            acked: AtomicU64::new(acked),
        })
    }

    pub(crate) fn set_acked(&self, acked: u64) {
        self.acked.store(acked, Ordering::SeqCst);
    }
}

#[cfg(test)]
impl AckSource for FakeAck {
    fn written(&self) -> u64 {
        self.written.load(Ordering::SeqCst)
    }

    fn acked(&self) -> Ack {
        match self.acked.load(Ordering::SeqCst) {
            Self::NO_SOURCE => Ack::NoSource,
            Self::DEAD => Ack::Unknown,
            n => Ack::Acked(n),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A video connection's socket keeps little unsent data: Linux
    /// `TCP_NOTSENT_LOWAT` 16 KiB, elsewhere a 32 KiB send buffer.
    #[test]
    fn a_video_connection_gets_a_bounded_send_queue() {
        use std::os::fd::AsRawFd;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let read = |level, opt| {
            let mut v: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: a live socket and an int-sized buffer.
            let r = unsafe {
                libc::getsockopt(
                    server.as_raw_fd(),
                    level,
                    opt,
                    &mut v as *mut libc::c_int as *mut libc::c_void,
                    &mut len,
                )
            };
            assert_eq!(r, 0);
            v
        };
        KernelAck::new(server.as_raw_fd(), Arc::new(AtomicU64::new(0))).bound_send_queue();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert_eq!(
            read(libc::IPPROTO_TCP, libc::TCP_NOTSENT_LOWAT),
            VIDEO_NOTSENT_LOWAT
        );
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let got = read(libc::SOL_SOCKET, libc::SO_SNDBUF);
            assert!(
                (VIDEO_SNDBUF..=2 * VIDEO_SNDBUF).contains(&got),
                "send buffer {got}"
            );
        }
        drop(client);
    }
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Re-review H1: the peer resets the connection (SO_LINGER 0) while the
    /// relay's send buffer still holds unacknowledged bytes. The source must
    /// not then report them acknowledged, so a copy ending there is
    /// re-queued at teardown, not released. Runs on every platform with a
    /// source (FreeBSD empties the buffer on the reset; Linux and macOS do
    /// not, the state check covers them all).
    #[test]
    fn a_reset_with_unacknowledged_bytes_never_reports_them_acknowledged() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        let set = |fd: std::os::fd::RawFd, level, name, value: &[u8]| {
            // SAFETY: a valid option buffer of its own length for a live fd.
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    level,
                    name,
                    value.as_ptr() as *const libc::c_void,
                    value.len() as libc::socklen_t,
                )
            };
            assert_eq!(rc, 0, "setsockopt");
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        set(
            peer.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &4096i32.to_ne_bytes(),
        );
        let (mut relay, _) = listener.accept().unwrap();
        relay.set_nonblocking(true).unwrap();
        let written = Arc::new(AtomicU64::new(0));
        let ack = KernelAck::new(relay.as_raw_fd(), written.clone());
        if ack.acked() == Ack::NoSource {
            return; // no source on this platform: the fallback applies
        }
        // Fill the relay's send buffer: the peer never reads.
        let chunk = vec![b'x'; 65536];
        let mut idle = 0;
        while idle < 20 {
            match relay.write(&chunk) {
                Ok(n) => {
                    written.fetch_add(n as u64, Ordering::SeqCst);
                    idle = 0;
                }
                Err(_) => {
                    idle += 1;
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        let total = written.load(Ordering::SeqCst);
        let Ack::Acked(before) = ack.acked() else {
            panic!("an open connection has an answer");
        };
        assert!(before < total, "bytes are unacknowledged before the reset");
        // A copy whose frame ends at the last byte written.
        let budget = Arc::new(crate::limits::HeldBudget::new(1 << 20, 1 << 20));
        let source: Arc<KernelAck> = Arc::new(ack);
        let held = super::super::held::HeldCopies::new(
            budget,
            super::super::held::HOLD_GUARD,
            source.clone(),
        );
        held.hold(
            tokio_tungstenite::tungstenite::Message::Binary(vec![0x02; 10]),
            None,
            std::time::Instant::now(),
        );
        // The peer resets the connection with the data unread.
        set(
            peer.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &[1i32.to_ne_bytes(), 0i32.to_ne_bytes()].concat(),
        );
        drop(peer);
        std::thread::sleep(std::time::Duration::from_millis(300));
        let after = source.acked();
        assert!(
            match after {
                Ack::Unknown => true,
                Ack::Acked(a) => a <= before + 8192 && a < total,
                Ack::NoSource => false,
            },
            "after the reset: {after:?} (before {before}, written {total})"
        );
        held.tick();
        assert_eq!(
            held.len(),
            1,
            "the copy is kept for re-queueing, not released"
        );
        // R2-M1: a frame read after the reset (data the client sent before
        // it) is no reason to release: no timing guard on a dead
        // connection, whatever the time.
        held.on_client_frame(std::time::Instant::now() + std::time::Duration::from_secs(3600));
        assert_eq!(
            held.len(),
            1,
            "a client frame after the reset releases nothing"
        );
        drop(relay);
    }

    /// The real kernel source on this platform: bytes written to a loopback
    /// peer that reads them are acknowledged; written stays counted.
    #[tokio::test]
    async fn kernel_source_reports_loopback_bytes_acknowledged() {
        use std::os::fd::AsRawFd;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut got = 0;
            while got < 1000 {
                got += c.read(&mut buf).await.unwrap();
            }
            c
        });
        let (server, _) = listener.accept().await.unwrap();
        let written = Arc::new(AtomicU64::new(0));
        let ack = KernelAck::new(server.as_raw_fd(), written.clone());
        let mut io = CountingIo::new(server, written);
        io.write_all(&[7u8; 1000]).await.unwrap();
        io.flush().await.unwrap();
        assert_eq!(ack.written(), 1000);
        let _c = client.await.unwrap();
        if unacked_bytes(io.inner.as_raw_fd()).is_none() {
            return; // a platform without a source: covered by the fallback
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while ack.acked() != Ack::Acked(1000) {
            assert!(std::time::Instant::now() < deadline, "never acknowledged");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}
