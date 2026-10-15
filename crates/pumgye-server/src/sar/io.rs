use super::*;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub(super) enum Mode {
    Budget(Arc<Budget>),
    Allow(Capture),
    Failed,
}
pub(super) struct Guarded<S> {
    pub(super) socket: S,
    pub(super) mode: Mode,
    pub(super) active: Arc<AtomicBool>,
    pub(super) connection: Arc<Budget>,
}
impl<S> Guarded<S> {
    pub(super) fn current(&mut self) -> std::io::Result<()> {
        let good = self.active.load(Ordering::Acquire)
            && self.connection.current()
            && match &self.mode {
                Mode::Budget(b) => b.current(),
                Mode::Allow(c) => c.current(),
                Mode::Failed => false,
            };
        // Recheck listener after every clock/source dependency; shutdown may
        // occur while a read is in progress or this task is descheduled.
        let good = good && self.active.load(Ordering::Acquire);
        if !good {
            self.mode = Mode::Failed;
            return Err(io_error());
        }
        Ok(())
    }
    fn observed<T>(&mut self, result: Poll<std::io::Result<T>>) -> Poll<std::io::Result<T>> {
        if matches!(&result, Poll::Ready(Err(_))) {
            self.mode = Mode::Failed;
        }
        result
    }
    pub(super) fn change(&mut self, mode: Mode) -> std::io::Result<()> {
        self.current()?;
        self.mode = mode;
        self.current()
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for Guarded<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.current()?;
        let result = Pin::new(&mut this.socket).poll_read(cx, buf);
        this.observed(result)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Guarded<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.current()?;
        let result = Pin::new(&mut this.socket).poll_write(cx, buf);
        this.observed(result)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.current()?;
        let result = Pin::new(&mut this.socket).poll_write_vectored(cx, buf);
        this.observed(result)
    }
    fn is_write_vectored(&self) -> bool {
        self.socket.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.current()?;
        let result = Pin::new(&mut this.socket).poll_flush(cx);
        this.observed(result)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.current()?;
        let result = Pin::new(&mut this.socket).poll_shutdown(cx);
        this.observed(result)
    }
}
