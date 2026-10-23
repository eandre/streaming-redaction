use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, ReadBuf};

use crate::{Error, StreamRedactor};

const CHUNK: usize = 8 * 1024;

pin_project! {
    /// An [`AsyncRead`] adapter that yields the redacted form of its inner reader.
    ///
    /// Created by [`Redactor::reader`](crate::Redactor::reader). Memory use is
    /// one fixed read chunk plus the output that chunk produced.
    pub struct RedactReader<R> {
        #[pin]
        inner: R,
        engine: StreamRedactor,
        in_buf: Box<[u8]>,
        out: Vec<u8>,
        out_pos: usize,
        state: State,
    }
}

enum State {
    Reading,
    Done,
    /// Redaction failed. Pending output is drained first, then this error
    /// is returned from every subsequent read.
    Failed(Error),
}

impl<R> RedactReader<R> {
    pub(crate) fn new(inner: R, engine: StreamRedactor) -> Self {
        RedactReader {
            inner,
            engine,
            in_buf: vec![0; CHUNK].into_boxed_slice(),
            out: Vec::with_capacity(CHUNK),
            out_pos: 0,
            state: State::Reading,
        }
    }

    /// Returns a reference to the wrapped reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Consumes the adapter, returning the wrapped reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: AsyncRead> AsyncRead for RedactReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();
        loop {
            if *this.out_pos < this.out.len() {
                let pending = &this.out[*this.out_pos..];
                let n = pending.len().min(buf.remaining());
                buf.put_slice(&pending[..n]);
                *this.out_pos += n;
                if *this.out_pos == this.out.len() {
                    this.out.clear();
                    *this.out_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match this.state {
                State::Done => return Poll::Ready(Ok(())),
                State::Failed(e) => return Poll::Ready(Err(e.clone().into())),
                State::Reading => {}
            }
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            let mut rb = ReadBuf::new(this.in_buf);
            if let Err(e) = ready!(this.inner.as_mut().poll_read(cx, &mut rb)) {
                // Inner I/O errors may be transient (e.g. Interrupted), so
                // they don't poison the redactor.
                return Poll::Ready(Err(e));
            }
            let res = if rb.filled().is_empty() {
                *this.state = State::Done;
                this.engine.finish(this.out)
            } else {
                this.engine.feed(rb.filled(), this.out)
            };
            if let Err(e) = res {
                // Output produced before the error is safe to hand out (it
                // never contains redacted data), so drain it first.
                *this.state = State::Failed(e);
            }
        }
    }
}
