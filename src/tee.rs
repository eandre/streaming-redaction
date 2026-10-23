use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, ReadBuf};

use crate::{Error, RedactedCopy};

pin_project! {
    /// An [`AsyncRead`] that passes its inner reader's bytes through
    /// unmodified while building a redacted copy on the side.
    ///
    /// Created by [`Redactor::tee`](crate::Redactor::tee). Reads go straight
    /// into the caller's buffer; the same bytes are then fed to the redactor.
    /// Redaction errors (e.g. malformed input) never affect the original
    /// stream; they surface from [`into_redacted`](Self::into_redacted).
    pub struct TeeReader<R> {
        #[pin]
        inner: R,
        copy: RedactedCopy,
        read: u64,
        eof: bool,
    }
}

impl<R> TeeReader<R> {
    pub(crate) fn new(inner: R, copy: RedactedCopy) -> Self {
        TeeReader {
            inner,
            copy,
            read: 0,
            eof: false,
        }
    }

    /// Returns a reference to the wrapped reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Removes and returns the redacted bytes that are final so far, for
    /// callers that want to ship the copy incrementally.
    pub fn take_redacted_ready(&mut self) -> Vec<u8> {
        self.copy.take_ready()
    }

    /// Bytes of redacted output currently held in memory.
    pub fn redacted_buffered_len(&self) -> usize {
        self.copy.buffered_len()
    }

    /// The redaction error, if redaction has failed. The original stream
    /// is unaffected.
    pub fn redaction_error(&self) -> Option<&Error> {
        self.copy.error()
    }

    /// Returns the redacted copy (minus anything already taken with
    /// [`take_redacted_ready`](Self::take_redacted_ready)).
    ///
    /// Fails if redaction failed, or if the inner reader wasn't read to the
    /// end: a protobuf prefix can look like a complete message, so a partial
    /// copy is never returned as if it were whole.
    pub fn into_redacted(self) -> Result<Vec<u8>, Error> {
        self.into_parts().1
    }

    /// Returns the inner reader and the redacted copy.
    pub fn into_parts(self) -> (R, Result<Vec<u8>, Error>) {
        let result = match (self.copy.error(), self.eof) {
            (Some(e), _) => Err(e.clone()),
            (None, false) => Err(Error::UnexpectedEof { offset: self.read }),
            (None, true) => self.copy.finish(),
        };
        (self.inner, result)
    }
}

impl<R: AsyncRead> AsyncRead for TeeReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        let before = buf.filled().len();
        let had_room = buf.remaining() > 0;
        ready!(this.inner.poll_read(cx, buf))?;
        let new = &buf.filled()[before..];
        if !new.is_empty() {
            *this.read += new.len() as u64;
            // A failure is recorded in the copy; the original stream goes on.
            let _ = this.copy.feed(new);
        } else if had_room && !*this.eof {
            *this.eof = true;
            this.copy.end();
        }
        Poll::Ready(Ok(()))
    }
}
