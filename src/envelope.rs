//! Length-prefixed message envelopes: `[flags:u8][len:u32 BE][message]`,
//! repeated. Used by gRPC, gRPC-Web and Connect streaming, which differ only
//! in which flag marks a metadata frame (gRPC-Web trailers: `0x80`, Connect
//! end-of-stream: `0x02`; plain gRPC has none). One parser handles all three.
//!
//! Each message is redacted with a fresh message engine.
//!
//! In stream mode message redaction is size-preserving (protobuf by
//! overwriting, JSON via its size-preserving mode), so headers, which are
//! written before the message is seen, pass through unchanged.
//!
//! In resize mode the header is written with a placeholder length that is
//! patched once the message ends, so redacted messages may change size.

use crate::detect::{self, WINDOW};
use crate::{Codec, Compiled, Error, json, proto};

/// The per-message redactor.
pub(crate) enum Msg {
    Proto(proto::Engine),
    Json(json::Engine),
    /// Codec not known from the content type: decided from the first
    /// non-empty message, then used for the rest of the stream.
    Detect(Box<DetectMsg>),
}

pub(crate) struct DetectMsg {
    compiled: Compiled,
    resize: bool,
    /// Length of the current message.
    len: u32,
    pending: Vec<u8>,
    chosen: Option<Msg>,
}

impl Msg {
    pub(crate) fn new(c: &Compiled, codec: Option<Codec>, resize: bool) -> Msg {
        match codec {
            // Without patching, frame lengths force same-size JSON.
            Some(Codec::Json) => Msg::Json(json::Engine::new(c.json.clone(), !resize)),
            Some(Codec::Proto) => Msg::Proto(proto::Engine::new(c.proto.clone(), resize)),
            Some(Codec::Form) | None => Msg::Detect(Box::new(DetectMsg {
                compiled: c.clone(),
                resize,
                len: 0,
                pending: Vec::new(),
                chosen: None,
            })),
        }
    }

    /// Prepares for a new message of `len` bytes.
    fn begin(&mut self, len: u32) {
        match self {
            Msg::Proto(e) => e.reset(),
            Msg::Json(e) => e.reset(),
            Msg::Detect(d) => match &mut d.chosen {
                Some(m) => m.begin(len),
                None => {
                    d.len = len;
                    d.pending.clear();
                }
            },
        }
    }

    fn position(&self) -> u64 {
        match self {
            Msg::Proto(e) => e.position(),
            Msg::Json(e) => e.position(),
            Msg::Detect(d) => match &d.chosen {
                Some(m) => m.position(),
                None => d.pending.len() as u64,
            },
        }
    }

    fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Msg::Proto(e) => e.feed(input, out),
            Msg::Json(e) => e.feed(input, out),
            Msg::Detect(d) => {
                if let Some(m) = &mut d.chosen {
                    return m.feed(input, out);
                }
                d.pending.extend_from_slice(input);
                // Decide once we have the whole message or a full window.
                let complete = d.pending.len() == d.len as usize;
                if !complete && d.pending.len() < WINDOW {
                    return Ok(());
                }
                let (codec, _) = detect::choose(
                    &d.compiled,
                    &[Codec::Json, Codec::Proto],
                    &d.pending,
                    complete,
                )?;
                let mut m = Msg::new(&d.compiled, codec, d.resize);
                m.begin(d.len);
                let pending = std::mem::take(&mut d.pending);
                m.feed(&pending, out)?;
                d.chosen = Some(m);
                Ok(())
            }
        }
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Msg::Proto(e) => e.finish(out),
            Msg::Json(e) => e.finish(out),
            Msg::Detect(d) => match &mut d.chosen {
                Some(m) => m.finish(out),
                // Only empty messages so far: nothing to parse.
                None => Ok(()),
            },
        }
    }

    fn committed(&self, out_len: usize) -> usize {
        match self {
            Msg::Proto(e) => e.committed(out_len),
            Msg::Json(_) => out_len,
            Msg::Detect(d) => d.chosen.as_ref().map_or(out_len, |m| m.committed(out_len)),
        }
    }

    fn shift(&mut self, k: usize) {
        match self {
            Msg::Proto(e) => e.shift(k),
            Msg::Json(_) => {}
            Msg::Detect(d) => {
                if let Some(m) = &mut d.chosen {
                    m.shift(k);
                }
            }
        }
    }
}

const COMPRESSED: u8 = 0x01;
/// Frames carrying protocol metadata rather than a message: gRPC-Web
/// trailers (`0x80`) and Connect end-of-stream (`0x02`). Passed through
/// untouched. Plain gRPC reserves these bits, so a gRPC peer would reject
/// such a frame anyway.
const METADATA: u8 = 0x80 | 0x02;

pub(crate) struct Engine {
    inner: Msg,
    /// Resize mode: patch each message's length after it ends.
    resize: bool,
    /// Resize mode: output position of the current message's header.
    header_pos: Option<usize>,
    header: [u8; 5],
    state: State,
    /// Absolute offset in the body, for error reporting.
    offset: u64,
}

enum State {
    Header(u8),
    Message { left: u32 },
    Metadata { left: u32 },
}

impl Engine {
    pub(crate) fn new(inner: Msg, resize: bool) -> Self {
        Engine {
            inner,
            resize,
            header_pos: None,
            header: [0; 5],
            state: State::Header(0),
            offset: 0,
        }
    }

    pub(crate) fn feed(&mut self, mut input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        while !input.is_empty() {
            match &mut self.state {
                State::Header(n) => {
                    let b = input[0];
                    input = &input[1..];
                    self.offset += 1;
                    if !self.resize {
                        out.push(b);
                    }
                    self.header[*n as usize] = b;
                    *n += 1;
                    if *n < 5 {
                        continue;
                    }
                    if self.resize {
                        // The length is a placeholder until the message ends.
                        self.header_pos = Some(out.len());
                        out.extend_from_slice(&self.header);
                    }
                    let flags = self.header[0];
                    let len = u32::from_be_bytes(self.header[1..5].try_into().unwrap());
                    if flags & METADATA != 0 {
                        // Copied as is, so there's no length to patch.
                        self.header_pos = None;
                        self.state = State::Metadata { left: len };
                    } else if flags & COMPRESSED != 0 {
                        return Err(Error::CompressedGrpcMessage {
                            offset: self.offset - 5,
                        });
                    } else {
                        self.inner.begin(len);
                        self.state = State::Message { left: len };
                    }
                    self.end_frame_if_complete(out)?;
                }
                State::Message { left } => {
                    let n = (*left as usize).min(input.len());
                    let base = self.offset - self.inner.position();
                    self.inner
                        .feed(&input[..n], out)
                        .map_err(|e| rebase(e, base))?;
                    *left -= n as u32;
                    input = &input[n..];
                    self.offset += n as u64;
                    self.end_frame_if_complete(out)?;
                }
                State::Metadata { left } => {
                    let n = (*left as usize).min(input.len());
                    out.extend_from_slice(&input[..n]);
                    *left -= n as u32;
                    input = &input[n..];
                    self.offset += n as u64;
                    self.end_frame_if_complete(out)?;
                }
            }
        }
        Ok(())
    }

    fn end_frame_if_complete(&mut self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self.state {
            State::Message { left: 0 } => {
                let base = self.offset - self.inner.position();
                self.inner.finish(out).map_err(|e| rebase(e, base))?;
                if let Some(pos) = self.header_pos.take() {
                    let len = out.len() - (pos + 5);
                    let len = u32::try_from(len).map_err(|_| Error::Malformed {
                        offset: self.offset,
                        reason: "redacted message too large for its frame",
                    })?;
                    out[pos + 1..pos + 5].copy_from_slice(&len.to_be_bytes());
                }
                self.state = State::Header(0);
            }
            State::Metadata { left: 0 } => {
                self.header_pos = None;
                self.state = State::Header(0);
            }
            _ => {}
        }
        Ok(())
    }

    /// Length of the output prefix that is final (see `proto::Engine::committed`).
    pub(crate) fn committed(&self, out_len: usize) -> usize {
        match (self.header_pos, &self.state) {
            (Some(pos), State::Message { .. }) => pos,
            _ => self.inner.committed(out_len),
        }
    }

    /// The caller removed `k` bytes from the front of the output buffer.
    pub(crate) fn shift(&mut self, k: usize) {
        if let Some(p) = &mut self.header_pos {
            *p -= k;
        }
        self.inner.shift(k);
    }

    pub(crate) fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), Error> {
        match self.state {
            State::Header(0) => Ok(()),
            _ => Err(Error::UnexpectedEof {
                offset: self.offset,
            }),
        }
    }
}

/// Converts an error offset within one message to an offset in the body.
fn rebase(e: Error, base: u64) -> Error {
    match e {
        Error::Malformed { offset, reason } => Error::Malformed {
            offset: offset + base,
            reason,
        },
        Error::UnexpectedEof { offset } => Error::UnexpectedEof {
            offset: offset + base,
        },
        Error::DepthLimitExceeded { offset, limit } => Error::DepthLimitExceeded {
            offset: offset + base,
            limit,
        },
        e => e,
    }
}
