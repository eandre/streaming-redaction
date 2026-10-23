//! Streaming redaction of JSON, Protobuf and HTML form payloads.
//!
//! A [`Redactor`] holds redaction rules for each codec:
//!
//! * JSON: JSONPath expressions such as `$.user.password`, `$..token` or
//!   `$.items[*].card`.
//! * Protobuf: field-number paths such as `1.3.2` (field 2 of the message in
//!   field 3 of the message in field 1).
//! * Forms: field names, for urlencoded and multipart bodies.
//!
//! Each payload is redacted with an optional content type. Whatever the
//! content type leaves open (or all of it, if there is none) is detected from
//! the payload's first bytes: plain JSON or NDJSON, a bare protobuf message,
//! gRPC / gRPC-Web / Connect frames (binary or base64 `grpc-web-text`) with
//! either codec inside, or a urlencoded / multipart form.
//!
//! The input is processed as it arrives, with memory independent of payload
//! size, and the redaction decision for every byte is made before that byte
//! is emitted, so partially written output never leaks redacted data.
//!
//! ```no_run
//! # async fn demo(body: impl tokio::io::AsyncRead + Unpin, mut upstream: impl tokio::io::AsyncWrite + Unpin) -> Result<(), Box<dyn std::error::Error>> {
//! use streaming_parse::Redactor;
//!
//! let redactor = Redactor::builder()
//!     .json(["$..password"])
//!     .proto(["2", "4.1"])
//!     .form(["password"])
//!     .build()?;
//!
//! // Forward the original bytes and keep a redacted copy, e.g. for tracing.
//! let mut tee = redactor.tee(body, Some("application/grpc-web-text"));
//! tokio::io::copy(&mut tee, &mut upstream).await?;
//! let redacted: Vec<u8> = tee.into_redacted()?;
//! # Ok(()) }
//! ```
//!
//! [`Redactor::reader`] instead redacts the stream itself, keeping sizes
//! unchanged where length prefixes require it. See the README for the exact
//! output semantics of each format.

mod base64;
mod detect;
mod envelope;
mod error;
mod form;
mod json;
mod proto;
mod reader;
mod tee;

use std::sync::Arc;

pub use error::Error;
pub use json::JsonPath;
pub use proto::{FieldPath, ProtoFill};
pub use reader::RedactReader;
pub use tee::TeeReader;

use detect::Auto;
use tokio::io::{AsyncRead, AsyncWrite};

/// How a payload's messages are encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Codec {
    /// JSON, including NDJSON and the protobuf JSON mapping in gRPC frames.
    Json,
    /// Binary protobuf.
    Proto,
    /// HTML forms: urlencoded or multipart.
    Form,
}

/// Tuning knobs. Construct with [`Options::default`] and the builder methods.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Options {
    /// JSON text written in place of each redacted JSON value.
    /// Default: `"[REDACTED]"` (a JSON string). Ignored when
    /// `preserve_json_size` is set.
    pub json_replacement: String,
    /// Replace each redacted JSON value with a string of `*` of exactly the
    /// same byte length (single-digit numbers become `0`), so the output is
    /// as long as the input. Useful when a `Content-Length` must stay valid.
    /// In stream mode it's always on for JSON inside gRPC/Connect frames,
    /// whose length prefixes are written before the message. Default: false.
    pub preserve_json_size: bool,
    /// Text written in place of each redacted form field value (encoded as
    /// needed). Default: `[REDACTED]`.
    pub form_replacement: String,
    /// What redacted length-delimited protobuf fields are filled with.
    pub proto_fill: ProtoFill,
    /// Maximum nesting depth of the input. Bounds memory use on hostile
    /// input. Default: 256.
    pub max_depth: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            json_replacement: "\"[REDACTED]\"".to_owned(),
            preserve_json_size: false,
            form_replacement: "[REDACTED]".to_owned(),
            proto_fill: ProtoFill::default(),
            max_depth: 256,
        }
    }
}

impl Options {
    /// Sets the raw JSON text used in place of redacted values, e.g. `null`.
    pub fn json_replacement(mut self, json: impl Into<String>) -> Self {
        self.json_replacement = json.into();
        self
    }

    /// Enables same-length JSON redaction; see [`Options::preserve_json_size`].
    pub fn preserve_json_size(mut self, on: bool) -> Self {
        self.preserve_json_size = on;
        self
    }

    /// Sets the text used in place of redacted form field values.
    pub fn form_replacement(mut self, text: impl Into<String>) -> Self {
        self.form_replacement = text.into();
        self
    }

    /// Sets the fill strategy for redacted length-delimited protobuf fields.
    pub fn proto_fill(mut self, fill: ProtoFill) -> Self {
        self.proto_fill = fill;
        self
    }

    /// Sets the maximum accepted nesting depth.
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }
}

/// Rules for every codec, compiled.
#[derive(Clone)]
pub(crate) struct Compiled {
    json: Arc<json::Compiled>,
    proto: Arc<proto::Compiled>,
    form: Arc<form::Compiled>,
}

/// Builds a [`Redactor`]. Codecs without rules are still parsed (and
/// validated) but nothing in them is redacted.
#[derive(Debug, Clone, Default)]
pub struct RedactorBuilder {
    json: Vec<String>,
    proto: Vec<String>,
    form: Vec<String>,
    options: Options,
}

impl RedactorBuilder {
    /// Adds JSONPath rules, e.g. `$..password`, `$.cards[*].number`.
    pub fn json<I, S>(mut self, rules: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.json
            .extend(rules.into_iter().map(|r| r.as_ref().to_owned()));
        self
    }

    /// Adds protobuf field-number paths, e.g. `2`, `4.1`.
    pub fn proto<I, S>(mut self, rules: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.proto
            .extend(rules.into_iter().map(|r| r.as_ref().to_owned()));
        self
    }

    /// Adds form field names, e.g. `password`.
    pub fn form<I, S>(mut self, rules: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.form
            .extend(rules.into_iter().map(|r| r.as_ref().to_owned()));
        self
    }

    /// Sets the options.
    pub fn options(mut self, options: Options) -> Self {
        self.options = options;
        self
    }

    /// Parses and compiles the rules.
    pub fn build(self) -> Result<Redactor, Error> {
        let json_paths = self
            .json
            .iter()
            .map(|r| r.parse())
            .collect::<Result<Vec<JsonPath>, _>>()?;
        let proto_paths = self
            .proto
            .iter()
            .map(|r| r.parse())
            .collect::<Result<Vec<FieldPath>, _>>()?;
        let o = &self.options;
        let compiled = Compiled {
            json: Arc::new(json::Compiled::new(
                json_paths,
                o,
                true,
                o.preserve_json_size,
            )?),
            proto: Arc::new(proto::Compiled::new(proto_paths, o)),
            form: Arc::new(form::Compiled::new(self.form, o)?),
        };
        Ok(Redactor { compiled })
    }
}

/// Compiled redaction rules for every codec.
///
/// Cheap to clone and safe to share between tasks: build one and reuse it for
/// every payload. Each payload is redacted with its own optional content
/// type; whatever that leaves open is detected from the payload itself.
#[derive(Clone)]
pub struct Redactor {
    compiled: Compiled,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor").finish_non_exhaustive()
    }
}

impl Redactor {
    /// Starts building a redactor.
    pub fn builder() -> RedactorBuilder {
        RedactorBuilder::default()
    }

    /// Wraps `reader` so that reading from the result yields the original
    /// bytes, unmodified, while a redacted copy is built on the side.
    ///
    /// `content_type` is the payload's `Content-Type`, if known.
    pub fn tee<R: AsyncRead>(&self, reader: R, content_type: Option<&str>) -> TeeReader<R> {
        TeeReader::new(reader, self.redacted_copy(content_type))
    }

    /// Wraps `reader` so that reading from the result yields redacted bytes.
    ///
    /// The output is a drop-in replacement for the input: sizes are preserved
    /// wherever a length prefix requires it (protobuf, RPC frames).
    pub fn reader<R: AsyncRead>(&self, reader: R, content_type: Option<&str>) -> RedactReader<R> {
        RedactReader::new(reader, self.stream(content_type))
    }

    /// Copies `reader` to `writer`, redacting along the way.
    /// Returns the number of bytes written.
    pub async fn redact<R, W>(
        &self,
        reader: R,
        writer: &mut W,
        content_type: Option<&str>,
    ) -> std::io::Result<u64>
    where
        R: AsyncRead,
        W: AsyncWrite + Unpin + ?Sized,
    {
        let mut reader = std::pin::pin!(self.reader(reader, content_type));
        tokio::io::copy(&mut reader, writer).await
    }

    /// Sans-IO version of [`reader`](Self::reader).
    pub fn stream(&self, content_type: Option<&str>) -> StreamRedactor {
        StreamRedactor {
            engine: Auto::new(self.compiled.clone(), content_type, false),
        }
    }

    /// Sans-IO version of [`tee`](Self::tee): builds a redacted copy of one
    /// payload in an internal buffer.
    ///
    /// Because the copy is buffered, redaction is free to change sizes:
    /// protobuf fields are removed outright, and JSON values (including
    /// inside RPC frames) get the normal `json_replacement`, with length
    /// prefixes patched afterwards.
    pub fn redacted_copy(&self, content_type: Option<&str>) -> RedactedCopy {
        RedactedCopy {
            engine: Auto::new(self.compiled.clone(), content_type, true),
            buf: Vec::new(),
            error: None,
            finished: false,
        }
    }
}

/// Sans-IO redaction state machine for a single payload.
///
/// Feed input chunks in order with [`feed`](Self::feed), then call
/// [`finish`](Self::finish) once at end of input. Output is appended to the
/// supplied buffer.
pub struct StreamRedactor {
    engine: Auto,
}

impl StreamRedactor {
    /// Processes the next chunk of input, appending redacted output to `out`.
    ///
    /// After an error the state machine must not be used again. Output
    /// written so far is still safe: it never contains redacted data.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        self.engine.feed(input, out)
    }

    /// Signals end of input, flushing any held-back output. Fails if the
    /// input was truncated.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.engine.finish(out)
    }
}

/// Sans-IO builder of a redacted copy of one payload. See
/// [`Redactor::redacted_copy`].
///
/// The copy is held internally. Bytes that can no longer change can be taken
/// early with [`take_ready`](Self::take_ready); what must be held back is
/// only the part that may still be patched: nothing for JSON, the current
/// message for RPC envelopes, and the outermost open sub-message on a rule
/// path for protobuf.
pub struct RedactedCopy {
    engine: Auto,
    buf: Vec<u8>,
    error: Option<Error>,
    finished: bool,
}

impl RedactedCopy {
    /// Processes the next chunk of the original payload.
    ///
    /// After an error, further calls return the same error.
    pub fn feed(&mut self, input: &[u8]) -> Result<(), Error> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        debug_assert!(!self.finished, "feed after finish");
        self.engine
            .feed(input, &mut self.buf)
            .inspect_err(|e| self.error = Some(e.clone()))
    }

    /// Removes and returns the redacted bytes that are final so far.
    pub fn take_ready(&mut self) -> Vec<u8> {
        let ready = if self.finished {
            self.buf.len()
        } else {
            self.engine.committed(self.buf.len())
        };
        let rest = self.buf.split_off(ready);
        self.engine.shift(ready);
        std::mem::replace(&mut self.buf, rest)
    }

    /// Bytes currently held (taken bytes excluded).
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// Signals end of input and returns the rest of the redacted copy
    /// (everything not already taken with [`take_ready`](Self::take_ready)).
    pub fn finish(mut self) -> Result<Vec<u8>, Error> {
        self.end();
        match self.error {
            Some(e) => Err(e),
            None => Ok(self.buf),
        }
    }

    fn end(&mut self) {
        if self.error.is_none() && !self.finished {
            self.finished = true;
            if let Err(e) = self.engine.finish(&mut self.buf) {
                self.error = Some(e);
            }
        }
    }

    fn error(&self) -> Option<&Error> {
        self.error.as_ref()
    }
}
