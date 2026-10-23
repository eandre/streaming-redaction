//! Streaming, constant-memory redaction of JSON and Protobuf payloads.
//!
//! A [`Redactor`] is built from a content type and a list of rules. The rule
//! syntax follows the message encoding ([`Codec`]):
//!
//! * JSON (`application/json`, `*+json`, NDJSON, `application/grpc+json`, …):
//!   rules are JSONPath expressions such as `$.user.password`, `$..token` or
//!   `$.items[*].card`.
//! * Protobuf (`application/x-protobuf`, `application/grpc`, …): rules are
//!   field masks written as field numbers, such as `1.3.2` (field 2 of the
//!   message in field 3 of the message in field 1).
//!
//! gRPC, gRPC-Web (binary and base64 `-text`) and Connect streaming envelopes
//! are understood, with either codec.
//!
//! The input is processed as it arrives. Nothing is buffered beyond the
//! current read chunk plus O(nesting depth) parser state, and the redaction
//! decision for every byte is made before that byte is emitted, so partially
//! written output never leaks redacted data.
//!
//! ```no_run
//! # async fn demo(body: impl tokio::io::AsyncRead + Unpin) -> std::io::Result<()> {
//! use streaming_parse::Redactor;
//!
//! let redactor = Redactor::new("application/json", ["$.password", "$..ssn"])?;
//! let mut redacted = redactor.reader(body); // implements AsyncRead
//! tokio::io::copy(&mut redacted, &mut tokio::io::stdout()).await?;
//! # Ok(()) }
//! ```
//!
//! To forward the original bytes untouched and keep a redacted copy on the
//! side (e.g. for tracing), use [`Redactor::tee`]. Because that copy is
//! buffered, redaction there may change sizes: protobuf fields are removed
//! and length prefixes rewritten.
//!
//! ```no_run
//! # async fn demo(body: impl tokio::io::AsyncRead + Unpin, mut upstream: impl tokio::io::AsyncWrite + Unpin) -> Result<(), Box<dyn std::error::Error>> {
//! # let redactor = streaming_parse::Redactor::new("application/grpc", ["2"])?;
//! let mut tee = redactor.tee(body);
//! tokio::io::copy(&mut tee, &mut upstream).await?; // original bytes
//! let redacted: Vec<u8> = tee.into_redacted()?;
//! # Ok(()) }
//! ```
//!
//! See the README for the exact output semantics of each format.

mod base64;
mod envelope;
mod error;
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

use tokio::io::{AsyncRead, AsyncWrite};

/// How individual messages are encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// Binary protobuf; rules are field-number paths ([`FieldPath`]).
    Proto,
    /// JSON (for RPC protocols: the protobuf JSON mapping); rules are
    /// JSONPath ([`JsonPath`]).
    Json,
}

/// Wire format of the payload, usually derived from a content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Format {
    /// A single JSON value.
    Json,
    /// A sequence of whitespace-separated JSON values (NDJSON / JSON Lines).
    JsonLines,
    /// A single binary protobuf message.
    Protobuf,
    /// A gRPC body: a sequence of length-prefixed messages.
    Grpc(Codec),
    /// A binary gRPC-Web body: like gRPC, plus a trailer frame which is
    /// passed through untouched.
    GrpcWeb(Codec),
    /// A gRPC-Web body, base64-encoded (`application/grpc-web-text`).
    GrpcWebText(Codec),
    /// A Connect streaming body (`application/connect+proto`/`+json`). The
    /// end-of-stream frame is passed through untouched. Connect unary RPCs
    /// use plain `application/proto` / `application/json`.
    ConnectStream(Codec),
}

impl Format {
    /// Maps a `Content-Type` header value to a format. Parameters such as
    /// `; charset=utf-8` are ignored. Returns `None` if unsupported.
    pub fn from_content_type(content_type: &str) -> Option<Format> {
        let essence = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();

        // Enveloped RPC protocols: `<base>[+<codec>]`.
        let (base, suffix) = match essence.split_once('+') {
            Some((b, s)) => (b, Some(s)),
            None => (essence.as_str(), None),
        };
        let envelope: Option<fn(Codec) -> Format> = match base {
            "application/grpc" => Some(Format::Grpc),
            "application/grpc-web" => Some(Format::GrpcWeb),
            "application/grpc-web-text" => Some(Format::GrpcWebText),
            "application/connect" => Some(Format::ConnectStream),
            _ => None,
        };
        if let Some(make) = envelope {
            let codec = match suffix {
                // gRPC defaults to protobuf; Connect always names the codec.
                None if base != "application/connect" => Codec::Proto,
                Some("proto" | "protobuf") => Codec::Proto,
                Some("json") => Codec::Json,
                _ => return None,
            };
            return Some(make(codec));
        }

        let f = match essence.as_str() {
            "application/json" | "text/json" => Format::Json,
            "application/x-ndjson"
            | "application/ndjson"
            | "application/jsonl"
            | "application/x-jsonlines"
            | "application/jsonlines"
            | "application/json-lines" => Format::JsonLines,
            "application/x-protobuf"
            | "application/protobuf"
            | "application/proto"
            | "application/x-google-protobuf"
            | "application/vnd.google.protobuf" => Format::Protobuf,
            s if s.ends_with("+json") => Format::Json,
            s if s.ends_with("+protobuf") || s.ends_with("+proto") => Format::Protobuf,
            _ => return None,
        };
        Some(f)
    }

    /// The message encoding, which determines the rule syntax.
    pub fn codec(self) -> Codec {
        match self {
            Format::Json | Format::JsonLines => Codec::Json,
            Format::Protobuf => Codec::Proto,
            Format::Grpc(c)
            | Format::GrpcWeb(c)
            | Format::GrpcWebText(c)
            | Format::ConnectStream(c) => c,
        }
    }

    /// The envelope protocol, if messages are length-prefixed.
    fn envelope(self) -> Option<envelope::Protocol> {
        match self {
            Format::Grpc(_) => Some(envelope::Protocol::Grpc),
            Format::GrpcWeb(_) | Format::GrpcWebText(_) => Some(envelope::Protocol::GrpcWeb),
            Format::ConnectStream(_) => Some(envelope::Protocol::Connect),
            _ => None,
        }
    }
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
    /// Always on for JSON inside gRPC/Connect envelopes, whose length
    /// prefixes are written before the message. Default: false.
    pub preserve_json_size: bool,
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

#[derive(Clone)]
enum Compiled {
    Json(Arc<json::Compiled>),
    Proto(Arc<proto::Compiled>),
}

/// A compiled set of redaction rules for one format.
///
/// Cheap to clone and safe to share between tasks; create one per
/// (content type, rule set) and reuse it for every payload.
#[derive(Clone)]
pub struct Redactor {
    format: Format,
    compiled: Compiled,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

impl Redactor {
    /// Builds a redactor for `content_type` with default [`Options`].
    ///
    /// Rules are parsed according to the format's [`Codec`]: JSONPath for
    /// JSON, dotted field numbers for protobuf.
    pub fn new<I, S>(content_type: &str, rules: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::with_options(content_type, rules, Options::default())
    }

    /// Like [`Redactor::new`] with explicit options.
    pub fn with_options<I, S>(content_type: &str, rules: I, options: Options) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let format = Format::from_content_type(content_type)
            .ok_or_else(|| Error::UnsupportedContentType(content_type.to_owned()))?;
        Self::for_format(format, rules, options)
    }

    /// Builds a redactor for an explicit format.
    pub fn for_format<I, S>(format: Format, rules: I, options: Options) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        match format.codec() {
            Codec::Json => {
                let paths = rules
                    .into_iter()
                    .map(|r| r.as_ref().parse::<JsonPath>())
                    .collect::<Result<Vec<_>, _>>()?;
                Self::json(format, paths, options)
            }
            Codec::Proto => {
                let paths = rules
                    .into_iter()
                    .map(|r| r.as_ref().parse::<FieldPath>())
                    .collect::<Result<Vec<_>, _>>()?;
                Self::protobuf(format, paths, options)
            }
        }
    }

    /// Builds a redactor from pre-parsed JSONPaths.
    /// `format` must use [`Codec::Json`].
    pub fn json(format: Format, paths: Vec<JsonPath>, options: Options) -> Result<Self, Error> {
        if format.codec() != Codec::Json {
            return Err(Error::InvalidOptions(format!(
                "{format:?} is not a JSON format"
            )));
        }
        let c = json::Compiled::new(
            paths,
            &options,
            format == Format::JsonLines,
            options.preserve_json_size,
        )?;
        Ok(Redactor {
            format,
            compiled: Compiled::Json(Arc::new(c)),
        })
    }

    /// Builds a redactor from pre-parsed field paths.
    /// `format` must use [`Codec::Proto`].
    pub fn protobuf(
        format: Format,
        paths: Vec<FieldPath>,
        options: Options,
    ) -> Result<Self, Error> {
        if format.codec() != Codec::Proto {
            return Err(Error::InvalidOptions(format!(
                "{format:?} is not a protobuf format"
            )));
        }
        let c = proto::Compiled::new(paths, &options);
        Ok(Redactor {
            format,
            compiled: Compiled::Proto(Arc::new(c)),
        })
    }

    /// The format this redactor handles.
    pub fn format(&self) -> Format {
        self.format
    }

    /// Creates a fresh sans-IO redaction state machine for one payload.
    ///
    /// Output is a drop-in replacement for the input: sizes are preserved
    /// wherever a length prefix requires it (protobuf, RPC envelopes).
    pub fn stream(&self) -> StreamRedactor {
        StreamRedactor {
            kind: self.engine(false),
        }
    }

    /// Creates a sans-IO redactor that builds a redacted copy of one payload
    /// in an internal buffer.
    ///
    /// Because the copy is buffered, redaction is free to change sizes:
    /// protobuf fields are removed outright, and JSON values (including
    /// inside RPC envelopes) get the normal `json_replacement`, with length
    /// prefixes patched afterwards.
    pub fn redacted_copy(&self) -> RedactedCopy {
        RedactedCopy {
            kind: self.engine(true),
            buf: Vec::new(),
            error: None,
            finished: false,
        }
    }

    /// Wraps `reader` so that reading from the result yields the original
    /// bytes, unmodified, while a redacted copy is built on the side.
    pub fn tee<R: AsyncRead>(&self, reader: R) -> TeeReader<R> {
        TeeReader::new(reader, self.redacted_copy())
    }

    fn engine(&self, resize: bool) -> Kind {
        let enveloped = self.format.envelope().is_some();
        let msg = match &self.compiled {
            // Fixed-length envelopes need same-size JSON unless we can patch them.
            Compiled::Json(c) => {
                envelope::Msg::Json(json::Engine::new(c.clone(), enveloped && !resize))
            }
            Compiled::Proto(c) => envelope::Msg::Proto(proto::Engine::new(c.clone(), resize)),
        };
        match (self.format.envelope(), msg) {
            (None, envelope::Msg::Json(e)) => Kind::Json(e),
            (None, envelope::Msg::Proto(e)) => Kind::Proto(e),
            (Some(p), msg) => {
                let env = envelope::Engine::new(p, msg, resize);
                if matches!(self.format, Format::GrpcWebText(_)) {
                    Kind::Text(base64::Engine::new(env, resize))
                } else {
                    Kind::Envelope(env)
                }
            }
        }
    }

    /// Wraps `reader` so that reading from the result yields redacted bytes.
    pub fn reader<R: AsyncRead>(&self, reader: R) -> RedactReader<R> {
        RedactReader::new(reader, self.stream())
    }

    /// Copies `reader` to `writer`, redacting along the way.
    /// Returns the number of bytes written.
    pub async fn redact<R, W>(&self, reader: R, writer: &mut W) -> std::io::Result<u64>
    where
        R: AsyncRead,
        W: AsyncWrite + Unpin + ?Sized,
    {
        let mut reader = std::pin::pin!(self.reader(reader));
        tokio::io::copy(&mut reader, writer).await
    }
}

/// Sans-IO redaction state machine for a single payload.
///
/// Feed input chunks in order with [`feed`](Self::feed), then call
/// [`finish`](Self::finish) once at end of input. Output is appended to the
/// supplied buffer; each call produces output proportional to its input.
pub struct StreamRedactor {
    kind: Kind,
}

enum Kind {
    Json(json::Engine),
    Proto(proto::Engine),
    Envelope(envelope::Engine),
    Text(base64::Engine),
}

impl Kind {
    fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Kind::Json(e) => e.feed(input, out),
            Kind::Proto(e) => e.feed(input, out),
            Kind::Envelope(e) => e.feed(input, out),
            Kind::Text(e) => e.feed(input, out),
        }
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Kind::Json(e) => e.finish(out),
            Kind::Proto(e) => e.finish(out),
            Kind::Envelope(e) => e.finish(out),
            Kind::Text(e) => e.finish(out),
        }
    }

    /// Length of the output prefix that will never be rewritten.
    fn committed(&self, out_len: usize) -> usize {
        match self {
            Kind::Proto(e) => e.committed(out_len),
            Kind::Envelope(e) => e.committed(out_len),
            Kind::Json(_) | Kind::Text(_) => out_len,
        }
    }

    /// `k` bytes were removed from the front of the output buffer.
    fn shift(&mut self, k: usize) {
        match self {
            Kind::Proto(e) => e.shift(k),
            Kind::Envelope(e) => e.shift(k),
            Kind::Json(_) | Kind::Text(_) => {}
        }
    }
}

impl StreamRedactor {
    /// Processes the next chunk of input, appending redacted output to `out`.
    ///
    /// After an error the state machine must not be used again. Output
    /// written so far is still safe: it never contains redacted data.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        self.kind.feed(input, out)
    }

    /// Signals end of input, flushing any held-back output. Fails if the
    /// input was truncated.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.kind.finish(out)
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
    kind: Kind,
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
        self.kind
            .feed(input, &mut self.buf)
            .inspect_err(|e| self.error = Some(e.clone()))
    }

    /// Removes and returns the redacted bytes that are final so far.
    pub fn take_ready(&mut self) -> Vec<u8> {
        let ready = if self.finished {
            self.buf.len()
        } else {
            self.kind.committed(self.buf.len())
        };
        let rest = self.buf.split_off(ready);
        self.kind.shift(ready);
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
            if let Err(e) = self.kind.finish(&mut self.buf) {
                self.error = Some(e);
            }
        }
    }

    fn error(&self) -> Option<&Error> {
        self.error.as_ref()
    }
}

/// Convenience: build a redactor and wrap `reader` in one call.
pub fn redact_reader<R, I, S>(
    content_type: &str,
    rules: I,
    reader: R,
) -> Result<RedactReader<R>, Error>
where
    R: AsyncRead,
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    Ok(Redactor::new(content_type, rules)?.reader(reader))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_types() {
        use Codec::*;
        let cases = [
            ("application/json; charset=utf-8", Some(Format::Json)),
            ("Application/Problem+JSON", Some(Format::Json)),
            ("application/x-ndjson", Some(Format::JsonLines)),
            ("application/x-protobuf", Some(Format::Protobuf)),
            ("application/proto", Some(Format::Protobuf)),
            ("application/vnd.foo+proto", Some(Format::Protobuf)),
            ("application/grpc", Some(Format::Grpc(Proto))),
            ("application/grpc+proto", Some(Format::Grpc(Proto))),
            ("application/grpc+json", Some(Format::Grpc(Json))),
            ("application/grpc-web", Some(Format::GrpcWeb(Proto))),
            ("application/grpc-web+json", Some(Format::GrpcWeb(Json))),
            (
                "application/grpc-web-text",
                Some(Format::GrpcWebText(Proto)),
            ),
            (
                "application/grpc-web-text+proto",
                Some(Format::GrpcWebText(Proto)),
            ),
            (
                "application/grpc-web-text+json",
                Some(Format::GrpcWebText(Json)),
            ),
            (
                "application/connect+proto",
                Some(Format::ConnectStream(Proto)),
            ),
            (
                "application/connect+json",
                Some(Format::ConnectStream(Json)),
            ),
            ("application/connect", None),
            ("application/grpc+thrift", None),
            ("application/grpc-web+flatbuffers", None),
            ("text/plain", None),
        ];
        for (ct, want) in cases {
            assert_eq!(Format::from_content_type(ct), want, "{ct}");
        }
    }
}
