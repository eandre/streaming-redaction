//! Works out how to parse a payload: from its content type where that's
//! specific enough, otherwise from its first bytes.
//!
//! A content type can pin down the framing, the codec, or both:
//!
//! | Content type                          | Framing         | Codec    |
//! |---------------------------------------|-----------------|----------|
//! | `application/json`, `*+json`, NDJSON  | plain           | JSON     |
//! | `application/x-protobuf`, `*+proto`   | plain           | protobuf |
//! | `application/grpc[-web][+ext]`, `application/connect[+ext]` | envelope | from `+ext`, else detected |
//! | `application/grpc-web-text[+ext]`     | base64 envelope | from `+ext`, else detected |
//! | `application/x-www-form-urlencoded`   | urlencoded      | form     |
//! | `multipart/form-data[; boundary=…]`   | multipart       | form     |
//! | missing or anything else              | detected        | detected |
//!
//! Detecting the framing:
//!
//! * A frame starts with a flags byte (`0x00`–`0x02`, `0x80`). For protobuf
//!   those decode as a tag with field number 0, which is invalid, and no JSON
//!   or form body starts with a control byte, so this is unambiguous.
//! * Base64 of a frame starts with `A` or `g`. We also require the first 8
//!   characters to decode to a frame header and the whole detection window
//!   to be base64.
//!
//! Detecting the codec (when neither the content type nor the framing says):
//! candidate parsers are run over the first [`WINDOW`] bytes (or the whole
//! message, inside a frame), strictest grammar first, and the first that
//! accepts them wins:
//!
//! 1. JSON. Binary protobuf essentially never passes a strict JSON parser.
//! 2. Form, if the bytes are all characters form encoders leave unescaped
//!    and include an `=`. That excludes JSON (`"`, `{`, `:` are always
//!    escaped) and practically all protobuf, which contains bytes below
//!    `0x21` (the tags of fields 1–3, short lengths, small numbers).
//! 3. Protobuf. Its grammar is the loosest: text often parses as protobuf
//!    for a while, which is why it goes last.
//!
//! If none accepts, the result is [`Error::UnrecognizedPayload`]. This is a
//! heuristic; pass the content type whenever it's known.

use crate::envelope::{self, Msg};
use crate::{Codec, Compiled, Error, base64, form, json, proto};

/// Bytes examined (and held back) when detecting the codec of an unframed
/// payload.
pub(crate) const WINDOW: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Framing {
    Plain,
    Envelope,
    Text,
    UrlEncoded,
    Multipart(Vec<u8>),
}

/// What a content type says about a payload. `None` means "detect it".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Hint {
    pub codec: Option<Codec>,
    pub framing: Option<Framing>,
}

impl Hint {
    pub(crate) fn from_content_type(content_type: Option<&str>) -> Hint {
        let Some(ct) = content_type else {
            return Hint::default();
        };
        let mut parts = ct.split(';');
        let essence = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let (base, suffix) = match essence.split_once('+') {
            Some((b, s)) => (b, Some(s)),
            None => (essence.as_str(), None),
        };
        let suffix_codec = match suffix {
            Some("json") => Some(Codec::Json),
            Some("proto" | "protobuf") => Some(Codec::Proto),
            _ => None,
        };
        let hint = |codec, framing| Hint {
            codec,
            framing: Some(framing),
        };
        match base {
            "application/grpc" | "application/grpc-web" | "application/connect" => {
                return hint(suffix_codec, Framing::Envelope);
            }
            "application/grpc-web-text" => return hint(suffix_codec, Framing::Text),
            _ => {}
        }
        match essence.as_str() {
            "application/json"
            | "text/json"
            | "application/x-ndjson"
            | "application/ndjson"
            | "application/jsonl"
            | "application/x-jsonlines"
            | "application/jsonlines"
            | "application/json-lines" => hint(Some(Codec::Json), Framing::Plain),
            "application/x-protobuf"
            | "application/protobuf"
            | "application/proto"
            | "application/x-google-protobuf"
            | "application/vnd.google.protobuf" => hint(Some(Codec::Proto), Framing::Plain),
            "application/x-www-form-urlencoded" => hint(Some(Codec::Form), Framing::UrlEncoded),
            "multipart/form-data" => {
                let boundary = parts.find_map(|p| {
                    let (k, v) = p.split_once('=')?;
                    k.trim()
                        .eq_ignore_ascii_case("boundary")
                        .then(|| v.trim().trim_matches('"').to_owned())
                });
                Hint {
                    codec: Some(Codec::Form),
                    framing: boundary
                        .filter(|b| (1..=70).contains(&b.len()))
                        .map(|b| Framing::Multipart(b.into_bytes())),
                }
            }
            _ if suffix_codec.is_some() => hint(suffix_codec, Framing::Plain),
            _ => Hint::default(),
        }
    }
}

/// Decides codec and framing for a payload starting with `buf`. Returns
/// `None` if more bytes are needed (always decides once `eof` is set or
/// `buf` holds [`WINDOW`] bytes). A `None` codec inside an envelope means
/// "detect per message".
fn decide(
    c: &Compiled,
    hint: &Hint,
    buf: &[u8],
    eof: bool,
) -> Option<Result<(Option<Codec>, Framing), Error>> {
    let must = eof || buf.len() >= WINDOW;
    match (&hint.framing, hint.codec) {
        (Some(f @ (Framing::Envelope | Framing::Text)), codec) => {
            return Some(Ok((codec, f.clone())));
        }
        (Some(f), Some(codec)) => return Some(Ok((Some(codec), f.clone()))),
        (None, Some(Codec::Form)) => {
            return detect_form(buf, must).map(|f| Ok((Some(Codec::Form), f)));
        }
        _ => {}
    }

    // Nothing known.
    let Some(&b0) = buf.first() else {
        return eof.then_some(Ok((None, Framing::Plain)));
    };
    match b0 {
        0x00..=0x07 => return Some(Ok((None, Framing::Envelope))),
        // E.g. a gRPC-Web trailer frame; as protobuf `8x 00` is field 0.
        0x80..=0x87 => match buf.get(1) {
            None if !eof => return None,
            Some(0) => return Some(Ok((None, Framing::Envelope))),
            _ => {}
        },
        _ => {}
    }
    if !must {
        return None;
    }
    if matches!(b0, b'A' | b'g') && looks_like_base64_stream(buf) {
        return Some(Ok((None, Framing::Text)));
    }
    Some(choose(
        c,
        &[Codec::Json, Codec::Form, Codec::Proto],
        buf,
        eof,
    ))
}

/// Picks the first of `candidates` (strictest first) whose parser accepts
/// `window`.
pub(crate) fn choose(
    c: &Compiled,
    candidates: &[Codec],
    window: &[u8],
    eof: bool,
) -> Result<(Option<Codec>, Framing), Error> {
    for &codec in candidates {
        let framing = match codec {
            Codec::Form => match detect_form(window, true) {
                Some(f) => f,
                None => continue,
            },
            _ => Framing::Plain,
        };
        if framing == Framing::UrlEncoded
            && !(window.contains(&b'=') && form::plausible_urlencoded(window))
        {
            continue;
        }
        let mut k = Kind::new(c, Some(codec), framing.clone(), false);
        let mut sink = Vec::new();
        if k.feed(window, &mut sink).is_ok() && (!eof || k.finish(&mut sink).is_ok()) {
            return Ok((Some(codec), framing));
        }
    }
    Err(Error::UnrecognizedPayload)
}

/// Starts with a valid base64 frame header, and the rest of `buf` is base64.
fn looks_like_base64_stream(buf: &[u8]) -> bool {
    if buf.len() < 8 {
        return false;
    }
    let is_b64 = |c: &u8| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=');
    buf.iter().all(is_b64) && looks_like_base64_frame(&buf[..8])
}

/// Whether 8 bytes are base64 (two groups of 4, each possibly padded, since
/// servers may encode every flush separately) starting with a valid flags
/// byte.
fn looks_like_base64_frame(chars: &[u8]) -> bool {
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let group_ok = |g: &[u8]| match g {
        [a, b, b'=', b'='] => val(*a).is_some() && val(*b).is_some(),
        [a, b, c, b'='] => val(*a).is_some() && val(*b).is_some() && val(*c).is_some(),
        _ => g.iter().all(|&c| val(c).is_some()),
    };
    if !chars.chunks(4).all(group_ok) {
        return false;
    }
    let (Some(v0), Some(v1)) = (val(chars[0]), val(chars[1])) else {
        return false;
    };
    let flags = (v0 << 2) | (v1 >> 4);
    matches!(flags, 0x00..=0x03 | 0x80..=0x83)
}

/// Multipart (body starts with `--boundary` CRLF) or urlencoded.
fn detect_form(buf: &[u8], must: bool) -> Option<Framing> {
    match buf {
        [] | [b'-'] if !must => None,
        [b'-', b'-', rest @ ..] => match rest.windows(2).position(|w| w == b"\r\n") {
            Some(end) => {
                let boundary = &rest[..end];
                let trimmed = boundary
                    .iter()
                    .rposition(|b| !matches!(b, b' ' | b'\t'))
                    .map_or(&boundary[..0], |i| &boundary[..=i]);
                if (1..=70).contains(&trimmed.len()) {
                    Some(Framing::Multipart(trimmed.to_vec()))
                } else {
                    Some(Framing::UrlEncoded)
                }
            }
            None if must => Some(Framing::UrlEncoded),
            None => None,
        },
        _ => Some(Framing::UrlEncoded),
    }
}

/// The concrete parser, once codec and framing are known.
pub(crate) enum Kind {
    /// Empty payload: nothing to parse.
    Empty,
    Json(json::Engine),
    Proto(proto::Engine),
    Envelope(envelope::Engine),
    Text(base64::Engine),
    UrlEncoded(form::UrlEncoded),
    Multipart(form::Multipart),
}

impl Kind {
    fn new(c: &Compiled, codec: Option<Codec>, framing: Framing, resize: bool) -> Kind {
        match (codec, framing) {
            (_, f @ (Framing::Envelope | Framing::Text)) => {
                let msg = Msg::new(c, codec, resize);
                let env = envelope::Engine::new(msg, resize);
                if f == Framing::Text {
                    Kind::Text(base64::Engine::new(env, resize))
                } else {
                    Kind::Envelope(env)
                }
            }
            (_, Framing::UrlEncoded) => Kind::UrlEncoded(form::UrlEncoded::new(c.form.clone())),
            (_, Framing::Multipart(b)) => Kind::Multipart(form::Multipart::new(c.form.clone(), &b)),
            (Some(Codec::Json), Framing::Plain) => {
                Kind::Json(json::Engine::new(c.json.clone(), false))
            }
            (Some(Codec::Proto), Framing::Plain) => {
                Kind::Proto(proto::Engine::new(c.proto.clone(), resize))
            }
            (Some(Codec::Form) | None, Framing::Plain) => Kind::Empty,
        }
    }

    fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Kind::Empty => {
                out.extend_from_slice(input);
                Ok(())
            }
            Kind::Json(e) => e.feed(input, out),
            Kind::Proto(e) => e.feed(input, out),
            Kind::Envelope(e) => e.feed(input, out),
            Kind::Text(e) => e.feed(input, out),
            Kind::UrlEncoded(e) => e.feed(input, out),
            Kind::Multipart(e) => e.feed(input, out),
        }
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Kind::Empty => Ok(()),
            Kind::Json(e) => e.finish(out),
            Kind::Proto(e) => e.finish(out),
            Kind::Envelope(e) => e.finish(out),
            Kind::Text(e) => e.finish(out),
            Kind::UrlEncoded(e) => e.finish(out),
            Kind::Multipart(e) => e.finish(out),
        }
    }

    fn committed(&self, out_len: usize) -> usize {
        match self {
            Kind::Proto(e) => e.committed(out_len),
            Kind::Envelope(e) => e.committed(out_len),
            _ => out_len,
        }
    }

    fn shift(&mut self, k: usize) {
        match self {
            Kind::Proto(e) => e.shift(k),
            Kind::Envelope(e) => e.shift(k),
            _ => {}
        }
    }
}

/// Holds the first bytes until codec and framing are known, then delegates.
pub(crate) struct Auto {
    compiled: Compiled,
    hint: Hint,
    resize: bool,
    pending: Vec<u8>,
    inner: Option<Kind>,
}

impl Auto {
    pub(crate) fn new(compiled: Compiled, content_type: Option<&str>, resize: bool) -> Self {
        Auto {
            compiled,
            hint: Hint::from_content_type(content_type),
            resize,
            pending: Vec::new(),
            inner: None,
        }
    }

    pub(crate) fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        if let Some(k) = &mut self.inner {
            return k.feed(input, out);
        }
        let take = input.len().min(WINDOW - self.pending.len());
        self.pending.extend_from_slice(&input[..take]);
        match decide(&self.compiled, &self.hint, &self.pending, false) {
            None => Ok(()),
            Some(decision) => {
                let (codec, framing) = decision?;
                let k = self.start(codec, framing, out)?;
                k.feed(&input[take..], out)
            }
        }
    }

    pub(crate) fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.inner.is_none() {
            let (codec, framing) =
                decide(&self.compiled, &self.hint, &self.pending, true).expect("decided at eof")?;
            self.start(codec, framing, out)?;
        }
        self.inner.as_mut().expect("started").finish(out)
    }

    fn start(
        &mut self,
        codec: Option<Codec>,
        framing: Framing,
        out: &mut Vec<u8>,
    ) -> Result<&mut Kind, Error> {
        let pending = std::mem::take(&mut self.pending);
        let k = self
            .inner
            .insert(Kind::new(&self.compiled, codec, framing, self.resize));
        k.feed(&pending, out)?;
        Ok(k)
    }

    /// Length of the output prefix that will never be rewritten.
    pub(crate) fn committed(&self, out_len: usize) -> usize {
        self.inner
            .as_ref()
            .map_or(out_len, |k| k.committed(out_len))
    }

    /// `k` bytes were removed from the front of the output buffer.
    pub(crate) fn shift(&mut self, k: usize) {
        if let Some(inner) = &mut self.inner {
            inner.shift(k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_hints() {
        use Codec::*;
        use Framing::*;
        let h = |ct: &str| {
            let h = Hint::from_content_type(Some(ct));
            (h.codec, h.framing)
        };
        assert_eq!(
            h("application/json; charset=utf-8"),
            (Some(Json), Some(Plain))
        );
        assert_eq!(h("Application/Problem+JSON"), (Some(Json), Some(Plain)));
        assert_eq!(h("application/x-ndjson"), (Some(Json), Some(Plain)));
        assert_eq!(h("application/proto"), (Some(Proto), Some(Plain)));
        assert_eq!(h("application/grpc"), (None, Some(Envelope)));
        assert_eq!(h("application/grpc+proto"), (Some(Proto), Some(Envelope)));
        assert_eq!(h("application/grpc-web+json"), (Some(Json), Some(Envelope)));
        assert_eq!(h("application/grpc-web-text"), (None, Some(Text)));
        assert_eq!(
            h("application/grpc-web-text+proto"),
            (Some(Proto), Some(Text))
        );
        assert_eq!(h("application/connect+json"), (Some(Json), Some(Envelope)));
        assert_eq!(
            h("application/x-www-form-urlencoded"),
            (Some(Form), Some(UrlEncoded))
        );
        assert_eq!(
            h("multipart/form-data; boundary=\"ab c\""),
            (Some(Form), Some(Multipart(b"ab c".to_vec())))
        );
        assert_eq!(h("multipart/form-data"), (Some(Form), None));
        assert_eq!(h("text/plain"), (None, None));
        assert_eq!(Hint::from_content_type(None), Hint::default());
    }

    #[test]
    fn base64_frame_header() {
        assert!(looks_like_base64_frame(b"AAAAAAUK"));
        assert!(looks_like_base64_frame(b"gAAAAA=="));
        // Padding mid-stream: the server encoded the flags byte on its own.
        assert!(looks_like_base64_frame(b"AA==AAAA"));
        assert!(!looks_like_base64_frame(b"A=AAAAAA"));
        assert!(!looks_like_base64_frame(b"A\x01\x02\x03\x04\x05\x06\x07"));
    }
}
