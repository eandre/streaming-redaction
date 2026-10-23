//! Streaming redaction of HTML form bodies: `application/x-www-form-urlencoded`
//! and `multipart/form-data`. Rules are field names.
//!
//! Neither format has length prefixes, so redacted values are simply
//! replaced (the output may change size) and nothing is ever patched.

use std::sync::Arc;

use crate::{Error, Options};

pub(crate) struct Compiled {
    names: Vec<Box<[u8]>>,
    /// Longest rule name. Longer keys can't match, so we stop decoding them.
    max_name: usize,
    /// Replacement for urlencoded values, already percent-encoded.
    url_replacement: Box<[u8]>,
    /// Replacement for multipart part bodies.
    raw_replacement: Box<[u8]>,
    max_header_bytes: usize,
}

impl Compiled {
    pub(crate) fn new(names: Vec<String>, opts: &Options) -> Result<Self, Error> {
        if let Some(bad) = names.iter().find(|n| n.is_empty()) {
            return Err(Error::InvalidRule {
                rule: bad.clone(),
                reason: "form field name must not be empty".into(),
            });
        }
        let names: Vec<Box<[u8]>> = names.into_iter().map(|n| n.into_bytes().into()).collect();
        let max_name = names.iter().map(|n| n.len()).max().unwrap_or(0);
        let raw = opts.form_replacement.as_bytes();
        Ok(Compiled {
            names,
            max_name,
            url_replacement: url_encode(raw).into(),
            raw_replacement: raw.into(),
            max_header_bytes: 16 * 1024,
        })
    }

    fn matches(&self, name: &[u8]) -> bool {
        self.names.iter().any(|n| **n == *name)
    }
}

/// Whether `window` looks like a standard urlencoded body. Stricter than the
/// parser: only characters that form serializers leave unescaped
/// (WHATWG, `encodeURIComponent`) are allowed. Used to tell forms apart from
/// JSON (`{"a":1}` is lenient-valid as a lone form key) when there's no
/// content type.
pub(crate) fn plausible_urlencoded(window: &[u8]) -> bool {
    window.iter().all(|&b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_'
                    | b'.'
                    | b'!'
                    | b'~'
                    | b'*'
                    | b'\''
                    | b'('
                    | b')'
                    | b'+'
                    | b'%'
                    | b'='
                    | b'&'
            )
    })
}

/// `application/x-www-form-urlencoded` byte serializer (WHATWG URL spec).
fn url_encode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in s {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => out.push(b),
            b' ' => out.push(b'+'),
            _ => out.extend_from_slice(format!("%{b:02X}").as_bytes()),
        }
    }
    out
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// `key=value&key=value`. Keys are percent-decoded for matching, following
/// the WHATWG rules (`+` is a space, malformed `%` escapes are literal).
pub(crate) struct UrlEncoded {
    c: Arc<Compiled>,
    in_value: bool,
    redact: bool,
    /// Decoded key, capped at `max_name + 1` bytes.
    key: Vec<u8>,
    /// Percent-escape progress: 0 = none, 1 = after `%`, 2 = after `%X`.
    pct: u8,
    hi: u8,
    offset: u64,
}

impl UrlEncoded {
    pub(crate) fn new(c: Arc<Compiled>) -> Self {
        UrlEncoded {
            c,
            in_value: false,
            redact: false,
            key: Vec::new(),
            pct: 0,
            hi: 0,
            offset: 0,
        }
    }

    pub(crate) fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        for &b in input {
            // Spaces are always encoded as `+`, and line breaks can't occur.
            // Rejecting them also stops a multipart body with a preamble
            // from being misread as urlencoded and passed through.
            if b < 0x21 || b == 0x7f {
                return Err(Error::Malformed {
                    offset: self.offset,
                    reason: "whitespace or control character in urlencoded form",
                });
            }
            self.offset += 1;
            if self.in_value {
                if b == b'&' {
                    out.push(b);
                    self.start_key();
                } else if !self.redact {
                    out.push(b);
                }
                continue;
            }
            out.push(b);
            match b {
                b'&' => self.start_key(),
                b'=' => {
                    self.flush_pct();
                    self.in_value = true;
                    self.redact = self.c.matches(&self.key);
                    if self.redact {
                        out.extend_from_slice(&self.c.url_replacement);
                    }
                }
                _ => self.key_byte(b),
            }
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), Error> {
        Ok(())
    }

    fn start_key(&mut self) {
        self.key.clear();
        self.pct = 0;
        self.in_value = false;
        self.redact = false;
    }

    fn key_byte(&mut self, b: u8) {
        match self.pct {
            0 if b == b'%' => self.pct = 1,
            0 => self.push(if b == b'+' { b' ' } else { b }),
            1 if hex(b).is_some() => {
                self.hi = b;
                self.pct = 2;
            }
            2 if hex(b).is_some() => {
                self.push(hex(self.hi).unwrap() << 4 | hex(b).unwrap());
                self.pct = 0;
            }
            _ => {
                // Not a valid escape: the `%` (and first digit) are literal.
                self.flush_pct();
                self.key_byte(b);
            }
        }
    }

    fn flush_pct(&mut self) {
        match std::mem::take(&mut self.pct) {
            1 => self.push(b'%'),
            2 => {
                self.push(b'%');
                self.push(self.hi);
            }
            _ => {}
        }
    }

    fn push(&mut self, b: u8) {
        if self.key.len() <= self.c.max_name {
            self.key.push(b);
        }
    }
}

/// `multipart/form-data`. Each part's headers are copied through; the body
/// of a part whose `Content-Disposition` name matches a rule is replaced.
pub(crate) struct Multipart {
    c: Arc<Compiled>,
    /// `\r\n--boundary`: what ends every part body.
    delim: Box<[u8]>,
    /// KMP failure function for `delim`.
    fail: Box<[usize]>,
    state: MState,
    /// Bytes of `delim` matched so far. While matching, those bytes are held
    /// back: they may be the delimiter rather than body content.
    matched: usize,
    /// How many bytes at the front of the current partial match are the
    /// virtual CRLF before the opening delimiter (not real input).
    virtual_crlf: usize,
    redact: bool,
    headers: Vec<u8>,
    offset: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MState {
    Body,
    /// After a delimiter: `--` (end) or optional padding then CRLF.
    AfterDelim,
    AfterDash,
    AfterCr,
    Headers,
    Epilogue,
}

impl Multipart {
    pub(crate) fn new(c: Arc<Compiled>, boundary: &[u8]) -> Self {
        let mut delim = b"\r\n--".to_vec();
        delim.extend_from_slice(boundary);
        let fail = kmp_failure(&delim);
        Multipart {
            c,
            delim: delim.into(),
            fail: fail.into(),
            state: MState::Body,
            // Treat the body as if it started with CRLF, so the opening
            // `--boundary` matches like any other delimiter. Anything before
            // it is a preamble and is copied through.
            matched: 2,
            virtual_crlf: 2,
            redact: false,
            headers: Vec::new(),
            offset: 0,
        }
    }

    fn malformed(&self, reason: &'static str) -> Error {
        Error::Malformed {
            offset: self.offset,
            reason,
        }
    }

    pub(crate) fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let mut i = 0;
        while i < input.len() {
            let b = input[i];
            match self.state {
                MState::Body => {
                    // Fast path: runs that can't start a delimiter.
                    if self.matched == 0 {
                        let rest = &input[i..];
                        let n = rest.iter().position(|&c| c == b'\r').unwrap_or(rest.len());
                        if n > 0 {
                            if !self.redact {
                                out.extend_from_slice(&rest[..n]);
                            }
                            i += n;
                            self.offset += n as u64;
                            continue;
                        }
                    }
                    self.body_byte(b, out)?;
                }
                MState::AfterDelim => {
                    out.push(b);
                    self.state = match b {
                        b'-' => MState::AfterDash,
                        b' ' | b'\t' => MState::AfterDelim,
                        b'\r' => MState::AfterCr,
                        _ => return Err(self.malformed("invalid multipart boundary line")),
                    };
                }
                MState::AfterDash => {
                    out.push(b);
                    if b != b'-' {
                        return Err(self.malformed("invalid multipart boundary line"));
                    }
                    self.state = MState::Epilogue;
                }
                MState::AfterCr => {
                    out.push(b);
                    if b != b'\n' {
                        return Err(self.malformed("invalid multipart boundary line"));
                    }
                    self.headers.clear();
                    self.state = MState::Headers;
                }
                MState::Headers => {
                    out.push(b);
                    self.headers.push(b);
                    if self.headers.len() > self.c.max_header_bytes {
                        return Err(self.malformed("multipart part headers too large"));
                    }
                    if self.headers == b"\r\n" || self.headers.ends_with(b"\r\n\r\n") {
                        self.redact = part_name(&self.headers).is_some_and(|n| self.c.matches(&n));
                        if self.redact {
                            out.extend_from_slice(&self.c.raw_replacement);
                        }
                        self.matched = 0;
                        self.state = MState::Body;
                    }
                }
                MState::Epilogue => {
                    out.extend_from_slice(&input[i..]);
                    self.offset += (input.len() - i) as u64;
                    return Ok(());
                }
            }
            i += 1;
            self.offset += 1;
        }
        Ok(())
    }

    fn body_byte(&mut self, b: u8, out: &mut Vec<u8>) -> Result<(), Error> {
        loop {
            if self.delim[self.matched] == b {
                self.matched += 1;
                break;
            }
            if self.matched == 0 {
                if !self.redact {
                    out.push(b);
                }
                break;
            }
            // The held bytes up to the longest delimiter prefix that is
            // still a candidate are body content after all.
            let k = self.fail[self.matched - 1];
            let n = self.matched - k;
            let v = self.virtual_crlf.min(n);
            if !self.redact {
                out.extend_from_slice(&self.delim[v..n]);
            }
            self.virtual_crlf -= v;
            self.matched = k;
        }
        if self.matched == self.delim.len() {
            out.extend_from_slice(&self.delim[self.virtual_crlf..]);
            self.virtual_crlf = 0;
            self.matched = 0;
            self.redact = false;
            self.state = MState::AfterDelim;
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), Error> {
        if self.state == MState::Epilogue {
            Ok(())
        } else {
            Err(Error::UnexpectedEof {
                offset: self.offset,
            })
        }
    }
}

fn kmp_failure(p: &[u8]) -> Vec<usize> {
    let mut f = vec![0; p.len()];
    let mut k = 0;
    for i in 1..p.len() {
        while k > 0 && p[i] != p[k] {
            k = f[k - 1];
        }
        if p[i] == p[k] {
            k += 1;
        }
        f[i] = k;
    }
    f
}

/// The `name` parameter of a part's `Content-Disposition` header.
fn part_name(headers: &[u8]) -> Option<Vec<u8>> {
    const CD: &[u8] = b"content-disposition:";
    let line = headers
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .find(|l| l.len() >= CD.len() && l[..CD.len()].eq_ignore_ascii_case(CD))?;
    let mut rest = &line[CD.len()..];
    // Skip the disposition type, then walk `; key=value` parameters.
    loop {
        let semi = rest.iter().position(|&b| b == b';')?;
        rest = trim_start(&rest[semi + 1..]);
        let eq = rest.iter().position(|&b| b == b'=')?;
        let key = trim_end(&rest[..eq]);
        rest = trim_start(&rest[eq + 1..]);
        let value;
        if rest.first() == Some(&b'"') {
            let mut v = Vec::new();
            let mut i = 1;
            while i < rest.len() && rest[i] != b'"' {
                if rest[i] == b'\\' && i + 1 < rest.len() {
                    i += 1;
                }
                v.push(rest[i]);
                i += 1;
            }
            value = v;
            rest = rest.get(i + 1..).unwrap_or(&[]);
        } else {
            let end = rest.iter().position(|&b| b == b';').unwrap_or(rest.len());
            value = trim_end(&rest[..end]).to_vec();
            rest = &rest[end..];
        }
        if key.eq_ignore_ascii_case(b"name") {
            return Some(value);
        }
    }
}

fn trim_start(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|b| matches!(b, b' ' | b'\t')).count();
    &s[n..]
}

fn trim_end(s: &[u8]) -> &[u8] {
    let n = s
        .iter()
        .rev()
        .take_while(|b| matches!(b, b' ' | b'\t'))
        .count();
    &s[..s.len() - n]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compiled(names: &[&str]) -> Arc<Compiled> {
        Arc::new(
            Compiled::new(
                names.iter().map(|s| s.to_string()).collect(),
                &Options::default(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn content_disposition_names() {
        let h = |s: &str| part_name(s.as_bytes()).map(|v| String::from_utf8(v).unwrap());
        assert_eq!(
            h("Content-Disposition: form-data; name=\"pw\"\r\n\r\n").as_deref(),
            Some("pw")
        );
        assert_eq!(
            h("content-type: text/plain\r\nCONTENT-DISPOSITION: form-data; filename=\"a\"; name=x\r\n\r\n").as_deref(),
            Some("x")
        );
        assert_eq!(
            h("Content-Disposition: form-data; name=\"a\\\"b\"\r\n\r\n").as_deref(),
            Some("a\"b")
        );
        assert_eq!(
            h("Content-Disposition: form-data; filename=\"name\"\r\n\r\n"),
            None
        );
        assert_eq!(h("\r\n"), None);
    }

    #[test]
    fn kmp() {
        assert_eq!(kmp_failure(b"\r\n--\r\n--x"), [0, 0, 0, 0, 1, 2, 3, 4, 0]);
    }

    #[test]
    fn urlencoded_keys_are_decoded() {
        let c = compiled(&["password", "a b"]);
        let mut e = UrlEncoded::new(c);
        let mut out = Vec::new();
        e.feed(b"pass%77ord=x&a+b=y&a%2=z&password", &mut out)
            .unwrap();
        assert_eq!(
            out,
            b"pass%77ord=%5BREDACTED%5D&a+b=%5BREDACTED%5D&a%2=z&password"
        );
    }
}
