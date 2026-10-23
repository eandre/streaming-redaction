//! Streaming JSON redaction.
//!
//! A byte-level tokenizer tracks the current position in the document and,
//! for each container on the stack, the set of rule states that are still
//! live below it (an NFA over path segments). When a value starts whose
//! path completes a rule, the replacement is written and the value's bytes
//! are consumed without being emitted. Everything else, including
//! whitespace, is copied through verbatim.
//!
//! In size-preserving mode the replacement is instead a string of `*` with
//! exactly the byte length of the original value, generated while the value
//! is consumed (with one byte held back, since the closing `"` can only be
//! written once the value is known to have ended).

mod path;

use std::sync::Arc;

pub use path::JsonPath;
use path::{Segment, Selector};

use crate::{Error, Options};

pub(crate) struct Compiled {
    rules: Vec<Vec<Segment>>,
    replacement: Box<[u8]>,
    /// Replace values with same-length `"****"` strings instead.
    preserve_size: bool,
    /// Accept a sequence of top-level values (NDJSON).
    multi: bool,
    /// Whether some rule is `$` (redact every top-level value).
    redact_root: bool,
    /// Initial live states: every non-empty rule at segment 0.
    root_states: Vec<St>,
    /// Longest member name in any rule. Keys longer than this can't match a
    /// name selector, so we stop decoding them.
    max_name: usize,
    max_depth: usize,
}

impl Compiled {
    pub(crate) fn new(
        paths: Vec<JsonPath>,
        opts: &Options,
        multi: bool,
        preserve_size: bool,
    ) -> Result<Self, Error> {
        let replacement = opts
            .json_replacement
            .trim()
            .as_bytes()
            .to_vec()
            .into_boxed_slice();
        validate_replacement(&replacement)?;

        let rules: Vec<Vec<Segment>> = paths.into_iter().map(|p| p.segments).collect();
        let redact_root = rules.iter().any(|r| r.is_empty());
        let root_states = (0..rules.len())
            .filter(|&r| !rules[r].is_empty())
            .map(|r| St {
                rule: r as u32,
                seg: 0,
            })
            .collect();
        let max_name = rules
            .iter()
            .flatten()
            .flat_map(|s| &s.selectors)
            .map(|s| match s {
                Selector::Name(n) => n.len(),
                _ => 0,
            })
            .max()
            .unwrap_or(0);
        Ok(Compiled {
            rules,
            replacement,
            preserve_size,
            multi,
            redact_root,
            root_states,
            max_name,
            max_depth: opts.max_depth,
        })
    }

    fn segment(&self, st: St) -> &Segment {
        &self.rules[st.rule as usize][st.seg as usize]
    }

    /// Advances `states` over one child edge. Returns true if a rule
    /// completes (the child must be redacted); otherwise fills `next` with
    /// the states live inside the child.
    fn step(&self, states: &[St], key: Key<'_>, next: &mut Vec<St>) -> bool {
        next.clear();
        for &st in states {
            let seg = self.segment(st);
            if seg.descendant {
                push_unique(next, st);
            }
            if seg.selectors.iter().any(|sel| key.matches(sel)) {
                if st.seg as usize + 1 == self.rules[st.rule as usize].len() {
                    return true;
                }
                push_unique(
                    next,
                    St {
                        rule: st.rule,
                        seg: st.seg + 1,
                    },
                );
            }
        }
        false
    }

    /// Whether any live state needs the decoded member name.
    fn needs_names(&self, states: &[St]) -> bool {
        states.iter().any(|&st| {
            self.segment(st)
                .selectors
                .iter()
                .any(|s| matches!(s, Selector::Name(_)))
        })
    }
}

fn validate_replacement(r: &[u8]) -> Result<(), Error> {
    let bad = |why: String| {
        Error::InvalidOptions(format!(
            "json_replacement is not a single JSON value: {why}"
        ))
    };
    if r.is_empty() {
        return Err(bad("empty".into()));
    }
    let plain = Compiled {
        rules: vec![],
        replacement: Box::new(*b"null"),
        preserve_size: false,
        multi: false,
        redact_root: false,
        root_states: vec![],
        max_name: 0,
        max_depth: 64,
    };
    let mut e = Engine::new(Arc::new(plain), false);
    let mut sink = Vec::new();
    e.feed(r, &mut sink)
        .and_then(|_| e.finish(&mut sink))
        .map_err(|err| bad(err.to_string()))
}

fn push_unique(v: &mut Vec<St>, st: St) {
    if !v.contains(&st) {
        v.push(st);
    }
}

/// A live rule state: `rule`'s segments before `seg` have matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct St {
    rule: u32,
    seg: u32,
}

#[derive(Clone, Copy)]
enum Key<'a> {
    /// Member name; `None` if not decoded (no name selector could match).
    Name(Option<&'a [u8]>),
    Index(u64),
}

impl Key<'_> {
    fn matches(self, sel: &Selector) -> bool {
        match (sel, self) {
            (Selector::Wildcard, _) => true,
            (Selector::Name(n), Key::Name(Some(k))) => **n == *k,
            (Selector::Index(i), Key::Index(k)) => *i == k,
            _ => false,
        }
    }
}

struct Frame {
    array: bool,
    /// Rule states live for this container's children. Empty means nothing
    /// below can be redacted, so no path tracking is done.
    states: Vec<St>,
    /// Decode member names (only for objects with name selectors live).
    names: bool,
    /// Index of the next array element.
    index: u64,
}

#[derive(Clone, Copy, Debug)]
enum Lex {
    /// Expecting a value (top level, after `:` or after `,` in an array).
    Value,
    /// After `[`: a value or `]`.
    ArrayStart,
    /// After `{`: a key or `}`.
    ObjectStart,
    /// After `,` in an object: a key.
    Key,
    /// After a key: `:`.
    Colon,
    /// After a value: `,`, a closing bracket, or end of a top-level value.
    AfterValue,
    /// Inside a string; `key` is true for member names.
    Str {
        key: bool,
        esc: Esc,
    },
    Number(Num),
    /// Inside `true`/`false`/`null`; the bytes still expected.
    Literal(&'static [u8]),
}

#[derive(Clone, Copy, Debug)]
enum Esc {
    None,
    /// After a backslash.
    Start,
    /// Inside `\uXXXX`, with `n` hex digits read so far.
    Unicode {
        n: u8,
        v: u16,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Num {
    Minus,
    Zero,
    Int,
    Dot,
    Frac,
    Exp,
    ExpSign,
    ExpDigits,
}

impl Num {
    fn accepting(self) -> bool {
        matches!(self, Num::Zero | Num::Int | Num::Frac | Num::ExpDigits)
    }
}

pub(crate) struct Engine {
    c: Arc<Compiled>,
    /// Same-length `"***"` replacements (see module docs).
    preserve_size: bool,
    lex: Lex,
    stack: Vec<Frame>,
    /// Stack depth at which the value currently being skipped started.
    /// While set, nothing is emitted and no paths are tracked.
    suppress: Option<usize>,
    /// Outcome for the value about to start (computed from its key).
    member_redact: bool,
    member_states: Vec<St>,
    /// Decoded member name (capped at `max_name + 1` bytes).
    key: Vec<u8>,
    capture_key: bool,
    /// Pending high surrogate from a `\uD8xx` escape in a key.
    high_surrogate: Option<u16>,
    /// Recycled state vectors, to avoid allocating per container.
    pool: Vec<Vec<St>>,
    /// Size-preserving mode: bytes of the current redacted value consumed.
    redacted_len: u64,
    offset: u64,
}

const WS: [bool; 256] = {
    let mut t = [false; 256];
    t[b' ' as usize] = true;
    t[b'\t' as usize] = true;
    t[b'\n' as usize] = true;
    t[b'\r' as usize] = true;
    t
};

impl Engine {
    /// `force_preserve_size` turns on size-preserving mode regardless of
    /// the options (needed inside fixed-length envelopes).
    pub(crate) fn new(c: Arc<Compiled>, force_preserve_size: bool) -> Self {
        Engine {
            preserve_size: force_preserve_size || c.preserve_size,
            c,
            lex: Lex::Value,
            stack: Vec::new(),
            suppress: None,
            member_redact: false,
            member_states: Vec::new(),
            key: Vec::new(),
            capture_key: false,
            high_surrogate: None,
            pool: Vec::new(),
            redacted_len: 0,
            offset: 0,
        }
    }

    /// Prepares for a new document, keeping allocations.
    pub(crate) fn reset(&mut self) {
        while let Some(mut f) = self.stack.pop() {
            f.states.clear();
            self.pool.push(f.states);
        }
        self.lex = Lex::Value;
        self.suppress = None;
        self.member_redact = false;
        self.member_states.clear();
        self.high_surrogate = None;
        self.redacted_len = 0;
        self.offset = 0;
    }

    /// Bytes consumed since the last reset.
    pub(crate) fn position(&self) -> u64 {
        self.offset
    }

    pub(crate) fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let mut i = 0;
        while i < input.len() {
            // Fast path: copy (or skip) runs of plain string content.
            if let Lex::Str {
                key,
                esc: Esc::None,
            } = self.lex
            {
                let rest = &input[i..];
                let n = rest
                    .iter()
                    .position(|&c| c == b'"' || c == b'\\' || c < 0x20)
                    .unwrap_or(rest.len());
                if n > 0 {
                    let run = &rest[..n];
                    self.emit_slice(run, out);
                    if key && self.capture_key {
                        self.flush_surrogate();
                        self.key_extend(run);
                    }
                    i += n;
                    self.offset += n as u64;
                    continue;
                }
            }
            if self.byte(input[i], out)? {
                i += 1;
                self.offset += 1;
            }
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), Error> {
        // A top-level number has no terminator other than end of input.
        if let Lex::Number(n) = self.lex
            && n.accepting()
            && self.stack.is_empty()
        {
            self.value_done(out);
        }
        match self.lex {
            Lex::Value | Lex::AfterValue if self.stack.is_empty() => Ok(()),
            _ => Err(Error::UnexpectedEof {
                offset: self.offset,
            }),
        }
    }

    fn malformed(&self, reason: &'static str) -> Error {
        Error::Malformed {
            offset: self.offset,
            reason,
        }
    }

    #[inline]
    fn emit(&mut self, b: u8, out: &mut Vec<u8>) {
        if self.suppress.is_none() {
            out.push(b);
        } else if self.preserve_size {
            self.pad(1, out);
        }
    }

    #[inline]
    fn emit_slice(&mut self, s: &[u8], out: &mut Vec<u8>) {
        if self.suppress.is_none() {
            out.extend_from_slice(s);
        } else if self.preserve_size {
            self.pad(s.len() as u64, out);
        }
    }

    /// Size-preserving mode: account for `n` more bytes of a redacted value.
    /// Output lags input by one byte: byte 1 is held back, byte 2 becomes
    /// the opening `"`, later bytes become `*`, and `value_done` writes the
    /// held byte as the closing `"` (or `0` for a one-byte value).
    fn pad(&mut self, n: u64, out: &mut Vec<u8>) {
        let before = self.redacted_len;
        self.redacted_len += n;
        if before < 2 && self.redacted_len >= 2 {
            out.push(b'"');
        }
        let stars = self.redacted_len.saturating_sub(2) - before.saturating_sub(2);
        out.resize(out.len() + stars as usize, b'*');
    }

    /// Processes one byte. Returns false if the byte terminated a number and
    /// must be processed again in the new state.
    fn byte(&mut self, b: u8, out: &mut Vec<u8>) -> Result<bool, Error> {
        match self.lex {
            Lex::Value => {
                if WS[b as usize] {
                    self.emit(b, out);
                } else {
                    self.start_value(b, out)?;
                }
            }
            Lex::ArrayStart => {
                if WS[b as usize] {
                    self.emit(b, out);
                } else if b == b']' {
                    self.emit(b, out);
                    self.close(out);
                } else {
                    self.start_value(b, out)?;
                }
            }
            Lex::ObjectStart | Lex::Key => {
                if WS[b as usize] {
                    self.emit(b, out);
                } else if b == b'"' {
                    self.emit(b, out);
                    self.start_key();
                } else if b == b'}' && matches!(self.lex, Lex::ObjectStart) {
                    self.emit(b, out);
                    self.close(out);
                } else {
                    return Err(self.malformed("expected object key"));
                }
            }
            Lex::Colon => {
                if WS[b as usize] {
                    self.emit(b, out);
                } else if b == b':' {
                    self.emit(b, out);
                    self.lex = Lex::Value;
                } else {
                    return Err(self.malformed("expected `:`"));
                }
            }
            Lex::AfterValue => {
                if WS[b as usize] {
                    self.emit(b, out);
                } else if let Some(top) = self.stack.last() {
                    match (b, top.array) {
                        (b',', true) => {
                            self.emit(b, out);
                            self.lex = Lex::Value;
                        }
                        (b',', false) => {
                            self.emit(b, out);
                            self.lex = Lex::Key;
                        }
                        (b']', true) | (b'}', false) => {
                            self.emit(b, out);
                            self.close(out);
                        }
                        _ => return Err(self.malformed("expected `,` or closing bracket")),
                    }
                } else if self.c.multi {
                    self.start_value(b, out)?;
                } else {
                    return Err(self.malformed("trailing data after JSON value"));
                }
            }
            Lex::Str { key, esc } => self.string_byte(b, key, esc, out)?,
            Lex::Number(n) => {
                let next = match (n, b) {
                    (Num::Minus, b'0') => Num::Zero,
                    (Num::Minus, b'1'..=b'9') => Num::Int,
                    (Num::Int, b'0'..=b'9') => Num::Int,
                    (Num::Zero | Num::Int, b'.') => Num::Dot,
                    (Num::Dot | Num::Frac, b'0'..=b'9') => Num::Frac,
                    (Num::Zero | Num::Int | Num::Frac, b'e' | b'E') => Num::Exp,
                    (Num::Exp, b'+' | b'-') => Num::ExpSign,
                    (Num::Exp | Num::ExpSign | Num::ExpDigits, b'0'..=b'9') => Num::ExpDigits,
                    (n, _) if n.accepting() => {
                        self.value_done(out);
                        return Ok(false);
                    }
                    _ => return Err(self.malformed("invalid number")),
                };
                self.emit(b, out);
                self.lex = Lex::Number(next);
            }
            Lex::Literal(rest) => {
                if b != rest[0] {
                    return Err(self.malformed("invalid literal"));
                }
                self.emit(b, out);
                if rest.len() == 1 {
                    self.value_done(out);
                } else {
                    self.lex = Lex::Literal(&rest[1..]);
                }
            }
        }
        Ok(true)
    }

    fn string_byte(&mut self, b: u8, key: bool, esc: Esc, out: &mut Vec<u8>) -> Result<(), Error> {
        let capture = key && self.capture_key;
        match esc {
            Esc::None => match b {
                b'"' => {
                    self.emit(b, out);
                    if key {
                        self.end_key();
                    } else {
                        self.value_done(out);
                    }
                }
                b'\\' => {
                    self.emit(b, out);
                    self.lex = Lex::Str {
                        key,
                        esc: Esc::Start,
                    };
                }
                // Plain bytes are handled by the fast path in `feed`.
                _ => return Err(self.malformed("control character in string")),
            },
            Esc::Start => {
                let decoded = match b {
                    b'"' | b'\\' | b'/' => b,
                    b'b' => 0x08,
                    b'f' => 0x0c,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'u' => {
                        self.emit(b, out);
                        self.lex = Lex::Str {
                            key,
                            esc: Esc::Unicode { n: 0, v: 0 },
                        };
                        return Ok(());
                    }
                    _ => return Err(self.malformed("invalid escape")),
                };
                self.emit(b, out);
                if capture {
                    self.flush_surrogate();
                    self.key_extend(&[decoded]);
                }
                self.lex = Lex::Str {
                    key,
                    esc: Esc::None,
                };
            }
            Esc::Unicode { n, v } => {
                let d = match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    b'A'..=b'F' => b - b'A' + 10,
                    _ => return Err(self.malformed("invalid \\u escape")),
                };
                self.emit(b, out);
                let v = (v << 4) | d as u16;
                if n == 3 {
                    if capture {
                        self.key_code_unit(v);
                    }
                    self.lex = Lex::Str {
                        key,
                        esc: Esc::None,
                    };
                } else {
                    self.lex = Lex::Str {
                        key,
                        esc: Esc::Unicode { n: n + 1, v },
                    };
                }
            }
        }
        Ok(())
    }

    fn start_key(&mut self) {
        self.key.clear();
        self.high_surrogate = None;
        self.capture_key = self.suppress.is_none() && self.stack.last().is_some_and(|f| f.names);
        self.lex = Lex::Str {
            key: true,
            esc: Esc::None,
        };
    }

    fn end_key(&mut self) {
        self.flush_surrogate();
        let top = self.stack.last().expect("key outside object");
        self.member_redact = false;
        self.member_states.clear();
        if self.suppress.is_none() && !top.states.is_empty() {
            let name =
                (self.capture_key && self.key.len() <= self.c.max_name).then_some(&self.key[..]);
            self.member_redact = self
                .c
                .step(&top.states, Key::Name(name), &mut self.member_states);
        }
        self.lex = Lex::Colon;
    }

    fn key_extend(&mut self, bytes: &[u8]) {
        // Keep one byte past the longest rule name so "too long" is
        // distinguishable from "exactly as long".
        let room = (self.c.max_name + 1).saturating_sub(self.key.len());
        self.key.extend_from_slice(&bytes[..bytes.len().min(room)]);
    }

    fn key_code_unit(&mut self, u: u16) {
        match u {
            0xD800..=0xDBFF => {
                self.flush_surrogate();
                self.high_surrogate = Some(u);
            }
            0xDC00..=0xDFFF => {
                let c = match self.high_surrogate.take() {
                    Some(hi) => char::from_u32(
                        0x10000 + (((hi as u32) - 0xD800) << 10) + ((u as u32) - 0xDC00),
                    ),
                    None => None,
                };
                self.push_char(c.unwrap_or(char::REPLACEMENT_CHARACTER));
            }
            _ => {
                self.flush_surrogate();
                self.push_char(char::from_u32(u as u32).unwrap_or(char::REPLACEMENT_CHARACTER));
            }
        }
    }

    fn flush_surrogate(&mut self) {
        if self.high_surrogate.take().is_some() {
            self.push_char(char::REPLACEMENT_CHARACTER);
        }
    }

    fn push_char(&mut self, c: char) {
        let mut buf = [0; 4];
        self.key_extend(c.encode_utf8(&mut buf).as_bytes());
    }

    fn take_vec(&mut self) -> Vec<St> {
        self.pool.pop().unwrap_or_default()
    }

    /// Handles the first byte of a value.
    fn start_value(&mut self, b: u8, out: &mut Vec<u8>) -> Result<(), Error> {
        // Work out whether this value is redacted and which rule states are
        // live inside it.
        let mut child = self.take_vec();
        let mut redact = false;
        if self.suppress.is_none() {
            match self.stack.last_mut() {
                None => {
                    redact = self.c.redact_root;
                    child.extend_from_slice(&self.c.root_states);
                }
                Some(top) if top.array => {
                    let idx = top.index;
                    top.index += 1;
                    if !top.states.is_empty() {
                        redact = self.c.step(&top.states, Key::Index(idx), &mut child);
                    }
                }
                Some(_) => {
                    redact = self.member_redact;
                    std::mem::swap(&mut child, &mut self.member_states);
                }
            }
        }
        if redact {
            if !self.preserve_size {
                out.extend_from_slice(&self.c.replacement);
            }
            self.redacted_len = 0;
            self.suppress = Some(self.stack.len());
            child.clear();
        }

        match b {
            b'{' | b'[' => {
                if self.stack.len() >= self.c.max_depth {
                    return Err(Error::DepthLimitExceeded {
                        offset: self.offset,
                        limit: self.c.max_depth,
                    });
                }
                self.emit(b, out);
                let array = b == b'[';
                let names = !array && !child.is_empty() && self.c.needs_names(&child);
                self.stack.push(Frame {
                    array,
                    states: child,
                    names,
                    index: 0,
                });
                self.lex = if array {
                    Lex::ArrayStart
                } else {
                    Lex::ObjectStart
                };
                return Ok(());
            }
            b'"' => {
                self.lex = Lex::Str {
                    key: false,
                    esc: Esc::None,
                }
            }
            b'-' => self.lex = Lex::Number(Num::Minus),
            b'0' => self.lex = Lex::Number(Num::Zero),
            b'1'..=b'9' => self.lex = Lex::Number(Num::Int),
            b't' => self.lex = Lex::Literal(b"rue"),
            b'f' => self.lex = Lex::Literal(b"alse"),
            b'n' => self.lex = Lex::Literal(b"ull"),
            _ => return Err(self.malformed("expected a JSON value")),
        }
        self.emit(b, out);
        child.clear();
        self.pool.push(child);
        Ok(())
    }

    /// Pops a container whose closing bracket was just consumed.
    fn close(&mut self, out: &mut Vec<u8>) {
        let mut frame = self.stack.pop().expect("close without open container");
        frame.states.clear();
        self.pool.push(frame.states);
        self.value_done(out);
    }

    fn value_done(&mut self, out: &mut Vec<u8>) {
        if self.suppress == Some(self.stack.len()) {
            self.suppress = None;
            if self.preserve_size {
                out.push(if self.redacted_len == 1 { b'0' } else { b'"' });
            }
        }
        self.lex = Lex::AfterValue;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(rules: &[&str], input: &str) -> Result<String, Error> {
        run_opts(rules, input, Options::default(), false)
    }

    fn run_opts(rules: &[&str], input: &str, opts: Options, multi: bool) -> Result<String, Error> {
        run_mode(rules, input, opts, multi, false)
    }

    fn run_mode(
        rules: &[&str],
        input: &str,
        opts: Options,
        multi: bool,
        preserve_size: bool,
    ) -> Result<String, Error> {
        let paths = rules.iter().map(|r| r.parse().unwrap()).collect();
        let c = Arc::new(Compiled::new(paths, &opts, multi, preserve_size)?);

        // Whole input at once.
        let mut e = Engine::new(c.clone(), false);
        let mut whole = Vec::new();
        let r1 = e
            .feed(input.as_bytes(), &mut whole)
            .and_then(|_| e.finish(&mut whole));

        // One byte at a time must give identical results.
        let mut e = Engine::new(c, false);
        let mut split = Vec::new();
        let r2 = input
            .as_bytes()
            .iter()
            .try_for_each(|b| e.feed(std::slice::from_ref(b), &mut split))
            .and_then(|_| e.finish(&mut split));
        assert_eq!(r1, r2);
        assert_eq!(whole, split);
        r1.map(|_| String::from_utf8(whole).unwrap())
    }

    const R: &str = r#""[REDACTED]""#;

    #[test]
    fn passthrough_preserves_formatting() {
        let doc = "{ \"a\" : [1, 2.5e-3 , -0, true,false,null],\n\t\"b\":{\"c\":\"x\\\"y\"} }";
        assert_eq!(run(&[], doc).unwrap(), doc);
        assert_eq!(run(&["$.zzz"], doc).unwrap(), doc);
    }

    #[test]
    fn redacts_members() {
        let doc = r#"{"user":{"name":"ann","password":"hunter2","age":3},"password":"top"}"#;
        assert_eq!(
            run(&["$.user.password"], doc).unwrap(),
            format!(r#"{{"user":{{"name":"ann","password":{R},"age":3}},"password":"top"}}"#)
        );
        assert_eq!(
            run(&["$..password"], doc).unwrap(),
            format!(r#"{{"user":{{"name":"ann","password":{R},"age":3}},"password":{R}}}"#)
        );
        assert_eq!(
            run(&["$.user"], doc).unwrap(),
            format!(r#"{{"user":{R},"password":"top"}}"#)
        );
        assert_eq!(run(&["$"], doc).unwrap(), R);
        assert_eq!(
            run(&["$.user.age"], doc).unwrap(),
            format!(
                r#"{{"user":{{"name":"ann","password":"hunter2","age":{R}}},"password":"top"}}"#
            )
        );
    }

    #[test]
    fn redacts_array_elements() {
        let doc = r#"[{"k":1,"v":[1,2]},{"k":2,"v":[3,4]},{"k":3}]"#;
        assert_eq!(
            run(&["$[1]"], doc).unwrap(),
            format!(r#"[{{"k":1,"v":[1,2]}},{R},{{"k":3}}]"#)
        );
        assert_eq!(
            run(&["$[*].v[0]"], doc).unwrap(),
            format!(r#"[{{"k":1,"v":[{R},2]}},{{"k":2,"v":[{R},4]}},{{"k":3}}]"#)
        );
        assert_eq!(
            run(&["$[0,2].k"], doc).unwrap(),
            format!(r#"[{{"k":{R},"v":[1,2]}},{{"k":2,"v":[3,4]}},{{"k":{R}}}]"#)
        );
        assert_eq!(
            run(&["$..[1]"], doc).unwrap(),
            format!(r#"[{{"k":1,"v":[1,{R}]}},{R},{{"k":3}}]"#)
        );
    }

    #[test]
    fn escaped_keys_still_match() {
        let doc = r#"{"pass\u0077ord":"x","\ud83d\ude00":"y","p\"q":"z"}"#;
        assert_eq!(
            run(&["$.password", "$['😀']", r#"$['p"q']"#], doc).unwrap(),
            format!(r#"{{"pass\u0077ord":{R},"\ud83d\ude00":{R},"p\"q":{R}}}"#)
        );
    }

    #[test]
    fn long_keys_do_not_match_prefix() {
        let doc = r#"{"abcdef":1,"abc":2}"#;
        assert_eq!(
            run(&["$.abc"], doc).unwrap(),
            format!(r#"{{"abcdef":1,"abc":{R}}}"#)
        );
    }

    #[test]
    fn numbers_at_boundaries() {
        assert_eq!(run(&["$"], "123").unwrap(), R);
        assert_eq!(
            run(&["$.a"], r#"{"a":-12.5E+3}"#).unwrap(),
            format!(r#"{{"a":{R}}}"#)
        );
        assert_eq!(run(&["$[0]"], "[0 ,1]").unwrap(), format!("[{R} ,1]"));
    }

    #[test]
    fn custom_replacement() {
        let opts = Options::default().json_replacement("null");
        assert_eq!(
            run_opts(&["$.a"], r#"{"a":{"b":1}}"#, opts, false).unwrap(),
            r#"{"a":null}"#
        );
        assert!(run_opts(&[], "1", Options::default().json_replacement("nope"), false).is_err());
        assert!(run_opts(&[], "1", Options::default().json_replacement("1 2"), false).is_err());
    }

    #[test]
    fn json_lines() {
        let doc = "{\"a\":1}\n{\"a\":2}\n3\n";
        assert_eq!(
            run_opts(&["$.a"], doc, Options::default(), true).unwrap(),
            format!("{{\"a\":{R}}}\n{{\"a\":{R}}}\n3\n")
        );
        assert!(run(&["$.a"], doc).is_err());
    }

    #[test]
    fn malformed() {
        for bad in [
            "{",
            "[1,]",
            "{\"a\" 1}",
            "{\"a\":1,}",
            "[1 2]",
            "tru",
            "nul",
            "01",
            "1.",
            "-",
            "\"abc",
            "\"a\nb\"",
            "\"\\x\"",
            "{1:2}",
            "[}",
            "{]",
            "1 2",
            "\"\\u12g4\"",
        ] {
            assert!(run(&["$..x"], bad).is_err(), "{bad:?} should be rejected");
        }
        assert_eq!(run(&[], "").unwrap(), "");
        assert_eq!(run(&[], " \n").unwrap(), " \n");
    }

    #[test]
    fn depth_limit() {
        let opts = Options::default().max_depth(3);
        assert!(run_opts(&[], "[[[1]]]", opts.clone(), false).is_ok());
        assert!(matches!(
            run_opts(&[], "[[[[1]]]]", opts, false),
            Err(Error::DepthLimitExceeded { .. })
        ));
    }

    fn run_sized(rules: &[&str], input: &str) -> String {
        let out = run_mode(rules, input, Options::default(), true, true).unwrap();
        assert_eq!(out.len(), input.len(), "size must be preserved: {out}");
        out
    }

    #[test]
    fn size_preserving() {
        assert_eq!(
            run_sized(
                &["$.pw", "$.n", "$.o"],
                r#"{"pw":"hunter2","n":7,"o":{"a": [1, 2]},"k":1}"#
            ),
            r#"{"pw":"*******","n":0,"o":"***********","k":1}"#
        );
        assert_eq!(
            run_sized(&["$[*]"], r#"[1,22,333,true,null,"",[]]"#),
            r#"[0,"","*","**","**","",""]"#
        );
        // Top-level values, including numbers terminated only by EOF.
        assert_eq!(run_sized(&["$"], "12345"), r#""***""#);
        assert_eq!(run_sized(&["$"], "5\n{\"a\":1}\n"), "0\n\"*****\"\n");
        // Multi-byte UTF-8 is replaced byte-for-byte with ASCII.
        assert_eq!(run_sized(&["$.s"], r#"{"s":"é😀"}"#), r#"{"s":"******"}"#);
    }
}
