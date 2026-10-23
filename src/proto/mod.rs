//! Streaming protobuf redaction.
//!
//! Protobuf length-prefixes nested messages, so dropping or shrinking a
//! field would change the length of every enclosing message, which has
//! already been written by the time we see the field. Instead redaction
//! preserves the encoded size of every field:
//!
//! * varint fields become `0`, encoded non-minimally in the original
//!   number of bytes (`0x80 0x80 .. 0x00`), which decoders accept;
//! * fixed32/fixed64 fields become all-zero bytes;
//! * length-delimited fields keep their length and get their payload
//!   overwritten (see [`ProtoFill`]);
//! * groups have every field inside them redacted recursively.
//!
//! As a result the output is exactly as long as the input and every length
//! prefix can be copied through unchanged.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use crate::{Error, Options};

/// Highest valid protobuf field number.
const MAX_FIELD: u32 = (1 << 29) - 1;

/// A field mask path made of field numbers, e.g. `1.3.2`.
///
/// Every component but the last must be a message (or group) field; the
/// last component is the field that gets redacted. Repeated fields match
/// every element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldPath(Vec<u32>);

impl FieldPath {
    /// Creates a path from field numbers. Fails if empty or if a number is
    /// outside `1..=536870911`.
    pub fn new(fields: impl Into<Vec<u32>>) -> Result<Self, Error> {
        let fields = fields.into();
        let path = FieldPath(fields);
        if path.0.is_empty() {
            return Err(path.invalid("empty field path"));
        }
        if let Some(f) = path.0.iter().find(|&&f| f == 0 || f > MAX_FIELD) {
            return Err(path.invalid(&format!("field number {f} is out of range")));
        }
        Ok(path)
    }

    /// The field numbers in this path.
    pub fn fields(&self) -> &[u32] {
        &self.0
    }

    fn invalid(&self, reason: &str) -> Error {
        Error::InvalidRule {
            rule: self.to_string(),
            reason: reason.to_owned(),
        }
    }
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, n) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{n}")?;
        }
        Ok(())
    }
}

impl FromStr for FieldPath {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let invalid = |reason: String| Error::InvalidRule {
            rule: s.to_owned(),
            reason,
        };
        let fields = s
            .trim()
            .split('.')
            .map(|c| {
                let c = c.trim();
                if c.is_empty() || !c.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid(format!("expected a field number, got {c:?}")));
                }
                c.parse::<u32>()
                    .map_err(|_| invalid(format!("field number {c} is out of range")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        FieldPath::new(fields).map_err(|_| invalid("field numbers must be in 1..=536870911".into()))
    }
}

/// How the payload of a redacted length-delimited field is overwritten.
///
/// On the wire, strings, bytes, sub-messages and packed repeated scalars all
/// look the same, and the redactor has no schema to tell them apart.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtoFill {
    /// Fill with bytes that are simultaneously valid UTF-8 and a valid
    /// protobuf message containing only unknown fields with number 19000
    /// (in the range reserved by protobuf, so it never clashes with a real
    /// field). The result decodes cleanly whether the field is a `string`,
    /// `bytes` or a sub-message. Payloads of 1–3 bytes are zero-filled,
    /// since no message encoding is that short.
    #[default]
    ReservedField,
    /// Fill with zero bytes. Decodes as a string or bytes of NULs or a
    /// packed repeated field of zeros, but is invalid as a sub-message.
    Zeros,
}

/// Rule trie over field numbers.
pub(crate) struct Compiled {
    nodes: Vec<Node>,
    fill: ProtoFill,
    max_depth: usize,
}

#[derive(Default)]
struct Node {
    /// Sorted by field number.
    children: Vec<(u32, u32)>,
    /// A rule ends here: redact this field entirely.
    leaf: bool,
}

const ROOT: u32 = 0;

impl Compiled {
    pub(crate) fn new(paths: Vec<FieldPath>, opts: &Options) -> Self {
        let mut nodes = vec![Node::default()];
        for path in paths {
            let mut cur = ROOT as usize;
            for &f in &path.0 {
                cur = match nodes[cur].children.binary_search_by_key(&f, |&(k, _)| k) {
                    Ok(i) => nodes[cur].children[i].1 as usize,
                    Err(i) => {
                        let id = nodes.len();
                        nodes.push(Node::default());
                        nodes[cur].children.insert(i, (f, id as u32));
                        id
                    }
                };
            }
            nodes[cur].leaf = true;
        }
        Compiled {
            nodes,
            fill: opts.proto_fill,
            max_depth: opts.max_depth,
        }
    }

    fn child(&self, node: u32, field: u32) -> Option<u32> {
        let n = &self.nodes[node as usize];
        n.children
            .binary_search_by_key(&field, |&(k, _)| k)
            .ok()
            .map(|i| n.children[i].1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Pass,
    Redact,
    /// Parse the payload as a message and continue matching at this node.
    Descend(u32),
}

#[derive(Debug)]
struct Frame {
    /// Trie node for fields of this message; `None` if nothing below matches.
    node: Option<u32>,
    end: End,
    /// Stream mode, inside a redacted group: redact every field.
    redact_all: bool,
    /// Absolute offset that no byte in this frame may reach: the end of the
    /// innermost enclosing length-delimited message.
    limit: u64,
    /// Resize mode: where this sub-message's length prefix sits in the
    /// output, so it can be rewritten once the sub-message ends.
    patch: Option<Patch>,
}

#[derive(Debug, Clone, Copy)]
struct Patch {
    prefix_pos: usize,
    width: u8,
    body_start: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    Eof,
    At(u64),
    Group(u32),
}

#[derive(Debug)]
enum State {
    Tag { acc: u64, n: u8 },
    Varint { redact: bool, n: u8 },
    Fixed { left: u8, redact: bool },
    LenPrefix { acc: u64, n: u8, action: Action },
    Payload { left: u64, mode: Payload },
}

#[derive(Debug)]
enum Payload {
    Pass,
    Fill(Filler),
    Skip,
}

const TAG_START: State = State::Tag { acc: 0, n: 0 };

/// Protobuf redaction state machine.
///
/// In stream mode (`resize == false`) redacted fields are overwritten in
/// place, keeping every size intact, and output never needs revisiting.
///
/// In resize mode redacted fields are removed entirely. The length prefixes
/// of sub-messages we descend into are rewritten when those sub-messages
/// end, so the output buffer must not be drained past [`Engine::committed`].
pub(crate) struct Engine {
    c: Arc<Compiled>,
    stack: Vec<Frame>,
    state: State,
    pos: u64,
    resize: bool,
    /// Resize mode: tag or length varint bytes, held until we know whether
    /// the field is kept.
    held: [u8; 10],
    /// Resize mode: stack depth of a removed group whose contents are being
    /// skipped.
    skip: Option<usize>,
}

impl Engine {
    pub(crate) fn new(c: Arc<Compiled>, resize: bool) -> Self {
        let mut e = Engine {
            c,
            stack: Vec::new(),
            state: TAG_START,
            pos: 0,
            resize,
            held: [0; 10],
            skip: None,
        };
        e.reset();
        e
    }

    /// Prepares for a new message, keeping allocations.
    pub(crate) fn reset(&mut self) {
        self.stack.clear();
        self.stack.push(Frame {
            node: Some(ROOT),
            end: End::Eof,
            redact_all: false,
            limit: u64::MAX,
            patch: None,
        });
        self.state = TAG_START;
        self.pos = 0;
        self.skip = None;
    }

    /// Bytes consumed since the last reset.
    pub(crate) fn position(&self) -> u64 {
        self.pos
    }

    /// Length of the output prefix that is final. Everything after it may
    /// still be rewritten (resize mode only).
    pub(crate) fn committed(&self, out_len: usize) -> usize {
        self.stack
            .iter()
            .find_map(|f| f.patch.map(|p| p.prefix_pos))
            .unwrap_or(out_len)
    }

    /// The caller removed `k` bytes from the front of the output buffer.
    pub(crate) fn shift(&mut self, k: usize) {
        for f in &mut self.stack {
            if let Some(p) = &mut f.patch {
                p.prefix_pos -= k;
                p.body_start -= k;
            }
        }
    }

    fn malformed(&self, reason: &'static str) -> Error {
        Error::Malformed {
            offset: self.pos,
            reason,
        }
    }

    pub(crate) fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), Error> {
        let at_boundary = matches!(self.state, State::Tag { n: 0, .. });
        if at_boundary && self.stack.len() == 1 {
            Ok(())
        } else {
            Err(Error::UnexpectedEof { offset: self.pos })
        }
    }

    pub(crate) fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let mut i = 0;
        while i < input.len() {
            let limit = self.stack.last().expect("root frame").limit;
            if self.pos >= limit {
                return Err(self.malformed(if matches!(self.top().end, End::Group(_)) {
                    "group not terminated before end of enclosing message"
                } else {
                    "field extends past end of enclosing message"
                }));
            }

            // Bulk path for length-delimited payloads.
            if let State::Payload { left, mode } = &mut self.state {
                let n = (*left).min((input.len() - i) as u64) as usize;
                match mode {
                    Payload::Pass if self.skip.is_none() => out.extend_from_slice(&input[i..i + n]),
                    Payload::Pass | Payload::Skip => {}
                    Payload::Fill(f) => f.fill(n, out),
                }
                *left -= n as u64;
                i += n;
                self.pos += n as u64;
                if *left == 0 {
                    self.value_done(out);
                }
                continue;
            }

            let b = input[i];
            i += 1;
            self.pos += 1;
            self.byte(b, out)?;
        }
        Ok(())
    }

    fn top(&self) -> &Frame {
        self.stack.last().expect("root frame")
    }

    #[inline]
    fn emit(&self, b: u8, out: &mut Vec<u8>) {
        if self.skip.is_none() {
            out.push(b);
        }
    }

    fn byte(&mut self, b: u8, out: &mut Vec<u8>) -> Result<(), Error> {
        match self.state {
            State::Tag { acc, n } => {
                if self.resize {
                    self.held[n as usize] = b;
                } else {
                    out.push(b);
                }
                let acc = acc | (((b & 0x7f) as u64) << (7 * n));
                if b & 0x80 != 0 {
                    if n >= 4 {
                        return Err(self.malformed("tag varint too long"));
                    }
                    self.state = State::Tag { acc, n: n + 1 };
                    return Ok(());
                }
                if acc > u32::MAX as u64 {
                    return Err(self.malformed("tag out of range"));
                }
                self.tag(acc as u32, n as usize + 1, out)?;
            }
            State::Varint { redact, n } => {
                match (redact, self.resize) {
                    (false, _) => self.emit(b, out),
                    (true, false) => out.push(b & 0x80),
                    (true, true) => {}
                }
                if b & 0x80 == 0 {
                    self.value_done(out);
                } else if n >= 9 {
                    return Err(self.malformed("varint too long"));
                } else {
                    self.state = State::Varint { redact, n: n + 1 };
                }
            }
            State::Fixed { left, redact } => {
                match (redact, self.resize) {
                    (false, _) => self.emit(b, out),
                    (true, false) => out.push(0),
                    (true, true) => {}
                }
                if left == 1 {
                    self.value_done(out);
                } else {
                    self.state = State::Fixed {
                        left: left - 1,
                        redact,
                    };
                }
            }
            State::LenPrefix { acc, n, action } => {
                if self.resize {
                    self.held[n as usize] = b;
                } else {
                    out.push(b);
                }
                let acc = acc | (((b & 0x7f) as u64) << (7 * n));
                if b & 0x80 != 0 {
                    if n >= 9 {
                        return Err(self.malformed("length varint too long"));
                    }
                    self.state = State::LenPrefix {
                        acc,
                        n: n + 1,
                        action,
                    };
                    return Ok(());
                }
                self.len_prefix(acc, n as usize + 1, action, out)?;
            }
            State::Payload { .. } => unreachable!("handled in feed"),
        }
        Ok(())
    }

    /// Handles a complete tag (`width` bytes, held in `self.held` in resize mode).
    fn tag(&mut self, tag: u32, width: usize, out: &mut Vec<u8>) -> Result<(), Error> {
        let field = tag >> 3;
        let wire = tag & 7;
        if field == 0 {
            return Err(self.malformed("field number 0"));
        }
        let top = self.top();
        let limit = top.limit;
        let action = if top.redact_all {
            Action::Redact
        } else {
            match top.node.and_then(|n| self.c.child(n, field)) {
                Some(n) if self.c.nodes[n as usize].leaf => Action::Redact,
                Some(n) => Action::Descend(n),
                None => Action::Pass,
            }
        };
        let redact = action == Action::Redact;

        if wire == 4 {
            if top.end != End::Group(field) {
                return Err(self.malformed("unmatched end-group tag"));
            }
            // Emitted only if the matching start-group tag was.
            if self.resize && self.skip.is_none() {
                out.extend_from_slice(&self.held[..width]);
            }
            self.stack.pop();
            if self.skip == Some(self.stack.len()) {
                self.skip = None;
            }
            // The group as a whole is a completed value in its parent.
            self.value_done(out);
            return Ok(());
        }

        // Resize mode: the tag is written only if the field is kept.
        if self.resize && !redact {
            let held = self.held;
            for &b in &held[..width] {
                self.emit(b, out);
            }
        }
        self.state = match wire {
            0 => State::Varint { redact, n: 0 },
            1 => State::Fixed { left: 8, redact },
            5 => State::Fixed { left: 4, redact },
            2 => State::LenPrefix {
                acc: 0,
                n: 0,
                action,
            },
            3 => {
                let node = match action {
                    Action::Descend(n) => Some(n),
                    _ => None,
                };
                let remove = self.resize && redact;
                if remove && self.skip.is_none() {
                    self.skip = Some(self.stack.len());
                }
                self.push(Frame {
                    node,
                    end: End::Group(field),
                    redact_all: redact && !remove,
                    limit,
                    patch: None,
                })?;
                TAG_START
            }
            _ => return Err(self.malformed("invalid wire type")),
        };
        Ok(())
    }

    /// Handles a complete length prefix (`width` bytes, held in
    /// `self.held` in resize mode).
    fn len_prefix(
        &mut self,
        len: u64,
        width: usize,
        action: Action,
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let limit = self.top().limit;
        let end = self.pos.checked_add(len).filter(|&e| e <= limit);
        let Some(end) = end else {
            return Err(self.malformed("length exceeds enclosing message"));
        };
        let held = self.held;
        match action {
            Action::Descend(node) => {
                // Never inside a removed group: those have no trie node.
                let patch = self.resize.then(|| {
                    let prefix_pos = out.len();
                    out.extend_from_slice(&held[..width]);
                    Patch {
                        prefix_pos,
                        width: width as u8,
                        body_start: out.len(),
                    }
                });
                self.push(Frame {
                    node: Some(node),
                    end: End::At(end),
                    redact_all: false,
                    limit: end,
                    patch,
                })?;
                self.state = TAG_START;
                self.pop_finished(out);
            }
            Action::Pass => {
                if self.resize {
                    for &b in &held[..width] {
                        self.emit(b, out);
                    }
                }
                if len == 0 {
                    self.value_done(out);
                } else {
                    self.state = State::Payload {
                        left: len,
                        mode: Payload::Pass,
                    };
                }
            }
            Action::Redact => {
                if len == 0 {
                    self.value_done(out);
                } else {
                    let mode = if self.resize {
                        Payload::Skip
                    } else {
                        Payload::Fill(Filler::new(self.c.fill, len))
                    };
                    self.state = State::Payload { left: len, mode };
                }
            }
        }
        Ok(())
    }

    fn push(&mut self, frame: Frame) -> Result<(), Error> {
        if self.stack.len() > self.c.max_depth {
            return Err(Error::DepthLimitExceeded {
                offset: self.pos,
                limit: self.c.max_depth,
            });
        }
        self.stack.push(frame);
        Ok(())
    }

    fn value_done(&mut self, out: &mut Vec<u8>) {
        self.state = TAG_START;
        self.pop_finished(out);
    }

    /// Pops length-delimited sub-messages that end exactly here, rewriting
    /// their length prefixes in resize mode.
    fn pop_finished(&mut self, out: &mut Vec<u8>) {
        while let Some(&Frame {
            end: End::At(end),
            patch,
            ..
        }) = self.stack.last()
        {
            if end != self.pos {
                break;
            }
            self.stack.pop();
            if let Some(p) = patch {
                // Fields were only removed, so the new length and its
                // minimal varint are never longer than the original.
                let mut buf = [0u8; 10];
                let k = encode_varint((out.len() - p.body_start) as u64, &mut buf);
                debug_assert!(k <= p.width as usize);
                let at = p.prefix_pos;
                out.splice(at..at + p.width as usize, buf[..k].iter().copied());
            }
        }
    }
}

fn encode_varint(mut v: u64, buf: &mut [u8; 10]) -> usize {
    let mut i = 0;
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            buf[i] = b;
            return i + 1;
        }
        buf[i] = b | 0x80;
        i += 1;
    }
}

/// Generates the overwrite bytes for one redacted length-delimited payload.
#[derive(Debug)]
struct Filler {
    zeros: bool,
    /// Bytes of the payload not yet generated.
    left: u64,
    /// Position within the current chunk, and the chunk's payload length.
    /// A chunk is `C2 A3 09 <len> <len zero bytes>`.
    pos: u8,
    len: u8,
}

/// Tag of field 19000 with wire type 2, as a varint. Also valid UTF-8 ("£\t").
const RESERVED_TAG: [u8; 3] = [0xC2, 0xA3, 0x09];
const CHUNK_HEADER: u64 = 4;
const MAX_CHUNK_PAYLOAD: u64 = 127; // keeps the length a single ASCII byte

impl Filler {
    fn new(fill: ProtoFill, total: u64) -> Self {
        let zeros = fill == ProtoFill::Zeros || total < CHUNK_HEADER;
        let mut f = Filler {
            zeros,
            left: total,
            pos: 0,
            len: 0,
        };
        if !zeros {
            f.start_chunk();
        }
        f
    }

    /// Picks the next chunk size so the remainder is either 0 or big enough
    /// for another chunk header.
    fn start_chunk(&mut self) {
        let r = self.left;
        let full = CHUNK_HEADER + MAX_CHUNK_PAYLOAD;
        let len = if r <= full {
            r - CHUNK_HEADER
        } else if r - full < CHUNK_HEADER {
            MAX_CHUNK_PAYLOAD - CHUNK_HEADER
        } else {
            MAX_CHUNK_PAYLOAD
        };
        self.pos = 0;
        self.len = len as u8;
    }

    fn fill(&mut self, mut n: usize, out: &mut Vec<u8>) {
        if self.zeros {
            out.resize(out.len() + n, 0);
            self.left -= n as u64;
            return;
        }
        while n > 0 {
            let chunk_total = CHUNK_HEADER as u8 + self.len;
            if self.pos == chunk_total {
                self.start_chunk();
                continue;
            }
            if self.pos < 3 {
                out.push(RESERVED_TAG[self.pos as usize]);
                self.pos += 1;
                n -= 1;
                self.left -= 1;
            } else if self.pos == 3 {
                out.push(self.len);
                self.pos += 1;
                n -= 1;
                self.left -= 1;
            } else {
                let k = ((chunk_total - self.pos) as usize).min(n);
                out.resize(out.len() + k, 0);
                self.pos += k as u8;
                n -= k;
                self.left -= k as u64;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_paths() {
        assert_eq!("1.3.2".parse::<FieldPath>().unwrap().fields(), &[1, 3, 2]);
        assert_eq!(" 7 ".parse::<FieldPath>().unwrap().fields(), &[7]);
        for bad in ["", "0", "1..2", "a", "1.-2", "536870912", "1.2."] {
            assert!(
                bad.parse::<FieldPath>().is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn filler_layout() {
        for total in 0..2000u64 {
            let mut f = Filler::new(ProtoFill::ReservedField, total);
            let mut out = Vec::new();
            // Generate in uneven pieces to exercise resumption.
            let mut left = total as usize;
            let mut step = 1;
            while left > 0 {
                let k = step.min(left);
                f.fill(k, &mut out);
                left -= k;
                step = step * 3 % 17 + 1;
            }
            assert_eq!(out.len() as u64, total);
            assert!(std::str::from_utf8(&out).is_ok(), "not UTF-8 for {total}");
            if total >= 4 {
                // Walk the chunks: every one must be field 19000, LEN.
                let mut i = 0;
                while i < out.len() {
                    assert_eq!(&out[i..i + 3], &RESERVED_TAG);
                    let len = out[i + 3] as usize;
                    assert!(len < 128);
                    assert!(out[i + 4..i + 4 + len].iter().all(|&b| b == 0));
                    i += 4 + len;
                }
                assert_eq!(i, out.len());
            } else {
                assert!(out.iter().all(|&b| b == 0));
            }
        }
    }
}
