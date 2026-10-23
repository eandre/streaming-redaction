use std::fmt;
use std::str::FromStr;

use crate::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Selector {
    /// Object member name, as decoded UTF-8 bytes.
    Name(Box<[u8]>),
    /// Array index.
    Index(u64),
    /// Any member or element.
    Wildcard,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Segment {
    /// `..` segment: matches at this level or any level below.
    pub descendant: bool,
    /// Union of selectors (`['a','b']`); the segment matches if any does.
    pub selectors: Vec<Selector>,
}

/// A parsed JSONPath redaction rule.
///
/// Supported subset of RFC 9535:
///
/// | Syntax                    | Meaning                                  |
/// |---------------------------|------------------------------------------|
/// | `$`                       | the whole document                       |
/// | `.name`, `['name']`       | object member                            |
/// | `[0]`                     | array element                            |
/// | `.*`, `[*]`               | every member / element                   |
/// | `['a', "b", 0]`           | union of selectors                       |
/// | `..name`, `..*`, `..[0]`  | descendant at any depth                  |
///
/// Negative indices, slices and filters are rejected: they can't be decided
/// without looking ahead, which a streaming redactor can't do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonPath {
    source: String,
    pub(crate) segments: Vec<Segment>,
}

impl JsonPath {
    /// The rule as originally written.
    pub fn as_str(&self) -> &str {
        &self.source
    }
}

impl fmt::Display for JsonPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

impl FromStr for JsonPath {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let segments = Parser {
            s: s.as_bytes(),
            i: 0,
        }
        .parse()
        .map_err(|reason| Error::InvalidRule {
            rule: s.to_owned(),
            reason,
        })?;
        Ok(JsonPath {
            source: s.to_owned(),
            segments,
        })
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn parse(mut self) -> Result<Vec<Segment>, String> {
        self.skip_ws();
        if self.peek() != Some(b'$') {
            return Err("must start with `$`".into());
        }
        self.i += 1;
        let mut segments = Vec::new();
        loop {
            self.skip_ws();
            let Some(c) = self.peek() else { break };
            let seg = match c {
                b'.' => {
                    self.i += 1;
                    if self.peek() == Some(b'.') {
                        self.i += 1;
                        if self.peek() == Some(b'[') {
                            Segment {
                                descendant: true,
                                selectors: self.bracket()?,
                            }
                        } else {
                            Segment {
                                descendant: true,
                                selectors: vec![self.member()?],
                            }
                        }
                    } else {
                        Segment {
                            descendant: false,
                            selectors: vec![self.member()?],
                        }
                    }
                }
                b'[' => Segment {
                    descendant: false,
                    selectors: self.bracket()?,
                },
                _ => return Err(format!("unexpected {:?} at offset {}", c as char, self.i)),
            };
            segments.push(seg);
        }
        Ok(segments)
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    /// Shorthand member after `.` or `..`: `*` or a bare name.
    fn member(&mut self) -> Result<Selector, String> {
        if self.peek() == Some(b'*') {
            self.i += 1;
            return Ok(Selector::Wildcard);
        }
        let start = self.i;
        while let Some(c) = self.peek() {
            if matches!(
                c,
                b'.' | b'[' | b']' | b'\'' | b'"' | b'*' | b' ' | b'\t' | b'\n' | b'\r'
            ) {
                break;
            }
            self.i += 1;
        }
        if self.i == start {
            return Err(format!("expected a member name at offset {start}"));
        }
        Ok(Selector::Name(self.s[start..self.i].into()))
    }

    /// `[ selector (, selector)* ]`
    fn bracket(&mut self) -> Result<Vec<Selector>, String> {
        debug_assert_eq!(self.peek(), Some(b'['));
        self.i += 1;
        let mut out = Vec::new();
        loop {
            self.skip_ws();
            let sel = match self.peek() {
                Some(q @ (b'\'' | b'"')) => Selector::Name(self.quoted(q)?.into_bytes().into()),
                Some(b'*') => {
                    self.i += 1;
                    Selector::Wildcard
                }
                Some(b'0'..=b'9') => {
                    let start = self.i;
                    while matches!(self.peek(), Some(b'0'..=b'9')) {
                        self.i += 1;
                    }
                    let digits = std::str::from_utf8(&self.s[start..self.i]).unwrap();
                    if digits.len() > 1 && digits.starts_with('0') {
                        return Err(format!("index with leading zero at offset {start}"));
                    }
                    if self.peek() == Some(b':') {
                        return Err("slices are not supported".into());
                    }
                    Selector::Index(
                        digits
                            .parse()
                            .map_err(|_| format!("index too large at offset {start}"))?,
                    )
                }
                Some(b'-') => return Err("negative indices are not supported".into()),
                Some(b':') => return Err("slices are not supported".into()),
                Some(b'?') => return Err("filter expressions are not supported".into()),
                Some(c) => return Err(format!("unexpected {:?} at offset {}", c as char, self.i)),
                None => return Err("unterminated `[`".into()),
            };
            out.push(sel);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(c) => return Err(format!("unexpected {:?} at offset {}", c as char, self.i)),
                None => return Err("unterminated `[`".into()),
            }
        }
    }

    fn quoted(&mut self, quote: u8) -> Result<String, String> {
        let start = self.i;
        self.i += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(c) = self.peek() else {
                return Err(format!("unterminated string at offset {start}"));
            };
            self.i += 1;
            match c {
                c if c == quote => break,
                b'\\' => {
                    let Some(e) = self.peek() else {
                        return Err(format!("unterminated string at offset {start}"));
                    };
                    self.i += 1;
                    let ch = match e {
                        b'\\' => '\\',
                        b'/' => '/',
                        b'\'' => '\'',
                        b'"' => '"',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => self.unicode_escape()?,
                        _ => return Err(format!("invalid escape at offset {}", self.i - 2)),
                    };
                    let mut buf = [0; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                c => out.push(c),
            }
        }
        String::from_utf8(out).map_err(|_| "invalid UTF-8".into())
    }

    fn hex4(&mut self) -> Result<u16, String> {
        let digits = self
            .s
            .get(self.i..self.i + 4)
            .ok_or("truncated \\u escape")?;
        let s = std::str::from_utf8(digits).map_err(|_| "invalid \\u escape")?;
        let v = u16::from_str_radix(s, 16).map_err(|_| "invalid \\u escape")?;
        self.i += 4;
        Ok(v)
    }

    fn unicode_escape(&mut self) -> Result<char, String> {
        let hi = self.hex4()?;
        let code = if (0xD800..0xDC00).contains(&hi) {
            if self.s.get(self.i..self.i + 2) != Some(b"\\u") {
                return Err("unpaired surrogate in \\u escape".into());
            }
            self.i += 2;
            let lo = self.hex4()?;
            if !(0xDC00..0xE000).contains(&lo) {
                return Err("unpaired surrogate in \\u escape".into());
            }
            0x10000 + (((hi as u32) - 0xD800) << 10) + ((lo as u32) - 0xDC00)
        } else {
            hi as u32
        };
        char::from_u32(code).ok_or_else(|| "unpaired surrogate in \\u escape".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segs(s: &str) -> Vec<Segment> {
        s.parse::<JsonPath>().unwrap().segments
    }

    fn name(s: &str) -> Selector {
        Selector::Name(s.as_bytes().into())
    }

    #[test]
    fn parses() {
        assert_eq!(segs("$"), vec![]);
        assert_eq!(
            segs("$.a['b c'][3]..d.*[*]"),
            vec![
                Segment {
                    descendant: false,
                    selectors: vec![name("a")]
                },
                Segment {
                    descendant: false,
                    selectors: vec![name("b c")]
                },
                Segment {
                    descendant: false,
                    selectors: vec![Selector::Index(3)]
                },
                Segment {
                    descendant: true,
                    selectors: vec![name("d")]
                },
                Segment {
                    descendant: false,
                    selectors: vec![Selector::Wildcard]
                },
                Segment {
                    descendant: false,
                    selectors: vec![Selector::Wildcard]
                },
            ]
        );
        assert_eq!(
            segs(r#"$..[ 'x', "yé", 1 ]"#),
            vec![Segment {
                descendant: true,
                selectors: vec![name("x"), name("yé"), Selector::Index(1)]
            }]
        );
    }

    #[test]
    fn rejects() {
        for bad in [
            "",
            "a.b",
            "$.",
            "$..",
            "$[",
            "$[-1]",
            "$[1:2]",
            "$[?(@.a)]",
            "$['a'",
            "$[01]",
            "$.a b",
        ] {
            assert!(
                bad.parse::<JsonPath>().is_err(),
                "{bad:?} should be rejected"
            );
        }
    }
}
