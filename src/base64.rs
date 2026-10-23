//! Base64 text encoding for `application/grpc-web-text`.
//!
//! The body is base64 of a binary gRPC-Web stream. Servers may base64-encode
//! each flush separately, so `=` padding can appear mid-stream, and not
//! necessarily at frame boundaries. We decode 4-character groups, feed the
//! bytes to the envelope engine, and re-encode its output. Whenever an input
//! group is padded we flush the encoder too, so the output keeps the same
//! segment structure (for protobuf the output is then the same length as the
//! input).
//!
//! In resize mode (redacted copy) the inner output may still be patched, so
//! only its committed prefix is encoded, and the output is one continuous
//! base64 stream with padding only at the end.
//!
//! Error offsets from the inner engine refer to decoded bytes.

use crate::Error;
use crate::envelope;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const INVALID: u8 = 0xFF;
const PAD: u8 = 0xFE;

const DECODE: [u8; 256] = {
    let mut t = [INVALID; 256];
    let mut i = 0;
    while i < 64 {
        t[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    t[b'=' as usize] = PAD;
    t
};

pub(crate) struct Engine {
    inner: envelope::Engine,
    quad: [u8; 4],
    qn: u8,
    /// Decoded bytes not yet fed to `inner`.
    decoded: Vec<u8>,
    /// Output of `inner` not yet encoded.
    plain: Vec<u8>,
    enc: Encoder,
    resize: bool,
    /// Offset in the base64 text, for error reporting.
    offset: u64,
}

impl Engine {
    pub(crate) fn new(inner: envelope::Engine, resize: bool) -> Self {
        Engine {
            inner,
            quad: [0; 4],
            qn: 0,
            decoded: Vec::new(),
            plain: Vec::new(),
            enc: Encoder::default(),
            resize,
            offset: 0,
        }
    }

    pub(crate) fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        for &c in input {
            self.offset += 1;
            if matches!(c, b'\r' | b'\n' | b' ' | b'\t') {
                continue;
            }
            let v = DECODE[c as usize];
            if v == INVALID {
                return Err(self.malformed("invalid base64 character"));
            }
            self.quad[self.qn as usize] = v;
            self.qn += 1;
            if self.qn == 4 {
                self.qn = 0;
                let padded = self.decode_group()?;
                if padded && !self.resize {
                    self.forward(out)?;
                    self.enc.flush(out);
                }
            }
        }
        self.forward(out)
    }

    pub(crate) fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), Error> {
        // Tolerate a final group without its `=` padding.
        match self.qn {
            0 => {}
            1 => return Err(self.malformed("truncated base64")),
            n => {
                self.quad[n as usize..].fill(PAD);
                self.decode_group()?;
            }
        }
        self.forward(out)?;
        self.inner.finish(&mut self.plain)?;
        self.enc.push(&self.plain, out);
        self.plain.clear();
        self.enc.flush(out);
        Ok(())
    }

    fn malformed(&self, reason: &'static str) -> Error {
        Error::Malformed {
            offset: self.offset,
            reason,
        }
    }

    /// Decodes `self.quad` into `self.decoded`. Returns whether it was padded.
    fn decode_group(&mut self) -> Result<bool, Error> {
        let [a, b, c, d] = self.quad;
        if a == PAD || b == PAD || (c == PAD && d != PAD) {
            return Err(self.malformed("misplaced base64 padding"));
        }
        let n = (a as u32) << 18
            | (b as u32) << 12
            | if c == PAD { 0 } else { (c as u32) << 6 }
            | if d == PAD { 0 } else { d as u32 };
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        let count = match (c == PAD, d == PAD) {
            (true, _) => 1,
            (false, true) => 2,
            (false, false) => 3,
        };
        self.decoded.extend_from_slice(&bytes[..count]);
        Ok(count < 3)
    }

    /// Feeds decoded bytes through the envelope engine and encodes the result.
    fn forward(&mut self, out: &mut Vec<u8>) -> Result<(), Error> {
        if !self.decoded.is_empty() {
            self.inner.feed(&self.decoded, &mut self.plain)?;
            self.decoded.clear();
        }
        let ready = if self.resize {
            self.inner.committed(self.plain.len())
        } else {
            self.plain.len()
        };
        self.enc.push(&self.plain[..ready], out);
        self.plain.drain(..ready);
        if self.resize {
            self.inner.shift(ready);
        }
        Ok(())
    }
}

#[derive(Default)]
struct Encoder {
    buf: [u8; 3],
    n: u8,
}

impl Encoder {
    fn push(&mut self, bytes: &[u8], out: &mut Vec<u8>) {
        for &b in bytes {
            self.buf[self.n as usize] = b;
            self.n += 1;
            if self.n == 3 {
                self.emit(out);
            }
        }
    }

    /// Writes any partial group with `=` padding.
    fn flush(&mut self, out: &mut Vec<u8>) {
        if self.n > 0 {
            self.buf[self.n as usize..].fill(0);
            self.emit(out);
        }
    }

    fn emit(&mut self, out: &mut Vec<u8>) {
        let [a, b, c] = self.buf;
        let n = (a as u32) << 16 | (b as u32) << 8 | c as u32;
        let chars = [
            ALPHABET[(n >> 18) as usize & 63],
            ALPHABET[(n >> 12) as usize & 63],
            if self.n >= 2 {
                ALPHABET[(n >> 6) as usize & 63]
            } else {
                b'='
            },
            if self.n >= 3 {
                ALPHABET[n as usize & 63]
            } else {
                b'='
            },
        ];
        out.extend_from_slice(&chars);
        self.n = 0;
    }
}
