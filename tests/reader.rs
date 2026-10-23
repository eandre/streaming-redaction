use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use streaming_parse::{Redactor, redact_reader};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

/// Yields its data a few bytes at a time, returning `Pending` in between.
struct Trickle {
    data: Vec<u8>,
    pos: usize,
    toggle: bool,
}

impl Trickle {
    fn new(data: impl Into<Vec<u8>>) -> Self {
        Trickle {
            data: data.into(),
            pos: 0,
            toggle: false,
        }
    }
}

impl AsyncRead for Trickle {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.toggle = !self.toggle;
        if self.toggle {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let n = 3.min(self.data.len() - self.pos).min(buf.remaining());
        let start = self.pos;
        buf.put_slice(&self.data[start..start + n]);
        self.pos += n;
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn async_read_adapter() {
    let input = r#"{"user": {"email": "a@b.c", "password": "hunter2"}, "items": [{"card": "4111"}, {"card": "5500"}]}"#;
    let mut r = redact_reader(
        "application/json",
        ["$..password", "$.items[*].card"],
        Trickle::new(input),
    )
    .unwrap();
    let mut out = String::new();
    r.read_to_string(&mut out).await.unwrap();
    assert_eq!(
        out,
        r#"{"user": {"email": "a@b.c", "password": "[REDACTED]"}, "items": [{"card": "[REDACTED]"}, {"card": "[REDACTED]"}]}"#
    );
}

#[tokio::test]
async fn large_input_with_small_reads() {
    // Bigger than the adapter's internal chunk, read through a tiny buffer.
    let item = r#"{"id":1,"secret":"xxxxxxxxxxxxxxxx"},"#;
    let mut input = String::from("[");
    for _ in 0..2000 {
        input.push_str(item);
    }
    input.push_str("{}]");
    let mut r = Redactor::new("application/json", ["$[*].secret"])
        .unwrap()
        .reader(input.as_bytes());
    let mut out = Vec::new();
    let mut buf = [0u8; 7];
    loop {
        let n = r.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    let out = String::from_utf8(out).unwrap();
    assert_eq!(out.matches("[REDACTED]").count(), 2000);
    assert!(!out.contains("xxxx"));
}

#[tokio::test]
async fn copy_to_writer() {
    let redactor = Redactor::new("application/json", ["$.a"]).unwrap();
    let mut out = Vec::new();
    let n = redactor
        .redact(&br#"{"a":1,"b":2}"#[..], &mut out)
        .await
        .unwrap();
    assert_eq!(out, br#"{"a":"[REDACTED]","b":2}"#);
    assert_eq!(n as usize, out.len());
}

#[tokio::test]
async fn errors_after_safe_prefix() {
    let input = r#"{"ok": 1, "pw": "secret" oops}"#;
    let mut r = Redactor::new("application/json", ["$.pw"])
        .unwrap()
        .reader(input.as_bytes());
    let mut out = Vec::new();
    let err = r.read_to_end(&mut out).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    let out = String::from_utf8(out).unwrap();
    assert_eq!(out, r#"{"ok": 1, "pw": "[REDACTED]" "#);
    // The error is sticky.
    assert!(r.read(&mut [0; 16]).await.is_err());
}

#[test]
fn rejects_unknown_content_type_and_bad_rules() {
    assert!(Redactor::new("text/html", ["$.a"]).is_err());
    assert!(Redactor::new("application/json", ["a.b"]).is_err());
    assert!(Redactor::new("application/x-protobuf", ["$.a"]).is_err());
}
