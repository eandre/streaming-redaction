//! One redactor with rules for every codec, fed every supported format with
//! a full, partial or missing content type.

use prost::Message;
use serde_json::{Value, json};
use streaming_parse::{Error, Redactor};

#[derive(Clone, PartialEq, Message)]
struct Login {
    #[prost(string, tag = "1")]
    user: String,
    #[prost(string, tag = "2")]
    password: String,
}

const SECRET: &str = "hunter2";

fn redactor() -> Redactor {
    Redactor::builder()
        .json(["$..password"])
        .proto(["2"])
        .form(["password"])
        .build()
        .unwrap()
}

fn login() -> Login {
    Login {
        user: "ann".into(),
        password: SECRET.into(),
    }
}

fn login_json() -> String {
    json!({"user": "ann", "password": SECRET}).to_string()
}

fn frame(flags: u8, msg: &[u8]) -> Vec<u8> {
    let mut f = vec![flags];
    f.extend((msg.len() as u32).to_be_bytes());
    f.extend(msg);
    f
}

fn frames(body: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let len = u32::from_be_bytes(rest[1..5].try_into().unwrap()) as usize;
        out.push((rest[0], rest[5..5 + len].to_vec()));
        rest = &rest[5 + len..];
    }
    out
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(data: &[u8]) -> Vec<u8> {
    data.chunks(3)
        .flat_map(|c| {
            let n = (c[0] as u32) << 16
                | (*c.get(1).unwrap_or(&0) as u32) << 8
                | *c.get(2).unwrap_or(&0) as u32;
            [
                B64[(n >> 18) as usize & 63],
                B64[(n >> 12) as usize & 63],
                if c.len() > 1 {
                    B64[(n >> 6) as usize & 63]
                } else {
                    b'='
                },
                if c.len() > 2 {
                    B64[n as usize & 63]
                } else {
                    b'='
                },
            ]
        })
        .collect()
}

fn unb64(s: &[u8]) -> Vec<u8> {
    let val = |c: u8| B64.iter().position(|&b| b == c).map(|v| v as u32);
    let mut out = Vec::new();
    for g in s.chunks(4) {
        let n = (val(g[0]).unwrap() << 18)
            | (val(g[1]).unwrap() << 12)
            | (val(g[2]).unwrap_or(0) << 6)
            | val(g[3]).unwrap_or(0);
        out.push((n >> 16) as u8);
        if g[2] != b'=' {
            out.push((n >> 8) as u8);
        }
        if g[3] != b'=' {
            out.push(n as u8);
        }
    }
    out
}

/// Runs both modes, feeding one byte at a time.
fn both_modes(r: &Redactor, ct: Option<&str>, input: &[u8]) -> Result<[Vec<u8>; 2], Error> {
    let mut s = r.stream(ct);
    let mut streamed = Vec::new();
    for b in input {
        s.feed(std::slice::from_ref(b), &mut streamed)?;
    }
    s.finish(&mut streamed)?;

    let mut c = r.redacted_copy(ct);
    let mut copied = Vec::new();
    for b in input {
        c.feed(std::slice::from_ref(b))?;
        copied.extend(c.take_ready());
    }
    copied.extend(c.finish()?);
    Ok([streamed, copied])
}

fn assert_no_secret(out: &[u8], what: &str) {
    assert!(
        !out.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()),
        "{what}: secret leaked"
    );
}

/// Every content type the format could arrive with, from none to complete.
fn cases(body: &[u8], cts: &[Option<&str>], check: impl Fn(&[u8], &str)) {
    let r = redactor();
    for ct in cts {
        let [streamed, copied] =
            both_modes(&r, *ct, body).unwrap_or_else(|e| panic!("{ct:?}: {e}"));
        for (out, mode) in [(streamed, "stream"), (copied, "tee")] {
            let what = format!("{ct:?} ({mode})");
            assert_no_secret(&out, &what);
            check(&out, &what);
        }
    }
}

#[test]
fn json() {
    let check = |out: &[u8], what: &str| {
        let v: Value = serde_json::from_slice(out).unwrap();
        assert_eq!(v["user"], "ann", "{what}");
    };
    cases(
        login_json().as_bytes(),
        &[
            None,
            Some("application/json"),
            Some("application/problem+json"),
        ],
        check,
    );
    // Pretty-printed, so it starts with whitespace.
    let pretty =
        serde_json::to_string_pretty(&serde_json::from_str::<Value>(&login_json()).unwrap())
            .unwrap();
    cases(format!("\n{pretty}").as_bytes(), &[None], check);
}

#[test]
fn ndjson() {
    let body = format!("{}\n{}\n", login_json(), login_json());
    cases(
        body.as_bytes(),
        &[None, Some("application/x-ndjson")],
        |out, what| {
            assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 2, "{what}");
        },
    );
}

fn check_proto(msg: &[u8], what: &str) {
    let m = Login::decode(msg).unwrap_or_else(|e| panic!("{what}: {e}"));
    assert_eq!(m.user, "ann", "{what}");
    assert_ne!(m.password, SECRET, "{what}");
}

#[test]
fn bare_protobuf() {
    cases(
        &login().encode_to_vec(),
        &[
            None,
            Some("application/x-protobuf"),
            Some("application/proto"),
        ],
        check_proto,
    );
}

#[test]
fn grpc_protobuf() {
    let body: Vec<u8> = [
        frame(0, &login().encode_to_vec()),
        frame(0, &[]),
        frame(0, &login().encode_to_vec()),
    ]
    .concat();
    cases(
        &body,
        &[
            None,
            Some("application/grpc"),
            Some("application/grpc+proto"),
        ],
        |out, what| {
            let fs = frames(out);
            assert_eq!(fs.len(), 3, "{what}");
            check_proto(&fs[0].1, what);
            check_proto(&fs[2].1, what);
        },
    );
}

#[test]
fn grpc_web_with_trailers() {
    let trailer = b"grpc-status: 0\r\n";
    let body = [frame(0, &login().encode_to_vec()), frame(0x80, trailer)].concat();
    cases(
        &body,
        &[
            None,
            Some("application/grpc-web"),
            Some("application/grpc-web+proto"),
        ],
        |out, what| {
            let fs = frames(out);
            check_proto(&fs[0].1, what);
            assert_eq!(fs[1], (0x80, trailer.to_vec()), "{what}");
        },
    );
}

#[test]
fn json_in_frames() {
    let body = [
        frame(0, login_json().as_bytes()),
        frame(0, login_json().as_bytes()),
    ]
    .concat();
    let cts = [
        None,
        Some("application/grpc"), // no `+json`: detected inside the frame
        Some("application/grpc+json"),
        Some("application/grpc-web+json"),
        Some("application/connect+json"),
    ];
    cases(&body, &cts, |out, what| {
        for (_, m) in frames(out) {
            let v: Value = serde_json::from_slice(&m).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_eq!(v["user"], "ann", "{what}");
        }
    });
}

#[test]
fn connect_end_stream() {
    let end = br#"{"metadata":{}}"#;
    let body = [frame(0, &login().encode_to_vec()), frame(0x02, end)].concat();
    cases(
        &body,
        &[None, Some("application/connect+proto")],
        |out, what| {
            let fs = frames(out);
            check_proto(&fs[0].1, what);
            assert_eq!(fs[1], (0x02, end.to_vec()), "{what}");
        },
    );
}

#[test]
fn grpc_web_text() {
    let proto_body = b64(&[
        frame(0, &login().encode_to_vec()),
        frame(0x80, b"grpc-status: 0\r\n"),
    ]
    .concat());
    let cts = [
        None,
        Some("application/grpc-web-text"),
        Some("application/grpc-web-text+proto"),
    ];
    cases(&proto_body, &cts, |out, what| {
        check_proto(&frames(&unb64(out))[0].1, what)
    });

    let json_body = b64(&frame(0, login_json().as_bytes()));
    let cts = [
        None,
        Some("application/grpc-web-text"),
        Some("application/grpc-web-text+json"),
    ];
    cases(&json_body, &cts, |out, what| {
        let v: Value = serde_json::from_slice(&frames(&unb64(out))[0].1).unwrap();
        assert_eq!(v["user"], "ann", "{what}");
    });
}

#[test]
fn urlencoded() {
    let body = b"user=ann&pass%77ord=hunter2&remember=1";
    cases(
        body,
        &[None, Some("application/x-www-form-urlencoded")],
        |out, what| {
            assert_eq!(
                out, b"user=ann&pass%77ord=%5BREDACTED%5D&remember=1",
                "{what}"
            );
        },
    );
}

fn multipart(boundary: &str, preamble: &str) -> String {
    format!(
        "{preamble}--{boundary}\r\n\
         Content-Disposition: form-data; name=\"user\"\r\n\r\n\
         ann\r\n--{boundary}\r\n\
         Content-Disposition: form-data; name=\"note\"\r\n\r\n\
         looks like a delimiter but isn't:\r\n--{b2}\r\n-\r\n--\r\n\
         --{boundary}\r\n\
         Content-Disposition: form-data; name=\"password\"; filename=\"pw.txt\"\r\n\
         Content-Type: text/plain\r\n\r\n\
         hunter2\r\n--{bpart}\r\n\
         --{boundary}--\r\nepilogue",
        b2 = &boundary[..boundary.len() - 1],
        bpart = &boundary[..3],
    )
}

#[test]
fn multipart_forms() {
    let boundary = "----WebKitFormBoundary7MA4YWxk";
    let body = multipart(boundary, "");
    let with_boundary = format!("multipart/form-data; boundary={boundary}");
    let cts = [
        None,
        Some("multipart/form-data"),
        Some(with_boundary.as_str()),
    ];
    // The password part's whole body (including the near-delimiter) is replaced.
    let expected = body.replace(&format!("hunter2\r\n--{}", &boundary[..3]), "[REDACTED]");
    cases(body.as_bytes(), &cts, |out, what| {
        assert_eq!(std::str::from_utf8(out).unwrap(), expected, "{what}");
    });

    // A preamble is only possible to handle when the header names the boundary.
    let body = multipart(boundary, "This is a preamble.\r\n");
    let r = redactor();
    let [out, _] = both_modes(&r, Some(&with_boundary), body.as_bytes()).unwrap();
    assert_no_secret(&out, "preamble");
    assert!(out.starts_with(b"This is a preamble.\r\n--"));
    assert!(both_modes(&r, None, body.as_bytes()).is_err());
    assert!(both_modes(&r, Some("multipart/form-data"), body.as_bytes()).is_err());
}

#[test]
fn priority_and_unrecognized() {
    let r = redactor();
    // `123` is valid JSON and a valid form key. JSON wins.
    let [out, _] = both_modes(&r, None, b"123").unwrap();
    assert_eq!(out, b"123");
    // A JSON array also parses as protobuf for a while (`[` and `{` are group
    // tags, `"` a length-delimited field), but it's JSON.
    let doc = format!("[{}]", vec![login_json(); 20].join(","));
    let [out, _] = both_modes(&r, None, doc.as_bytes()).unwrap();
    assert_no_secret(&out, "array");

    assert!(matches!(
        both_modes(&r, None, b"<html>hi</html>"),
        Err(Error::UnrecognizedPayload)
    ));
    assert!(both_modes(&r, None, b"").is_ok());
}

struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }

    fn string(&mut self, alphabet: &[u8], max: usize) -> String {
        let len = self.below(max + 1);
        (0..len)
            .map(|_| alphabet[self.below(alphabet.len())] as char)
            .collect()
    }
}

/// Characters that make text look like JSON or form data.
const NASTY: &[u8] = b"{}[]\":,=&+%-_.~*'()0123456789abcdefnrtuABCDEFZ \n";
const FORM_SAFE: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~*";

#[test]
fn random_payloads_are_detected_without_content_type() {
    let r = redactor();
    let mut rng = Rng(0x5DEE_CE66_D1CE_4E5B);
    for case in 0..3000 {
        // Protobuf whose strings look like JSON or form data.
        let m = Login {
            user: rng.string(NASTY, 300),
            password: format!("{SECRET}{}", rng.string(NASTY, 50)),
        };
        let body = m.encode_to_vec();
        let [streamed, copied] =
            both_modes(&r, None, &body).unwrap_or_else(|e| panic!("case {case}: {e} {m:?}"));
        for out in [streamed, copied] {
            let got = Login::decode(&out[..]).unwrap();
            assert_eq!(got.user, m.user, "case {case}");
            assert!(!got.password.contains(SECRET), "case {case}: {m:?}");
        }

        // A urlencoded form with random fields around the password.
        let mut fields: Vec<String> = (0..rng.below(4))
            .map(|_| {
                format!(
                    "{}={}",
                    rng.string(FORM_SAFE, 10),
                    rng.string(FORM_SAFE, 30)
                )
            })
            .collect();
        fields.insert(rng.below(fields.len() + 1), format!("password={SECRET}"));
        let body = fields.join("&");
        let [out, _] = both_modes(&r, None, body.as_bytes())
            .unwrap_or_else(|e| panic!("case {case}: {e} {body}"));
        assert_no_secret(&out, &body);
    }
}

#[test]
fn codecs_without_rules_pass_through() {
    // Only protobuf rules: a JSON payload has nothing to redact, so the
    // ambiguity between JSON and form doesn't matter.
    let r = Redactor::builder().proto(["2"]).build().unwrap();
    let [out, _] = both_modes(&r, None, b"123").unwrap();
    assert_eq!(out, b"123");
    let body = login_json();
    let [out, _] = both_modes(&r, None, body.as_bytes()).unwrap();
    assert_eq!(out, body.as_bytes());
}
