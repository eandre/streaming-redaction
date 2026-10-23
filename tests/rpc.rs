//! gRPC / gRPC-Web / gRPC-Web-text / Connect envelopes with both codecs.

use prost::Message;
use serde_json::{Value, json};
use streaming_parse::{Error, Options, Redactor};

#[derive(Clone, PartialEq, Message)]
struct Login {
    #[prost(string, tag = "1")]
    user: String,
    #[prost(string, tag = "2")]
    password: String,
    #[prost(int64, tag = "3")]
    pin: i64,
}

fn login(user: &str, password: &str) -> Login {
    Login {
        user: user.into(),
        password: password.into(),
        pin: 987_654,
    }
}

fn frame(flags: u8, msg: &[u8]) -> Vec<u8> {
    let mut f = vec![flags];
    f.extend((msg.len() as u32).to_be_bytes());
    f.extend(msg);
    f
}

/// Splits a body into frames, checking the headers are intact.
fn frames(body: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let len = u32::from_be_bytes(rest[1..5].try_into().unwrap()) as usize;
        out.push((rest[0], &rest[5..5 + len]));
        rest = &rest[5 + len..];
    }
    out
}

/// Runs a redactor over `input` in chunks of `chunk` bytes.
fn run(ct: &str, rules: &[&str], input: &[u8], chunk: usize) -> Result<Vec<u8>, Error> {
    run_opts(ct, rules, input, chunk, Options::default())
}

fn run_opts(
    ct: &str,
    rules: &[&str],
    input: &[u8],
    chunk: usize,
    opts: Options,
) -> Result<Vec<u8>, Error> {
    let r = Redactor::with_options(ct, rules, opts)?;
    let mut s = r.stream();
    let mut out = Vec::new();
    for c in input.chunks(chunk.max(1)) {
        s.feed(c, &mut out)?;
    }
    s.finish(&mut out)?;
    Ok(out)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut s = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        s.push(B64[(n >> 18) as usize & 63] as char);
        s.push(B64[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        s.push(if c.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    s
}

/// Decodes base64 that may contain padding mid-stream (each 4-char group
/// is self-contained).
fn b64_decode(s: &str) -> Vec<u8> {
    let val = |c: u8| B64.iter().position(|&b| b == c).map(|v| v as u32);
    let mut out = Vec::new();
    for g in s.as_bytes().chunks(4) {
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

fn grpc_proto_body() -> (Vec<u8>, Vec<Login>) {
    let msgs = vec![
        login("ann", "hunter2"),
        login("bob", "correct horse battery staple"),
        Login::default(),
    ];
    let body = msgs
        .iter()
        .flat_map(|m| frame(0, &m.encode_to_vec()))
        .collect();
    (body, msgs)
}

fn check_redacted_logins(body: &[u8], originals: &[Login]) {
    let fs = frames(body);
    assert_eq!(fs.len(), originals.len());
    for ((flags, msg), orig) in fs.iter().zip(originals) {
        assert_eq!(*flags, 0);
        let got = Login::decode(*msg).unwrap();
        assert_eq!(got.user, orig.user);
        assert_eq!(got.pin, 0);
        if orig.password.is_empty() {
            assert!(got.password.is_empty());
        } else {
            assert_ne!(got.password, orig.password);
        }
    }
}

#[test]
fn grpc_web_text_proto() {
    let (body, msgs) = grpc_proto_body();
    let text = b64_encode(&body);
    for ct in [
        "application/grpc-web-text",
        "application/grpc-web-text+proto",
    ] {
        for chunk in [1, 3, 7, 4096] {
            let out = run(ct, &["2", "3"], text.as_bytes(), chunk).unwrap();
            let out = String::from_utf8(out).unwrap();
            // Size preserving end to end, so the base64 is the same length.
            assert_eq!(out.len(), text.len());
            check_redacted_logins(&b64_decode(&out), &msgs);
        }
    }
}

#[test]
fn grpc_web_text_padding_mid_stream() {
    // Encode each flush separately, at boundaries unrelated to frames,
    // as a server flushing partial buffers would.
    let (body, msgs) = grpc_proto_body();
    let mut text = String::new();
    let mut rest = &body[..];
    for size in [1, 2, 4, 8, 5, 13].iter().cycle() {
        if rest.is_empty() {
            break;
        }
        let n = (*size).min(rest.len());
        text.push_str(&b64_encode(&rest[..n]));
        rest = &rest[n..];
    }
    assert!(
        text.trim_end_matches('=').contains('='),
        "test needs mid-stream padding"
    );

    let out = String::from_utf8(
        run("application/grpc-web-text", &["2", "3"], text.as_bytes(), 5).unwrap(),
    )
    .unwrap();
    // Padding lands in the same places.
    let pads = |s: &str| s.match_indices('=').map(|(i, _)| i).collect::<Vec<_>>();
    assert_eq!(pads(&out), pads(&text));
    check_redacted_logins(&b64_decode(&out), &msgs);
}

#[test]
fn grpc_web_text_trailers_and_errors() {
    let (mut body, _) = grpc_proto_body();
    let trailer = b"grpc-status: 0\r\n";
    body.extend(frame(0x80, trailer));
    let out = run(
        "application/grpc-web-text",
        &["2"],
        b64_encode(&body).as_bytes(),
        64,
    )
    .unwrap();
    let decoded = b64_decode(std::str::from_utf8(&out).unwrap());
    assert!(decoded.ends_with(trailer));

    assert!(run("application/grpc-web-text", &["2"], b"AAA*", 64).is_err());
    assert!(run("application/grpc-web-text", &["2"], b"A=AA", 64).is_err());
    // Truncated mid-frame.
    let text = b64_encode(&body[..10]);
    assert!(matches!(
        run("application/grpc-web-text", &["2"], text.as_bytes(), 64),
        Err(Error::UnexpectedEof { .. })
    ));
}

fn json_frames(msgs: &[Value]) -> Vec<u8> {
    msgs.iter()
        .flat_map(|m| frame(0, serde_json::to_string(m).unwrap().as_bytes()))
        .collect()
}

#[test]
fn grpc_json_codecs() {
    let msgs = [
        json!({"user": "ann", "password": "hunter2", "pin": "987654", "nested": {"token": [1, 2, 3]}}),
        json!({"user": "bob", "password": 12}),
        json!(7),
    ];
    let body = json_frames(&msgs);
    let rules = ["$.password", "$..token", "$.pin"];
    for ct in [
        "application/grpc+json",
        "application/grpc-web+json",
        "application/connect+json",
    ] {
        for chunk in [1, 5, 1000] {
            let out = run(ct, &rules, &body, chunk).unwrap();
            assert_eq!(out.len(), body.len(), "{ct}");
            let got: Vec<Value> = frames(&out)
                .iter()
                .map(|(_, m)| serde_json::from_slice(m).unwrap())
                .collect();
            assert_eq!(
                got,
                [
                    json!({"user": "ann", "password": "*******", "pin": "******", "nested": {"token": "*****"}}),
                    json!({"user": "bob", "password": ""}), // `12` is 2 bytes: `""`
                    json!(7),
                ],
                "{ct}"
            );
        }
    }

    // Text mode with JSON inside.
    let text = b64_encode(&body);
    let out = run("application/grpc-web-text+json", &rules, text.as_bytes(), 3).unwrap();
    let decoded = b64_decode(std::str::from_utf8(&out).unwrap());
    let first: Value = serde_json::from_slice(frames(&decoded)[0].1).unwrap();
    assert_eq!(first["password"], "*******");
}

#[test]
fn connect_end_stream_passes_through() {
    let a = login("ann", "hunter2").encode_to_vec();
    let end = br#"{"metadata":{"x-secret":["not a message"]}}"#;
    let mut body = frame(0, &a);
    body.extend(frame(0x02, end));
    let out = run("application/connect+proto", &["2"], &body, 4).unwrap();
    let fs = frames(&out);
    assert_ne!(Login::decode(fs[0].1).unwrap().password, "hunter2");
    assert_eq!(fs[1], (0x02, &end[..]));

    // Compressed messages can't be redacted.
    assert!(matches!(
        run("application/connect+proto", &["2"], &frame(0x01, &a), 4),
        Err(Error::CompressedGrpcMessage { .. })
    ));
}

#[test]
fn json_rules_for_json_codecs_field_numbers_for_proto() {
    assert!(Redactor::new("application/grpc+json", ["2"]).is_err());
    assert!(Redactor::new("application/grpc", ["$.password"]).is_err());
}

#[test]
fn plain_json_size_preserving_option() {
    let input = br#"{"a": {"b": [1, 2]}, "c": "keep"}"#;
    let out = run_opts(
        "application/json",
        &["$.a"],
        input,
        2,
        Options::default().preserve_json_size(true),
    )
    .unwrap();
    assert_eq!(out.len(), input.len());
    assert_eq!(
        serde_json::from_slice::<Value>(&out).unwrap(),
        json!({"a": "***********", "c": "keep"})
    );
}
