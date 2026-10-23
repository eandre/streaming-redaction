//! Tee reader / redacted-copy mode, where redaction may change sizes.

use prost::Message;
use serde_json::{Value, json};
use streaming_parse::{Error, Redactor};
use tokio::io::AsyncReadExt;

#[derive(Clone, PartialEq, Message)]
struct User {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, tag = "2")]
    password: String,
    #[prost(int64, tag = "3")]
    id: i64,
    #[prost(message, optional, tag = "4")]
    address: Option<Address>,
    #[prost(message, repeated, tag = "5")]
    cards: Vec<Card>,
    #[prost(fixed64, tag = "6")]
    token: u64,
    #[prost(int32, repeated, packed = "true", tag = "9")]
    nums: Vec<i32>,
}

#[derive(Clone, PartialEq, Message)]
struct Address {
    #[prost(string, tag = "1")]
    street: String,
    #[prost(string, tag = "2")]
    zip: String,
    #[prost(message, optional, tag = "3")]
    geo: Option<Geo>,
}

#[derive(Clone, PartialEq, Message)]
struct Geo {
    #[prost(float, tag = "1")]
    lat: f32,
    #[prost(float, tag = "2")]
    lng: f32,
}

#[derive(Clone, PartialEq, Message)]
struct Card {
    #[prost(string, tag = "1")]
    number: String,
    #[prost(uint32, tag = "2")]
    cvv: u32,
}

struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
    fn string(&mut self) -> String {
        // Sometimes long, so length prefixes get multi-byte varints.
        let len = [0, 3, 20, 200, 20_000][self.below(5) as usize];
        "x".repeat(len)
    }
}

fn random_user(rng: &mut Rng) -> User {
    User {
        name: rng.string(),
        password: rng.string(),
        id: rng.below(1 << 40) as i64,
        address: (rng.below(3) > 0).then(|| Address {
            street: rng.string(),
            zip: rng.string(),
            geo: (rng.below(2) > 0).then(|| Geo {
                lat: rng.below(90) as f32,
                lng: 1.5,
            }),
        }),
        cards: (0..rng.below(4))
            .map(|_| Card {
                number: rng.string(),
                cvv: rng.below(1000) as u32,
            })
            .collect(),
        token: rng.below(u64::MAX),
        nums: (0..rng.below(5))
            .map(|_| rng.below(100_000) as i32)
            .collect(),
    }
}

/// Each rule and the equivalent edit on the decoded message.
type Edit = fn(&mut User);

const RULES: [(&str, Edit); 9] = [
    ("2", |u| u.password.clear()),
    ("3", |u| u.id = 0),
    ("4", |u| u.address = None),
    ("4.2", |u| u.address.iter_mut().for_each(|a| a.zip.clear())),
    ("4.3", |u| u.address.iter_mut().for_each(|a| a.geo = None)),
    ("4.3.1", |u| {
        u.address
            .iter_mut()
            .flat_map(|a| a.geo.as_mut())
            .for_each(|g| g.lat = 0.0)
    }),
    ("5.1", |u| u.cards.iter_mut().for_each(|c| c.number.clear())),
    ("6", |u| u.token = 0),
    ("9", |u| u.nums.clear()),
];

/// Feeds `input` in random chunks, taking ready output along the way.
fn copy_chunked(r: &Redactor, input: &[u8], rng: &mut Rng) -> Result<Vec<u8>, Error> {
    let mut c = r.redacted_copy();
    let mut out = Vec::new();
    let mut rest = input;
    while !rest.is_empty() {
        let n = (1 + rng.below(3000) as usize).min(rest.len());
        c.feed(&rest[..n])?;
        rest = &rest[n..];
        if rng.below(2) == 0 {
            out.extend(c.take_ready());
        }
    }
    out.extend(c.finish()?);
    Ok(out)
}

#[test]
fn protobuf_fields_are_removed() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for case in 0..500 {
        let user = random_user(&mut rng);
        let picked: Vec<_> = RULES.iter().filter(|_| rng.below(3) == 0).collect();
        let rules: Vec<&str> = picked.iter().map(|(r, _)| *r).collect();

        let mut expected = user.clone();
        for (_, edit) in &picked {
            edit(&mut expected);
        }

        let r = Redactor::new("application/x-protobuf", &rules).unwrap();
        let got = copy_chunked(&r, &user.encode_to_vec(), &mut rng).unwrap();
        // Removing fields gives exactly what prost encodes for the edited
        // message, including minimal length prefixes.
        assert_eq!(
            got,
            expected.encode_to_vec(),
            "case {case}, rules {rules:?}"
        );
    }
}

#[test]
fn protobuf_groups_are_removed() {
    // field 1 = group { field 2 = varint 150 }, field 3 = varint 1
    let input = [0x0B, 0x10, 0x96, 0x01, 0x0C, 0x18, 0x01];
    let run = |rules: &[&str]| {
        let mut c = Redactor::new("application/x-protobuf", rules)
            .unwrap()
            .redacted_copy();
        c.feed(&input).unwrap();
        c.finish().unwrap()
    };
    assert_eq!(run(&["1"]), [0x18, 0x01]);
    assert_eq!(run(&["1.2"]), [0x0B, 0x0C, 0x18, 0x01]);
    assert_eq!(run(&["3"]), [0x0B, 0x10, 0x96, 0x01, 0x0C]);

    // A group inside a patched sub-message: 1 = msg { 2 = group { 3 = varint } }.
    let input = [0x0A, 0x04, 0x13, 0x18, 0x05, 0x14];
    assert_eq!(
        {
            let mut c = Redactor::new("application/x-protobuf", ["1.2.3"])
                .unwrap()
                .redacted_copy();
            c.feed(&input).unwrap();
            c.finish().unwrap()
        },
        [0x0A, 0x02, 0x13, 0x14]
    );
}

fn frame(msg: &[u8]) -> Vec<u8> {
    let mut f = vec![0];
    f.extend((msg.len() as u32).to_be_bytes());
    f.extend(msg);
    f
}

fn frames(body: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let len = u32::from_be_bytes(rest[1..5].try_into().unwrap()) as usize;
        out.push(&rest[5..5 + len]);
        rest = &rest[5 + len..];
    }
    out
}

#[test]
fn grpc_frames_are_resized() {
    let mut rng = Rng(7);
    let users: Vec<User> = (0..20).map(|_| random_user(&mut rng)).collect();
    let body: Vec<u8> = users
        .iter()
        .flat_map(|u| frame(&u.encode_to_vec()))
        .collect();
    let r = Redactor::new("application/grpc", ["2", "4"]).unwrap();
    let out = copy_chunked(&r, &body, &mut rng).unwrap();
    let got: Vec<User> = frames(&out)
        .into_iter()
        .map(|m| User::decode(m).unwrap())
        .collect();
    let want: Vec<User> = users
        .into_iter()
        .map(|u| User {
            password: String::new(),
            address: None,
            ..u
        })
        .collect();
    assert_eq!(got, want);
}

#[test]
fn grpc_json_uses_normal_replacement() {
    let msgs = [
        json!({"user": "ann", "password": 1}),
        json!({"password": {"long": "secret value"}}),
    ];
    let body: Vec<u8> = msgs
        .iter()
        .flat_map(|m| frame(m.to_string().as_bytes()))
        .collect();
    let r = Redactor::new("application/grpc-web+json", ["$.password"]).unwrap();
    let out = copy_chunked(&r, &body, &mut Rng(3)).unwrap();
    let got: Vec<Value> = frames(&out)
        .into_iter()
        .map(|m| serde_json::from_slice(m).unwrap())
        .collect();
    assert_eq!(
        got,
        [
            json!({"user": "ann", "password": "[REDACTED]"}),
            json!({"password": "[REDACTED]"})
        ]
    );
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(data: &[u8]) -> String {
    data.chunks(3)
        .flat_map(|c| {
            let n = (c[0] as u32) << 16
                | (*c.get(1).unwrap_or(&0) as u32) << 8
                | *c.get(2).unwrap_or(&0) as u32;
            [
                B64[(n >> 18) as usize & 63] as char,
                B64[(n >> 12) as usize & 63] as char,
                if c.len() > 1 {
                    B64[(n >> 6) as usize & 63] as char
                } else {
                    '='
                },
                if c.len() > 2 {
                    B64[n as usize & 63] as char
                } else {
                    '='
                },
            ]
        })
        .collect()
}

#[test]
fn grpc_web_text_is_resized_and_reencoded() {
    let user = User {
        name: "ann".into(),
        password: "hunter2".into(),
        ..Default::default()
    };
    let users = vec![user; 3];
    let body: Vec<u8> = users
        .iter()
        .flat_map(|u| frame(&u.encode_to_vec()))
        .collect();
    // Input with mid-stream padding: each frame encoded separately.
    let text: String = users
        .iter()
        .map(|u| b64(&frame(&u.encode_to_vec())))
        .collect();
    let r = Redactor::new("application/grpc-web-text", ["2"]).unwrap();
    let out = copy_chunked(&r, text.as_bytes(), &mut Rng(11)).unwrap();

    let expected: Vec<u8> = users
        .iter()
        .flat_map(|u| {
            frame(
                &User {
                    password: String::new(),
                    ..u.clone()
                }
                .encode_to_vec(),
            )
        })
        .collect();
    assert!(expected.len() < body.len());
    assert_eq!(String::from_utf8(out).unwrap(), b64(&expected));
}

#[test]
fn take_ready_holds_back_only_what_can_change() {
    let r = Redactor::new("application/grpc", ["2"]).unwrap();
    let msg = User {
        name: "ann".into(),
        password: "hunter2".into(),
        ..Default::default()
    }
    .encode_to_vec();
    let f = frame(&msg);
    let mut c = r.redacted_copy();
    c.feed(&f[..f.len() - 1]).unwrap();
    // The frame's length isn't known until the message ends.
    assert!(c.take_ready().is_empty());
    c.feed(&f[f.len() - 1..]).unwrap();
    let first = c.take_ready();
    assert_eq!(frames(&first).len(), 1);
    assert_eq!(c.buffered_len(), 0);

    // JSON never holds anything back.
    let mut c = Redactor::new("application/json", ["$.pw"])
        .unwrap()
        .redacted_copy();
    c.feed(br#"{"pw": "x", "ok": [1, "#).unwrap();
    assert_eq!(c.take_ready(), br#"{"pw": "[REDACTED]", "ok": [1, "#);
}

#[tokio::test]
async fn tee_passes_original_through() {
    let input = br#"{"user": "ann", "password": "hunter2", "nested": {"password": "x"}}"#;
    let r = Redactor::new("application/json", ["$..password"]).unwrap();
    let mut tee = r.tee(&input[..]);
    let mut original = Vec::new();
    tee.read_to_end(&mut original).await.unwrap();
    assert_eq!(original, input);
    assert_eq!(
        String::from_utf8(tee.into_redacted().unwrap()).unwrap(),
        r#"{"user": "ann", "password": "[REDACTED]", "nested": {"password": "[REDACTED]"}}"#
    );
}

#[tokio::test]
async fn tee_redaction_errors_dont_affect_original() {
    let input = br#"{"password": "hunter2" garbage"#;
    let r = Redactor::new("application/json", ["$.password"]).unwrap();
    let mut tee = r.tee(&input[..]);
    let mut original = Vec::new();
    tee.read_to_end(&mut original).await.unwrap();
    assert_eq!(original, input);
    assert!(tee.redaction_error().is_some());
    assert!(matches!(tee.into_redacted(), Err(Error::Malformed { .. })));
}

#[tokio::test]
async fn tee_requires_reading_to_the_end() {
    // A protobuf prefix can look complete, so a partial read must not be
    // reported as a full redacted copy.
    let msg = User {
        name: "ann".into(),
        password: "hunter2".into(),
        ..Default::default()
    }
    .encode_to_vec();
    let r = Redactor::new("application/x-protobuf", ["2"]).unwrap();
    let mut tee = r.tee(&msg[..]);
    let mut first = [0u8; 5];
    tee.read_exact(&mut first).await.unwrap();
    assert!(matches!(
        tee.into_redacted(),
        Err(Error::UnexpectedEof { offset: 5 })
    ));
}
