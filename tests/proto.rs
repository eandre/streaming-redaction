use prost::Message;
use streaming_parse::{Error, Options, ProtoFill, Redactor};

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
    #[prost(double, tag = "7")]
    score: f64,
    #[prost(sint32, tag = "8")]
    delta: i32,
    #[prost(int32, repeated, packed = "true", tag = "9")]
    nums: Vec<i32>,
    #[prost(bytes = "vec", tag = "10")]
    blob: Vec<u8>,
    #[prost(bool, tag = "11")]
    admin: bool,
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

fn sample() -> User {
    User {
        name: "Ann".into(),
        password: "correct horse battery staple, but much longer than one chunk of filler: "
            .repeat(4),
        id: 1_234_567_890_123,
        address: Some(Address {
            street: "1 Infinite Loop".into(),
            zip: "95014".into(),
            geo: Some(Geo {
                lat: 37.33,
                lng: -122.03,
            }),
        }),
        cards: vec![
            Card {
                number: "4111111111111111".into(),
                cvv: 123,
            },
            Card {
                number: "5500000000000004".into(),
                cvv: 456,
            },
        ],
        token: 0xdead_beef_cafe_f00d,
        score: 99.5,
        delta: -42,
        nums: vec![1, 300, 70000],
        blob: vec![1, 2, 3, 4, 5],
        admin: true,
    }
}

fn redact_with(rules: &[&str], input: &[u8], opts: Options) -> Result<Vec<u8>, Error> {
    let r = Redactor::builder().proto(rules).options(opts).build()?;

    let mut whole = Vec::new();
    let mut s = r.stream(Some("application/x-protobuf"));
    let res = s.feed(input, &mut whole).and_then(|_| s.finish(&mut whole));

    // Byte-at-a-time feeding must produce identical output.
    let mut split = Vec::new();
    let mut s = r.stream(Some("application/x-protobuf"));
    let res2 = input
        .iter()
        .try_for_each(|b| s.feed(std::slice::from_ref(b), &mut split))
        .and_then(|_| s.finish(&mut split));
    assert_eq!(res, res2);
    assert_eq!(whole, split);

    res.map(|_| {
        assert_eq!(whole.len(), input.len(), "redaction must preserve size");
        whole
    })
}

fn redact(rules: &[&str], input: &[u8]) -> Vec<u8> {
    redact_with(rules, input, Options::default()).unwrap()
}

fn redact_user(rules: &[&str]) -> User {
    let out = redact(rules, &sample().encode_to_vec());
    User::decode(&out[..]).expect("redacted output must decode")
}

#[test]
fn no_rules_is_identity() {
    let input = sample().encode_to_vec();
    assert_eq!(redact(&[], &input), input);
    assert_eq!(redact(&["99", "4.99", "5.7"], &input), input);
}

#[test]
fn scalars_become_zero() {
    let u = redact_user(&["3", "6", "7", "8", "11"]);
    let expected = User {
        id: 0,
        token: 0,
        score: 0.0,
        delta: 0,
        admin: false,
        ..sample()
    };
    assert_eq!(u, expected);
}

#[test]
fn strings_are_overwritten_and_still_valid() {
    let u = redact_user(&["2"]);
    assert_ne!(u.password, sample().password);
    assert_eq!(u.password.len(), sample().password.len());
    assert!(!u.password.contains("horse"));
    assert_eq!(
        User {
            password: sample().password,
            ..u
        },
        sample()
    );
}

#[test]
fn whole_submessage_decodes_as_empty() {
    let u = redact_user(&["4"]);
    assert_eq!(u.address, Some(Address::default()));
    assert_eq!(
        User {
            address: sample().address,
            ..u
        },
        sample()
    );
}

#[test]
fn nested_paths() {
    let u = redact_user(&["4.3.1", "4.2"]);
    let addr = u.address.clone().unwrap();
    assert_eq!(
        addr.geo,
        Some(Geo {
            lat: 0.0,
            lng: -122.03
        })
    );
    assert_ne!(addr.zip, "95014");
    assert_eq!(addr.street, "1 Infinite Loop");
}

#[test]
fn repeated_fields_match_every_element() {
    let u = redact_user(&["5.1"]);
    assert_eq!(u.cards.len(), 2);
    for (got, orig) in u.cards.iter().zip(sample().cards) {
        assert_ne!(got.number, orig.number);
        assert_eq!(got.cvv, orig.cvv);
    }
}

#[test]
fn leaf_wins_over_deeper_rule() {
    let u = redact_user(&["4", "4.1"]);
    assert_eq!(u.address, Some(Address::default()));
}

#[test]
fn zero_fill() {
    let opts = Options::default().proto_fill(ProtoFill::Zeros);
    let out = redact_with(&["2", "9", "10"], &sample().encode_to_vec(), opts).unwrap();
    let u = User::decode(&out[..]).unwrap();
    assert!(u.password.bytes().all(|b| b == 0));
    assert!(u.nums.iter().all(|&n| n == 0));
    assert_eq!(u.blob, vec![0; 5]);
}

#[test]
fn groups() {
    // field 1 = group { field 2 = varint 150 }, field 3 = varint 1
    let input = [0x0B, 0x10, 0x96, 0x01, 0x0C, 0x18, 0x01];
    assert_eq!(
        redact(&["1"], &input),
        [0x0B, 0x10, 0x80, 0x00, 0x0C, 0x18, 0x01]
    );
    assert_eq!(
        redact(&["1.2"], &input),
        [0x0B, 0x10, 0x80, 0x00, 0x0C, 0x18, 0x01]
    );
    assert_eq!(
        redact(&["3"], &input),
        [0x0B, 0x10, 0x96, 0x01, 0x0C, 0x18, 0x00]
    );
    assert_eq!(redact(&["1.3"], &input), input);
}

#[test]
fn malformed() {
    let input = sample().encode_to_vec();
    let cases: Vec<Vec<u8>> = vec![
        input[..input.len() - 1].to_vec(),           // truncated
        vec![0x00],                                  // field 0
        vec![0x0F],                                  // wire type 7
        vec![0x0A, 0x05, 0x01],                      // LEN longer than input
        vec![0x22, 0x02, 0x0A, 0x05, 0, 0, 0, 0, 0], // inner LEN exceeds outer message
        vec![0x0B, 0x10, 0x01],                      // unterminated group
        vec![0x0C],                                  // stray end-group
        vec![
            0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
        ], // varint > 10 bytes
    ];
    for c in cases {
        assert!(
            redact_with(&["4.1"], &c, Options::default()).is_err(),
            "{c:02x?} should be rejected"
        );
    }
    assert_eq!(redact(&["1"], &[]), Vec::<u8>::new());
}

#[test]
fn depth_limit() {
    // 5 nested groups of field 1.
    let mut input = vec![0x0B; 5];
    input.extend([0x0C; 5]);
    assert!(redact_with(&[], &input, Options::default().max_depth(5)).is_ok());
    assert!(matches!(
        redact_with(&[], &input, Options::default().max_depth(4)),
        Err(Error::DepthLimitExceeded { .. })
    ));
}

fn grpc_frame(flags: u8, msg: &[u8]) -> Vec<u8> {
    let mut f = vec![flags];
    f.extend((msg.len() as u32).to_be_bytes());
    f.extend(msg);
    f
}

fn run_grpc(ct: &str, rules: &[&str], input: &[u8]) -> Result<Vec<u8>, Error> {
    let r = Redactor::builder().proto(rules).build()?;
    let mut out = Vec::new();
    let mut s = r.stream(Some(ct));
    for chunk in input.chunks(3) {
        s.feed(chunk, &mut out)?;
    }
    s.finish(&mut out)?;
    Ok(out)
}

#[test]
fn grpc_framing() {
    let a = sample().encode_to_vec();
    let b = User {
        password: "pw".into(),
        ..Default::default()
    }
    .encode_to_vec();
    let mut body = grpc_frame(0, &a);
    body.extend(grpc_frame(0, &[]));
    body.extend(grpc_frame(0, &b));

    let out = run_grpc("application/grpc", &["2"], &body).unwrap();
    assert_eq!(out.len(), body.len());
    let m1 = User::decode(&out[5..5 + a.len()]).unwrap();
    let off = 5 + a.len() + 5;
    assert_eq!(&out[off..off + 5], &grpc_frame(0, &b)[..5]);
    let m2 = User::decode(&out[off + 5..]).unwrap();
    assert_ne!(m1.password, sample().password);
    assert_eq!(m2.password, "\0\0"); // too short for a filler chunk

    assert!(matches!(
        run_grpc("application/grpc", &["2"], &grpc_frame(1, &a)),
        Err(Error::CompressedGrpcMessage { offset: 0 })
    ));
    assert!(matches!(
        run_grpc("application/grpc", &["2"], &body[..body.len() - 1]),
        Err(Error::UnexpectedEof { .. })
    ));
}

#[test]
fn grpc_web_trailers_pass_through() {
    let a = sample().encode_to_vec();
    let trailer = b"grpc-status:0\r\ngrpc-message:\r\n";
    let mut body = grpc_frame(0, &a);
    body.extend(grpc_frame(0x80, trailer));
    let out = run_grpc("application/grpc-web", &["4"], &body).unwrap();
    assert!(out.ends_with(trailer));
    assert_eq!(
        User::decode(&out[5..5 + a.len()]).unwrap().address,
        Some(Address::default())
    );
}
