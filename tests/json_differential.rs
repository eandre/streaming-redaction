//! Randomized comparison of the streaming JSON redactor against a simple
//! tree-based reference implementation written independently of it.

use serde_json::{Map, Value};
use streaming_parse::{Options, Redactor};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const KEYS: [&str; 4] = ["a", "b", "pw", "é\"x"];

fn gen_value(rng: &mut Rng, depth: u32) -> Value {
    let leaf = depth >= 4 || rng.below(3) == 0;
    if leaf {
        return match rng.below(6) {
            0 => Value::Null,
            1 => Value::Bool(rng.below(2) == 0),
            2 => Value::from(rng.below(100_000) as i64 - 50_000),
            3 => Value::from((rng.below(1000) as f64) / 7.0),
            4 => Value::String(format!("s\u{1F600}\n{}", rng.below(100))),
            _ => Value::String(String::new()),
        };
    }
    if rng.below(2) == 0 {
        Value::Array(
            (0..rng.below(4))
                .map(|_| gen_value(rng, depth + 1))
                .collect(),
        )
    } else {
        let mut m = Map::new();
        for _ in 0..rng.below(4) {
            m.insert(
                KEYS[rng.below(KEYS.len() as u64) as usize].to_owned(),
                gen_value(rng, depth + 1),
            );
        }
        Value::Object(m)
    }
}

#[derive(Clone, Debug)]
enum Sel {
    Name(&'static str),
    Index(usize),
    Any,
}

#[derive(Clone, Debug)]
struct Seg {
    descendant: bool,
    sels: Vec<Sel>,
}

#[derive(Clone, Debug)]
enum Step {
    Key(String),
    Idx(usize),
}

fn gen_path(rng: &mut Rng) -> Vec<Seg> {
    (0..rng.below(4))
        .map(|_| Seg {
            descendant: rng.below(3) == 0,
            sels: (0..1 + rng.below(2))
                .map(|_| match rng.below(4) {
                    0 => Sel::Any,
                    1 => Sel::Index(rng.below(3) as usize),
                    _ => Sel::Name(KEYS[rng.below(KEYS.len() as u64) as usize]),
                })
                .collect(),
        })
        .collect()
}

fn path_to_string(p: &[Seg]) -> String {
    let mut s = "$".to_owned();
    for seg in p {
        if seg.descendant {
            s.push_str("..");
        }
        let sels: Vec<String> = seg
            .sels
            .iter()
            .map(|sel| match sel {
                Sel::Name(n) => serde_json::to_string(n).unwrap(),
                Sel::Index(i) => i.to_string(),
                Sel::Any => "*".into(),
            })
            .collect();
        s.push('[');
        s.push_str(&sels.join(","));
        s.push(']');
    }
    s
}

fn sel_matches(sel: &Sel, step: &Step) -> bool {
    match (sel, step) {
        (Sel::Any, _) => true,
        (Sel::Name(n), Step::Key(k)) => n == k,
        (Sel::Index(i), Step::Idx(j)) => i == j,
        _ => false,
    }
}

/// Does `segs` match the concrete location `loc` exactly?
fn path_matches(segs: &[Seg], loc: &[Step]) -> bool {
    let Some((seg, rest)) = segs.split_first() else {
        return loc.is_empty();
    };
    let starts: Vec<usize> = if seg.descendant {
        (0..loc.len()).collect()
    } else {
        vec![0]
    };
    starts.into_iter().any(|k| {
        k < loc.len()
            && seg.sels.iter().any(|s| sel_matches(s, &loc[k]))
            && path_matches(rest, &loc[k + 1..])
    })
}

fn reference(v: &Value, rules: &[Vec<Seg>], loc: &mut Vec<Step>) -> Value {
    if rules.iter().any(|r| path_matches(r, loc)) {
        return Value::String("[REDACTED]".into());
    }
    match v {
        Value::Array(a) => Value::Array(
            a.iter()
                .enumerate()
                .map(|(i, x)| {
                    loc.push(Step::Idx(i));
                    let r = reference(x, rules, loc);
                    loc.pop();
                    r
                })
                .collect(),
        ),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| {
                    loc.push(Step::Key(k.clone()));
                    let r = reference(x, rules, loc);
                    loc.pop();
                    (k.clone(), r)
                })
                .collect(),
        ),
        v => v.clone(),
    }
}

/// Re-encodes some member names with `\u` escapes so key decoding is exercised.
fn escape_keys(s: &str) -> String {
    s.replace("\"pw\"", "\"p\\u0077\"")
}

#[test]
fn matches_reference_implementation() {
    differential(false);
}

#[test]
fn size_preserving_matches_reference_implementation() {
    differential(true);
}

/// In size-preserving mode a redacted value is a `"***"` string (or `0`)
/// of unknown length, so compare structurally.
fn equivalent(got: &Value, want: &Value) -> bool {
    match (got, want) {
        (g, Value::String(w)) if w == "[REDACTED]" => match g {
            Value::String(s) => s.bytes().all(|b| b == b'*'),
            Value::Number(n) => n.as_u64() == Some(0),
            _ => false,
        },
        (Value::Array(g), Value::Array(w)) => {
            g.len() == w.len() && g.iter().zip(w).all(|(a, b)| equivalent(a, b))
        }
        (Value::Object(g), Value::Object(w)) => {
            g.len() == w.len()
                && g.iter()
                    .all(|(k, v)| w.get(k).is_some_and(|wv| equivalent(v, wv)))
        }
        (g, w) => g == w,
    }
}

fn differential(preserve_size: bool) {
    let opts = Options::default().preserve_json_size(preserve_size);
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut redacted_cases = 0;
    for case in 0..5000 {
        let doc = gen_value(&mut rng, 0);
        let rules: Vec<Vec<Seg>> = (0..1 + rng.below(3)).map(|_| gen_path(&mut rng)).collect();
        let rule_strs: Vec<String> = rules.iter().map(|r| path_to_string(r)).collect();

        let text = if rng.below(2) == 0 {
            serde_json::to_string(&doc).unwrap()
        } else {
            serde_json::to_string_pretty(&doc).unwrap()
        };
        let text = escape_keys(&text);

        let redactor = Redactor::builder()
            .json(&rule_strs)
            .options(opts.clone())
            .build()
            .unwrap();
        // Half the cases detect the codec from the payload.
        let ct = (case % 2 == 0).then_some("application/json");
        let mut out = Vec::new();
        let mut s = redactor.stream(ct);
        let mut rest = text.as_bytes();
        while !rest.is_empty() {
            let n = (1 + rng.below(16) as usize).min(rest.len());
            s.feed(&rest[..n], &mut out).unwrap();
            rest = &rest[n..];
        }
        s.finish(&mut out).unwrap();

        let got: Value = serde_json::from_slice(&out).unwrap_or_else(|e| {
            panic!(
                "case {case}: output is not JSON ({e}): {}",
                String::from_utf8_lossy(&out)
            )
        });
        // Compare against the re-parsed input: serde_json's float printing
        // doesn't always round-trip exactly.
        let doc: Value = serde_json::from_str(&text).unwrap();
        let want = reference(&doc, &rules, &mut Vec::new());
        let ctx = format!(
            "case {case}\nrules: {rule_strs:?}\ninput: {text}\noutput: {}",
            String::from_utf8_lossy(&out)
        );
        if preserve_size {
            assert_eq!(out.len(), text.len(), "{ctx}");
            assert!(equivalent(&got, &want), "{ctx}");
        } else {
            assert_eq!(got, want, "{ctx}");
        }
        if got != doc {
            redacted_cases += 1;
        }
    }
    // Make sure the generator actually exercises redaction.
    assert!(
        redacted_cases > 1000,
        "only {redacted_cases} cases redacted anything"
    );
}
