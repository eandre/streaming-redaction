//! Redacts stdin to stdout.
//!
//! ```sh
//! echo '{"user":{"password":"x"}}' | cargo run --example redact -- 'json:$..password'
//! cargo run --example redact -- -t application/grpc-web-text 'proto:2' < body > redacted
//! ```
//!
//! Rules are `json:<JSONPath>`, `proto:<field path>` or `form:<field name>`.
//! `-t` gives the content type; without it, the format is detected.

use streaming_parse::{Redactor, RedactorBuilder};

#[tokio::main]
async fn main() {
    let (content_type, builder) = parse_args(std::env::args().skip(1));
    let redactor = builder.build().unwrap_or_else(|e| fail(&e.to_string()));
    let mut stdout = tokio::io::stdout();
    if let Err(e) = redactor
        .redact(tokio::io::stdin(), &mut stdout, content_type.as_deref())
        .await
    {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn parse_args(mut args: impl Iterator<Item = String>) -> (Option<String>, RedactorBuilder) {
    let mut content_type = None;
    let mut builder = Redactor::builder();
    while let Some(arg) = args.next() {
        if arg == "-t" {
            content_type = Some(
                args.next()
                    .unwrap_or_else(|| fail("-t needs a content type")),
            );
            continue;
        }
        builder = match arg.split_once(':') {
            Some(("json", rule)) => builder.json([rule]),
            Some(("proto", rule)) => builder.proto([rule]),
            Some(("form", rule)) => builder.form([rule]),
            _ => fail(&format!("unrecognized argument {arg:?}")),
        };
    }
    (content_type, builder)
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    eprintln!(
        "usage: redact [-t <content-type>] [json:<path> | proto:<path> | form:<name>]... < input > output"
    );
    std::process::exit(2);
}
