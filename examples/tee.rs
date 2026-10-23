//! Copies stdin to stdout unmodified while writing a redacted copy to a file.
//!
//! ```sh
//! cargo run --example tee -- redacted.json 'json:$..password' < in.json > out.json
//! ```
//!
//! Rules are `json:<JSONPath>`, `proto:<field path>` or `form:<field name>`.
//! `-t` gives the content type; without it, the format is detected.

use streaming_parse::Redactor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut content_type = None;
    let mut redacted_path = None;
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
            _ if redacted_path.is_none() => {
                redacted_path = Some(arg);
                builder
            }
            _ => fail(&format!("unrecognized argument {arg:?}")),
        };
    }
    let redacted_path = redacted_path.unwrap_or_else(|| fail("missing redacted output file"));
    let redactor = builder.build().unwrap_or_else(|e| fail(&e.to_string()));

    let mut tee = redactor.tee(tokio::io::stdin(), content_type.as_deref());
    let mut stdout = tokio::io::stdout();
    let mut redacted = tokio::fs::File::create(&redacted_path).await?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = tee.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        stdout.write_all(&buf[..n]).await?;
        // Ship finished redacted bytes as we go instead of holding them.
        redacted.write_all(&tee.take_redacted_ready()).await?;
    }
    stdout.flush().await?;
    match tee.into_redacted() {
        Ok(rest) => redacted.write_all(&rest).await?,
        Err(e) => eprintln!("redaction failed (original stream unaffected): {e}"),
    }
    redacted.flush().await
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    eprintln!(
        "usage: tee [-t <content-type>] <redacted-file> [json:<path> | proto:<path> | form:<name>]... < input > output"
    );
    std::process::exit(2);
}
