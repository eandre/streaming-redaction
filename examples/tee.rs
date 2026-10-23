//! Copies stdin to stdout unmodified while writing a redacted copy to a file.
//!
//! ```sh
//! cargo run --example tee -- application/json redacted.json '$..password' < in.json > out.json
//! ```

use streaming_parse::Redactor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(content_type), Some(redacted_path)) = (args.next(), args.next()) else {
        eprintln!("usage: tee <content-type> <redacted-output> [rule...] < input > output");
        std::process::exit(2);
    };
    let rules: Vec<String> = args.collect();
    let redactor = Redactor::new(&content_type, &rules).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(2);
    });

    let mut tee = redactor.tee(tokio::io::stdin());
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
