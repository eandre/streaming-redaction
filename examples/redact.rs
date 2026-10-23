//! Redacts stdin to stdout.
//!
//! ```sh
//! echo '{"user":{"password":"x"}}' | cargo run --example redact -- application/json '$..password'
//! ```

use streaming_parse::Redactor;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let Some(content_type) = args.next() else {
        eprintln!("usage: redact <content-type> [rule...] < input > output");
        std::process::exit(2);
    };
    let rules: Vec<String> = args.collect();

    let redactor = match Redactor::new(&content_type, &rules) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };
    let mut stdout = tokio::io::stdout();
    if let Err(e) = redactor.redact(tokio::io::stdin(), &mut stdout).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
