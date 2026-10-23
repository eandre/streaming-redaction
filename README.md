# streaming-parse

Streaming redaction of JSON, Protobuf and HTML form payloads for tokio, including gRPC,
gRPC-Web and Connect. You give it rules for each codec and a byte stream, optionally with
its content type, and it produces a redacted version of the data as the bytes arrive.
Memory use doesn't depend on payload size.

It runs in one of two modes:

* **Tee**: the original bytes pass through untouched while a redacted copy is built on
  the side. Use this to forward a request or response and record a safe version of it
  (logs, traces, audit).
* **Stream**: the stream itself is redacted, and the output is a drop-in replacement for
  the input.

## Quick start

```rust
use streaming_parse::Redactor;

// Rules for each codec. Build once and reuse: Redactor is Clone + Send + Sync.
let redactor = Redactor::builder()
    .json(["$..password", "$.cards[*].number"])
    .proto(["2", "4.1"])
    .form(["password"])
    .build()?;

// Tee: forward the original body, keep a redacted copy.
// The content type is optional; whatever it doesn't say is detected from the body.
let mut tee = redactor.tee(body, Some("application/grpc-web-text"));
tokio::io::copy(&mut tee, &mut upstream).await?;      // original bytes, unmodified
let redacted: Vec<u8> = tee.into_redacted()?;

// Stream: the reader yields redacted bytes.
let mut redacted = redactor.reader(body, None);
tokio::io::copy(&mut redacted, &mut sink).await?;
```

Two example programs read stdin. Rules are written `json:…`, `proto:…` or `form:…`, and
`-t` sets the content type:

```sh
# Redacted stream to stdout
echo '{"user":{"password":"x"}}' | cargo run --example redact -- 'json:$..password'

# Original to stdout, redacted copy to a file
cargo run --example tee -- -t application/grpc redacted.bin 'proto:2' < in.bin > out.bin
```

## Choosing a mode

| | Tee: `redactor.tee(r, ct)` | Stream: `redactor.reader(r, ct)` |
|---|---|---|
| What you read | The original bytes, unmodified | The redacted bytes |
| Where the redacted output goes | A separate buffer | The stream itself |
| Redacted protobuf fields | Removed | Overwritten in place, same size |
| Redacted JSON inside RPC frames | `"[REDACTED]"` | Same-length `"****"` |
| Redaction errors (malformed input, …) | Recorded; the original stream continues | Fail the stream |
| Memory for redacted output | Whatever you haven't taken yet ([details](#memory-and-latency)) | One read chunk |

Why the difference: protobuf sub-messages and RPC frames start with their length, so that
length goes out before the contents are seen. In stream mode it's already gone, so every
redaction has to keep sizes unchanged. In tee mode the redactor owns the output buffer, so
it writes a placeholder length and fixes it once the sub-message or frame ends. That lets
redacted fields be removed outright.

## Rules

Rules are written per codec, not per transport. JSONPath rules apply to plain JSON and to
JSON inside gRPC or Connect frames alike. A codec without rules is still parsed, but
nothing in it is redacted.

### JSON: JSONPath

A subset of [RFC 9535](https://www.rfc-editor.org/rfc/rfc9535):

| Syntax                   | Matches                       |
|--------------------------|-------------------------------|
| `$`                      | the whole document            |
| `.name`, `['name']`      | object member                 |
| `[0]`                    | array element                 |
| `.*`, `[*]`              | every member / element        |
| `['a', "b", 0]`          | any of the listed selectors   |
| `..name`, `..*`, `..[0]` | at any depth below            |

Negative indices (`[-1]`), slices (`[1:3]`) and filters (`[?@.type == 'card']`) are
rejected when the redactor is built. Each would need to see data that comes later in
the stream, such as the array length or a sibling member.

Member names are compared after decoding escapes, so `{"pass\u0077ord": ...}` matches
`$.password`.

For JSON-encoded protobuf (`application/grpc+json`, …), messages use the protobuf JSON
mapping, so rules refer to JSON field names (`$.password`), not field numbers.

### Protobuf: field paths

Dot-separated field numbers, e.g. `4.3.1`: field 1 of the message in field 3 of the message
in field 4.

* Every component except the last must be a sub-message (or group). If the field turns
  out not to be one, the rule doesn't apply there.
* Repeated fields match every occurrence.
* If one rule covers a field and another covers something inside it, the whole field is
  redacted.

There's no schema involved, so the redactor can't tell a `string` from a `bytes` from a
sub-message. That only matters in stream mode; see [Protobuf output](#protobuf).

### Forms: field names

Exact field names, e.g. `password`. They match urlencoded keys after percent-decoding
(`pass%77ord` matches `password`) and the `name` of multipart parts.

## Content types and detection

Each payload can come with its `Content-Type`. Whatever the content type pins down is used
as given. Whatever it leaves open, including when it's missing, is detected from the
payload's first bytes.

| Content type | Framing | Codec |
|---|---|---|
| `application/json`, `text/json`, `*/*+json`, NDJSON types | plain | JSON |
| `application/x-protobuf`, `application/protobuf`, `application/proto`, `*/*+proto` | plain | protobuf |
| `application/grpc`, `application/grpc-web`, `application/connect`, with optional `+proto`/`+json` | frames | from the suffix, otherwise detected |
| `application/grpc-web-text`, with optional `+proto`/`+json` | base64 frames | from the suffix, otherwise detected |
| `application/x-www-form-urlencoded` | urlencoded | form |
| `multipart/form-data; boundary=…` | multipart | form |
| `multipart/form-data` without a boundary | multipart (boundary detected) | form |
| missing, or anything else | detected | detected |

Parameters such as `; charset=utf-8` are ignored. NDJSON needs nothing special: several
whitespace-separated JSON values are always accepted, and rules apply to each one.

**Detecting the framing** relies on structure, not guesswork:

* A gRPC/Connect frame starts with a flags byte (`0x00`–`0x02`, `0x80`). For protobuf those
  bytes are a tag with field number 0, which is invalid, and no JSON or form body starts
  with a control byte.
* Base64 frames start with `A` or `g`, and must decode to a frame header with everything
  after it being base64.
* A multipart body starts with `--boundary` and a line break, which gives the boundary.

**Detecting the codec** (when there's no frame and no content type, or a frame without a
`+ext`) looks at the first 512 bytes, or the first message in a frame. Parsers are tried
from strictest to loosest, and the first that accepts the bytes wins:

1. **JSON.** Binary protobuf essentially never passes a strict JSON parser.
2. **Form**, but only if every byte is one that form encoders leave unescaped and there's
   an `=`. That excludes JSON, which always contains `"`, `{` or `:`. It also excludes
   practically all protobuf, which has bytes below `0x21` (tags of fields 1–3, short
   lengths, small numbers).
3. **Protobuf.** Text often parses as protobuf for a while, so it goes last.

If nothing accepts the payload, the result is `Error::UnrecognizedPayload`. This is a
heuristic, so pass the content type whenever you have it.

## Output

### JSON

* Each matched value (string, number, object, array, …) is replaced with
  `"[REDACTED]"`, or whatever `Options::json_replacement` is set to (any JSON value, e.g. `null`).
* Everything else, including whitespace and escape sequences, is copied byte for byte.
* With `Options::preserve_json_size(true)`, each value becomes a string of `*` of exactly
  the original byte length instead: `"hunter2"` → `"*******"`, `{"a": 1}` → `"******"`.
  Two-byte values become `""` and single digits become `0`. This keeps a
  `Content-Length` valid. In stream mode it's switched on automatically for JSON inside RPC frames.
* The input is fully validated, including inside redacted values. Invalid UTF-8 inside
  strings is passed through. Empty input is accepted.

### Protobuf

**Tee mode** removes redacted fields, including whole sub-messages and groups. The lengths of
the enclosing sub-messages are rewritten. The result is byte-for-byte what a protobuf
library encodes for the same message with those fields cleared, so it's valid whatever
the field types are.

**Stream mode** keeps every field the same size, so all lengths stay correct:

| Wire type | Redacted as |
|---|---|
| varint | `0`, padded to the original byte count (`80 80 … 00`); decoders accept this |
| fixed32 / fixed64 | zero bytes (`0`, `0.0`) |
| length-delimited | same length, contents overwritten (see below) |
| group | every field inside redacted |

What a length-delimited field is overwritten with is set by `Options::proto_fill`:

* `ProtoFill::ReservedField` (default): bytes that are valid UTF-8 *and* a valid message
  made only of unknown field 19000. That number is in the range protobuf reserves for
  itself, so it can't clash with a real field. A redacted `string`, `bytes` or
  sub-message all still decode. Packed repeated numbers decode to meaningless values.
* `ProtoFill::Zeros`: zero bytes. Fine for strings, bytes and packed numbers, but invalid
  as a sub-message.

Fields of 1–3 bytes are always zero-filled, since no non-empty message is that short.

### Forms

* **Urlencoded:** the value of each matching key is replaced with `[REDACTED]`
  (percent-encoded: `%5BREDACTED%5D`), or whatever `Options::form_replacement` is set to.
* **Multipart:** the body of each matching part is replaced, including file uploads.
  Part headers, the preamble and the epilogue are copied through.
* Neither format has length prefixes, so both modes produce the same output.

### RPC frames

gRPC, gRPC-Web and Connect wrap each message in a 5-byte header: a flags byte and a 4-byte
length. One parser handles all three.

* Each message is redacted on its own. In tee mode its length is fixed once it ends;
  in stream mode the redacted message has the same size, so the header is copied as is.
* gRPC-Web trailer frames (`0x80`) and Connect end-of-stream frames (`0x02`) are copied
  through untouched. Plain gRPC reserves those bits, so a gRPC peer rejects such frames anyway.
* Compressed messages (`grpc-encoding: gzip`, …) can't be read and produce
  `Error::CompressedGrpcMessage`.
* `grpc-web-text` is base64-decoded, redacted and re-encoded on the fly. Servers may
  encode each flush separately, so `=` padding can appear mid-stream.
  * Stream mode keeps the padding in the same places when the codec is known. When it's
    detected, the first message is held until it's decided, which shifts padding there.
  * Tee mode writes one continuous base64 stream.

## Memory and latency

No mode ever buffers a whole value, field or message of the input. What each part keeps:

| Part | Kept in memory |
|---|---|
| `RedactReader` (stream mode) | One 8 KiB read chunk, plus the output from it |
| `TeeReader` | Nothing for the original stream: it reads straight into your buffer |
| Detection | Up to 512 bytes, only while the codec is being detected (see below) |
| JSON parser | A few bytes per nesting level, plus the current key (cut off once longer than the longest name in the rules) |
| Protobuf parser | A partial tag or length (≤ 10 bytes), plus one entry per sub-message a rule reaches into |
| Form parsers | The current urlencoded key / part headers (capped at 16 KiB), plus up to a boundary's length while checking for a delimiter |
| RPC frames / base64 | The 5-byte header / a few bytes of base64 |

Nesting is capped by `Options::max_depth` (default 256) so hostile input can't grow
the parser state.

In stream mode, output keeps pace with input, apart from a few bytes:

* the start of the payload while its codec is detected: up to 512 bytes, or up to the
  first message in a frame. A content type that names the codec avoids this.
* one byte inside a same-length JSON value, because its closing `"` can only be written
  once the value ends;
* up to 3 characters of base64, or a boundary's length in a multipart part.

In tee mode, the redacted copy can't be final where a length may still change. Call
`tee.take_redacted_ready()` (or `RedactedCopy::take_ready`) to take the part that is final,
and ship it as you go. What stays behind:

* JSON and forms: nothing.
* RPC frames: the current message.
* Protobuf: the outermost open sub-message that a rule reaches into. Sub-messages no rule
  touches are copied straight through.

If you only call `into_redacted()` at the end, the whole copy is held. There's no size
cap built in.

Measured on a 199 MB JSON file (release build, macOS laptop), with rules for all three
codecs:

| | Time | Peak memory (whole process) |
|---|---|---|
| `redact` example, content type given | ~0.5 s | ~3 MB |
| `redact` example, codec detected | ~0.65 s | ~3 MB |
| `tee` example, taking ready output as it goes | ~0.6 s | ~5 MB |

## Errors

`Error` covers bad rules, unrecognized payloads, malformed or truncated input, the depth
limit and compressed gRPC messages.

* **Stream mode:** the redact decision for each byte is made before the byte is written, so
  everything output before an error is safely redacted. The output just stops at that
  point. `RedactReader` hands out that output, then returns `io::ErrorKind::InvalidData`.
* **Tee mode:** the original stream is never affected. `tee.redaction_error()` reports the
  problem, and `into_redacted()` returns it.
* `into_redacted()` also fails if the reader wasn't read to the end. A cut-off protobuf
  message can look complete, so a partial copy is never returned as if it were whole.

## API overview

| Item | Purpose |
|---|---|
| `Redactor::builder()` | `.json(rules)`, `.proto(rules)`, `.form(rules)`, `.options(Options)`, `.build()` |
| `redactor.tee(r, ct) -> TeeReader<R>` | Original bytes out; `take_redacted_ready()`, `into_redacted()`, `into_parts()`, `redaction_error()` |
| `redactor.reader(r, ct) -> RedactReader<R>` | Redacted bytes out |
| `redactor.redact(r, &mut w, ct).await` | Copy redacted bytes to a writer |
| `redactor.redacted_copy(ct) -> RedactedCopy` | Tee mode without tokio: `feed(&[u8])`, `take_ready()`, `finish()` |
| `redactor.stream(ct) -> StreamRedactor` | Stream mode without tokio: `feed(&[u8], &mut Vec<u8>)`, `finish(&mut Vec<u8>)` |
| `Options` | `json_replacement`, `preserve_json_size`, `form_replacement`, `proto_fill`, `max_depth` |
| `JsonPath`, `FieldPath` | Parse and validate a single rule |

`ct` is the payload's content type as an `Option<&str>`. Output never depends on how the
input is split into chunks.

## Limitations

* No JSONPath filters, slices or negative indices (see [Rules](#json-jsonpath)).
* No schema: protobuf rules use field numbers, and JSON-encoded protobuf needs separate
  JSONPath rules.
* Codec detection without a content type is a heuristic (see
  [Content types and detection](#content-types-and-detection)).
* Compressed gRPC/Connect messages are rejected rather than decompressed.
* Form rules are exact names; nested JSON inside a multipart part isn't redacted by JSON rules.
* No built-in size cap for the redacted copy in tee mode.

## Development

```sh
cargo test     # 70 tests
cargo clippy --all-targets
```

The tests include:

* A randomized comparison of the JSON redactor against a separate, simple tree-based
  implementation (5,000 documents × rule sets × random chunk sizes, in both normal and
  same-length mode, with the codec detected in half the cases).
* Protobuf output decoded with `prost`. In tee mode it's compared byte for byte with
  `prost`'s own encoding of the expected message (500 random cases).
* Every format through one redactor with a full, partial or missing content type, in both
  modes, fed one byte at a time.
* 3,000 random protobuf messages with JSON- and form-like strings, and random forms, all
  detected without a content type.

Dependencies: `tokio` (only the `io-util` feature) and `pin-project-lite`.
