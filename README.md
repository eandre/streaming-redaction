# streaming-parse

Streaming redaction of JSON and Protobuf payloads (including gRPC, gRPC-Web and Connect)
for tokio. You give it a byte stream, a content type and a list of rules, and it produces a
redacted version of the data as the bytes arrive. Memory use doesn't depend on payload size.

It runs in one of two modes:

* **Tee**: the original bytes pass through untouched while a redacted copy is built on
  the side. Use this to forward a request or response and record a safe version of it
  (logs, traces, audit).
* **Stream**: the stream itself is redacted, and the output is a drop-in replacement for
  the input.

## Quick start

```rust
use streaming_parse::Redactor;

// Compile the rules once per content type and reuse them. Redactor is Clone + Send + Sync.
let redactor = Redactor::new("application/json", ["$..password", "$.cards[*].number"])?;

// Tee: forward the original body, keep a redacted copy.
let mut tee = redactor.tee(body);
tokio::io::copy(&mut tee, &mut upstream).await?;      // original bytes, unmodified
let redacted: Vec<u8> = tee.into_redacted()?;

// Stream: the reader yields redacted bytes.
let mut redacted = redactor.reader(body);
tokio::io::copy(&mut redacted, &mut sink).await?;
```

For protobuf, rules are field numbers:

```rust
// Field 2, field 1 inside the message in field 4, and field 1 of every element of field 5.
let redactor = Redactor::new("application/grpc", ["2", "4.1", "5.1"])?;
```

Two example programs read stdin:

```sh
# Redacted stream to stdout
echo '{"user":{"password":"x"}}' | cargo run --example redact -- application/json '$..password'

# Original to stdout, redacted copy to a file
cargo run --example tee -- application/json redacted.json '$..password' < in.json > out.json
```

## Choosing a mode

| | Tee: `redactor.tee(r)` | Stream: `redactor.reader(r)` |
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

The rule syntax depends on how the messages are encoded, not on the transport. Use
JSONPath for JSON (including `application/grpc+json`) and field-number paths for protobuf.

### JSONPath

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

### Protobuf field paths

Dot-separated field numbers, e.g. `4.3.1`: field 1 of the message in field 3 of the message
in field 4.

* Every component except the last must be a sub-message (or group). If the field turns
  out not to be one, the rule doesn't apply there.
* Repeated fields match every occurrence.
* If one rule covers a field and another covers something inside it, the whole field is
  redacted.

There's no schema involved, so the redactor can't tell a `string` from a `bytes` from a
sub-message. That only matters in stream mode; see [Protobuf output](#protobuf).

For the `+json` RPC codecs, messages use the protobuf JSON mapping, so rules refer to JSON
field names (`$.password`). One rule set can't cover both codecs without a schema to map
numbers to names.

## Content types

Parameters such as `; charset=utf-8` are ignored.

| Content type | `Format` |
|---|---|
| `application/json`, `text/json`, `*/*+json` | `Json` |
| `application/x-ndjson`, `application/jsonl`, `application/jsonlines`, … | `JsonLines` (rules apply per document) |
| `application/x-protobuf`, `application/protobuf`, `application/proto`, `*/*+proto` | `Protobuf` |
| `application/grpc`, `application/grpc+proto`, `application/grpc+json` | `Grpc(codec)` |
| `application/grpc-web`, `application/grpc-web+proto`, `…+json` | `GrpcWeb(codec)` |
| `application/grpc-web-text`, `application/grpc-web-text+proto`, `…+json` | `GrpcWebText(codec)` |
| `application/connect+proto`, `application/connect+json` | `ConnectStream(codec)` |

gRPC types without a suffix default to protobuf. Other codecs (`+thrift`, …) are rejected.
Connect unary RPCs use plain `application/proto` and `application/json`. To skip
content-type detection, use `Redactor::for_format(Format::Grpc(Codec::Json), rules, options)`.

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

### RPC envelopes

gRPC, gRPC-Web and Connect wrap each message in a 5-byte header: a flags byte and a 4-byte
length.

* Each message is redacted on its own. In tee mode its length is fixed once it ends;
  in stream mode the redacted message has the same size, so the header is copied as is.
* gRPC-Web trailer frames and Connect end-of-stream frames are passed through untouched.
* Compressed messages (`grpc-encoding: gzip`, …) can't be read and produce
  `Error::CompressedGrpcMessage`.
* `grpc-web-text` is base64-decoded, redacted and re-encoded on the fly. Servers may
  encode each flush separately, so `=` padding can appear mid-stream.
  * Stream mode keeps the padding in the same places.
  * Tee mode writes one continuous base64 stream.

## Memory and latency

No mode ever buffers a whole value, field or message of the input. What each part keeps:

| Part | Kept in memory |
|---|---|
| `RedactReader` (stream mode) | One 8 KiB read chunk, plus the output from it |
| `TeeReader` | Nothing for the original stream: it reads straight into your buffer |
| JSON parser | A few bytes per nesting level, plus the current key (cut off once longer than the longest name in the rules) |
| Protobuf parser | A partial tag or length (≤ 10 bytes), plus one entry per sub-message a rule reaches into |
| RPC frames / base64 | The 5-byte header / a few bytes of base64 |

Nesting is capped by `Options::max_depth` (default 256) so hostile input can't grow
the parser state.

In stream mode, output keeps pace with input. The only things held back are one byte
inside a same-length JSON value, because its closing `"` can only be written once the value
ends, and up to 3 characters of base64.

In tee mode, the redacted copy can't be final where a length may still change. Call
`tee.take_redacted_ready()` (or `RedactedCopy::take_ready`) to take the part that is final,
and ship it as you go. What stays behind:

* JSON: nothing.
* RPC envelopes: the current message.
* Protobuf: the outermost open sub-message that a rule reaches into. Sub-messages no rule
  touches are copied straight through.

If you only call `into_redacted()` at the end, the whole copy is held. There's no size
cap built in.

Measured on a 199 MB JSON file (release build, macOS laptop):

| | Time | Peak memory (whole process) |
|---|---|---|
| `redact` example (stream) | ~1.0 s | ~3 MB |
| `tee` example, taking ready output as it goes | ~0.6 s | ~5 MB |

## Errors

`Error` covers bad rules, unsupported content types, malformed or truncated input, the depth
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
| `Redactor::new(content_type, rules)` | Build from a content type and rule strings |
| `Redactor::with_options(…, Options)` | Same, with options |
| `Redactor::for_format(format, rules, options)` | Explicit format instead of content type |
| `Redactor::json(format, Vec<JsonPath>, …)` / `protobuf(format, Vec<FieldPath>, …)` | Pre-parsed rules |
| `redactor.tee(r) -> TeeReader<R>` | Original bytes out; `take_redacted_ready()`, `into_redacted()`, `into_parts()`, `redaction_error()` |
| `redactor.reader(r) -> RedactReader<R>` | Redacted bytes out |
| `redactor.redact(r, &mut w).await` | Copy redacted bytes to a writer |
| `redactor.redacted_copy() -> RedactedCopy` | Tee mode without tokio: `feed(&[u8])`, `take_ready()`, `finish()` |
| `redactor.stream() -> StreamRedactor` | Stream mode without tokio: `feed(&[u8], &mut Vec<u8>)`, `finish(&mut Vec<u8>)` |
| `Options` | `json_replacement`, `preserve_json_size`, `proto_fill`, `max_depth` |
| `Format`, `Codec` | Wire format; `Format::from_content_type` |

Output never depends on how the input is split into chunks.

## Limitations

* No JSONPath filters, slices or negative indices (see [Rules](#jsonpath)).
* No schema: protobuf rules use field numbers, and JSON-encoded protobuf needs separate
  JSONPath rules.
* Compressed gRPC/Connect messages are rejected rather than decompressed.
* No built-in size cap for the redacted copy in tee mode.

## Development

```sh
cargo test     # 54 tests
cargo clippy --all-targets
```

The tests include:

* A randomized comparison of the JSON redactor against a separate, simple tree-based
  implementation (5,000 documents × rule sets × random chunk sizes, in both normal and
  same-length mode).
* Protobuf output decoded with `prost`. In tee mode it's compared byte for byte with
  `prost`'s own encoding of the expected message (500 random cases).
* Every RPC protocol with both codecs, including base64 padding at awkward positions.

Dependencies: `tokio` (only the `io-util` feature) and `pin-project-lite`.
