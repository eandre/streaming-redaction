use std::fmt;

/// Errors from building a redactor or from redacting a payload.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The payload isn't JSON, protobuf or a form (or not one this crate
    /// can tell apart without a content type).
    UnrecognizedPayload,
    /// A redaction rule could not be parsed.
    InvalidRule { rule: String, reason: String },
    /// The options are invalid (e.g. the JSON replacement is not valid JSON).
    InvalidOptions(String),
    /// The input is not well-formed for its format.
    Malformed { offset: u64, reason: &'static str },
    /// The input ended in the middle of a value.
    UnexpectedEof { offset: u64 },
    /// The input is nested deeper than [`Options::max_depth`](crate::Options).
    DepthLimitExceeded { offset: u64, limit: usize },
    /// A gRPC message is compressed, so its contents can't be inspected.
    CompressedGrpcMessage { offset: u64 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnrecognizedPayload => {
                write!(
                    f,
                    "payload is not recognizable as JSON, protobuf or form data"
                )
            }
            Error::InvalidRule { rule, reason } => {
                write!(f, "invalid redaction rule {rule:?}: {reason}")
            }
            Error::InvalidOptions(msg) => write!(f, "invalid options: {msg}"),
            Error::Malformed { offset, reason } => {
                write!(f, "malformed input at byte {offset}: {reason}")
            }
            Error::UnexpectedEof { offset } => {
                write!(f, "unexpected end of input at byte {offset}")
            }
            Error::DepthLimitExceeded { offset, limit } => {
                write!(
                    f,
                    "nesting depth limit of {limit} exceeded at byte {offset}"
                )
            }
            Error::CompressedGrpcMessage { offset } => {
                write!(
                    f,
                    "compressed gRPC message at byte {offset} can't be redacted"
                )
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    }
}
