use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Position {
    /// One-based line number.
    pub line: usize,
    /// One-based Unicode scalar column.
    pub column: usize,
    /// Zero-based byte offset in the source file.
    pub byte_offset: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Location {
    /// Forward-slash-normalized path relative to the scan root.
    pub path: String,
    pub start: Position,
    pub end: Position,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Capture {
    pub text: String,
    pub location: Location,
}
