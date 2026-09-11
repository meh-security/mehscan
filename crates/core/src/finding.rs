use serde::{Deserialize, Serialize};

use crate::Location;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Unknown,
    Note,
    Low,
    Medium,
    High,
    Critical,
}

/// A confirmed result. The deterministic code scanner emits `Evidence`, not
/// `Finding`; this type reserves the stable boundary for later AI decisions.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub severity: Severity,
    pub cwe: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub confidence: f32,
    pub exploitability: String,
    pub locations: Vec<Location>,
    pub rationale: String,
    pub remediation: String,
}
