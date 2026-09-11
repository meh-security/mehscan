use serde::{Deserialize, Serialize};

use crate::{Coverage, Evidence, SecurityPath};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangedFileStatus {
    Added,
    Modified,
    Deleted,
    Renamed,
    Untracked,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChangedLineRange {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChangedFile {
    pub path: String,
    pub status: ChangedFileStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed_lines: Vec<ChangedLineRange>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ImpactScopeFile {
    pub path: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ImpactScanScope {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    pub strategy: String,
    /// Which findings are returned after the scan: `changed_locations`,
    /// `impact_scope`, or `all` after a conservative full fallback.
    pub result_policy: String,
    pub full_scan: bool,
    pub included_file_count: usize,
    pub changed_files: Vec<ChangedFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub included_files: Vec<ImpactScopeFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanRequest {
    pub root: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLevel {
    Warning,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub level: DiagnosticLevel,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanResult {
    pub schema_version: String,
    pub root: String,
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security_paths: Vec<SecurityPath>,
    pub coverage: Coverage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact_scope: Option<ImpactScanScope>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
}
