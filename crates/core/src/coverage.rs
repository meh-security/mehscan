use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Language;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    Scanned,
    SecretScanned,
    SecretSkipped,
    Ignored,
    Unsupported,
    ParseFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileCoverage {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    pub status: FileStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Routine exclusions omitted from the per-path code-scan ledger. Counts
/// remain in `CoverageTotals`; files may still supply project context.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OmittedExtensionCoverage {
    #[serde(default, skip_serializing_if = "is_zero")]
    pub non_source: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub secret_scan_disabled: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unsupported_source: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CoverageTotals {
    pub discovered: usize,
    pub scanned: usize,
    pub ignored: usize,
    pub unsupported: usize,
    pub parse_failed: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub secret_scanned: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub secret_skipped: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub secret_suppressed: usize,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LanguageCoverage {
    pub discovered: usize,
    pub scanned: usize,
    pub parse_failed: usize,
    pub evidence: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CweSupportLevel {
    Partial,
    Full,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CweCoverage {
    pub cwe: String,
    pub level: CweSupportLevel,
    /// Languages backed by loaded declarative rules for this scan.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declarative_languages: Vec<Language>,
    /// Languages where a procedural producer emitted matching evidence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_procedural_languages: Vec<Language>,
    /// Union retained for clients that only need the effective claim.
    pub supported_languages: Vec<Language>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub language_independent: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProducerCoverage {
    pub loaded_declarative_rules: usize,
    pub observed_procedural_evidence: usize,
    /// Procedural evidence whose file could not be attributed to a scanner
    /// language. It remains visible without widening a language/CWE claim.
    pub unattributed_procedural_evidence: usize,
}

impl ProducerCoverage {
    fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Coverage {
    pub totals: CoverageTotals,
    pub languages: BTreeMap<Language, LanguageCoverage>,
    pub security_surfaces: BTreeMap<String, usize>,
    pub cwe: Vec<CweCoverage>,
    #[serde(default, skip_serializing_if = "ProducerCoverage::is_empty")]
    pub producers: ProducerCoverage,
    /// Analyzed files and exclusions that need a path-specific explanation.
    pub files: Vec<FileCoverage>,
    /// Routine exclusions are counted by extension rather than repeated here.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub omitted_files_by_extension: BTreeMap<String, OmittedExtensionCoverage>,
    /// Pruned directories are listed explicitly so ignored content is not silent.
    pub ignored_subtrees: Vec<String>,
}
