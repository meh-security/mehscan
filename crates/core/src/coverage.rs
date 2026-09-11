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
    pub supported_languages: Vec<Language>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub language_independent: bool,
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
    pub files: Vec<FileCoverage>,
    /// Pruned directories are listed explicitly so ignored content is not silent.
    pub ignored_subtrees: Vec<String>,
}
