//! Repository analysis and security-evidence enumeration.

pub mod benchmark;
pub mod code;
mod csharp_review;
pub mod evaluation;
pub mod impact;
pub mod investigation;
mod report_policy;
pub mod repository;
pub mod rules;
pub mod secrets;

use std::fmt::{Display, Formatter};
use std::path::Path;

use mehscan_core::{ChangedFile, ScanResult};

pub use code::{FileAnalysisProfile, ScanProfile};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanOptions {
    pub include_tests: bool,
    pub jobs: Option<usize>,
    /// Secret detection is opt-in while its precision is being redesigned.
    pub scan_secrets: bool,
    pub impact_scope: Option<ImpactScopeRequest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImpactScopeRequest {
    pub mode: String,
    pub base: Option<String>,
    pub changed_files: Vec<ChangedFile>,
    pub diff_mode: ImpactDiffMode,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ImpactDiffMode {
    /// Analyze the complete repository, then return observations and paths
    /// that touch changed locations.
    #[default]
    Full,
    /// Analyze a bounded changed/dependent scope, falling back to a complete
    /// repository result when narrowing is unsafe.
    Impact,
}

#[derive(Debug)]
pub struct EngineError(pub String);

impl Display for EngineError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for EngineError {}

impl From<std::io::Error> for EngineError {
    fn from(value: std::io::Error) -> Self {
        Self(value.to_string())
    }
}

pub fn scan_path(path: impl AsRef<Path>) -> Result<ScanResult, EngineError> {
    scan_path_with_options(path, ScanOptions::default())
}

pub fn scan_path_with_options(
    path: impl AsRef<Path>,
    options: ScanOptions,
) -> Result<ScanResult, EngineError> {
    scan_path_profiled_with_options(path, options).map(|(result, _)| result)
}

pub fn scan_path_profiled(
    path: impl AsRef<Path>,
) -> Result<(ScanResult, ScanProfile), EngineError> {
    scan_path_profiled_with_options(path, ScanOptions::default())
}

pub fn scan_path_profiled_with_options(
    path: impl AsRef<Path>,
    options: ScanOptions,
) -> Result<(ScanResult, ScanProfile), EngineError> {
    let total_started = std::time::Instant::now();
    let rules_started = std::time::Instant::now();
    let rules = rules::load_builtin_rules()?;
    let relations = rules::load_builtin_relations(&rules)?;
    let rule_loading_microseconds = rules_started.elapsed().as_micros();
    let (result, mut profile) = code::scan_profiled(path.as_ref(), &rules, &relations, options)?;
    profile.rule_loading_microseconds = rule_loading_microseconds;
    profile.total_microseconds = total_started.elapsed().as_micros();
    Ok((result, profile))
}
