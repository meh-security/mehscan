use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Availability, AvailabilityState, ConfigurationDependency, EvidenceContext, Language};

/// Established source selection and its declaration provenance, not a verdict.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceConfiguration {
    pub availability: Availability,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<ConfigurationDependency>,
}

impl SourceConfiguration {
    pub fn apply_to(&self, context: &mut EvidenceContext) {
        const MAX_CONDITION_BYTES: usize = 8192;
        const MAX_DEPENDENCIES: usize = 64;
        const LIMIT: &str = "configuration detail limit reached; inspect source declarations";
        let local = context.availability.take().unwrap_or(Availability {
            state: AvailabilityState::Always,
            condition: None,
        });
        let mut state = match (self.availability.state, local.state) {
            (AvailabilityState::Excluded, _) | (_, AvailabilityState::Excluded) => {
                AvailabilityState::Excluded
            }
            (AvailabilityState::Unknown, _) | (_, AvailabilityState::Unknown) => {
                AvailabilityState::Unknown
            }
            (AvailabilityState::Always, AvailabilityState::Always) => AvailabilityState::Always,
            _ => AvailabilityState::Conditional,
        };
        let mut limited = false;
        let mut condition = match (
            self.availability.condition.as_deref(),
            local.condition.as_deref(),
        ) {
            (Some(a), Some(b)) if a != b => {
                if a.len().saturating_add(b.len()).saturating_add(8) > MAX_CONDITION_BYTES {
                    limited = true;
                    Some(LIMIT.into())
                } else {
                    Some(format!("({a}) && ({b})"))
                }
            }
            (Some(a), _) | (_, Some(a)) => {
                if a.len() > MAX_CONDITION_BYTES {
                    limited = true;
                    Some(LIMIT.into())
                } else {
                    Some(a.to_string())
                }
            }
            _ => None,
        };
        for dependency in &self.dependencies {
            if !context.configuration_dependencies.contains(dependency) {
                if context.configuration_dependencies.len() >= MAX_DEPENDENCIES {
                    limited = true;
                    break;
                }
                context.configuration_dependencies.push(dependency.clone());
            }
        }
        if limited {
            if state != AvailabilityState::Excluded {
                state = AvailabilityState::Unknown;
            }
            condition = Some(LIMIT.into());
        }
        context.availability = Some(Availability { state, condition });
    }
}

#[cfg(test)]
mod configuration_tests {
    use super::*;

    #[test]
    fn composed_configuration_is_bounded_without_manufacturing_unconditional_or_excluded_state() {
        let mut context = EvidenceContext::default();
        let mut configuration = SourceConfiguration {
            availability: Availability {
                state: AvailabilityState::Conditional,
                condition: Some("feature=\"first\"".into()),
            },
            dependencies: Vec::new(),
        };
        configuration.apply_to(&mut context);
        configuration.availability.condition = Some("x".repeat(8192));
        configuration.apply_to(&mut context);
        assert_eq!(
            context.availability.as_ref().unwrap().state,
            AvailabilityState::Unknown
        );
        assert!(
            context
                .availability
                .as_ref()
                .unwrap()
                .condition
                .as_ref()
                .unwrap()
                .contains("limit reached")
        );
        configuration.availability.state = AvailabilityState::Excluded;
        configuration.apply_to(&mut context);
        assert_eq!(
            context.availability.as_ref().unwrap().state,
            AvailabilityState::Excluded
        );
    }
}

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
    /// Non-unconditional source applicability, including files with no code facts.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub source_configurations: BTreeMap<String, SourceConfiguration>,
    /// Routine exclusions are counted by extension rather than repeated here.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub omitted_files_by_extension: BTreeMap<String, OmittedExtensionCoverage>,
    /// Pruned directories are listed explicitly so ignored content is not silent.
    pub ignored_subtrees: Vec<String>,
}
