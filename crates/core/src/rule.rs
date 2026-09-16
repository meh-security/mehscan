use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Capability, Confidence, EvidenceKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    C,
    Cpp,
    Csharp,
    Java,
    Javascript,
    Typescript,
    Tsx,
    Python,
    Go,
    Rust,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PatternSpec {
    pub pattern: String,
    /// Optional parse context for syntactically ambiguous standalone patterns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// AST kind selected from `context`. Must be supplied together with `context`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    /// Maps semantic capture names to ast-grep metavariable names.
    #[serde(default)]
    pub captures: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MatchSpec {
    pub any: Vec<PatternSpec>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SymbolSpec {
    /// Canonical callable name used by the language-independent security rule.
    pub canonical: String,
    /// Maps semantic capture names to zero-based call argument indexes.
    #[serde(default)]
    pub captures: BTreeMap<String, usize>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AiGuidance {
    #[serde(default)]
    pub investigate: Vec<String>,
    #[serde(default)]
    pub verify: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuleProvenance {
    pub note: String,
    #[serde(default)]
    pub references: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub version: u32,
    pub title: String,
    pub language: Language,
    pub kind: EvidenceKind,
    pub capability: Capability,
    #[serde(default = "default_confidence")]
    pub confidence: Confidence,
    #[serde(default)]
    pub cwe: Vec<String>,
    #[serde(rename = "match")]
    pub match_spec: MatchSpec,
    #[serde(default)]
    pub symbols: Vec<SymbolSpec>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub ai: AiGuidance,
    pub provenance: RuleProvenance,
}

fn default_confidence() -> Confidence {
    Confidence::High
}
