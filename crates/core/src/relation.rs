use std::collections::BTreeSet;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::Capability;

/// A source selector for a deterministic security relationship.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelationSource {
    pub capabilities: Vec<Capability>,
}

impl RelationSource {
    pub fn accepts(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationSourceWire {
    #[serde(default)]
    capability: Option<Capability>,
    #[serde(default)]
    capabilities: Option<Vec<Capability>>,
}

impl<'de> Deserialize<'de> for RelationSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RelationSourceWire::deserialize(deserializer)?;
        let capabilities = match (wire.capability, wire.capabilities) {
            (Some(capability), None) => vec![capability],
            (None, Some(capabilities)) => capabilities,
            (None, None) => {
                return Err(D::Error::custom(
                    "relation source requires capability or capabilities",
                ));
            }
            (Some(_), Some(_)) => {
                return Err(D::Error::custom(
                    "relation source cannot define both capability and capabilities",
                ));
            }
        };
        let unique = capabilities.iter().copied().collect::<BTreeSet<_>>();
        if capabilities.is_empty() || unique.len() != capabilities.len() {
            return Err(D::Error::custom(
                "relation source capabilities must be non-empty and unique",
            ));
        }
        Ok(Self { capabilities })
    }
}

/// A sink selector plus the semantic capture roles that may receive a source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationSink {
    pub capability: Capability,
    pub input_roles: Vec<String>,
}

/// How a protection observation is associated with a source-to-sink relation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionApplication {
    /// The protection and sink share a semantic capture, such as a query or
    /// command, and protected values are supplied through separate roles.
    RelatedCapture,
    /// The protection is a value-producing expression that encloses the source
    /// and is itself enclosed by a sink input.
    ValueTransform,
}

/// A conservative protection association. Presence is contextual evidence,
/// not a declaration that the path is safe.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationProtection {
    pub capability: Capability,
    pub application: ProtectionApplication,
    pub relation_role: String,
    pub value_roles: Vec<String>,
}

/// Selects the bounded deterministic builder used by a relation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationStrategy {
    BoundedLocalValue,
    StoredSubtitleFile,
}

/// Data-driven security relationship compiled independently from syntax
/// matchers. A relation creates review candidates; it does not confirm a
/// vulnerability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationContract {
    pub id: String,
    pub version: u32,
    pub source: RelationSource,
    pub sink: RelationSink,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection: Option<RelationProtection>,
    pub cwe_candidates: Vec<String>,
    pub strategy: RelationStrategy,
}
