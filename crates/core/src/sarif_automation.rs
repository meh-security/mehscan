//! Stable SARIF partitions, separate from reviewer and native finding identity.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedAutomation")]
pub struct SarifAutomationConfiguration {
    category: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedAutomation {
    category: String,
    #[serde(default)]
    run_id: Option<String>,
}

impl TryFrom<UncheckedAutomation> for SarifAutomationConfiguration {
    type Error = String;
    fn try_from(value: UncheckedAutomation) -> Result<Self, Self::Error> {
        Self::new(&value.category, value.run_id.as_deref())
    }
}

impl SarifAutomationConfiguration {
    pub fn new(category: &str, run_id: Option<&str>) -> Result<Self, String> {
        if category.len() > 256 || !category.split('/').all(valid_segment) {
            return Err("--sarif-category must be 1-256 ASCII characters in nonempty slash-separated segments using letters, digits, '.', '_' or '-' (excluding '.' and '..' segments)".into());
        }
        if run_id.is_some_and(|id| id.len() > 128 || !valid_segment(id)) {
            return Err("--sarif-run-id must be 1-128 ASCII letters, digits, '.', '_' or '-' without slashes (excluding '.' and '..')".into());
        }
        Ok(Self {
            category: category.into(),
            run_id: run_id.map(str::to_owned),
        })
    }

    pub fn category(&self) -> &str {
        &self.category
    }
    pub fn run_id(&self) -> Option<&str> {
        self.run_id.as_deref()
    }

    /// The trailing slash preserves a category when no run ID is supplied.
    pub fn automation_id(&self) -> String {
        format!(
            "{}/{}",
            self.category,
            self.run_id.as_deref().unwrap_or_default()
        )
    }
}

fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && !matches!(segment, "." | "..")
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingAnalysisScope {
    ScanRoot,
    ChangeComparison,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingAlertDisposition {
    NotEstablished,
}

/// Advisory export metadata. GitHub ignores these custom properties; they do
/// not prevent a consumer from closing absent alerts after an unsafe upload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingSarifPublication {
    pub automation: SarifAutomationConfiguration,
    pub analysis_scope: FindingAnalysisScope,
    /// Completeness of validated manifest work, never repository-wide coverage.
    pub review_work_complete: bool,
    pub alert_disposition: FindingAlertDisposition,
}

impl crate::FindingReport {
    pub fn default_sarif_category(&self) -> &'static str {
        if self.scan.impact_scope.is_some() {
            "mehscan/triaged/changed"
        } else {
            "mehscan/triaged"
        }
    }

    pub fn sarif_publication(&self) -> FindingSarifPublication {
        let work = &self.triage.work;
        FindingSarifPublication {
            automation: self.scan.sarif_automation.clone().unwrap_or_else(|| {
                SarifAutomationConfiguration::new(self.default_sarif_category(), None)
                    .expect("valid default category")
            }),
            analysis_scope: if self.scan.impact_scope.is_some() {
                FindingAnalysisScope::ChangeComparison
            } else {
                FindingAnalysisScope::ScanRoot
            },
            review_work_complete: work.complete
                && work.completed_review_count == work.scheduled_review_count
                && work.completed_bundle_count == work.scheduled_bundle_count
                && work.missing_review_ids.is_empty()
                && work.invalid_review_ids.is_empty()
                && work.deferred_review_ids.is_empty(),
            alert_disposition: FindingAlertDisposition::NotEstablished,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_and_run_id_have_unambiguous_github_boundaries() {
        let no_run = SarifAutomationConfiguration::new("mehscan/triaged", None).unwrap();
        assert_eq!(no_run.automation_id(), "mehscan/triaged/");
        for id in ["attempt-1", "attempt-2"] {
            let config = SarifAutomationConfiguration::new("mehscan/triaged", Some(id)).unwrap();
            let automation_id = config.automation_id();
            assert_eq!(
                automation_id.rsplit_once('/'),
                Some(("mehscan/triaged", id))
            );
        }
        for category in [
            "",
            "bad/",
            "/bad",
            "bad//category",
            "bad/../category",
            "bad category",
            "bad\ncategory",
            "https://host",
            "é",
        ] {
            assert!(
                SarifAutomationConfiguration::new(category, None).is_err(),
                "{category:?}"
            );
        }
        for id in ["", "bad/id", "bad\nid", "..", "é"] {
            assert!(
                SarifAutomationConfiguration::new("valid", Some(id)).is_err(),
                "{id:?}"
            );
        }
        assert!(SarifAutomationConfiguration::new(&"x".repeat(257), None).is_err());
        assert!(SarifAutomationConfiguration::new("valid", Some(&"x".repeat(129))).is_err());
    }

    #[test]
    fn deserialization_also_validates_partition_boundaries() {
        let config =
            SarifAutomationConfiguration::new("mehscan/release-delta", Some("42")).unwrap();
        let bytes = serde_json::to_vec(&config).unwrap();
        assert_eq!(
            serde_json::from_slice::<SarifAutomationConfiguration>(&bytes).unwrap(),
            config
        );
        assert!(
            serde_json::from_str::<SarifAutomationConfiguration>(
                r#"{"category":"valid","run_id":"nested/run"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<SarifAutomationConfiguration>(
                r#"{"category":"valid","allow_close":true}"#
            )
            .is_err()
        );
    }
}
