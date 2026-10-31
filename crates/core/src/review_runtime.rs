//! Effective review profile and trusted runtime compatibility, not a spend promise.
use crate::ReviewCompletionPolicy;
use serde::{Deserialize, Serialize};

pub const REVIEW_WORKER_PROTOCOL: u32 = 2;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewResearchLimits {
    pub rounds: usize,
    pub queries: usize,
    pub bytes: usize,
    pub timeout_seconds: usize,
}

impl ReviewResearchLimits {
    pub fn for_policy(policy: ReviewCompletionPolicy) -> Self {
        match policy {
            // Coverage selection differs; each selected investigation receives
            // the same bounded allowance exercised by the live Value studies.
            ReviewCompletionPolicy::Value | ReviewCompletionPolicy::Comprehensive => Self {
                rounds: 5,
                queries: 24,
                bytes: 512 * 1024,
                timeout_seconds: 900,
            },
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.rounds > 10
            || self.queries > 100
            || !(1..=8 * 1024 * 1024).contains(&self.bytes)
            || !(1..=3600).contains(&self.timeout_seconds)
        {
            return Err("review research limits exceed supported bounds".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod default_profile_tests {
    use super::*;

    #[test]
    fn selected_work_has_the_same_allowance_in_both_coverage_profiles() {
        let limits = ReviewResearchLimits::for_policy(ReviewCompletionPolicy::Value);
        assert_eq!(limits.rounds + 1, 6);
        assert_eq!(limits.queries, 24);
        assert_eq!(limits.bytes, 524_288);
        assert_eq!(limits.timeout_seconds, 900);
        assert_eq!(
            limits,
            ReviewResearchLimits::for_policy(ReviewCompletionPolicy::Comprehensive)
        );
        // Previously bound work and explicit smaller overrides remain valid.
        assert!(
            ReviewResearchLimits {
                rounds: 2,
                queries: 8,
                bytes: 131_072,
                timeout_seconds: 300
            }
            .validate()
            .is_ok()
        );
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewProviderContract {
    pub schema_version: String,
    pub provider: String,
    pub executable_version: String,
    pub model: String,
    pub reasoning_effort: String,
}

impl ReviewProviderContract {
    pub fn validate(&self) -> Result<(), String> {
        let label = |value: &str| {
            !value.is_empty()
                && value.as_bytes()[0].is_ascii_alphanumeric()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
        };
        if self.schema_version != "1"
            || self.provider != "codex-cli"
            || !label(&self.executable_version)
            || !label(&self.model)
            || !matches!(
                self.reasoning_effort.as_str(),
                "low" | "medium" | "high" | "xhigh" | "max" | "ultra"
            )
        {
            return Err("unsupported or inconsistent review provider contract".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRuntimeContract {
    pub schema_version: String,
    pub policy: ReviewCompletionPolicy,
    pub worker_protocol: u32,
    pub engine_version: String,
    pub engine_sha256: String,
    pub skill_bundle_id: String,
    pub limits: ReviewResearchLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ReviewProviderContract>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orchestration: Option<ReviewOrchestrationContract>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBudgetLimits {
    pub model_calls: usize,
    pub queries: usize,
    pub bytes: usize,
    pub timeout_seconds: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewOrchestrationContract {
    pub expert: ReviewProviderContract,
    pub case_limits: ReviewBudgetLimits,
    pub run_limits: ReviewBudgetLimits,
    pub max_reviews_per_job: usize,
    pub audit_percent: usize,
    pub audit_seed: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality: Option<ReviewQualityPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewQualityPolicy {
    pub adjudicate_disagreements: bool,
    pub final_qa: bool,
}

impl ReviewOrchestrationContract {
    pub fn validate(&self, primary: Option<&ReviewProviderContract>) -> Result<(), String> {
        let primary = primary.ok_or("tiered review requires a bound primary provider")?;
        self.expert.validate()?;
        if self.expert.model == primary.model {
            return Err("expert review requires a different model, not a higher effort".into());
        }
        let case = &self.case_limits;
        let run = &self.run_limits;
        if !(2..=44).contains(&case.model_calls)
            || case.queries > 200
            || !(1..=16 * 1024 * 1024).contains(&case.bytes)
            || !(1..=7200).contains(&case.timeout_seconds)
            || !(1..=100_000).contains(&run.model_calls)
            || run.queries > 1_000_000
            || !(1..=8_589_934_592_usize).contains(&run.bytes)
            || !(1..=86_400).contains(&run.timeout_seconds)
            || !(1..=20).contains(&self.max_reviews_per_job)
            || self.audit_percent > 100
            || self.audit_seed.is_empty()
            || self.audit_seed.len() > 128
        {
            return Err("review orchestration limits exceed supported bounds".into());
        }
        Ok(())
    }
}

/// Assertions from the trusted controller, not provider authentication or proof
/// of semantic correctness. Native admission checks coverage and profile policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewAssessmentReceipt {
    pub job_id: String,
    pub profile: String,
    pub role: String,
    pub provider: ReviewProviderContract,
    pub decision: crate::ReviewDecision,
    pub response_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewCaseExecution {
    pub review_id: String,
    pub assessments: Vec<ReviewAssessmentReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<ReviewResolution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality_review: Option<ReviewAssessmentReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revalidation: Option<ReviewRevalidation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocker: Option<String>,
}

/// One bounded fresh pair over recovered source; prior assessments remain intact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRevalidation {
    pub reason: String,
    pub assessments: Vec<ReviewAssessmentReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality_review: Option<ReviewAssessmentReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewResolution {
    pub disputed_claim: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewExecutionReceipt {
    pub schema_version: String,
    pub package_id: String,
    pub cases: Vec<ReviewCaseExecution>,
}

impl ReviewRuntimeContract {
    pub fn validate(&self, policy: ReviewCompletionPolicy) -> Result<(), String> {
        let digest = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if self.schema_version != "1"
            || self.worker_protocol != REVIEW_WORKER_PROTOCOL
            || self.policy != policy
            || self.engine_version.is_empty()
            || !digest(&self.engine_sha256)
            || !self
                .skill_bundle_id
                .strip_prefix("mehscanSkillBundle/v1:")
                .is_some_and(digest)
        {
            return Err("unsupported or inconsistent review runtime contract".into());
        }
        if let Some(provider) = &self.provider {
            provider.validate()?;
        }
        if let Some(orchestration) = &self.orchestration {
            orchestration.validate(self.provider.as_ref())?;
        }
        self.limits.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_defaults_and_zero_research_are_bounded_without_implying_completion() {
        let mut value = ReviewResearchLimits::for_policy(ReviewCompletionPolicy::Value);
        let comprehensive = ReviewResearchLimits::for_policy(ReviewCompletionPolicy::Comprehensive);
        assert_eq!(value, comprehensive);
        value.rounds = 0;
        value.queries = 0;
        assert!(value.validate().is_ok());
        value.bytes = 0;
        assert!(value.validate().is_err());
        value.bytes = comprehensive.bytes;
        value.timeout_seconds = 3601;
        assert!(value.validate().is_err());
    }

    #[test]
    fn compatibility_requires_exact_policy_protocol_and_digest_shape() {
        let mut runtime = ReviewRuntimeContract {
            schema_version: "1".into(),
            policy: ReviewCompletionPolicy::Value,
            worker_protocol: REVIEW_WORKER_PROTOCOL,
            engine_version: "0.8.0".into(),
            engine_sha256: "a".repeat(64),
            skill_bundle_id: format!("mehscanSkillBundle/v1:{}", "b".repeat(64)),
            limits: ReviewResearchLimits::for_policy(ReviewCompletionPolicy::Value),
            provider: None,
            orchestration: None,
        };
        assert!(runtime.validate(ReviewCompletionPolicy::Value).is_ok());
        assert!(
            runtime
                .validate(ReviewCompletionPolicy::Comprehensive)
                .is_err()
        );
        runtime.worker_protocol += 1;
        assert!(runtime.validate(ReviewCompletionPolicy::Value).is_err());
        runtime.worker_protocol = REVIEW_WORKER_PROTOCOL;
        runtime.skill_bundle_id = "mehscanSkillBundle/v1:unbound".into();
        assert!(runtime.validate(ReviewCompletionPolicy::Value).is_err());
    }
    #[test]
    fn byok_contract_binds_model_effort_and_client_version() {
        let mut provider = ReviewProviderContract {
            schema_version: "1".into(),
            provider: "codex-cli".into(),
            executable_version: "0.162.0".into(),
            model: "gpt-6-luna".into(),
            reasoning_effort: "medium".into(),
        };
        assert!(provider.validate().is_ok());
        provider.model = "--unsafe".into();
        assert!(provider.validate().is_err());
        provider.model = "gpt-6-luna".into();
        provider.reasoning_effort = "automatic".into();
        assert!(provider.validate().is_err());
    }

    #[test]
    fn tiered_review_binds_distinct_models_and_shared_limits() {
        let primary = ReviewProviderContract {
            schema_version: "1".into(),
            provider: "codex-cli".into(),
            executable_version: "fixture-1".into(),
            model: "gpt-6-luna".into(),
            reasoning_effort: "medium".into(),
        };
        let limits = ReviewBudgetLimits {
            model_calls: 4,
            queries: 12,
            bytes: 262144,
            timeout_seconds: 600,
        };
        let mut policy = ReviewOrchestrationContract {
            expert: ReviewProviderContract {
                reasoning_effort: "xhigh".into(),
                ..primary.clone()
            },
            case_limits: limits.clone(),
            run_limits: limits,
            max_reviews_per_job: 5,
            audit_percent: 10,
            audit_seed: "fixed".into(),
            quality: None,
        };
        assert!(policy.validate(Some(&primary)).is_err());
        policy.expert.model = "gpt-6-sol".into();
        assert!(policy.validate(Some(&primary)).is_ok());
        assert!(policy.validate(None).is_err());
        policy.case_limits.model_calls = 1;
        assert!(policy.validate(Some(&primary)).is_err());
    }
}
