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
            ReviewCompletionPolicy::Value => Self {
                rounds: 2,
                queries: 8,
                bytes: 128 * 1024,
                timeout_seconds: 300,
            },
            ReviewCompletionPolicy::Comprehensive => Self {
                rounds: 3,
                queries: 12,
                bytes: 256 * 1024,
                timeout_seconds: 600,
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
        assert!(value.queries < comprehensive.queries);
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
}
