use std::collections::BTreeSet;

use mehscan_core::Rule;

use crate::EngineError;

pub(crate) fn validate_rules(rules: &[Rule]) -> Result<(), EngineError> {
    let mut ids = BTreeSet::new();
    for rule in rules {
        if rule.id.trim().is_empty() {
            return Err(EngineError("rule id must not be empty".to_string()));
        }
        if !ids.insert(rule.id.as_str()) {
            return Err(EngineError(format!("duplicate rule id: {}", rule.id)));
        }
        if !valid_rule_id(&rule.id) {
            return Err(EngineError(format!(
                "rule id must contain only lowercase ASCII letters, digits, and hyphens: {}",
                rule.id
            )));
        }
        if rule.version == 0 {
            return Err(EngineError(format!("rule {} has version zero", rule.id)));
        }
        if rule.match_spec.any.is_empty() {
            return Err(EngineError(format!(
                "rule {} has no structural patterns",
                rule.id
            )));
        }
        if rule.title.trim().is_empty() {
            return Err(EngineError(format!("rule {} has no title", rule.id)));
        }
        if rule.cwe.is_empty() || rule.cwe.iter().any(|cwe| !valid_cwe(cwe)) {
            return Err(EngineError(format!(
                "rule {} must contain valid CWE-N identifiers",
                rule.id
            )));
        }
        if rule.ai.investigate.is_empty()
            || rule
                .ai
                .investigate
                .iter()
                .any(|item| item.trim().is_empty())
        {
            return Err(EngineError(format!(
                "rule {} must provide non-empty AI investigation guidance",
                rule.id
            )));
        }
        if rule.provenance.note.trim().is_empty()
            || rule.provenance.references.is_empty()
            || rule
                .provenance
                .references
                .iter()
                .any(|reference| !reference.starts_with("https://"))
        {
            return Err(EngineError(format!(
                "rule {} must provide a provenance note and HTTPS references",
                rule.id
            )));
        }
        let mut patterns = BTreeSet::new();
        for matcher in &rule.match_spec.any {
            if matcher.pattern.trim().is_empty() {
                return Err(EngineError(format!(
                    "rule {} has an empty pattern",
                    rule.id
                )));
            }
            if matcher.context.is_some() != matcher.selector.is_some() {
                return Err(EngineError(format!(
                    "rule {} pattern context and selector must be supplied together",
                    rule.id
                )));
            }
            let pattern_key = (
                matcher.pattern.as_str(),
                matcher.context.as_deref(),
                matcher.selector.as_deref(),
            );
            if !patterns.insert(pattern_key) {
                return Err(EngineError(format!(
                    "rule {} contains a duplicate structural pattern",
                    rule.id
                )));
            }
            if matcher.context.as_deref().is_some_and(str::is_empty)
                || matcher.selector.as_deref().is_some_and(str::is_empty)
            {
                return Err(EngineError(format!(
                    "rule {} pattern context and selector must not be empty",
                    rule.id
                )));
            }
            for capture in matcher.captures.values() {
                if capture.starts_with('$') || capture.trim().is_empty() {
                    return Err(EngineError(format!(
                        "rule {} capture names must omit the '$' sigil",
                        rule.id
                    )));
                }
            }
        }
        let mut symbols = BTreeSet::new();
        for symbol in &rule.symbols {
            if symbol.canonical.trim().is_empty()
                || symbol.canonical.chars().any(char::is_whitespace)
            {
                return Err(EngineError(format!(
                    "rule {} contains an invalid canonical symbol",
                    rule.id
                )));
            }
            if !symbols.insert(symbol.canonical.as_str()) {
                return Err(EngineError(format!(
                    "rule {} contains a duplicate canonical symbol",
                    rule.id
                )));
            }
            if symbol.captures.keys().any(|name| name.trim().is_empty()) {
                return Err(EngineError(format!(
                    "rule {} contains an empty canonical-symbol capture name",
                    rule.id
                )));
            }
        }
    }
    Ok(())
}

fn valid_rule_id(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('-')
        && !id.ends_with('-')
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_cwe(cwe: &str) -> bool {
    cwe.strip_prefix("CWE-").is_some_and(|number| {
        !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_identifier_shapes() {
        assert!(valid_rule_id("python-dynamic-code"));
        assert!(!valid_rule_id("Python_dynamic_code"));
        assert!(valid_cwe("CWE-918"));
        assert!(!valid_cwe("918"));
    }
}
