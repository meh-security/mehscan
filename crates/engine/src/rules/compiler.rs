use ast_grep_core::Pattern;
use ast_grep_language::SupportLang;
use mehscan_core::{Language, PatternSpec, Rule};

use crate::EngineError;

pub(crate) struct CompiledPattern {
    pub pattern: Pattern,
    pub specification: PatternSpec,
    pub required_source_text: Option<String>,
}

pub(crate) struct CompiledRule {
    pub rule: Rule,
    pub patterns: Vec<CompiledPattern>,
}

pub(crate) fn compile_for_language(
    rules: &[Rule],
    language: Language,
) -> Result<Vec<CompiledRule>, EngineError> {
    let parser_language = parser_language(language);
    rules
        .iter()
        .filter(|rule| rule.language == language)
        .map(|rule| {
            let patterns = rule
                .match_spec
                .any
                .iter()
                .map(|specification| {
                    let pattern = match (&specification.context, &specification.selector) {
                        (Some(context), Some(selector)) => {
                            Pattern::contextual(context, selector, parser_language)
                        }
                        (None, None) => Pattern::try_new(&specification.pattern, parser_language),
                        _ => unreachable!("rule validation requires context and selector together"),
                    }
                    .map_err(|error| {
                        EngineError(format!(
                            "rule {} pattern {:?} is invalid: {error}",
                            rule.id, specification.pattern
                        ))
                    })?;
                    for capture in specification.captures.values() {
                        if !pattern.defined_vars().contains(capture.as_str()) {
                            return Err(EngineError(format!(
                                "rule {} references undefined capture {capture}",
                                rule.id
                            )));
                        }
                    }
                    Ok(CompiledPattern {
                        pattern,
                        specification: specification.clone(),
                        required_source_text: required_source_text(&specification.pattern),
                    })
                })
                .collect::<Result<Vec<_>, EngineError>>()?;
            Ok(CompiledRule {
                rule: rule.clone(),
                patterns,
            })
        })
        .collect()
}

fn required_source_text(pattern: &str) -> Option<String> {
    let bytes = pattern.as_bytes();
    let mut candidates = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor].is_ascii_alphabetic() || bytes[cursor] == b'_' {
            let start = cursor;
            cursor += 1;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
            {
                cursor += 1;
            }
            if start > 0 && bytes[start - 1] == b'$' {
                continue;
            }
            let token = &pattern[start..cursor];
            if token.len() >= 3 && !is_syntax_keyword(token) {
                candidates.push(token);
            }
        } else {
            cursor += 1;
        }
    }
    candidates
        .into_iter()
        .max_by_key(|candidate| candidate.len())
        .map(str::to_string)
}

fn is_syntax_keyword(token: &str) -> bool {
    matches!(
        token,
        "new"
            | "await"
            | "async"
            | "return"
            | "true"
            | "false"
            | "null"
            | "None"
            | "nil"
            | "class"
            | "func"
            | "package"
            | "void"
    )
}

pub(crate) fn parser_language(language: Language) -> SupportLang {
    match language {
        Language::C => SupportLang::C,
        Language::Cpp => SupportLang::Cpp,
        Language::Csharp => SupportLang::CSharp,
        Language::Java => SupportLang::Java,
        Language::Kotlin => SupportLang::Kotlin,
        Language::Javascript => SupportLang::JavaScript,
        Language::Typescript => SupportLang::TypeScript,
        Language::Tsx => SupportLang::Tsx,
        Language::Python => SupportLang::Python,
        Language::Php => SupportLang::PhpMixed,
        Language::Go => SupportLang::Go,
        Language::Rust => SupportLang::Rust,
    }
}

#[cfg(test)]
mod tests {
    use super::required_source_text;

    #[test]
    fn extracts_only_literal_pattern_identifiers() {
        assert_eq!(
            required_source_text("child_process.execFile($COMMAND, $$$ARGUMENTS)").as_deref(),
            Some("child_process")
        );
        assert_eq!(
            required_source_text("$RESPONSE.WriteAsync($CONTENT)").as_deref(),
            Some("WriteAsync")
        );
        assert_eq!(required_source_text("$OBJECT[$KEY]"), None);
    }
}
