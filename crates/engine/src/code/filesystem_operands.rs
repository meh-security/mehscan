//! Effective modes on already matched filesystem effects. Unknown modes remain
//! one unresolved operation; flags/mode text is not itself a sanitizer.
use std::collections::BTreeMap;

use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{Capability, Capture, Evidence, Language, LiteralState, LiteralValue};

pub(super) fn annotate<'a>(
    language: Language,
    root: &Node<'a, StrDoc<SupportLang>>,
    literals: &super::literals::LiteralEnvironment<'a, StrDoc<SupportLang>>,
    evidence: &mut [Evidence],
) {
    if !matches!(language, Language::Go | Language::Python)
        || !evidence.iter().any(|e| {
            e.rule_id == "go-filesystem-read" && e.captures.contains_key("flags")
                || e.rule_id == "python-filesystem-read"
        })
    {
        return;
    }
    let calls = root
        .dfs()
        .filter(|n| matches!(n.kind().as_ref(), "call" | "call_expression"))
        .map(|n| ((n.range().start, n.range().end), n))
        .collect::<BTreeMap<_, _>>();
    for e in evidence.iter_mut().filter(|e| {
        e.rule_id == "go-filesystem-read" && e.captures.contains_key("flags")
            || e.rule_id == "python-filesystem-read"
    }) {
        let Some(call) = calls.get(&(e.location.start.byte_offset, e.location.end.byte_offset))
        else {
            continue;
        };
        let Some(args) = call.field("arguments") else {
            continue;
        };
        let Some(mode) = args
            .children()
            .filter(|n| n.is_named() && !n.kind().as_ref().contains("comment"))
            .nth(1)
        else {
            continue;
        };
        let mode = if mode.kind().as_ref() == "keyword_argument" {
            if mode.field("name").is_none_or(|n| n.text() != "mode") {
                continue;
            }
            let Some(value) = mode.field("value") else {
                continue;
            };
            value
        } else {
            mode
        };
        // Other pathlib/copy calls can have a second argument unrelated to modes.
        if language == Language::Python
            && call
                .field("function")
                .is_none_or(|n| !matches!(n.text().as_ref(), "open" | "codecs.open"))
        {
            continue;
        }
        let fact = literals.evaluate(&mode);
        let write = match language {
            Language::Python => fact.value.as_ref().and_then(|v| {
                if let LiteralValue::String(s) = v {
                    Some(s.chars().any(|c| matches!(c, 'w' | 'a' | 'x' | '+')))
                } else {
                    None
                }
            }),
            Language::Go => call
                .field("function")
                .and_then(|f| {
                    f.text()
                        .rsplit_once('.')
                        .and_then(|(owner, _)| go_write_flags(mode.text().as_ref(), owner))
                })
                .or_else(|| {
                    (fact.state == LiteralState::Known
                        && fact.value == Some(LiteralValue::Number("0".into())))
                    .then_some(false)
                }),
            _ => None,
        };
        let role = if language == Language::Go {
            "flags"
        } else {
            "mode"
        };
        e.captures.insert(
            role.into(),
            Capture {
                text: mode.text().into_owned(),
                location: super::matcher::location(&e.location.path, &mode),
            },
        );
        e.context.literals.insert(role.into(), fact);
        match write {
            Some(true) => {
                e.capability = Capability::FilesystemWrite;
                e.rule_id = if language == Language::Go {
                    "go-filesystem-write"
                } else {
                    "python-filesystem-write"
                }
                .into();
                e.provenance.rule_version = 2;
                e.id = super::matcher::evidence_id(
                    &e.location.path,
                    &e.rule_id,
                    call.range().start,
                    call.range().end,
                );
                e.tags.push("filesystem-mode:write".into());
            }
            Some(false) => e.tags.push("filesystem-mode:read".into()),
            None => e.tags.push("filesystem-mode:unresolved".into()),
        }
    }
}

fn go_write_flags(text: &str, owner: &str) -> Option<bool> {
    let mut write = false;
    for part in text.split('|') {
        let part = part.trim().trim_matches(['(', ')']).trim();
        let (qualifier, flag) = part.rsplit_once('.')?;
        if qualifier != owner {
            return None;
        }
        match flag {
            "O_WRONLY" | "O_RDWR" | "O_CREATE" | "O_TRUNC" | "O_APPEND" => write = true,
            "O_RDONLY" | "O_EXCL" | "O_SYNC" => (),
            _ => return None,
        }
    }
    Some(write)
}
