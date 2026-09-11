use std::collections::BTreeMap;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "ast-grep 0.45.1 + bounded-node-randomness-policy";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Generator {
    MathRandom,
    CryptoRandomBytes,
    CryptoRandomUuid,
    WebCrypto,
}

pub(crate) fn add_node_randomness_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    ) {
        return;
    }

    let imports = CryptoImports::from_source(root.text().as_ref());
    for call in root.dfs().filter_map(call_site) {
        if comments.is_in_comment(call.node.range()) {
            continue;
        }
        let Some(generator) = classify_generator(root, &imports, &call) else {
            continue;
        };
        let Some((role, role_node)) = security_lifecycle_role(&call.node) else {
            continue;
        };

        let (suffix, kind, cwes, tags, confidence) = match generator {
            Generator::MathRandom => (
                "insecure-security-randomness",
                EvidenceKind::SecurityConfiguration,
                vec!["CWE-330".to_string()],
                vec![
                    "cryptography".to_string(),
                    "security-randomness".to_string(),
                    "math-random".to_string(),
                    "predictable-randomness".to_string(),
                    "recommendation:fix-application".to_string(),
                    format!("lifecycle-role:{role}"),
                ],
                Confidence::High,
            ),
            Generator::CryptoRandomBytes | Generator::CryptoRandomUuid | Generator::WebCrypto => (
                "secure-security-randomness-control",
                EvidenceKind::Validation,
                Vec::new(),
                vec![
                    "cryptography".to_string(),
                    "security-randomness".to_string(),
                    "cryptographically-secure-generator".to_string(),
                    "recommendation:control-present".to_string(),
                    format!("lifecycle-role:{role}"),
                    match generator {
                        Generator::CryptoRandomBytes => "crypto-random-bytes",
                        Generator::CryptoRandomUuid => "crypto-random-uuid",
                        Generator::WebCrypto => "web-crypto",
                        Generator::MathRandom => unreachable!(),
                    }
                    .to_string(),
                ],
                Confidence::High,
            ),
        };
        let rule_id = language_rule(language, suffix);
        let range = call.node.range();
        evidence.push(Evidence {
            id: evidence_id(path, rule_id, range.start, range.end),
            kind,
            capability: Capability::RandomGeneration,
            location: location(path, &call.node),
            enclosing_symbol: enclosing_symbol(&call.node),
            captures: BTreeMap::from([
                ("generator".to_string(), capture(path, &call.node)),
                ("lifecycle_role".to_string(), capture(path, &role_node)),
            ]),
            cwe_candidates: cwes,
            tags,
            confidence,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: ENGINE.to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: false,
                reachability: Some(reachability::classify(&call.node, literals)),
                availability: Some(conditional.availability_for(call.node.range())),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: rule_id.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

struct CallSite<'tree> {
    node: Node<'tree, StrDoc<SupportLang>>,
    callee: String,
}

fn call_site(node: Node<'_, StrDoc<SupportLang>>) -> Option<CallSite<'_>> {
    if node.kind().as_ref() != "call_expression" {
        return None;
    }
    let arguments = node.field("arguments")?;
    let callee_length = arguments.range().start.checked_sub(node.range().start)?;
    let text = node.text();
    Some(CallSite {
        node,
        callee: compact(text.get(..callee_length)?),
    })
}

fn classify_generator(
    root: &Node<'_, StrDoc<SupportLang>>,
    imports: &CryptoImports,
    call: &CallSite<'_>,
) -> Option<Generator> {
    if call.callee == "Math.random" && !has_value_declaration(root, "Math") {
        return Some(Generator::MathRandom);
    }
    if imports.random_bytes.iter().any(|name| name == &call.callee) {
        return Some(Generator::CryptoRandomBytes);
    }
    if imports
        .crypto_objects
        .iter()
        .any(|name| call.callee == format!("{name}.randomBytes"))
    {
        return Some(Generator::CryptoRandomBytes);
    }
    if imports
        .crypto_objects
        .iter()
        .any(|name| call.callee == format!("{name}.randomUUID"))
    {
        return Some(Generator::CryptoRandomUuid);
    }
    if matches!(
        call.callee.as_str(),
        "globalThis.crypto.getRandomValues"
            | "window.crypto.getRandomValues"
            | "self.crypto.getRandomValues"
            | "globalThis.crypto.randomUUID"
            | "window.crypto.randomUUID"
            | "self.crypto.randomUUID"
    ) {
        return Some(Generator::WebCrypto);
    }
    None
}

#[derive(Default)]
struct CryptoImports {
    crypto_objects: Vec<String>,
    random_bytes: Vec<String>,
}

impl CryptoImports {
    fn from_source(source: &str) -> Self {
        let mut imports = Self::default();
        for line in source.lines() {
            let compact = compact(line);
            let statement = compact.trim_end_matches(';');
            let crypto_module = compact.contains("from'crypto'")
                || compact.contains("from\"crypto\"")
                || compact.contains("from'node:crypto'")
                || compact.contains("from\"node:crypto\"");
            if crypto_module && compact.starts_with("import") {
                let clause = compact
                    .strip_prefix("import")
                    .and_then(|text| text.split("from").next())
                    .unwrap_or_default();
                if let Some(namespace) = clause.strip_prefix("*as") {
                    push_identifier(&mut imports.crypto_objects, namespace);
                } else if clause.starts_with('{') {
                    for entry in clause.trim_matches(['{', '}']).split(',') {
                        let (imported, local) = entry
                            .split_once("as")
                            .map_or((entry, entry), |(imported, local)| (imported, local));
                        if imported == "randomBytes" {
                            push_identifier(&mut imports.random_bytes, local);
                        }
                    }
                } else if let Some(default) = clause.split(',').next() {
                    push_identifier(&mut imports.crypto_objects, default);
                }
            }

            for module in ["'crypto'", "\"crypto\"", "'node:crypto'", "\"node:crypto\""] {
                let suffix = format!("=require({module})");
                if let Some(local) = statement
                    .strip_prefix("const")
                    .and_then(|text| text.strip_suffix(&suffix))
                {
                    push_identifier(&mut imports.crypto_objects, local);
                }
            }
        }
        imports
    }
}

fn push_identifier(values: &mut Vec<String>, candidate: &str) {
    if is_identifier(candidate) && !values.iter().any(|value| value == candidate) {
        values.push(candidate.to_string());
    }
}

fn has_value_declaration(root: &Node<'_, StrDoc<SupportLang>>, name: &str) -> bool {
    root.dfs().any(|node| {
        matches!(
            node.kind().as_ref(),
            "variable_declarator" | "formal_parameter" | "required_parameter" | "import_clause"
        ) && node
            .field("name")
            .is_some_and(|candidate| candidate.text().trim() == name)
    })
}

fn security_lifecycle_role<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<(String, Node<'tree, StrDoc<SupportLang>>)> {
    for ancestor in call.ancestors() {
        let candidate = match ancestor.kind().as_ref() {
            "variable_declarator" => ancestor.field("name"),
            "assignment_expression" => ancestor.field("left"),
            "pair" => ancestor.field("key"),
            "function_declaration" | "method_definition" => ancestor.field("name"),
            _ => None,
        };
        let Some(candidate) = candidate else {
            continue;
        };
        let normalized = normalize_role(candidate.text().as_ref());
        if is_strong_security_role(&normalized) || normalized == "token" && has_token_context(call)
        {
            return Some((normalized, candidate));
        }
    }
    None
}

fn is_strong_security_role(role: &str) -> bool {
    [
        "accesstoken",
        "activationcode",
        "apikey",
        "apitoken",
        "authtoken",
        "csrftoken",
        "invitecode",
        "nonce",
        "otp",
        "passwordreset",
        "resettoken",
        "salt",
        "sessionid",
        "sessionkey",
        "verificationcode",
        "verificationtoken",
    ]
    .iter()
    .any(|term| role.contains(term))
}

fn has_token_context(call: &Node<'_, StrDoc<SupportLang>>) -> bool {
    call.ancestors()
        .take_while(|ancestor| ancestor.kind().as_ref() != "program")
        .any(|ancestor| {
            let text = compact(ancestor.text().as_ref()).to_ascii_lowercase();
            [
                "'/api/token'",
                "\"/api/token\"",
                "generatetoken",
                "createtoken",
                "issuetoken",
                "resettoken",
                "authtoken",
            ]
            .iter()
            .any(|marker| text.contains(marker))
        })
}

fn language_rule(language: Language, suffix: &str) -> &'static str {
    match (language, suffix) {
        (Language::Javascript, "insecure-security-randomness") => {
            "javascript-insecure-security-randomness"
        }
        (Language::Typescript, "insecure-security-randomness") => {
            "typescript-insecure-security-randomness"
        }
        (Language::Tsx, "insecure-security-randomness") => "tsx-insecure-security-randomness",
        (Language::Javascript, "secure-security-randomness-control") => {
            "javascript-secure-security-randomness-control"
        }
        (Language::Typescript, "secure-security-randomness-control") => {
            "typescript-secure-security-randomness-control"
        }
        (Language::Tsx, "secure-security-randomness-control") => {
            "tsx-secure-security-randomness-control"
        }
        _ => unreachable!(),
    }
}

fn normalize_role(text: &str) -> String {
    text.chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn is_identifier(text: &str) -> bool {
    let mut characters = text.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character == '$' || character.is_alphabetic())
        && characters
            .all(|character| character == '_' || character == '$' || character.is_alphanumeric())
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}

fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.to_string(),
        start: Position {
            line: start.line() + 1,
            column: start.column(node) + 1,
            byte_offset: node.range().start,
        },
        end: Position {
            line: end.line() + 1,
            column: end.column(node) + 1,
            byte_offset: node.range().end,
        },
    }
}

fn evidence_id(path: &str, rule_id: &str, start: usize, end: usize) -> String {
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}
