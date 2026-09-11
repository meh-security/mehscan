use std::collections::BTreeMap;
use std::ops::Range;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution, SymbolResolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;
use super::symbols::FileSymbolEnvironment;

const ENGINE: &str = "ast-grep 0.45.1 + bounded-password-lifecycle";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_password_lifecycle<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    symbols: &FileSymbolEnvironment,
    evidence: &mut Vec<Evidence>,
) {
    if !is_node_language(language) {
        return;
    }
    add_password_change_observations(
        path,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_password_storage_observations(
        path,
        root,
        language,
        comments,
        conditional,
        literals,
        symbols,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_password_change_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for node in root.dfs() {
        let Some(call) = call_site(node) else {
            continue;
        };
        if terminal_symbol(&call.callee) != "update"
            || call.arguments.is_empty()
            || comments.is_in_comment(call.node.range())
        {
            continue;
        }
        let Some(password_value) = object_property(&call.arguments[0], "password") else {
            continue;
        };
        let scope = function_scope(&call.node, root);
        let Some(origin) =
            request_origin(root, &password_value, &scope, call.node.range().start, 0)
        else {
            continue;
        };

        if let Some(authority) = accepted_password_authority(root, &call.node, &scope, literals) {
            let rule_id = language_rule(language, "password-change-authority");
            let mut captures = BTreeMap::new();
            captures.insert("authority".to_string(), capture(path, &authority.node));
            captures.insert("password_change".to_string(), capture(path, &call.node));
            evidence.push(Evidence {
                id: evidence_id(
                    path,
                    rule_id,
                    authority.node.range().start,
                    call.node.range().end,
                ),
                kind: EvidenceKind::Guard,
                capability: Capability::Authentication,
                location: location(path, &authority.node),
                enclosing_symbol: enclosing_symbol(&call.node),
                captures,
                cwe_candidates: Vec::new(),
                tags: vec![
                    "password-lifecycle".to_string(),
                    "password-change".to_string(),
                    "rejecting-control".to_string(),
                    authority.tag.to_string(),
                ],
                confidence: Confidence::Medium,
                provenance: provenance(),
                context: evidence_context(&authority.node, comments, conditional, literals),
                symbol_resolution: None,
                rule_id: rule_id.to_string(),
                related_evidence: Vec::new(),
            });
            continue;
        }

        let source_rule = language_rule(language, "password-change-request-value");
        let sink_rule = language_rule(language, "password-change-without-reauthentication");
        let source_id = evidence_id(
            path,
            source_rule,
            password_value.range().start,
            password_value.range().end,
        );
        let mut source_captures = BTreeMap::new();
        source_captures.insert("name".to_string(), capture(path, &password_value));
        source_captures.insert("origin".to_string(), capture(path, &origin));
        evidence.push(Evidence {
            id: source_id.clone(),
            kind: EvidenceKind::Source,
            capability: Capability::HttpRequestData,
            location: location(path, &password_value),
            enclosing_symbol: enclosing_symbol(&call.node),
            captures: source_captures,
            cwe_candidates: vec!["CWE-20".to_string()],
            tags: vec![
                "http".to_string(),
                "request".to_string(),
                "password-change".to_string(),
                "bounded-request-alias".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: provenance(),
            context: evidence_context(&password_value, comments, conditional, literals),
            symbol_resolution: None,
            rule_id: source_rule.to_string(),
            related_evidence: Vec::new(),
        });

        let mut sink_captures = BTreeMap::new();
        sink_captures.insert("new_password".to_string(), capture(path, &password_value));
        sink_captures.insert("password_change".to_string(), capture(path, &call.node));
        if let Some(optional) = optional_current_password_check(root, &call.node, &scope, literals)
        {
            sink_captures.insert("optional_check".to_string(), capture(path, &optional));
        }
        evidence.push(Evidence {
            id: evidence_id(
                path,
                sink_rule,
                call.node.range().start,
                call.node.range().end,
            ),
            kind: EvidenceKind::Sink,
            capability: Capability::Authentication,
            location: location(path, &call.node),
            enclosing_symbol: enclosing_symbol(&call.node),
            captures: sink_captures,
            cwe_candidates: vec!["CWE-620".to_string()],
            tags: vec![
                "password-lifecycle".to_string(),
                "password-change".to_string(),
                "reauthentication-not-mandatory".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: provenance(),
            context: evidence_context(&call.node, comments, conditional, literals),
            symbol_resolution: None,
            rule_id: sink_rule.to_string(),
            related_evidence: vec![source_id],
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn add_password_storage_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    symbols: &FileSymbolEnvironment,
    evidence: &mut Vec<Evidence>,
) {
    for node in root.dfs() {
        let Some(call) = call_site(node) else {
            continue;
        };
        if terminal_symbol(&call.callee) != "setDataValue"
            || call.arguments.len() != 2
            || exact_quoted(call.arguments[0].text().trim()).map(normalize_name)
                != Some("password".to_string())
            || comments.is_in_comment(call.node.range())
        {
            continue;
        }
        let stored_value = call.arguments[1].clone();
        let assessment = assess_password_transform(&stored_value, symbols);
        let rule_suffix = if assessment.is_candidate() {
            "password-storage-review"
        } else {
            "password-kdf-configuration"
        };
        let rule_id = language_rule(language, rule_suffix);
        let mut captures = BTreeMap::new();
        captures.insert("password".to_string(), capture(path, &stored_value));
        captures.insert("storage".to_string(), capture(path, &call.node));
        if let Some(transform) = &assessment.transform {
            captures.insert("transform".to_string(), capture(path, transform));
        }
        let mut tags = vec![
            "password-lifecycle".to_string(),
            "password-storage".to_string(),
            format!("algorithm:{}", assessment.algorithm),
            assessment.state.tag().to_string(),
        ];
        if let Some(work_factor) = assessment.work_factor {
            tags.push(format!("work-factor:{work_factor}"));
        } else if assessment.algorithm != "plaintext-or-unknown" {
            tags.push("work-factor:unknown".to_string());
        }
        tags.push(
            if assessment.salt_is_constant {
                "salt:constant"
            } else {
                "salt:not-obviously-constant"
            }
            .to_string(),
        );

        if !assessment.is_candidate() {
            evidence.push(Evidence {
                id: evidence_id(
                    path,
                    rule_id,
                    call.node.range().start,
                    call.node.range().end,
                ),
                kind: EvidenceKind::SecurityConfiguration,
                capability: Capability::CryptographicHash,
                location: location(path, &call.node),
                enclosing_symbol: enclosing_symbol(&call.node),
                captures,
                cwe_candidates: Vec::new(),
                tags,
                confidence: Confidence::Medium,
                provenance: provenance(),
                context: evidence_context(&call.node, comments, conditional, literals),
                symbol_resolution: assessment.symbol_resolution,
                rule_id: rule_id.to_string(),
                related_evidence: Vec::new(),
            });
            continue;
        }

        let source_node = assessment
            .password_input
            .clone()
            .unwrap_or_else(|| stored_value.clone());
        let source_rule = language_rule(language, "password-material");
        let source_id = evidence_id(
            path,
            source_rule,
            source_node.range().start,
            source_node.range().end,
        );
        let mut source_captures = BTreeMap::new();
        source_captures.insert("name".to_string(), capture(path, &source_node));
        evidence.push(Evidence {
            id: source_id.clone(),
            kind: EvidenceKind::Source,
            capability: Capability::CredentialMaterial,
            location: location(path, &source_node),
            enclosing_symbol: enclosing_symbol(&call.node),
            captures: source_captures,
            cwe_candidates: Vec::new(),
            tags: vec![
                "credential".to_string(),
                "password".to_string(),
                "storage-input".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: provenance(),
            context: evidence_context(&source_node, comments, conditional, literals),
            symbol_resolution: None,
            rule_id: source_rule.to_string(),
            related_evidence: Vec::new(),
        });
        evidence.push(Evidence {
            id: evidence_id(
                path,
                rule_id,
                call.node.range().start,
                call.node.range().end,
            ),
            kind: EvidenceKind::Sink,
            capability: Capability::CryptographicHash,
            location: location(path, &call.node),
            enclosing_symbol: enclosing_symbol(&call.node),
            captures,
            cwe_candidates: vec!["CWE-916".to_string()],
            tags,
            confidence: Confidence::Medium,
            provenance: provenance(),
            context: evidence_context(&call.node, comments, conditional, literals),
            symbol_resolution: assessment.symbol_resolution,
            rule_id: rule_id.to_string(),
            related_evidence: vec![source_id],
        });
    }
}

#[derive(Clone, Copy)]
enum StorageState {
    WeakFastDigest,
    WeakParameters,
    ReviewUnknown,
    StrongKdf,
}

impl StorageState {
    fn tag(self) -> &'static str {
        match self {
            Self::WeakFastDigest => "password-kdf:fast-digest",
            Self::WeakParameters => "password-kdf:weak-parameters",
            Self::ReviewUnknown => "password-kdf:unknown",
            Self::StrongKdf => "password-kdf:recognized",
        }
    }
}

struct StorageAssessment<'tree> {
    state: StorageState,
    algorithm: String,
    work_factor: Option<u64>,
    salt_is_constant: bool,
    transform: Option<Node<'tree, StrDoc<SupportLang>>>,
    password_input: Option<Node<'tree, StrDoc<SupportLang>>>,
    symbol_resolution: Option<SymbolResolution>,
}

impl StorageAssessment<'_> {
    fn is_candidate(&self) -> bool {
        !matches!(self.state, StorageState::StrongKdf)
    }
}

fn assess_password_transform<'tree>(
    value: &Node<'tree, StrDoc<SupportLang>>,
    symbols: &FileSymbolEnvironment,
) -> StorageAssessment<'tree> {
    for node in value.dfs() {
        let Some(call) = call_site(node) else {
            continue;
        };
        if let Some((resolution, summary)) = symbols.resolve_fixed_format(&call.callee) {
            return StorageAssessment {
                state: StorageState::WeakFastDigest,
                algorithm: summary.algorithm,
                work_factor: None,
                salt_is_constant: false,
                transform: Some(call.node),
                password_input: call.arguments.first().cloned(),
                symbol_resolution: Some(resolution),
            };
        }
        if let Some((resolution, summary)) = symbols.resolve_password_kdf(&call.callee) {
            let state = kdf_state(
                &summary.algorithm,
                summary.work_factor,
                summary.salt_is_constant,
                false,
            );
            return StorageAssessment {
                state,
                algorithm: summary.algorithm,
                work_factor: summary.work_factor,
                salt_is_constant: summary.salt_is_constant,
                transform: Some(call.node),
                password_input: call.arguments.first().cloned(),
                symbol_resolution: Some(resolution),
            };
        }
        if terminal_symbol(&call.callee) == "createHash" {
            let algorithm = call
                .arguments
                .first()
                .and_then(|argument| {
                    let text = argument.text();
                    exact_quoted(text.trim()).map(str::to_string)
                })
                .unwrap_or_else(|| "unknown-fast-digest".to_string())
                .to_ascii_lowercase();
            let password_input = value
                .dfs()
                .filter_map(call_site)
                .find(|nested| terminal_symbol(&nested.callee) == "update")
                .and_then(|nested| nested.arguments.first().cloned());
            return StorageAssessment {
                state: StorageState::WeakFastDigest,
                algorithm,
                work_factor: None,
                salt_is_constant: false,
                transform: Some(call.node),
                password_input,
                symbol_resolution: None,
            };
        }
        if let Some((algorithm, resolution)) = direct_kdf(&call.callee, symbols) {
            let work_factor = match algorithm {
                "bcrypt" => call.arguments.get(1).and_then(numeric_literal),
                "pbkdf2" => call.arguments.get(2).and_then(numeric_literal),
                _ => None,
            };
            let salt = matches!(algorithm, "scrypt" | "pbkdf2")
                .then(|| call.arguments.get(1))
                .flatten();
            let salt_is_constant =
                salt.is_some_and(|node| exact_quoted(node.text().trim()).is_some());
            let salt_is_random = salt.is_some_and(|node| {
                let text = compact(node.text().as_ref()).to_ascii_lowercase();
                text.contains("randombytes(") || text.contains("randomfill(")
            });
            let state = kdf_state(algorithm, work_factor, salt_is_constant, salt_is_random);
            return StorageAssessment {
                state,
                algorithm: algorithm.to_string(),
                work_factor,
                salt_is_constant,
                transform: Some(call.node),
                password_input: call.arguments.first().cloned(),
                symbol_resolution: resolution,
            };
        }
    }
    StorageAssessment {
        state: StorageState::ReviewUnknown,
        algorithm: "plaintext-or-unknown".to_string(),
        work_factor: None,
        salt_is_constant: false,
        transform: None,
        password_input: Some(value.clone()),
        symbol_resolution: None,
    }
}

fn direct_kdf(
    observed: &str,
    symbols: &FileSymbolEnvironment,
) -> Option<(&'static str, Option<SymbolResolution>)> {
    for (algorithm, canonicals) in [
        (
            "bcrypt",
            &[
                "bcrypt.hash",
                "bcrypt.hashSync",
                "bcryptjs.hash",
                "bcryptjs.hashSync",
            ][..],
        ),
        ("argon2", &["argon2.hash"][..]),
        ("scrypt", &["crypto.scrypt", "crypto.scryptSync"][..]),
        ("pbkdf2", &["crypto.pbkdf2", "crypto.pbkdf2Sync"][..]),
    ] {
        for canonical in canonicals {
            if let Some(resolution) = symbols.resolve(observed, canonical) {
                return Some((algorithm, Some(resolution)));
            }
        }
    }
    None
}

fn kdf_state(
    algorithm: &str,
    work_factor: Option<u64>,
    salt_is_constant: bool,
    salt_is_random: bool,
) -> StorageState {
    match algorithm {
        "bcrypt" if work_factor.is_some_and(|rounds| rounds >= 10) => StorageState::StrongKdf,
        "bcrypt" if work_factor.is_some() => StorageState::WeakParameters,
        "argon2" => StorageState::StrongKdf,
        "scrypt" if salt_is_random => StorageState::StrongKdf,
        "scrypt" if salt_is_constant => StorageState::WeakParameters,
        "pbkdf2" if work_factor.is_some_and(|rounds| rounds >= 100_000) && salt_is_random => {
            StorageState::StrongKdf
        }
        "pbkdf2" if salt_is_constant || work_factor.is_some_and(|rounds| rounds < 100_000) => {
            StorageState::WeakParameters
        }
        _ => StorageState::ReviewUnknown,
    }
}

struct AcceptedAuthority<'tree> {
    node: Node<'tree, StrDoc<SupportLang>>,
    tag: &'static str,
}

fn accepted_password_authority<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    update: &Node<'tree, StrDoc<SupportLang>>,
    scope: &Range<usize>,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Option<AcceptedAuthority<'tree>> {
    for ancestor in update
        .ancestors()
        .take_while(|ancestor| ancestor.range() != *scope)
        .filter(|ancestor| ancestor.kind().as_ref() == "if_statement")
    {
        let condition = ancestor.field("condition")?;
        let condition_text = condition_text(condition.text().as_ref());
        if positive_authority_condition(&condition_text) {
            return Some(AcceptedAuthority {
                node: condition,
                tag: authority_tag(&condition_text),
            });
        }
    }

    let mut current_presence = false;
    let mut current_verification: Option<Node<'tree, StrDoc<SupportLang>>> = None;
    let mut token_presence = false;
    let mut token_verification: Option<Node<'tree, StrDoc<SupportLang>>> = None;
    for statement in root.dfs().filter(|node| {
        node.kind().as_ref() == "if_statement"
            && scope.start <= node.range().start
            && node.range().end <= update.range().start
            && function_scope(node, root) == *scope
    }) {
        let (Some(condition), Some(consequence)) =
            (statement.field("condition"), statement.field("consequence"))
        else {
            continue;
        };
        if !reachability::always_terminates(&consequence, literals) {
            continue;
        }
        let text = condition_text(condition.text().as_ref());
        if optional_current_condition(&text) {
            continue;
        }
        if missing_credential_condition(&text, &["currentpassword", "current_password", "current"])
        {
            current_presence = true;
        }
        if rejecting_current_verification(&text) {
            current_verification = Some(condition.clone());
        }
        if missing_credential_condition(&text, &["resettoken", "reset_token", "token"]) {
            token_presence = true;
        }
        if rejecting_token_verification(&text) {
            token_verification = Some(condition);
        }
    }
    if let Some(node) = current_verification
        && (current_presence || rejecting_verifier_runs_unconditionally(&node))
    {
        return Some(AcceptedAuthority {
            node,
            tag: "current-credential",
        });
    }
    if let Some(node) = token_verification
        && (token_presence || rejecting_verifier_runs_unconditionally(&node))
    {
        return Some(AcceptedAuthority {
            node,
            tag: "reset-token",
        });
    }
    None
}

fn positive_authority_condition(text: &str) -> bool {
    if text.contains("hmac(answer)")
        && (text.contains("===data.answer") || text.contains("==data.answer"))
    {
        return true;
    }
    if text.contains("!==") || text.contains("!=") || text.starts_with('!') {
        return false;
    }
    let positive_current = (text.contains("compare(")
        || text.contains("verifycurrent")
        || text.contains("checkpassword")
        || text.contains("hash(current"))
        && (text.contains("===") || text.contains("==") || !text.contains("false"));
    let positive_reset = (text.contains("verifyresettoken(")
        || text.contains("validateresettoken("))
        && (text.contains("===") || text.contains("==") || !text.contains("false"));
    positive_current || positive_reset
}

fn rejecting_current_verification(text: &str) -> bool {
    let verifier = text.contains("compare(")
        || text.contains("verifycurrent")
        || text.contains("checkpassword")
        || text.contains("hash(current");
    verifier
        && (text.starts_with('!')
            || text.contains("!==")
            || text.contains("!=")
            || text.contains("===false")
            || text.contains("==false"))
}

fn rejecting_token_verification(text: &str) -> bool {
    let verifier = text.contains("verifyresettoken(") || text.contains("validateresettoken(");
    verifier
        && (text.starts_with('!')
            || text.contains("===false")
            || text.contains("==false")
            || text.contains("!==true")
            || text.contains("!=true"))
}

fn rejecting_verifier_runs_unconditionally(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    !optional_current_condition(&condition_text(node.text().as_ref()))
}

fn optional_current_condition(text: &str) -> bool {
    (text.starts_with("currentpassword&&")
        || text.starts_with("current_password&&")
        || text.starts_with("current&&"))
        && rejecting_current_verification(text)
}

fn missing_credential_condition(text: &str, names: &[&str]) -> bool {
    names.iter().any(|name| {
        text == format!("!{name}")
            || text.starts_with(&format!("!{name}||"))
            || text.contains(&format!("||!{name}"))
            || text.contains(&format!("{name}==null"))
            || text.contains(&format!("{name}===null"))
    })
}

fn authority_tag(text: &str) -> &'static str {
    if text.contains("token") {
        "reset-token"
    } else if text.contains("answer") {
        "recovery-answer"
    } else {
        "current-credential"
    }
}

fn optional_current_password_check<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    update: &Node<'tree, StrDoc<SupportLang>>,
    scope: &Range<usize>,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| {
            node.kind().as_ref() == "if_statement"
                && scope.start <= node.range().start
                && node.range().end <= update.range().start
                && function_scope(node, root) == *scope
        })
        .filter(|statement| {
            statement
                .field("consequence")
                .is_some_and(|consequence| reachability::always_terminates(&consequence, literals))
        })
        .filter_map(|statement| statement.field("condition"))
        .find(|condition| optional_current_condition(&condition_text(condition.text().as_ref())))
}

fn request_origin<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    value: &Node<'tree, StrDoc<SupportLang>>,
    scope: &Range<usize>,
    before: usize,
    depth: usize,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if depth > 4 {
        return None;
    }
    let text = compact(value.text().as_ref()).replace("?.", ".");
    let lower = text.to_ascii_lowercase();
    if lower.contains("req.body.")
        || lower.contains("req.query.")
        || lower.contains("request.body.")
        || lower.contains("request.query.")
        || ((lower.starts_with("body.") || lower.starts_with("query."))
            && function_header_is_request(value))
    {
        return Some(value.clone());
    }
    let identifiers = value
        .dfs()
        .filter(|node| node.kind().as_ref() == "identifier")
        .filter_map(|node| simple_identifier(node.text().trim()).map(|_| node))
        .collect::<Vec<_>>();
    for identifier in identifiers {
        let name = identifier.text();
        let name = name.trim();
        let Some(assigned) = latest_assigned_value(root, name, before, scope) else {
            continue;
        };
        if let Some(origin) =
            request_origin(root, &assigned, scope, assigned.range().start, depth + 1)
        {
            return Some(origin);
        }
    }
    None
}

fn latest_assigned_value<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
    before: usize,
    scope: &Range<usize>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter_map(|node| {
            if node.range().end > before || function_scope(&node, root) != *scope {
                return None;
            }
            match node.kind().as_ref() {
                "variable_declarator"
                    if node
                        .field("name")
                        .is_some_and(|field| field.text().trim() == name) =>
                {
                    node.field("value").map(|value| (node.range().start, value))
                }
                "assignment_expression"
                    if node
                        .field("left")
                        .is_some_and(|field| field.text().trim() == name) =>
                {
                    node.field("right").map(|value| (node.range().start, value))
                }
                _ => None,
            }
        })
        .max_by_key(|(start, _)| *start)
        .map(|(_, value)| value)
}

fn object_property<'tree>(
    object: &Node<'tree, StrDoc<SupportLang>>,
    expected: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if !matches!(object.kind().as_ref(), "object" | "object_expression") {
        return None;
    }
    object
        .children()
        .filter(|node| node.is_named())
        .find_map(|property| {
            let key = property.field("key")?;
            let key_text = key.text();
            let key = exact_quoted(key_text.trim()).unwrap_or_else(|| key_text.trim());
            (normalize_name(key) == expected)
                .then(|| property.field("value"))
                .flatten()
        })
}

struct CallSite<'tree> {
    node: Node<'tree, StrDoc<SupportLang>>,
    callee: String,
    arguments: Vec<Node<'tree, StrDoc<SupportLang>>>,
}

fn call_site(node: Node<'_, StrDoc<SupportLang>>) -> Option<CallSite<'_>> {
    if node.kind().as_ref() != "call_expression" {
        return None;
    }
    let arguments = node.field("arguments")?;
    let callee_length = arguments.range().start.checked_sub(node.range().start)?;
    let text = node.text();
    let callee = text.get(..callee_length)?.trim().to_string();
    let arguments = arguments
        .children()
        .filter(|child| child.is_named())
        .collect();
    Some(CallSite {
        node,
        callee,
        arguments,
    })
}

fn function_scope(
    node: &Node<'_, StrDoc<SupportLang>>,
    root: &Node<'_, StrDoc<SupportLang>>,
) -> Range<usize> {
    node.ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
            )
        })
        .map(|ancestor| ancestor.range())
        .unwrap_or_else(|| root.range())
}

fn function_header_is_request(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
            )
        })
        .is_some_and(|function| {
            let text = compact(function.text().as_ref());
            text.contains(":Request") || text.contains("req,") || text.contains("request,")
        })
}

fn language_rule(language: Language, suffix: &str) -> &'static str {
    match (language, suffix) {
        (Language::Javascript, "password-change-authority") => {
            "javascript-password-change-authority"
        }
        (Language::Typescript, "password-change-authority") => {
            "typescript-password-change-authority"
        }
        (Language::Tsx, "password-change-authority") => "tsx-password-change-authority",
        (Language::Javascript, "password-change-request-value") => {
            "javascript-password-change-request-value"
        }
        (Language::Typescript, "password-change-request-value") => {
            "typescript-password-change-request-value"
        }
        (Language::Tsx, "password-change-request-value") => "tsx-password-change-request-value",
        (Language::Javascript, "password-change-without-reauthentication") => {
            "javascript-password-change-without-reauthentication"
        }
        (Language::Typescript, "password-change-without-reauthentication") => {
            "typescript-password-change-without-reauthentication"
        }
        (Language::Tsx, "password-change-without-reauthentication") => {
            "tsx-password-change-without-reauthentication"
        }
        (Language::Javascript, "password-storage-review") => "javascript-password-storage-review",
        (Language::Typescript, "password-storage-review") => "typescript-password-storage-review",
        (Language::Tsx, "password-storage-review") => "tsx-password-storage-review",
        (Language::Javascript, "password-kdf-configuration") => {
            "javascript-password-kdf-configuration"
        }
        (Language::Typescript, "password-kdf-configuration") => {
            "typescript-password-kdf-configuration"
        }
        (Language::Tsx, "password-kdf-configuration") => "tsx-password-kdf-configuration",
        (Language::Javascript, "password-material") => "javascript-password-material",
        (Language::Typescript, "password-material") => "typescript-password-material",
        (Language::Tsx, "password-material") => "tsx-password-material",
        _ => unreachable!(),
    }
}

fn evidence_context<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> EvidenceContext {
    EvidenceContext {
        comment: comments.is_in_comment(node.range()),
        reachability: Some(reachability::classify(node, literals)),
        availability: Some(conditional.availability_for(node.range())),
        ..EvidenceContext::default()
    }
}

fn provenance() -> Provenance {
    Provenance {
        resolution: Resolution::Ast,
        engine: ENGINE.to_string(),
        rule_version: 1,
    }
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

fn numeric_literal(node: &Node<'_, StrDoc<SupportLang>>) -> Option<u64> {
    node.text().trim().replace('_', "").parse().ok()
}

fn exact_quoted(text: &str) -> Option<&str> {
    let quote = text.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"')
        || text.as_bytes().last().copied() != Some(quote)
        || text.len() < 2
        || text[1..text.len() - 1].contains('\\')
    {
        return None;
    }
    Some(&text[1..text.len() - 1])
}

fn simple_identifier(text: &str) -> Option<&str> {
    let mut characters = text.chars();
    characters
        .next()
        .is_some_and(|first| {
            (first == '_' || first.is_ascii_alphabetic())
                && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
        })
        .then_some(text)
}

fn terminal_symbol(symbol: &str) -> &str {
    symbol.rsplit('.').next().unwrap_or(symbol)
}

fn normalize_name(text: &str) -> String {
    text.chars()
        .filter(|character| !matches!(character, '_' | '-' | ' '))
        .flat_map(char::to_lowercase)
        .collect()
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn condition_text(text: &str) -> String {
    compact(text).trim_matches(['(', ')']).to_ascii_lowercase()
}

fn is_node_language(language: Language) -> bool {
    matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    )
}
