use std::collections::{BTreeMap, BTreeSet};

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

const ENGINE: &str = "mehscan java-identity-policy 1";

pub(crate) fn add_java_identity_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Java {
        return;
    }
    let imports = imports(root);
    let declarations = declared_types(root);
    add_nimbus_observations(
        path,
        root,
        comments,
        conditional,
        literals,
        &imports,
        &declarations,
        evidence,
    );
    add_jjwt_generation(
        path,
        root,
        comments,
        conditional,
        literals,
        &imports,
        evidence,
    );
    add_otp_lifecycle(path, root, comments, conditional, literals, evidence);
    add_reset_lifecycle(
        path,
        root,
        comments,
        conditional,
        literals,
        &imports,
        &declarations,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_nimbus_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    evidence: &mut Vec<Evidence>,
) {
    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_invocation")
    {
        let Some(name) = invocation.field("name") else {
            continue;
        };
        let object_text = invocation
            .field("object")
            .map(|object| object.text().into_owned())
            .unwrap_or_default();
        let method = nearest_method(&invocation);
        let method_text = method
            .as_ref()
            .map(|method| method.text().into_owned())
            .unwrap_or_default();

        if name.text().as_ref() == "parse"
            && object_text == "JWTParser"
            && imported_exact(
                imports,
                declarations,
                "com.nimbusds.jwt.JWTParser",
                "JWTParser",
            )
            && method_text.contains("getJWTClaimsSet()")
            && !method_text.contains(".verify(")
            && let Some(token) = first_argument(&invocation)
        {
            push(
                path,
                &invocation,
                &token,
                "java-nimbus-claims-without-verification",
                EvidenceKind::SensitiveOperation,
                Capability::Authentication,
                "token",
                &["CWE-347"],
                &[
                    "jwt",
                    "nimbus",
                    "claims-before-verification",
                    "signature-not-observed-in-method",
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if name.text().as_ref() == "parse"
            && object_text == "PlainJWT"
            && imported_exact(
                imports,
                declarations,
                "com.nimbusds.jwt.PlainJWT",
                "PlainJWT",
            )
            && method_text.contains("return true")
            && let Some(token) = first_argument(&invocation)
        {
            push(
                path,
                &invocation,
                &token,
                "java-nimbus-plain-jwt-accepted",
                EvidenceKind::SensitiveOperation,
                Capability::Authentication,
                "token",
                &["CWE-347"],
                &["jwt", "nimbus", "plain-jwt", "accepted-as-valid"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if name.text().as_ref() == "getAlgorithm"
            && imported_exact(
                imports,
                declarations,
                "com.nimbusds.jose.JWSHeader",
                "JWSHeader",
            )
            && method_text.contains("new MACVerifier(")
            && method_text.contains("new RSASSAVerifier(")
            && method_text.contains("alg.getName()")
        {
            push_without_capture(
                path,
                &invocation,
                "java-jwt-header-selects-verifier-family",
                EvidenceKind::SensitiveOperation,
                Capability::Authentication,
                &["CWE-347"],
                &[
                    "jwt",
                    "algorithm-confusion",
                    "header-selected-verifier-family",
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if name.text().as_ref() == "getJWKURL"
            && imported_exact(
                imports,
                declarations,
                "com.nimbusds.jose.JWSHeader",
                "JWSHeader",
            )
            && method_text.contains("openConnection()")
        {
            push_without_capture(
                path,
                &invocation,
                "java-jwt-header-jku-key-trust",
                EvidenceKind::SensitiveOperation,
                Capability::Authentication,
                &["CWE-347", "CWE-918"],
                &["jwt", "jku", "header-selected-key-url", "remote-key-trust"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if name.text().as_ref() == "getKeyID"
            && imported_exact(
                imports,
                declarations,
                "com.nimbusds.jose.JWSHeader",
                "JWSHeader",
            )
            && method_text.contains("/dev/null")
            && method_text.contains("\"AA==\"")
        {
            push_without_capture(
                path,
                &invocation,
                "java-jwt-kid-selects-known-hmac-key",
                EvidenceKind::SensitiveOperation,
                Capability::Authentication,
                &["CWE-347"],
                &["jwt", "kid", "known-key-material", "path-like-key-id"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if name.text().as_ref() == "verify"
            && imported_exact(
                imports,
                declarations,
                "com.nimbusds.jwt.SignedJWT",
                "SignedJWT",
            )
            && method_text.contains("SignedJWT.parse(")
        {
            push_without_capture(
                path,
                &invocation,
                "java-nimbus-signature-verification-control",
                EvidenceKind::Validation,
                Capability::Authentication,
                &["CWE-347"],
                &["jwt", "nimbus", "signature-verification"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_jjwt_generation<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    evidence: &mut Vec<Evidence>,
) {
    if !imports
        .iter()
        .any(|import| import == "io.jsonwebtoken.*" || import == "io.jsonwebtoken.Jwts")
    {
        return;
    }
    for method in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_declaration")
    {
        let text = method.text();
        if !text.contains("Jwts.builder()")
            || !text.contains(".signWith(")
            || !text.contains(".compact()")
        {
            continue;
        }
        let Some(builder) = method.dfs().find(|node| {
            node.kind().as_ref() == "method_invocation"
                && node
                    .field("name")
                    .is_some_and(|name| name.text().as_ref() == "builder")
                && node
                    .field("object")
                    .is_some_and(|object| object.text().as_ref() == "Jwts")
        }) else {
            continue;
        };
        let expiring = text.contains(".expiration(") || text.contains(".setExpiration(");
        push_without_capture(
            path,
            &builder,
            if expiring {
                "java-jwt-expiring-signed-token-control"
            } else {
                "java-jwt-signed-token-without-expiration"
            },
            if expiring {
                EvidenceKind::Validation
            } else {
                EvidenceKind::SensitiveOperation
            },
            Capability::TokenGeneration,
            &["CWE-613"],
            if expiring {
                &["jwt", "signed", "expiration-present"]
            } else {
                &["jwt", "signed", "expiration-absent", "long-lived-token"]
            },
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_otp_lifecycle<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let imports = imports(root);
    let declarations = declared_types(root);
    for class in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "class_declaration")
    {
        let text = class.text();
        let name = class
            .field("name")
            .map(|name| name.text().into_owned())
            .unwrap_or_default();
        if name == "Otp"
            && text.contains("String otp")
            && text.contains("String status")
            && !["expires", "expiry", "expiration", "createdAt", "issuedAt"]
                .iter()
                .any(|field| {
                    text.to_ascii_lowercase()
                        .contains(&field.to_ascii_lowercase())
                })
        {
            push_without_capture(
                path,
                &class,
                "java-otp-record-without-expiry",
                EvidenceKind::SecurityConfiguration,
                Capability::Authentication,
                &["CWE-613"],
                &["otp", "persistence", "expiry-field-not-observed"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_invocation")
    {
        let Some(name) = invocation.field("name") else {
            continue;
        };
        if name.text().as_ref() == "generateRandom"
            && invocation.field("object").is_some_and(|object| object.text().as_ref() == "OTPGenerator")
            && imported_short(&imports, &declarations, "OTPGenerator")
            && let Some(length) = first_argument(&invocation)
            && literals
                .evaluate(&length)
                .value
                .as_ref()
                .is_some_and(|value| matches!(value, mehscan_core::LiteralValue::Number(number) if number == "4"))
        {
            push(
                path,
                &invocation,
                &length,
                "java-short-numeric-otp-generation",
                EvidenceKind::SecurityConfiguration,
                Capability::Authentication,
                "length",
                &["CWE-307"],
                &["otp", "four-digit", "requires-attempt-limit"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    for method in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_declaration")
    {
        let text = method.text();
        let method_name = method
            .field("name")
            .map(|name| name.text().into_owned())
            .unwrap_or_default();
        if text.contains("setCount(") && text.contains("getCount() + 1") {
            let limited = text.contains("getCount() ==")
                || text.contains("getCount() >")
                || text.contains("getCount() >=")
                || text.contains("invalidateOtp(");
            push_without_capture(
                path,
                &method,
                if limited {
                    "java-otp-attempt-limit-control"
                } else {
                    "java-otp-counter-without-enforced-limit"
                },
                if limited {
                    EvidenceKind::Validation
                } else {
                    EvidenceKind::SecurityConfiguration
                },
                Capability::Authentication,
                &["CWE-307"],
                if limited {
                    &["otp", "attempt-limit", "invalidation-observed"]
                } else {
                    &["otp", "attempt-counter", "limit-not-observed"]
                },
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if method_name.to_ascii_lowercase().starts_with("validate")
            && text.contains("setStatus(")
            && text.contains("INACTIVE")
        {
            push_without_capture(
                path,
                &method,
                "java-otp-single-use-invalidation-control",
                EvidenceKind::Validation,
                Capability::Authentication,
                &["CWE-613"],
                &["otp", "single-use", "inactive-after-success"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if method_name.to_ascii_lowercase().starts_with("validate")
            && text.contains("getStatus()")
            && text.contains("ACTIVE")
            && text.contains("getOtp()")
        {
            push_without_capture(
                path,
                &method,
                "java-otp-active-status-validation-control",
                EvidenceKind::Validation,
                Capability::Authentication,
                &["CWE-613"],
                &["otp", "active-status", "value-and-subject-match"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_reset_lifecycle<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    evidence: &mut Vec<Evidence>,
) {
    for class in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "class_declaration")
    {
        let lower = class.text().to_ascii_lowercase();
        if lower.contains("string emailtoken")
            && !["expires", "expiry", "expiration", "createdat", "issuedat"]
                .iter()
                .any(|field| lower.contains(field))
        {
            push_without_capture(
                path,
                &class,
                "java-stateful-email-token-without-expiry",
                EvidenceKind::SecurityConfiguration,
                Capability::Authentication,
                &["CWE-613"],
                &["email-token", "persistence", "expiry-field-not-observed"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_invocation")
    {
        let Some(name) = invocation.field("name") else {
            continue;
        };
        let method = nearest_method(&invocation);
        let method_text = method
            .as_ref()
            .map(|method| method.text().into_owned())
            .unwrap_or_default();
        let method_name = method
            .as_ref()
            .and_then(|method| method.field("name"))
            .map(|name| name.text().into_owned())
            .unwrap_or_default();

        if name.text().as_ref() == "encode"
            && imported_exact(
                imports,
                declarations,
                "org.springframework.security.crypto.password.PasswordEncoder",
                "PasswordEncoder",
            )
        {
            push_without_capture(
                path,
                &invocation,
                "java-spring-password-encoding-control",
                EvidenceKind::Validation,
                Capability::CredentialMaterial,
                &[],
                &["password", "spring-security", "encoding"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if name.text().as_ref() == "generateRandom"
            && invocation
                .field("object")
                .is_some_and(|object| object.text().as_ref() == "EmailTokenGenerator")
            && imported_short(imports, declarations, "EmailTokenGenerator")
            && let Some(length) = first_argument(&invocation)
            && literals
                .evaluate(&length)
                .value
                .as_ref()
                .is_some_and(|value| matches!(value, mehscan_core::LiteralValue::Number(number) if number == "10"))
        {
            push(
                path,
                &invocation,
                &length,
                "java-short-email-token-generation",
                EvidenceKind::SecurityConfiguration,
                Capability::TokenGeneration,
                "length",
                &["CWE-330"],
                &["email-token", "ten-character", "entropy-review"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if name.text().as_ref() == "findByEmailToken"
            && !method_text.contains("getStatus()")
            && !method_text.contains("setStatus(")
            && !method_text.contains("setEmailToken(")
            && !method_text.contains(".delete(")
        {
            push_without_capture(
                path,
                &invocation,
                "java-email-token-use-without-lifecycle-control",
                EvidenceKind::SensitiveOperation,
                Capability::Authentication,
                &["CWE-613"],
                &[
                    "email-token",
                    "status-check-not-observed",
                    "single-use-not-observed",
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if method_name.to_ascii_lowercase().contains("resetpassword")
            && name.text().as_ref() == "getUserFromToken"
            && method_text.contains("encoder.encode(")
        {
            push_without_capture(
                path,
                &invocation,
                "java-password-reset-authenticated-subject-control",
                EvidenceKind::Validation,
                Capability::Authentication,
                &[],
                &[
                    "password-reset",
                    "authenticated-subject",
                    "password-encoding",
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    for method in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_declaration")
    {
        let method_name = method
            .field("name")
            .map(|name| name.text().to_ascii_lowercase())
            .unwrap_or_default();
        if method_name != "generateapikey" {
            continue;
        }
        if let Some(debug_call) = method.dfs().find(|node| {
            node.kind().as_ref() == "method_invocation"
                && node
                    .field("name")
                    .is_some_and(|name| name.text().as_ref() == "debug")
                && node
                    .field("object")
                    .is_some_and(|object| matches!(object.text().trim(), "log" | "logger"))
                && node.field("arguments").is_some_and(|arguments| {
                    arguments
                        .children()
                        .filter(|argument| argument.is_named())
                        .any(|argument| argument.text().trim() == "apiKey")
                })
        }) {
            push_without_capture(
                path,
                &debug_call,
                "java-api-key-debug-logging",
                EvidenceKind::SensitiveOperation,
                Capability::CredentialMaterial,
                &["CWE-532"],
                &["api-key", "debug-log", "plaintext-value"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    captured: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    role: &str,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    push_evidence(
        path,
        node,
        rule_id,
        kind,
        capability,
        BTreeMap::from([(
            role.to_string(),
            Capture {
                text: captured.text().into_owned(),
                location: location(path, captured),
            },
        )]),
        BTreeMap::from([(role.to_string(), literals.evaluate(captured))]),
        cwes,
        tags,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_without_capture<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    push_evidence(
        path,
        node,
        rule_id,
        kind,
        capability,
        BTreeMap::new(),
        BTreeMap::new(),
        cwes,
        tags,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_evidence<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    captures: BTreeMap<String, Capture>,
    literal_values: BTreeMap<String, mehscan_core::LiteralEvaluation>,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if comments.is_in_comment(node.range())
        || evidence.iter().any(|item| {
            item.rule_id == rule_id
                && item.location.path == path
                && item.location.start.byte_offset == node.range().start
        })
    {
        return;
    }
    evidence.push(Evidence {
        id: format!(
            "{path}:{}:{}:{rule_id}",
            node.range().start,
            node.range().end
        ),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes.iter().map(|cwe| (*cwe).to_string()).collect(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            literals: literal_values,
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

fn imports(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "import_declaration")
        .map(|import| {
            import
                .text()
                .trim()
                .trim_start_matches("import ")
                .trim_start_matches("static ")
                .trim_end_matches(';')
                .to_string()
        })
        .collect()
}

fn declared_types(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| {
            matches!(
                node.kind().as_ref(),
                "class_declaration"
                    | "interface_declaration"
                    | "record_declaration"
                    | "enum_declaration"
            )
        })
        .filter_map(|node| node.field("name"))
        .map(|name| name.text().into_owned())
        .collect()
}

fn imported_exact(
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    canonical: &str,
    short: &str,
) -> bool {
    !declarations.contains(short)
        && (imports.contains(canonical)
            || canonical
                .rsplit_once('.')
                .is_some_and(|(namespace, _)| imports.contains(&format!("{namespace}.*"))))
}

fn imported_short(
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    short: &str,
) -> bool {
    !declarations.contains(short)
        && imports.iter().any(|import| {
            import
                .rsplit_once('.')
                .is_some_and(|(_, name)| name == short)
        })
}

fn first_argument<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    invocation
        .field("arguments")?
        .children()
        .find(|child| child.is_named())
}

fn nearest_method<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    node.ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "method_declaration")
}

fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let range = node.range();
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.to_string(),
        start: Position {
            byte_offset: range.start,
            line: start.line() + 1,
            column: start.column(node) + 1,
        },
        end: Position {
            byte_offset: range.end,
            line: end.line() + 1,
            column: end.column(node) + 1,
        },
    }
}
