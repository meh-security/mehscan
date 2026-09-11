use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution, SymbolConfidence, SymbolResolution, SymbolResolutionMethod,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::{enclosing_symbol, lexical_declaration_visible_at};
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan java-jca-randomness-policy 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_java_crypto_observations<'tree>(
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
    evidence.retain(|item| item.rule_id != "java-hash-algorithm-selection");
    let imports = imports(root);
    let declarations = declared_types(root);
    add_algorithm_selections(
        path,
        root,
        &imports,
        &declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_key_kdf_material(
        path,
        root,
        &imports,
        &declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_randomness_policy(
        path,
        root,
        &imports,
        &declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_algorithm_selections<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let algorithms = [
        (
            "MessageDigest",
            "java.security.MessageDigest",
            Capability::CryptographicHash,
            "java-message-digest-selection",
        ),
        (
            "Cipher",
            "javax.crypto.Cipher",
            Capability::CryptographicEncryption,
            "java-cipher-transformation",
        ),
        (
            "Mac",
            "javax.crypto.Mac",
            Capability::CryptographicHash,
            "java-mac-algorithm-selection",
        ),
        (
            "Signature",
            "java.security.Signature",
            Capability::CryptographicHash,
            "java-signature-algorithm-selection",
        ),
        (
            "KeyGenerator",
            "javax.crypto.KeyGenerator",
            Capability::CryptographicEncryption,
            "java-key-generator-selection",
        ),
        (
            "SecretKeyFactory",
            "javax.crypto.SecretKeyFactory",
            Capability::CryptographicHash,
            "java-password-kdf-algorithm-selection",
        ),
    ];
    for invocation in invocations(root) {
        if invocation
            .field("name")
            .is_none_or(|name| name.text().trim() != "getInstance")
        {
            continue;
        }
        let Some(object) = invocation.field("object") else {
            continue;
        };
        let Some(algorithm) = arguments(&invocation).first().cloned() else {
            continue;
        };
        let Some((short, canonical, capability, rule_id)) =
            algorithms.iter().find(|(short, canonical, _, _)| {
                object.text().trim() == *canonical
                    || object.text().trim() == *short
                        && imported_exact(imports, declarations, canonical, short)
            })
        else {
            continue;
        };
        let algorithm_text = literal_string(algorithm.text().as_ref());
        let classification = classify_algorithm(short, algorithm_text.as_deref());
        let mut tags = vec!["cryptography", "java-jca", classification];
        if let Some(value) = algorithm_text.as_deref() {
            tags.push(if value.contains('/') {
                "transformation-literal"
            } else {
                "algorithm-literal"
            });
        }
        push(
            path,
            &invocation,
            EvidenceKind::SecurityConfiguration,
            *capability,
            rule_id,
            algorithm_cwes(short, classification),
            &tags,
            &[("algorithm", &algorithm)],
            Some(SymbolResolution {
                canonical: format!("{canonical}.getInstance"),
                observed: invocation.text().into_owned(),
                method: SymbolResolutionMethod::ImportedNamespace,
                confidence: SymbolConfidence::Exact,
            }),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn classify_algorithm(kind: &str, algorithm: Option<&str>) -> &'static str {
    let Some(algorithm) = algorithm.map(|value| value.to_ascii_uppercase().replace('-', "")) else {
        return "algorithm-runtime-review";
    };
    if kind == "Cipher" {
        if algorithm.contains("/ECB")
            || matches!(algorithm.as_str(), "DES" | "DESEDE" | "RC2" | "RC4")
        {
            "weak-primitive-or-mode"
        } else if algorithm.contains("/GCM/")
            || algorithm.contains("/CCM/")
            || algorithm.contains("CHACHA20POLY1305")
        {
            "authenticated-encryption"
        } else if algorithm.contains("/CBC/") || algorithm.contains("/CTR/") {
            "authentication-not-established"
        } else if algorithm.starts_with("RSA") && !algorithm.contains("OAEP") {
            "rsa-padding-review"
        } else {
            "transformation-review"
        }
    } else if kind == "KeyGenerator"
        && matches!(algorithm.as_str(), "DES" | "DESEDE" | "RC2" | "RC4")
        || algorithm.contains("MD5")
        || algorithm.contains("SHA1") && !algorithm.starts_with("PBKDF2")
    {
        "weak-algorithm"
    } else {
        "modern-algorithm"
    }
}

fn algorithm_cwes(kind: &str, classification: &str) -> &'static [&'static str] {
    if matches!(classification, "weak-algorithm" | "weak-primitive-or-mode")
        || kind == "Cipher" && classification == "authentication-not-established"
    {
        &["CWE-327"]
    } else {
        &[]
    }
}

#[allow(clippy::too_many_arguments)]
fn add_key_kdf_material<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for creation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "object_creation_expression")
    {
        let Some(kind) = creation.field("type") else {
            continue;
        };
        let kind_text = kind.text();
        let short = short_type(kind_text.as_ref());
        let args = creation
            .field("arguments")
            .map(|node| {
                node.children()
                    .filter(|child| child.is_named())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if short == "SecretKeySpec"
            && imported_exact(
                imports,
                declarations,
                "javax.crypto.spec.SecretKeySpec",
                short,
            )
            && args.len() >= 2
            && syntactically_fixed_material(&args[0])
        {
            push(
                path,
                &creation,
                EvidenceKind::SecurityConfiguration,
                Capability::CredentialMaterial,
                "java-hardcoded-secret-key-material",
                &["CWE-321"],
                &["cryptography", "hard-coded-key", "application-fix"],
                &[("key", &args[0]), ("algorithm", &args[1])],
                None,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        let parameter_canonical = match short {
            "IvParameterSpec" => Some("javax.crypto.spec.IvParameterSpec"),
            "GCMParameterSpec" => Some("javax.crypto.spec.GCMParameterSpec"),
            _ => None,
        };
        if parameter_canonical.is_some_and(|canonical| {
            kind_text.as_ref() == canonical
                || imported_exact(imports, declarations, canonical, short)
        }) && let Some(material) = args.last()
            && syntactically_fixed_material(material)
        {
            push(
                path,
                &creation,
                EvidenceKind::SecurityConfiguration,
                Capability::CryptographicEncryption,
                "java-fixed-iv-or-nonce-material",
                &["CWE-329"],
                &["cryptography", "fixed-iv-or-nonce", "application-fix"],
                &[("value", material)],
                None,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if short == "PBEKeySpec"
            && imported_exact(imports, declarations, "javax.crypto.spec.PBEKeySpec", short)
            && args.len() >= 3
        {
            let iteration = numeric_literal(args[2].text().as_ref());
            let classification = match iteration {
                Some(value) if value < 100_000 => "weak-work-factor",
                Some(_) => "explicit-work-factor",
                None => "runtime-work-factor-review",
            };
            let cwes = if classification == "weak-work-factor" {
                &["CWE-916"][..]
            } else {
                &[]
            };
            push(
                path,
                &creation,
                EvidenceKind::SecurityConfiguration,
                Capability::CryptographicHash,
                "java-password-kdf-parameters",
                cwes,
                &["cryptography", "password-kdf", classification],
                &[
                    ("password", &args[0]),
                    ("salt", &args[1]),
                    ("iterations", &args[2]),
                ],
                None,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn syntactically_fixed_material(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    let text = compact(node.text().as_ref());
    matches!(
        node.kind().as_ref(),
        "array_creation_expression" | "array_initializer"
    ) || text.starts_with("newbyte[")
        || text.contains(".getBytes(") && text.starts_with('"')
}

#[allow(clippy::too_many_arguments)]
fn add_randomness_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let random = imported_exact(imports, declarations, "java.util.Random", "Random");
    let secure_random = imported_exact(
        imports,
        declarations,
        "java.security.SecureRandom",
        "SecureRandom",
    );
    for invocation in invocations(root) {
        if !security_random_purpose(&invocation) {
            continue;
        }
        let name = invocation
            .field("name")
            .map(|node| node.text().into_owned())
            .unwrap_or_default();
        let object = invocation
            .field("object")
            .map(|node| node.text().trim().to_string());
        if name == "random" && object.as_deref() == Some("Math") && !declarations.contains("Math") {
            push(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::RandomGeneration,
                "java-insecure-security-randomness",
                &["CWE-338"],
                &[
                    "cryptography",
                    "security-randomness",
                    "math-random",
                    "application-fix",
                ],
                &[],
                Some(SymbolResolution {
                    canonical: "java.lang.Math.random".to_string(),
                    observed: "Math.random".to_string(),
                    method: SymbolResolutionMethod::Unqualified,
                    confidence: SymbolConfidence::Exact,
                }),
                comments,
                conditional,
                literals,
                evidence,
            );
            continue;
        }
        let Some(object) = invocation.field("object") else {
            continue;
        };
        if matches!(
            name.as_str(),
            "nextInt" | "nextLong" | "nextBytes" | "nextDouble"
        ) && random
            && receiver_is_at(&invocation, &object, "Random")
        {
            push(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::RandomGeneration,
                "java-insecure-security-randomness",
                &["CWE-338"],
                &[
                    "cryptography",
                    "security-randomness",
                    "java-util-random",
                    "application-fix",
                ],
                &[],
                None,
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if matches!(name.as_str(), "nextInt" | "nextLong" | "nextBytes")
            && secure_random
            && receiver_is_at(&invocation, &object, "SecureRandom")
        {
            push(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::RandomGeneration,
                "java-secure-security-randomness-control",
                &[],
                &[
                    "cryptography",
                    "security-randomness",
                    "secure-random",
                    "control",
                ],
                &[],
                None,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn security_random_purpose(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    let mut names = Vec::new();
    for ancestor in node.ancestors() {
        if matches!(
            ancestor.kind().as_ref(),
            "method_declaration" | "class_declaration"
        ) && let Some(name) = ancestor.field("name")
        {
            names.push(name.text().to_ascii_lowercase());
        }
    }
    names.iter().any(|name| {
        [
            "token", "otp", "password", "reset", "secret", "nonce", "salt", "session", "apikey",
            "api_key",
        ]
        .iter()
        .any(|term| name.contains(term))
    })
}

fn receiver_is_at(
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &Node<'_, StrDoc<SupportLang>>,
    expected: &str,
) -> bool {
    let name = receiver.text();
    let name = name.trim();
    let Some(method) = use_site
        .ancestors()
        .find(|node| node.kind().as_ref() == "method_declaration")
    else {
        return false;
    };
    method
        .dfs()
        .filter(|node| node.range().start <= use_site.range().start)
        .any(|node| {
            (node.kind().as_ref() == "formal_parameter"
                || node.kind().as_ref() == "local_variable_declaration"
                    && lexical_declaration_visible_at(&node, use_site))
                && node
                    .field("type")
                    .is_some_and(|kind| short_type(kind.text().as_ref()) == expected)
                && (node
                    .field("name")
                    .is_some_and(|candidate| candidate.text().trim() == name)
                    || node.children().any(|child| {
                        child
                            .field("name")
                            .is_some_and(|candidate| candidate.text().trim() == name)
                    }))
        })
}

fn invocations<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> impl Iterator<Item = Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "method_invocation")
}

fn arguments<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    invocation
        .field("arguments")
        .map(|args| args.children().filter(|child| child.is_named()).collect())
        .unwrap_or_default()
}

fn imports(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "import_declaration")
        .map(|node| {
            node.text()
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
    let namespace = canonical
        .rsplit_once('.')
        .map(|(namespace, _)| namespace)
        .unwrap_or_default();
    !declarations.contains(short)
        && (imports.contains(canonical) || imports.contains(&format!("{namespace}.*")))
}

fn short_type(kind: &str) -> &str {
    kind.trim()
        .rsplit('.')
        .next()
        .unwrap_or(kind.trim())
        .split('<')
        .next()
        .unwrap_or(kind.trim())
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn literal_string(text: &str) -> Option<String> {
    let text = text.trim();
    text.strip_prefix('"')?
        .strip_suffix('"')
        .map(str::to_string)
}

fn numeric_literal(text: &str) -> Option<u64> {
    text.trim().replace('_', "").parse().ok()
}

#[allow(clippy::too_many_arguments)]
fn push<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    cwes: &[&str],
    tags: &[&str],
    captures: &[(&str, &Node<'tree, StrDoc<SupportLang>>)],
    symbol_resolution: Option<SymbolResolution>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let id = format!(
        "{path}:{}:{}:{rule_id}",
        node.range().start,
        node.range().end
    );
    if comments.is_in_comment(node.range()) || evidence.iter().any(|item| item.id == id) {
        return;
    }
    let mut literal_values = BTreeMap::new();
    let captures = captures
        .iter()
        .map(|(role, capture)| {
            literal_values.insert((*role).to_string(), literals.evaluate(capture));
            (
                (*role).to_string(),
                Capture {
                    text: capture.text().into_owned(),
                    location: location(path, capture),
                },
            )
        })
        .collect();
    evidence.push(Evidence {
        id,
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
        symbol_resolution,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
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
