use std::collections::BTreeMap;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language,
    LiteralValue, Location, Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::{enclosing_symbol, lexical_declaration_visible_at};
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan csharp-crypto-policy 2";
const IDENTITY_PBKDF2_BASELINE: u64 = 100_000;
const DIRECT_PBKDF2_SHA256_BASELINE: u64 = 600_000;

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_crypto_policy_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Csharp {
        return;
    }
    add_password_hasher_options(path, root, comments, conditional, literals, evidence);
    add_identity_account_policy(path, root, comments, conditional, literals, evidence);
    add_password_kdfs(path, root, comments, conditional, literals, evidence);
    add_fast_security_hashes(path, root, comments, conditional, literals, evidence);
    add_security_randomness(path, root, comments, conditional, literals, evidence);
    add_symmetric_crypto(path, root, comments, conditional, literals, evidence);
    add_jwt_signing(path, root, comments, conditional, literals, evidence);
}

#[derive(Clone, Copy)]
enum FastHashRole {
    Password,
    PasswordReset,
}

#[allow(clippy::too_many_arguments)]
fn add_fast_security_hashes<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for invocation in invocations(root) {
        let Some(function) = invocation.field("function") else {
            continue;
        };
        let function_text = compact(function.text().as_ref());
        let Some(receiver) = function_text.strip_suffix(".ComputeHash") else {
            continue;
        };
        let Some(receiver) = simple_identifier(receiver) else {
            continue;
        };
        let Some(initializer) = root
            .dfs()
            .filter(|node| {
                node.kind().as_ref() == "variable_declarator"
                    && node.range().start < invocation.range().start
                    && same_method(node.range(), &invocation)
                    && lexical_declaration_visible_at(node, &invocation)
                    && node
                        .field("name")
                        .is_some_and(|name| name.text().trim() == receiver)
            })
            .filter_map(|node| {
                node.field("value")
                    .or_else(|| node.children().filter(|child| child.is_named()).last())
            })
            .last()
        else {
            continue;
        };
        let initializer_text = compact(initializer.text().as_ref());
        let weak_algorithm = [
            ("MD5.Create(", "System.Security.Cryptography.MD5"),
            ("SHA1.Create(", "System.Security.Cryptography.SHA1"),
        ]
        .iter()
        .any(|(factory, canonical)| {
            initializer_text
                .strip_suffix(".Create()")
                .is_some_and(|actual| {
                    initializer_text.ends_with(factory)
                        || source_type_matches(root, actual, canonical)
                })
        });
        if !weak_algorithm {
            continue;
        }
        let Some(input) = arguments(&invocation).first().cloned() else {
            continue;
        };
        let Some(role) = fast_hash_role(&invocation, &input) else {
            continue;
        };
        let (rule_id, capture_role, cwes, tags): (&str, &str, &[&str], &[&str]) = match role {
            FastHashRole::Password => (
                "csharp-password-fast-hash",
                "password",
                &["CWE-916"],
                &[
                    "password-hashing",
                    "fast-hash",
                    "missing-password-kdf",
                    "recommendation:fix-application",
                ],
            ),
            FastHashRole::PasswordReset => (
                "csharp-predictable-password-reset-hash",
                "reset_token_material",
                &["CWE-640", "CWE-327"],
                &[
                    "password-reset",
                    "deterministic-token",
                    "fast-hash",
                    "recommendation:fix-application",
                ],
            ),
        };
        push(
            path,
            &invocation,
            EvidenceKind::SecurityConfiguration,
            Capability::CryptographicHash,
            rule_id,
            capture_role,
            cwes,
            tags,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn fast_hash_role(
    invocation: &Node<'_, StrDoc<SupportLang>>,
    input: &Node<'_, StrDoc<SupportLang>>,
) -> Option<FastHashRole> {
    let mut context = input.text().to_ascii_lowercase();
    for ancestor in invocation.ancestors().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "method_declaration" | "class_declaration"
        )
    }) {
        if let Some(name) = ancestor.field("name") {
            context.push_str(&name.text().to_ascii_lowercase());
        }
    }
    if context.contains("password") && !context.contains("reset") {
        Some(FastHashRole::Password)
    } else if context.contains("reset")
        && (context.contains("email") || context.contains("token") || context.contains("key"))
    {
        Some(FastHashRole::PasswordReset)
    } else {
        None
    }
}

fn add_identity_account_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for invocation in invocations(root) {
        let text = compact(invocation.text().as_ref());
        let identity_options = text.contains("Configure<IdentityOptions>(")
            || text.contains("AddIdentity<")
            || text.contains("AddDefaultIdentity<");
        if !identity_options {
            continue;
        }

        if let Some(length) = assigned_number(&invocation, "Password.RequiredLength", literals) {
            let (kind, rule_id, disposition) = if length < 8 {
                (
                    EvidenceKind::SecurityConfiguration,
                    "csharp-identity-weak-password-policy",
                    "recommendation:fix-application",
                )
            } else if length >= 15 {
                (
                    EvidenceKind::Validation,
                    "csharp-identity-password-length-control",
                    "recommendation:control-present",
                )
            } else {
                (
                    EvidenceKind::SecurityConfiguration,
                    "csharp-identity-password-policy-review",
                    "recommendation:review-policy",
                )
            };
            let digits = assigned_bool(&invocation, "Password.RequireDigit", literals);
            let lower = assigned_bool(&invocation, "Password.RequireLowercase", literals);
            let upper = assigned_bool(&invocation, "Password.RequireUppercase", literals);
            let symbols = assigned_bool(&invocation, "Password.RequireNonAlphanumeric", literals);
            let unique = assigned_number(&invocation, "Password.RequiredUniqueChars", literals);
            push(
                path,
                &invocation,
                kind,
                Capability::Authentication,
                rule_id,
                "password_policy",
                &["CWE-521"],
                &[
                    "aspnet-identity",
                    "password-policy",
                    disposition,
                    &format!("required-length:{length}"),
                    &format!("require-digit:{}", policy_value(digits)),
                    &format!("require-lowercase:{}", policy_value(lower)),
                    &format!("require-uppercase:{}", policy_value(upper)),
                    &format!("require-symbol:{}", policy_value(symbols)),
                    &format!(
                        "required-unique-chars:{}",
                        unique.map_or_else(|| "unknown".to_string(), |value| value.to_string())
                    ),
                    "needs-verification",
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        let allowed = assigned_bool(&invocation, "Lockout.AllowedForNewUsers", literals);
        let attempts = assigned_number(&invocation, "Lockout.MaxFailedAccessAttempts", literals);
        if allowed.is_none() && attempts.is_none() {
            continue;
        }
        let weak = allowed == Some(false) || attempts.is_some_and(|value| value == 0 || value > 10);
        let controlled =
            allowed == Some(true) && attempts.is_some_and(|value| (1..=10).contains(&value));
        let (kind, rule_id, disposition) = if weak {
            (
                EvidenceKind::SecurityConfiguration,
                "csharp-identity-weak-lockout-policy",
                "recommendation:fix-application",
            )
        } else if controlled {
            (
                EvidenceKind::Validation,
                "csharp-identity-lockout-control",
                "recommendation:control-present",
            )
        } else {
            (
                EvidenceKind::SecurityConfiguration,
                "csharp-identity-lockout-policy-review",
                "recommendation:review-policy",
            )
        };
        push(
            path,
            &invocation,
            kind,
            Capability::Authentication,
            rule_id,
            "lockout_policy",
            &["CWE-307"],
            &[
                "aspnet-identity",
                "account-lockout",
                disposition,
                &format!("allowed-for-new-users:{}", policy_value(allowed)),
                &format!(
                    "max-failed-attempts:{}",
                    attempts.map_or_else(|| "unknown".to_string(), |value| value.to_string())
                ),
                "needs-verification",
            ],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn policy_value(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    }
}

fn add_password_hasher_options<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for invocation in invocations(root) {
        let text = compact(invocation.text().as_ref());
        if !text.contains("Configure<PasswordHasherOptions>") {
            continue;
        }
        let iterations = assigned_number(&invocation, "IterationCount", literals);
        let identity_v2 =
            text.contains("CompatibilityMode=PasswordHasherCompatibilityMode.IdentityV2");
        let identity_v3 =
            text.contains("CompatibilityMode=PasswordHasherCompatibilityMode.IdentityV3");
        if identity_v2 || iterations.is_some_and(|value| value < IDENTITY_PBKDF2_BASELINE) {
            push(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::CryptographicHash,
                "csharp-identity-password-hasher-weak-parameters",
                "password",
                &["CWE-916"],
                &[
                    "aspnet-identity",
                    "password-hashing",
                    "weak-parameters",
                    "needs-verification",
                    &format!(
                        "iterations:{}",
                        iterations.map_or_else(|| "unknown".into(), |v| v.to_string())
                    ),
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if iterations.is_some_and(|value| value >= IDENTITY_PBKDF2_BASELINE)
            && (!text.contains("CompatibilityMode=") || identity_v3)
        {
            push(
                path,
                &invocation,
                EvidenceKind::Validation,
                Capability::CryptographicHash,
                "csharp-identity-password-hasher-parameter-control",
                "password",
                &["CWE-916"],
                &[
                    "aspnet-identity",
                    "password-hashing",
                    "explicit-work-factor",
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn add_password_kdfs<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for invocation in invocations(root) {
        let Some(function) = invocation.field("function") else {
            continue;
        };
        let function = compact(function.text().as_ref());
        let arguments = arguments(&invocation);
        if function.ends_with("KeyDerivation.Pbkdf2") || function == "KeyDerivation.Pbkdf2" {
            let iterations = arguments.get(3).and_then(|node| numeric(node, literals));
            let random_salt = arguments
                .get(1)
                .is_some_and(|salt| value_is_random(root, &invocation, salt));
            let weak = iterations.is_some_and(|value| value < DIRECT_PBKDF2_SHA256_BASELINE)
                || arguments
                    .get(1)
                    .is_some_and(|salt| value_is_constant(salt, literals));
            push_kdf(
                path,
                &invocation,
                if weak {
                    EvidenceKind::SecurityConfiguration
                } else if iterations.is_some_and(|value| value >= DIRECT_PBKDF2_SHA256_BASELINE)
                    && random_salt
                {
                    EvidenceKind::Validation
                } else {
                    continue;
                },
                "pbkdf2",
                iterations,
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if function.ends_with("BCrypt.HashPassword") {
            let cost = arguments.get(1).and_then(|node| numeric(node, literals));
            let Some(cost) = cost else { continue };
            push_kdf(
                path,
                &invocation,
                if cost < 10 {
                    EvidenceKind::SecurityConfiguration
                } else {
                    EvidenceKind::Validation
                },
                "bcrypt",
                Some(cost),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    for creation in object_creations(root, "Argon2id") {
        let iterations = assigned_number(&creation, "Iterations", literals);
        let memory = assigned_number(&creation, "MemorySize", literals);
        let parallelism = assigned_number(&creation, "DegreeOfParallelism", literals);
        let (Some(iterations), Some(memory), Some(parallelism)) = (iterations, memory, parallelism)
        else {
            continue;
        };
        let acceptable = parallelism >= 1
            && [
                (47_104, 1),
                (19_456, 2),
                (12_288, 3),
                (9_216, 4),
                (7_168, 5),
            ]
            .iter()
            .any(|(minimum_memory, minimum_iterations)| {
                memory >= *minimum_memory && iterations >= *minimum_iterations
            });
        push(
            path,
            &creation,
            if acceptable {
                EvidenceKind::Validation
            } else {
                EvidenceKind::SecurityConfiguration
            },
            Capability::CryptographicHash,
            if acceptable {
                "csharp-argon2id-parameter-control"
            } else {
                "csharp-argon2id-weak-parameters"
            },
            "password",
            &["CWE-916"],
            &[
                "password-hashing",
                "argon2id",
                if acceptable {
                    "parameter-control"
                } else {
                    "weak-parameters"
                },
                &format!("memory-kib:{memory}"),
                &format!("iterations:{iterations}"),
                &format!("parallelism:{parallelism}"),
            ],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn push_kdf<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    algorithm: &str,
    work_factor: Option<u64>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let control = kind == EvidenceKind::Validation;
    push(
        path,
        node,
        kind,
        Capability::CryptographicHash,
        if control {
            "csharp-password-kdf-parameter-control"
        } else {
            "csharp-password-kdf-weak-parameters"
        },
        "password",
        &["CWE-916"],
        &[
            "password-hashing",
            algorithm,
            if control {
                "parameter-control"
            } else {
                "weak-parameters"
            },
            &format!(
                "work-factor:{}",
                work_factor.map_or_else(|| "unknown".into(), |v| v.to_string())
            ),
        ],
        comments,
        conditional,
        literals,
        evidence,
    );
}

fn add_security_randomness<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for invocation in invocations(root) {
        let Some(function) = invocation.field("function") else {
            continue;
        };
        let function = compact(function.text().as_ref());
        let Some(generator) = classify_security_generator(root, &invocation, &function) else {
            continue;
        };
        let Some(role) = security_lifecycle_role(root, &invocation) else {
            continue;
        };
        let (kind, rule_id, cwe, generator_tag, disposition) = match generator {
            SecurityGenerator::Csprng => (
                EvidenceKind::Validation,
                "csharp-security-token-csprng-control",
                "CWE-338",
                "csprng",
                "recommendation:control-present",
            ),
            SecurityGenerator::SystemRandom => (
                EvidenceKind::SecurityConfiguration,
                "csharp-security-token-weak-randomness",
                "CWE-338",
                "predictable-randomness",
                "recommendation:fix-application",
            ),
            SecurityGenerator::Guid => (
                EvidenceKind::SecurityConfiguration,
                "csharp-security-token-guid-suitability-review",
                "CWE-330",
                "guid-suitability-review",
                "recommendation:review-policy",
            ),
        };
        push(
            path,
            &invocation,
            kind,
            Capability::RandomGeneration,
            rule_id,
            "random_value",
            &[cwe],
            &[
                "security-token",
                generator_tag,
                disposition,
                &format!("lifecycle-role:{role}"),
                if generator == SecurityGenerator::Guid {
                    "not-a-predictability-claim"
                } else {
                    "generator-classified"
                },
            ],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecurityGenerator {
    Csprng,
    SystemRandom,
    Guid,
}

fn classify_security_generator<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    invocation: &Node<'tree, StrDoc<SupportLang>>,
    function: &str,
) -> Option<SecurityGenerator> {
    let method = function.rsplit('.').next()?;
    let receiver = function.strip_suffix(&format!(".{method}"))?;
    if matches!(
        method,
        "GetBytes"
            | "GetNonZeroBytes"
            | "GetInt32"
            | "Fill"
            | "GetHexString"
            | "GetString"
            | "GetItems"
    ) && receiver_has_type(
        root,
        invocation,
        receiver,
        "System.Security.Cryptography.RandomNumberGenerator",
    ) {
        return Some(SecurityGenerator::Csprng);
    }
    if matches!(method, "GetBytes" | "GetNonZeroBytes")
        && receiver_has_type(
            root,
            invocation,
            receiver,
            "System.Security.Cryptography.RNGCryptoServiceProvider",
        )
    {
        return Some(SecurityGenerator::Csprng);
    }
    if matches!(
        method,
        "Next" | "NextInt64" | "NextDouble" | "NextSingle" | "NextBytes"
    ) && receiver_has_type(root, invocation, receiver, "System.Random")
    {
        return Some(SecurityGenerator::SystemRandom);
    }
    (method == "NewGuid" && receiver_has_type(root, invocation, receiver, "System.Guid"))
        .then_some(SecurityGenerator::Guid)
}

fn receiver_has_type(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
    canonical: &str,
) -> bool {
    if receiver == canonical || source_type_matches(root, receiver, canonical) {
        return true;
    }
    if let Some(created) = receiver
        .strip_prefix("new")
        .and_then(|text| text.strip_suffix("()"))
    {
        return source_type_matches(root, created, canonical);
    }
    if let Some(factory) = receiver.strip_suffix(".Create()") {
        return source_type_matches(root, factory, canonical);
    }
    if canonical == "System.Random" && receiver == "Random.Shared" {
        return source_type_matches(root, "Random", canonical);
    }
    root.dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .filter(|node| node.range().start < use_site.range().start)
        .filter(|node| same_method(node.range(), use_site))
        .filter(|node| lexical_declaration_visible_at(node, use_site))
        .filter(|node| {
            node.field("name")
                .is_some_and(|name| compact(name.text().as_ref()) == receiver)
        })
        .any(|node| {
            node.parent()
                .and_then(|parent| parent.field("type"))
                .is_some_and(|kind| source_type_matches(root, kind.text().trim(), canonical))
                || node
                    .field("value")
                    .or_else(|| node.children().filter(|child| child.is_named()).last())
                    .is_some_and(|value| {
                        let value = compact(value.text().as_ref());
                        value
                            .strip_prefix("new")
                            .and_then(|created| created.split_once('('))
                            .is_some_and(|(created, _)| {
                                source_type_matches(root, created, canonical)
                            })
                            || value.split_once(".Create(").is_some_and(|(factory, _)| {
                                source_type_matches(root, factory, canonical)
                            })
                    })
        })
}

fn source_type_matches(
    root: &Node<'_, StrDoc<SupportLang>>,
    actual: &str,
    canonical: &str,
) -> bool {
    let actual = actual.trim().trim_start_matches("global::");
    let canonical = canonical.trim_start_matches("global::");
    if actual == canonical {
        return true;
    }
    let (namespace, short) = canonical.rsplit_once('.').unwrap_or(("", canonical));
    for directive in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "using_directive")
    {
        let using = compact(directive.text().as_ref())
            .trim_start_matches("using")
            .trim_end_matches(';')
            .trim_start_matches("global::")
            .to_string();
        if let Some((alias, target)) = using.split_once('=') {
            if target == canonical && actual == alias {
                return true;
            }
        } else if using == namespace && actual == short && !declares_type(root, short) {
            return true;
        }
    }
    false
}

fn declares_type(root: &Node<'_, StrDoc<SupportLang>>, expected: &str) -> bool {
    root.dfs().any(|node| {
        matches!(
            node.kind().as_ref(),
            "class_declaration" | "struct_declaration" | "record_declaration"
        ) && node
            .field("name")
            .is_some_and(|name| name.text().trim() == expected)
    })
}

fn security_lifecycle_role<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<&'static str> {
    for ancestor in invocation
        .ancestors()
        .take_while(|node| !matches!(node.kind().as_ref(), "block" | "method_declaration"))
    {
        if let Some(role) = direct_lifecycle_role(&ancestor) {
            return Some(role);
        }
    }

    let method = invocation
        .ancestors()
        .find(|node| node.kind().as_ref() == "method_declaration");
    if invocation.ancestors().any(|node| {
        matches!(
            node.kind().as_ref(),
            "return_statement" | "arrow_expression_clause"
        )
    }) && let Some(role) = method
        .as_ref()
        .and_then(|node| node.field("name"))
        .and_then(|name| lifecycle_role(name.text().as_ref()))
    {
        return Some(role);
    }

    let generated_name = generated_value_name(invocation)?;
    if let Some(role) = lifecycle_role(generated_name.as_str()) {
        return Some(role);
    }
    let scope = method.unwrap_or_else(|| root.clone());
    scope
        .dfs()
        .filter(|node| node.range().start > invocation.range().start)
        .filter(|node| node.text().as_ref().contains(generated_name.as_str()))
        .find_map(|node| direct_lifecycle_role(&node))
}

fn direct_lifecycle_role(node: &Node<'_, StrDoc<SupportLang>>) -> Option<&'static str> {
    match node.kind().as_ref() {
        "variable_declarator" => node
            .field("name")
            .and_then(|name| lifecycle_role(name.text().as_ref())),
        "assignment_expression" => node
            .field("left")
            .and_then(|left| lifecycle_role(left.text().as_ref())),
        "invocation_expression" => node
            .field("function")
            .and_then(|function| lifecycle_role(function.text().as_ref())),
        "argument" => node
            .parent()
            .and_then(|arguments| arguments.parent())
            .and_then(|call| {
                call.field("function")
                    .and_then(|function| lifecycle_role(function.text().as_ref()))
            }),
        _ => None,
    }
}

fn generated_value_name(invocation: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let function = compact(invocation.field("function")?.text().as_ref());
    if ["NextBytes", "Fill", "GetBytes", "GetNonZeroBytes"]
        .iter()
        .any(|method| function.ends_with(&format!(".{method}")))
    {
        return arguments(invocation)
            .first()
            .map(|argument| compact(argument.text().as_ref()))
            .filter(|name| simple_identifier(name).is_some());
    }
    invocation
        .ancestors()
        .find_map(|node| match node.kind().as_ref() {
            "variable_declarator" => node
                .field("name")
                .map(|name| compact(name.text().as_ref()))
                .filter(|name| simple_identifier(name).is_some()),
            "assignment_expression" => node
                .field("left")
                .map(|left| compact(left.text().as_ref()))
                .filter(|name| simple_identifier(name).is_some()),
            "statement" | "return_statement" | "block" => None,
            _ => None,
        })
}

fn lifecycle_role(name: &str) -> Option<&'static str> {
    let words = identifier_words(name);
    let has = |expected: &str| words.iter().any(|word| word == expected);
    let credential = has("token") || has("code");
    if !credential {
        return None;
    }
    if has("reset") {
        Some("password-reset")
    } else if has("recovery") || has("recover") {
        Some("account-recovery")
    } else if has("invitation") || has("invite") {
        Some("invitation")
    } else if has("verification") || has("verify") || has("confirmation") || has("confirm") {
        Some("verification")
    } else if has("approval") || has("approve") {
        Some("approval")
    } else {
        None
    }
}

fn identifier_words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut previous_lower_or_digit = false;
    for character in name.chars() {
        if !character.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            previous_lower_or_digit = false;
            continue;
        }
        if character.is_ascii_uppercase() && previous_lower_or_digit && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        current.push(character.to_ascii_lowercase());
        previous_lower_or_digit = character.is_ascii_lowercase() || character.is_ascii_digit();
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn add_symmetric_crypto<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for assignment in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
    {
        let (Some(left), Some(right)) = (assignment.field("left"), assignment.field("right"))
        else {
            continue;
        };
        let left = compact(left.text().as_ref());
        let right_text = compact(right.text().as_ref());
        if left.ends_with(".Mode") && right_text.ends_with("CipherMode.ECB") {
            push(
                path,
                &assignment,
                EvidenceKind::SecurityConfiguration,
                Capability::CryptographicEncryption,
                "csharp-aes-ecb-mode",
                "mode",
                &["CWE-327"],
                &["aes", "ecb", "weak-mode"],
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if left.ends_with(".IV") {
            let random = value_is_random(root, &assignment, &right);
            let constant = value_is_constant(&right, literals) || zeroed_byte_array(&right_text);
            if random || constant {
                push(
                    path,
                    &assignment,
                    if random {
                        EvidenceKind::Validation
                    } else {
                        EvidenceKind::SecurityConfiguration
                    },
                    Capability::CryptographicEncryption,
                    if random {
                        "csharp-aes-random-iv-control"
                    } else {
                        "csharp-aes-constant-iv"
                    },
                    "iv",
                    &["CWE-329"],
                    &["aes", if random { "random-iv" } else { "constant-iv" }],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }
    }
    for invocation in invocations(root) {
        let Some(function) = invocation.field("function") else {
            continue;
        };
        if !compact(function.text().as_ref()).ends_with(".Encrypt")
            || !receiver_is_aes_gcm(root, &invocation, &function)
        {
            continue;
        }
        let Some(nonce) = arguments(&invocation).first().cloned() else {
            continue;
        };
        let random = value_is_random(root, &invocation, &nonce);
        let resolved_nonce = resolve_initializer(root, &invocation, &nonce);
        let constant_node = resolved_nonce.as_ref().unwrap_or(&nonce);
        let constant = value_is_constant(constant_node, literals)
            || zeroed_byte_array(compact(constant_node.text().as_ref()).as_str());
        if random || constant {
            push(
                path,
                &invocation,
                if random {
                    EvidenceKind::Validation
                } else {
                    EvidenceKind::SecurityConfiguration
                },
                Capability::CryptographicEncryption,
                if random {
                    "csharp-aes-gcm-random-nonce-control"
                } else {
                    "csharp-aes-gcm-constant-nonce"
                },
                "nonce",
                &["CWE-323"],
                &[
                    "aes-gcm",
                    if random {
                        "fresh-local-csprng-nonce"
                    } else {
                        "constant-nonce"
                    },
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn add_jwt_signing<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for signing in object_creations(root, "SigningCredentials") {
        let Some(key_argument) = arguments(&signing).first().cloned() else {
            continue;
        };
        let key_expression =
            resolve_initializer(root, &signing, &key_argument).unwrap_or(key_argument);
        let Some((secret, definition)) =
            hardcoded_key_node(root, &signing, &key_expression, literals)
        else {
            continue;
        };
        push_pair(
            path,
            &secret,
            &signing,
            "csharp-hardcoded-jwt-signing-key",
            "csharp-jwt-signing-with-hardcoded-key",
            "signing_key",
            "CWE-321",
            &["jwt", "signing", "hardcoded-key"],
            comments,
            conditional,
            literals,
            evidence,
        );
        let source_id = evidence_id(
            "csharp-hardcoded-jwt-signing-key",
            path,
            secret.range().start,
            secret.range().end,
        );
        if definition.range() != secret.range()
            && let Some(source) = evidence.iter_mut().find(|item| item.id == source_id)
        {
            source.captures.insert(
                "key_definition".to_string(),
                Capture {
                    text: definition.text().into_owned(),
                    location: location(path, &definition),
                },
            );
        }
    }
    for token in root.dfs().filter(|node| {
        node.kind().as_ref() == "object_creation_expression"
            && node.field("type").is_some_and(|kind| {
                matches!(
                    short_type(kind.text().as_ref()),
                    "JwtSecurityToken" | "SecurityTokenDescriptor"
                )
            })
    }) {
        let text = compact(token.text().as_ref());
        let has_expiry = text.contains("expires:") || text.contains("Expires=");
        push(
            path,
            &token,
            if has_expiry {
                EvidenceKind::Validation
            } else {
                EvidenceKind::SecurityConfiguration
            },
            Capability::TokenGeneration,
            if has_expiry {
                "csharp-jwt-expiry-control"
            } else {
                "csharp-jwt-missing-expiry-review"
            },
            "expiry",
            &["CWE-613"],
            &[
                "jwt",
                "token-lifecycle",
                if has_expiry {
                    "expiry-configured"
                } else {
                    "missing-expiry"
                },
            ],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn assigned_number<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
    property: &str,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Option<u64> {
    node.dfs()
        .filter(|child| child.kind().as_ref() == "assignment_expression")
        .find_map(|assignment| {
            let left = assignment.field("left")?;
            (compact(left.text().as_ref()).ends_with(property))
                .then(|| assignment.field("right"))
                .flatten()
                .and_then(|right| numeric(&right, literals))
        })
}

fn assigned_bool<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
    property: &str,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Option<bool> {
    node.dfs()
        .filter(|child| child.kind().as_ref() == "assignment_expression")
        .find_map(|assignment| {
            let left = assignment.field("left")?;
            compact(left.text().as_ref())
                .ends_with(property)
                .then(|| assignment.field("right"))
                .flatten()
                .and_then(|right| literals.known_bool(&right))
        })
}

fn numeric<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Option<u64> {
    match literals.evaluate(node).value {
        Some(LiteralValue::Number(value)) => value.parse().ok(),
        _ => node.text().trim().replace('_', "").parse().ok(),
    }
}

fn value_is_constant<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> bool {
    matches!(
        literals.evaluate(node).value,
        Some(LiteralValue::String(_) | LiteralValue::Array(_))
    ) || node
        .dfs()
        .any(|child| child.kind().as_ref() == "string_literal")
}

fn value_is_random<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    value: &Node<'tree, StrDoc<SupportLang>>,
) -> bool {
    let text = compact(value.text().as_ref());
    if text.contains("RandomNumberGenerator.GetBytes(") {
        return true;
    }
    let Some(name) = simple_identifier(text.as_str()) else {
        return false;
    };
    if resolve_initializer(root, use_site, value).is_some_and(|initializer| {
        compact(initializer.text().as_ref()).contains("RandomNumberGenerator.GetBytes(")
    }) {
        return true;
    }
    root.dfs().any(|candidate| {
        candidate.kind().as_ref() == "invocation_expression"
            && candidate.range().start < use_site.range().start
            && compact(candidate.text().as_ref())
                .contains(&format!("RandomNumberGenerator.Fill({name})"))
            && same_method(candidate.range(), use_site)
    })
}

fn receiver_is_aes_gcm(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    function: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let text = compact(function.text().as_ref());
    let receiver = text.strip_suffix(".Encrypt").unwrap_or_default();
    receiver.contains("newAesGcm(")
        || root.dfs().any(|node| {
            node.kind().as_ref() == "variable_declarator"
                && node.range().start < use_site.range().start
                && same_method(node.range(), use_site)
                && lexical_declaration_visible_at(&node, use_site)
                && node
                    .field("name")
                    .is_some_and(|name| name.text().trim() == receiver)
                && node
                    .parent()
                    .and_then(|parent| parent.field("type"))
                    .is_some_and(|kind| short_type(kind.text().as_ref()) == "AesGcm")
        })
}

fn resolve_initializer<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    value: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let text = compact(value.text().as_ref());
    let name = simple_identifier(text.as_str())?;
    root.dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .filter(|node| node.range().start < use_site.range().start)
        .filter(|node| lexical_declaration_visible_at(node, use_site))
        .filter(|node| {
            node.field("name")
                .is_some_and(|field| field.text().trim() == name)
        })
        .filter(|node| same_method(node.range(), use_site))
        .filter_map(|node| {
            node.field("value")
                .or_else(|| node.children().filter(|child| child.is_named()).last())
        })
        .last()
}

type HardcodedKeyProof<'tree> = (
    Node<'tree, StrDoc<SupportLang>>,
    Node<'tree, StrDoc<SupportLang>>,
);

fn hardcoded_key_node<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    expression: &Node<'tree, StrDoc<SupportLang>>,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Option<HardcodedKeyProof<'tree>> {
    let text = compact(expression.text().as_ref());
    if [
        "Configuration[",
        "GetEnvironmentVariable(",
        "GetSection(",
        "GetValue<",
        "KeyVault",
    ]
    .iter()
    .any(|dynamic| text.contains(dynamic))
    {
        return None;
    }
    expression.dfs().find_map(|node| {
        hardcoded_key_proof(root, use_site, &node, literals, 0).map(|definition| (node, definition))
    })
}

fn hardcoded_key_proof<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    value: &Node<'tree, StrDoc<SupportLang>>,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    depth: usize,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if depth > 4 {
        return None;
    }
    if value.kind().as_ref() == "string_literal"
        && matches!(literals.evaluate(value).value, Some(LiteralValue::String(ref value)) if value.len() >= 8)
    {
        return Some(value.clone());
    }
    let text = compact(value.text().as_ref());
    let name = simple_identifier(&text)?;
    if let Some(initializer) = resolve_initializer(root, use_site, value) {
        return hardcoded_key_proof(root, use_site, &initializer, literals, depth + 1);
    }
    let mut declarations = root
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "variable_declarator"
                && node
                    .field("name")
                    .is_some_and(|field| field.text().trim() == name)
        })
        .filter_map(|node| {
            let declaration = node
                .ancestors()
                .find(|ancestor| ancestor.kind().as_ref() == "field_declaration")?;
            let declaration_text = compact(declaration.text().as_ref());
            declaration_text.contains("const").then(|| {
                let name = node.field("name")?;
                let value = node
                    .field("value")
                    .or_else(|| node.children().filter(|child| child.is_named()).last())?;
                Some((name, value))
            })?
        });
    let (declaration_name, initializer) = declarations.next()?;
    if declarations.next().is_some() {
        return None;
    }
    hardcoded_key_proof(root, use_site, &initializer, literals, depth + 1).map(|_| declaration_name)
}

fn zeroed_byte_array(text: &str) -> bool {
    text.starts_with("newbyte[") && !text.contains('{')
}

fn same_method(range: std::ops::Range<usize>, node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "method_declaration")
        .is_some_and(|method| {
            method.range().start <= range.start && range.end <= method.range().end
        })
}

fn simple_identifier(text: &str) -> Option<&str> {
    (!text.is_empty()
        && text
            .chars()
            .all(|character| character == '_' || character.is_ascii_alphanumeric())
        && !text.as_bytes()[0].is_ascii_digit())
    .then_some(text)
}

fn object_creations<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    expected: &str,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "object_creation_expression")
        .filter(|node| {
            node.field("type")
                .is_some_and(|kind| short_type(kind.text().as_ref()) == expected)
        })
        .collect()
}

fn invocations<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "invocation_expression")
        .collect()
}

fn arguments<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    node.field("arguments")
        .map(|arguments| {
            arguments
                .children()
                .filter(|child| child.is_named())
                .collect()
        })
        .unwrap_or_default()
}

fn short_type(text: &str) -> &str {
    text.trim()
        .trim_end_matches('?')
        .rsplit('.')
        .next()
        .unwrap_or(text)
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn push_pair<'tree>(
    path: &str,
    source_node: &Node<'tree, StrDoc<SupportLang>>,
    sink_node: &Node<'tree, StrDoc<SupportLang>>,
    source_rule: &str,
    sink_rule: &str,
    sink_role: &str,
    cwe: &str,
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let source_id = evidence_id(
        source_rule,
        path,
        source_node.range().start,
        source_node.range().end,
    );
    if !evidence.iter().any(|item| item.id == source_id) {
        evidence.push(make_evidence(
            source_id.clone(),
            path,
            source_node,
            sink_node,
            EvidenceKind::Source,
            Capability::CredentialMaterial,
            source_rule,
            "value",
            &[],
            &["hardcoded-key"],
            comments,
            conditional,
            literals,
            vec![],
        ));
    }
    let sink_id = evidence_id(
        sink_rule,
        path,
        sink_node.range().start,
        sink_node.range().end,
    );
    if !evidence.iter().any(|item| item.id == sink_id) {
        evidence.push(make_evidence(
            sink_id,
            path,
            source_node,
            sink_node,
            EvidenceKind::Sink,
            Capability::TokenGeneration,
            sink_rule,
            sink_role,
            &[cwe],
            tags,
            comments,
            conditional,
            literals,
            vec![source_id],
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn push<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    capture_role: &str,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let id = evidence_id(rule_id, path, node.range().start, node.range().end);
    if evidence.iter().any(|item| item.id == id) {
        return;
    }
    evidence.push(make_evidence(
        id,
        path,
        node,
        node,
        kind,
        capability,
        rule_id,
        capture_role,
        cwes,
        tags,
        comments,
        conditional,
        literals,
        vec![],
    ));
}

#[allow(clippy::too_many_arguments)]
fn make_evidence<'tree>(
    id: String,
    path: &str,
    capture_node: &Node<'tree, StrDoc<SupportLang>>,
    evidence_node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    capture_role: &str,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    related_evidence: Vec<String>,
) -> Evidence {
    Evidence {
        id,
        kind,
        capability,
        location: location(path, evidence_node),
        enclosing_symbol: enclosing_symbol(evidence_node),
        captures: BTreeMap::from([(
            capture_role.to_string(),
            Capture {
                text: capture_node.text().into_owned(),
                location: location(path, capture_node),
            },
        )]),
        cwe_candidates: cwes.iter().map(|cwe| (*cwe).to_string()).collect(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.into(),
            rule_version: 2,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(evidence_node.range()),
            reachability: Some(reachability::classify(evidence_node, literals)),
            availability: Some(conditional.availability_for(evidence_node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.into(),
        related_evidence,
    }
}

fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.into(),
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

fn evidence_id(rule_id: &str, path: &str, start: usize, end: usize) -> String {
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}
