use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, HttpRouteAccess,
    Language, Location, Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan python-identity-policy 1";

#[derive(Clone, Debug, Default)]
pub(crate) struct PythonIdentityContext {
    default_access: Option<HttpRouteAccess>,
    default_guard: Option<String>,
}

impl PythonIdentityContext {
    pub(crate) fn from_sources<'a>(
        sources: impl Iterator<Item = (&'a str, Language, &'a str)>,
    ) -> Self {
        for (path, language, source) in sources {
            if language != Language::Python || !is_settings_path(path) {
                continue;
            }
            let Some(policy) = setting_container(source, "REST_FRAMEWORK") else {
                continue;
            };
            let permissions_declared = policy.contains("DEFAULT_PERMISSION_CLASSES");
            if permissions_declared && policy.contains("IsAdminUser") {
                return Self {
                    default_access: Some(HttpRouteAccess::RoleRestricted),
                    default_guard: Some("DEFAULT_PERMISSION_CLASSES:IsAdminUser".to_string()),
                };
            }
            if permissions_declared && policy.contains("IsAuthenticated") {
                return Self {
                    default_access: Some(HttpRouteAccess::Authenticated),
                    default_guard: Some("DEFAULT_PERMISSION_CLASSES:IsAuthenticated".to_string()),
                };
            }
            return Self {
                default_access: Some(HttpRouteAccess::ExplicitlyPublic),
                default_guard: Some(
                    if permissions_declared && policy.contains("AllowAny") {
                        "DEFAULT_PERMISSION_CLASSES:AllowAny"
                    } else {
                        "DEFAULT_PERMISSION_CLASSES:framework-default-AllowAny"
                    }
                    .to_string(),
                ),
            };
        }
        Self::default()
    }

    pub(crate) fn effective_access(
        &self,
        local: HttpRouteAccess,
        guards: &mut Vec<String>,
    ) -> HttpRouteAccess {
        if local != HttpRouteAccess::Unknown || guards.iter().any(|guard| guard == "AllowAny") {
            return local;
        }
        if let Some(guard) = &self.default_guard
            && !guards.contains(guard)
        {
            guards.push(guard.clone());
            guards.sort();
        }
        self.default_access.unwrap_or(local)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_observations<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        if language != Language::Python {
            return;
        }
        add_jwt_observations(path, root, comments, conditional, literals, evidence);
        add_python_cors_observations(path, root, comments, conditional, literals, evidence);
        if is_settings_path(path) {
            add_django_settings(path, root, comments, conditional, literals, evidence);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_jwt_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for call in root.dfs().filter(|node| node.kind().as_ref() == "call") {
        let Some(function) = call.field("function") else {
            continue;
        };
        let callee = function.text();
        let compact = compact(call.text().as_ref());
        if callee.ends_with("jwt.decode") || callee.trim() == "jwt.decode" {
            let unverified = option_false(&call, "verify_signature");
            let expiration_disabled = option_false(&call, "verify_exp");
            let identity_claims_disabled =
                option_false(&call, "verify_aud") || option_false(&call, "verify_iss");
            if expiration_disabled {
                push(
                    path,
                    &call,
                    EvidenceKind::SecurityConfiguration,
                    Capability::Authentication,
                    "python-jwt-expiration-validation-disabled",
                    &["CWE-613"],
                    vec![
                        "jwt",
                        "expiration-validation-disabled",
                        "explicit-security-disable",
                        "recommendation:fix-application",
                    ],
                    "token",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            if identity_claims_disabled {
                push(
                    path,
                    &call,
                    EvidenceKind::SecurityConfiguration,
                    Capability::Authentication,
                    "python-jwt-identity-claim-validation-disabled",
                    &["CWE-287"],
                    vec![
                        "jwt",
                        "audience-or-issuer-validation-disabled",
                        "explicit-security-disable",
                        "recommendation:fix-application",
                    ],
                    "token",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            if unverified {
                let scope = call
                    .ancestors()
                    .find(|node| node.kind().as_ref() == "function_definition")
                    .map_or_else(String::new, |node| node.text().into_owned());
                let external = scope.contains("requests.post(")
                    && (scope.contains("status_code") || scope.contains("HTTP_200_OK"));
                push(
                    path,
                    &call,
                    EvidenceKind::SecurityConfiguration,
                    Capability::Authentication,
                    if external {
                        "python-jwt-external-verification-boundary-review"
                    } else {
                        "python-jwt-unverified-decode"
                    },
                    &["CWE-347"],
                    if external {
                        vec![
                            "jwt",
                            "decode-without-local-signature-check",
                            "external-verification-observed",
                            "recommendation:review-boundary",
                            "verify-same-token-binding-and-authenticated-transport",
                        ]
                    } else {
                        vec![
                            "jwt",
                            "decode-without-signature-check",
                            "recommendation:fix-application",
                        ]
                    },
                    "token",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            } else if compact.contains("algorithms=") || compact.contains("algorithms:") {
                push(
                    path,
                    &call,
                    EvidenceKind::Validation,
                    Capability::Authentication,
                    "python-jwt-signature-validation-control",
                    &[],
                    vec!["jwt", "signature-validation", "algorithm-allowlist"],
                    "token",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        } else if callee.ends_with("jwt.encode") || callee.trim() == "jwt.encode" {
            let arguments = call_arguments(&call);
            if let Some(payload) = arguments.first()
                && payload.kind().as_ref() == "dictionary"
                && !payload.text().contains("exp")
            {
                push(
                    path,
                    &call,
                    EvidenceKind::SecurityConfiguration,
                    Capability::Authentication,
                    "python-jwt-token-without-expiry-review",
                    &["CWE-613"],
                    vec![
                        "jwt",
                        "signing",
                        "expiration-not-observed",
                        "review-token-lifetime",
                    ],
                    "token",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            if let Some(key) = arguments.get(1)
                && key.kind().as_ref() == "string"
            {
                push(
                    path,
                    key,
                    EvidenceKind::SecurityConfiguration,
                    Capability::Authentication,
                    "python-jwt-hardcoded-signing-key",
                    &["CWE-321"],
                    vec![
                        "jwt",
                        "signing",
                        "hardcoded-key",
                        "recommendation:fix-application",
                    ],
                    "key",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }
    }
}

fn option_false(call: &Node<'_, StrDoc<SupportLang>>, option: &str) -> bool {
    call_arguments(call).into_iter().any(|argument| {
        if argument.kind().as_ref() == "keyword_argument"
            && argument
                .field("name")
                .is_some_and(|name| name.text().trim() == option)
        {
            return argument
                .field("value")
                .is_some_and(|value| value.kind().as_ref() == "false");
        }
        argument.dfs().any(|pair| {
            pair.kind().as_ref() == "pair"
                && pair
                    .field("key")
                    .is_some_and(|key| key.text().trim_matches(['\'', '"']) == option)
                && pair
                    .field("value")
                    .is_some_and(|value| value.kind().as_ref() == "false")
        })
    })
}

#[allow(clippy::too_many_arguments)]
fn add_python_cors_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let constructors = flask_cors_constructors(root);
    if constructors.is_empty() {
        return;
    }
    for call in root.dfs().filter(|node| node.kind().as_ref() == "call") {
        let Some(function) = call.field("function") else {
            continue;
        };
        let callee = function.text();
        if !constructors.contains(callee.trim()) {
            continue;
        }
        if keyword_argument_value(&call, "supports_credentials")
            .is_some_and(|value| value.kind().as_ref() == "true")
            && keyword_argument_value(&call, "origins").is_some_and(|value| {
                value.kind().as_ref() == "string" && value.text().trim_matches(['\'', '"']) == "*"
            })
        {
            push(
                path,
                &call,
                EvidenceKind::SecurityConfiguration,
                Capability::CorsConfiguration,
                "python-flask-credentialed-wildcard-cors",
                &["CWE-942"],
                vec![
                    "flask-cors",
                    "wildcard-origin",
                    "credentials-enabled",
                    "explicit-permissive-policy",
                ],
                "policy",
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn flask_cors_constructors(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    let mut constructors = BTreeSet::new();
    for import in root.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "import_statement" | "import_from_statement"
        )
    }) {
        let text = import.text();
        let trimmed = text.trim();
        if let Some(names) = trimmed.strip_prefix("from flask_cors import ") {
            for name in names.trim_matches(['(', ')']).split(',') {
                let name = name.trim();
                let (original, visible) = name.split_once(" as ").unwrap_or((name, name));
                if original.trim() == "CORS" {
                    constructors.insert(visible.trim().to_string());
                }
            }
        } else if let Some(names) = trimmed.strip_prefix("import ") {
            for name in names.split(',') {
                let name = name.trim();
                let (module, visible) = name.split_once(" as ").unwrap_or((name, name));
                if module.trim() == "flask_cors" {
                    constructors.insert(format!("{}.CORS", visible.trim()));
                }
            }
        }
    }
    constructors
}

fn keyword_argument_value<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
    expected: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    call_arguments(call).into_iter().find_map(|argument| {
        (argument.kind().as_ref() == "keyword_argument"
            && argument
                .field("name")
                .is_some_and(|name| name.text().trim() == expected))
        .then(|| argument.field("value"))
        .flatten()
    })
}

#[allow(clippy::too_many_arguments)]
fn add_django_settings<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let credentialed_all_origins = setting_is_true(root, "CORS_ALLOW_CREDENTIALS")
        && (setting_is_true(root, "CORS_ORIGIN_ALLOW_ALL")
            || setting_is_true(root, "CORS_ALLOW_ALL_ORIGINS"));
    for assignment in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment")
    {
        let (Some(left), Some(right)) = (assignment.field("left"), assignment.field("right"))
        else {
            continue;
        };
        let name = left.text();
        let value = compact(right.text().as_ref());
        match name.trim() {
            "DEBUG" if value == "True" => push_setting(
                path,
                &right,
                EvidenceKind::SecurityConfiguration,
                Capability::HttpRequestHandling,
                "python-django-debug-enabled",
                &["CWE-489"],
                vec![
                    "django",
                    "debug",
                    "enabled",
                    "recommendation:fix-production-configuration",
                ],
                comments,
                conditional,
                literals,
                evidence,
            ),
            "ALLOWED_HOSTS" if value.contains("\"*\"") || value.contains("'*'") => push_setting(
                path,
                &right,
                EvidenceKind::SecurityConfiguration,
                Capability::HttpRequestHandling,
                "python-django-wildcard-allowed-hosts-review",
                &["CWE-346"],
                vec![
                    "django",
                    "allowed-hosts",
                    "wildcard",
                    "recommendation:review-deployment",
                    "verify-ingress-host-validation",
                ],
                comments,
                conditional,
                literals,
                evidence,
            ),
            "CORS_ORIGIN_ALLOW_ALL" | "CORS_ALLOW_ALL_ORIGINS" if value == "True" => push_setting(
                path,
                &right,
                EvidenceKind::SecurityConfiguration,
                Capability::CorsConfiguration,
                "python-django-cors-all-origins-review",
                &["CWE-942"],
                if credentialed_all_origins {
                    vec![
                        "django",
                        "cors",
                        "all-origins",
                        "credentials-enabled",
                        "explicit-permissive-policy",
                    ]
                } else {
                    vec![
                        "django",
                        "cors",
                        "all-origins",
                        "recommendation:review-effective-policy",
                        "verify-api-gateway-and-credential-mode",
                    ]
                },
                comments,
                conditional,
                literals,
                evidence,
            ),
            "MIDDLEWARE" => {
                let csrf = right
                    .text()
                    .contains("django.middleware.csrf.CsrfViewMiddleware");
                push_setting(
                    path,
                    &right,
                    if csrf {
                        EvidenceKind::Validation
                    } else {
                        EvidenceKind::SecurityConfiguration
                    },
                    Capability::Authorization,
                    if csrf {
                        "python-django-csrf-middleware-control"
                    } else {
                        "python-django-csrf-middleware-not-observed-review"
                    },
                    if csrf { &[] } else { &["CWE-352"] },
                    if csrf {
                        vec!["django", "csrf", "middleware-present", "control"]
                    } else {
                        vec![
                            "django",
                            "csrf",
                            "middleware-not-observed",
                            "review-cookie-authentication",
                        ]
                    },
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            "REST_FRAMEWORK" => {
                let text = right.text();
                let protected = text.contains("DEFAULT_PERMISSION_CLASSES")
                    && (text.contains("IsAuthenticated") || text.contains("IsAdminUser"));
                push_setting(
                    path,
                    &right,
                    if protected {
                        EvidenceKind::Validation
                    } else {
                        EvidenceKind::SecurityConfiguration
                    },
                    Capability::Authorization,
                    if protected {
                        "python-drf-default-permission-control"
                    } else {
                        "python-drf-default-allow-any-review"
                    },
                    if protected {
                        &[]
                    } else {
                        &["CWE-306", "CWE-862"]
                    },
                    if protected {
                        vec![
                            "django",
                            "drf",
                            "default-permission",
                            "authenticated-default",
                            "control",
                        ]
                    } else {
                        vec![
                            "django",
                            "drf",
                            "default-permission",
                            "allow-any-or-unspecified",
                            "recommendation:review-endpoint-coverage",
                        ]
                    },
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            "SESSION_COOKIE_SECURE" | "CSRF_COOKIE_SECURE" => cookie_boolean_setting(
                path,
                &right,
                name.trim(),
                &value,
                "secure",
                "CWE-614",
                comments,
                conditional,
                literals,
                evidence,
            ),
            "SESSION_COOKIE_HTTPONLY" | "CSRF_COOKIE_HTTPONLY" => cookie_boolean_setting(
                path,
                &right,
                name.trim(),
                &value,
                "httponly",
                "CWE-1004",
                comments,
                conditional,
                literals,
                evidence,
            ),
            "SESSION_COOKIE_SAMESITE" | "CSRF_COOKIE_SAMESITE" => {
                let weak = value.contains("None");
                push_setting(
                    path,
                    &right,
                    if weak {
                        EvidenceKind::SecurityConfiguration
                    } else {
                        EvidenceKind::Validation
                    },
                    Capability::CookieConfiguration,
                    if weak {
                        "python-django-cookie-samesite-none-review"
                    } else {
                        "python-django-cookie-samesite-control"
                    },
                    if weak { &["CWE-1275"] } else { &[] },
                    vec![
                        "django",
                        "cookie",
                        "samesite",
                        if weak { "none" } else { "lax-or-strict" },
                        if weak {
                            "recommendation:review-cross-site-requirement"
                        } else {
                            "control"
                        },
                    ],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            "SECURE_SSL_REDIRECT" if value == "True" || value == "False" => push_setting(
                path,
                &right,
                if value == "True" {
                    EvidenceKind::Validation
                } else {
                    EvidenceKind::SecurityConfiguration
                },
                Capability::TlsConfiguration,
                if value == "True" {
                    "python-django-https-redirect-control"
                } else {
                    "python-django-https-redirect-review"
                },
                if value == "True" { &[] } else { &["CWE-319"] },
                vec![
                    "django",
                    "https-redirect",
                    if value == "True" {
                        "enabled"
                    } else {
                        "disabled"
                    },
                    if value == "True" {
                        "control"
                    } else {
                        "recommendation:review-edge-redirect"
                    },
                ],
                comments,
                conditional,
                literals,
                evidence,
            ),
            "SECURE_PROXY_SSL_HEADER" => push_setting(
                path,
                &right,
                EvidenceKind::SecurityConfiguration,
                Capability::HttpRequestHandling,
                "python-django-proxy-ssl-header-review",
                &[],
                vec![
                    "django",
                    "proxy",
                    "ssl-header",
                    "recommendation:review-trusted-proxy",
                    "verify-header-stripping-and-ingress-boundary",
                ],
                comments,
                conditional,
                literals,
                evidence,
            ),
            _ => {}
        }
    }
}

fn setting_is_true(root: &Node<'_, StrDoc<SupportLang>>, expected: &str) -> bool {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "assignment")
        .any(|assignment| {
            assignment
                .field("left")
                .is_some_and(|left| left.text().trim() == expected)
                && assignment
                    .field("right")
                    .is_some_and(|right| compact(right.text().as_ref()) == "True")
        })
}

#[allow(clippy::too_many_arguments)]
fn cookie_boolean_setting<'tree>(
    path: &str,
    value_node: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
    value: &str,
    property: &str,
    cwe: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if value != "True" && value != "False" {
        return;
    }
    let enabled = value == "True";
    let disabled_cwe = [cwe];
    push_setting(
        path,
        value_node,
        if enabled {
            EvidenceKind::Validation
        } else {
            EvidenceKind::SecurityConfiguration
        },
        Capability::CookieConfiguration,
        if enabled {
            "python-django-cookie-flag-control"
        } else {
            "python-django-cookie-flag-disabled"
        },
        if enabled { &[] } else { &disabled_cwe },
        vec![
            "django",
            "cookie",
            property,
            if enabled { "enabled" } else { "disabled" },
            if enabled {
                "control"
            } else {
                "recommendation:fix-application"
            },
            name,
        ],
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_setting<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    cwes: &[&str],
    tags: Vec<&str>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    push(
        path,
        node,
        kind,
        capability,
        rule_id,
        cwes,
        tags,
        "policy",
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    cwes: &[&str],
    tags: Vec<&str>,
    capture: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let location = location(path, node);
    evidence.push(Evidence {
        id: format!(
            "{path}:{}:{}:{rule_id}",
            node.range().start,
            node.range().end
        ),
        kind,
        capability,
        location: location.clone(),
        enclosing_symbol: enclosing_symbol(node),
        captures: BTreeMap::from([(
            capture.to_string(),
            Capture {
                text: node.text().into_owned(),
                location,
            },
        )]),
        cwe_candidates: cwes.iter().map(|value| (*value).to_string()).collect(),
        tags: tags.into_iter().map(str::to_string).collect(),
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(node.range()),
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

fn is_settings_path(path: &str) -> bool {
    path.replace('\\', "/").ends_with("settings.py")
}

fn setting_container<'a>(source: &'a str, name: &str) -> Option<&'a str> {
    let start = source.find(&format!("{name} ="))?;
    let value = &source[start + name.len() + 2..];
    let open = value.find('{')?;
    let mut depth = 0usize;
    for (index, character) in value[open..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(&value[open..=open + index]);
                }
            }
            _ => {}
        }
    }
    None
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn call_arguments<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    call.children()
        .find(|child| child.kind().as_ref() == "argument_list")
        .map(|arguments| {
            arguments
                .children()
                .filter(|node| !matches!(node.kind().as_ref(), "(" | ")" | ","))
                .collect()
        })
        .unwrap_or_default()
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
