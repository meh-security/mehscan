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

const ENGINE: &str = "mehscan csharp-identity-policy 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_identity_policy_observations<'tree>(
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

    add_jwt_policy(path, root, comments, conditional, literals, evidence);
    add_cookie_policy(path, root, comments, conditional, literals, evidence);
    add_session_cookie_policy(path, root, comments, conditional, literals, evidence);
    add_antiforgery_policy(path, root, comments, conditional, literals, evidence);
    add_cors_policy(path, root, comments, conditional, literals, evidence);
    add_forwarded_headers_policy(path, root, comments, conditional, literals, evidence);
    add_authorization_policy(path, root, comments, conditional, literals, evidence);
    add_middleware_ordering(path, root, comments, conditional, literals, evidence);
}

fn add_session_cookie_policy<'tree>(
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
        let text = compact(invocation.text().as_ref());
        if !(function.ends_with(".AddSession") || text.contains("Configure<SessionOptions>("))
            || !text.contains(".Cookie.")
        {
            continue;
        }
        let http_only = cookie_setting(&text, ".Cookie.HttpOnly=true", ".Cookie.HttpOnly=false");
        let secure = if text.contains(".Cookie.SecurePolicy=CookieSecurePolicy.Always") {
            "always"
        } else if text.contains(".Cookie.SecurePolicy=CookieSecurePolicy.None") {
            "none"
        } else if text.contains(".Cookie.SecurePolicy=CookieSecurePolicy.SameAsRequest") {
            "same-as-request"
        } else {
            "unknown"
        };
        let same_site = if text.contains(".Cookie.SameSite=SameSiteMode.Strict") {
            "strict"
        } else if text.contains(".Cookie.SameSite=SameSiteMode.Lax") {
            "lax"
        } else if text.contains(".Cookie.SameSite=SameSiteMode.None") {
            "none"
        } else {
            "unknown"
        };
        let weak = http_only == "false" || secure == "none";
        let controlled =
            http_only == "true" && secure == "always" && matches!(same_site, "strict" | "lax");
        let (kind, rule_id, disposition) = if weak {
            (
                EvidenceKind::SecurityConfiguration,
                "csharp-session-cookie-policy-risk",
                "recommendation:fix-application",
            )
        } else if controlled {
            (
                EvidenceKind::Validation,
                "csharp-session-cookie-policy-control",
                "recommendation:control-present",
            )
        } else {
            (
                EvidenceKind::SecurityConfiguration,
                "csharp-session-cookie-policy-review",
                "recommendation:review-policy",
            )
        };
        push(
            path,
            &invocation,
            kind,
            Capability::CookieConfiguration,
            rule_id,
            &["CWE-614", "CWE-1004", "CWE-1275"],
            &[
                "aspnet-core",
                "session-cookie",
                disposition,
                &format!("http-only:{http_only}"),
                &format!("secure-policy:{secure}"),
                &format!("same-site:{same_site}"),
                "unspecified-settings-retain-framework-defaults",
                "needs-verification",
            ],
            "policy",
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn cookie_setting(text: &str, enabled: &str, disabled: &str) -> &'static str {
    if text.contains(enabled) {
        "true"
    } else if text.contains(disabled) {
        "false"
    } else {
        "unknown"
    }
}

fn add_jwt_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for creation in root.dfs().filter(|node| {
        node.kind().as_ref() == "object_creation_expression"
            && node
                .field("type")
                .is_some_and(|kind| short_type(kind.text().as_ref()) == "TokenValidationParameters")
    }) {
        if comments.is_in_comment(creation.range()) {
            continue;
        }
        let text = compact(creation.text().as_ref());
        let required = [
            "ValidateIssuer=true",
            "ValidateAudience=true",
            "ValidateLifetime=true",
            "ValidateIssuerSigningKey=true",
        ];
        let disabled = [
            "ValidateIssuer=false",
            "ValidateAudience=false",
            "ValidateLifetime=false",
            "ValidateIssuerSigningKey=false",
            "RequireSignedTokens=false",
            "RequireExpirationTime=false",
        ]
        .into_iter()
        .filter(|setting| text.contains(setting))
        .collect::<Vec<_>>();
        if !disabled.is_empty() {
            push(
                path,
                &creation,
                EvidenceKind::SecurityConfiguration,
                Capability::Authentication,
                "csharp-jwt-validation-review",
                &["CWE-347", "CWE-613"],
                &[
                    "aspnet-core",
                    "jwt-bearer",
                    "token-validation",
                    "disabled-validation",
                    "needs-verification",
                    "verify-identity-provider-and-effective-options",
                ],
                "policy",
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if required.iter().all(|setting| text.contains(setting))
            && !text.contains("RequireSignedTokens=false")
            && !text.contains("RequireExpirationTime=false")
        {
            push(
                path,
                &creation,
                EvidenceKind::Validation,
                Capability::Authentication,
                "csharp-jwt-validation-control",
                &["CWE-347", "CWE-613"],
                &[
                    "aspnet-core",
                    "jwt-bearer",
                    "token-validation",
                    "explicit-validation",
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

fn add_cookie_policy<'tree>(
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
        if !compact(function.text().as_ref()).ends_with(".AddCookie") {
            continue;
        }
        let text = compact(invocation.text().as_ref());
        let weak = text.contains(".Cookie.SecurePolicy=CookieSecurePolicy.None")
            || text.contains(".Cookie.HttpOnly=false")
            || (text.contains(".Cookie.SameSite=SameSiteMode.None")
                && !text.contains(".Cookie.SecurePolicy=CookieSecurePolicy.Always"));
        if weak {
            push(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::CookieConfiguration,
                "csharp-cookie-authentication-review",
                &["CWE-614", "CWE-1004", "CWE-1275"],
                &[
                    "aspnet-core",
                    "authentication-cookie",
                    "browser-boundary",
                    "needs-verification",
                    "verify-tls-proxy-and-cookie-purpose",
                ],
                "policy",
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if text.contains(".Cookie.SecurePolicy=CookieSecurePolicy.Always")
            && text.contains(".Cookie.HttpOnly=true")
            && (text.contains(".Cookie.SameSite=SameSiteMode.Strict")
                || text.contains(".Cookie.SameSite=SameSiteMode.Lax"))
        {
            push(
                path,
                &invocation,
                EvidenceKind::Validation,
                Capability::CookieConfiguration,
                "csharp-cookie-authentication-control",
                &["CWE-614", "CWE-1004", "CWE-1275"],
                &[
                    "aspnet-core",
                    "authentication-cookie",
                    "explicit-browser-controls",
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

fn add_antiforgery_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for attribute in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "attribute")
    {
        let text = compact(attribute.text().as_ref());
        let Some(method) = attribute
            .ancestors()
            .find(|ancestor| ancestor.kind().as_ref() == "method_declaration")
        else {
            continue;
        };
        if text.starts_with("IgnoreAntiforgeryToken") && state_changing_method(&method) {
            push(
                path,
                &attribute,
                EvidenceKind::SecurityConfiguration,
                Capability::Authorization,
                "csharp-antiforgery-exemption-review",
                &["CWE-352"],
                &[
                    "aspnet-core",
                    "antiforgery",
                    "state-changing-endpoint",
                    "needs-verification",
                    "verify-cookie-authentication-and-origin-controls",
                ],
                "policy",
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if matches!(
            text.trim_end_matches("Attribute"),
            "ValidateAntiForgeryToken" | "AutoValidateAntiforgeryToken"
        ) {
            push(
                path,
                &attribute,
                EvidenceKind::Guard,
                Capability::Authorization,
                "csharp-antiforgery-control",
                &["CWE-352"],
                &["aspnet-core", "antiforgery", "endpoint-guard"],
                "policy",
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    for invocation in invocations(root) {
        let callee = invocation
            .field("function")
            .map(|function| compact(function.text().as_ref()))
            .unwrap_or_default();
        if callee.ends_with(".DisableAntiforgery") && contains_antiforgery_map(&callee) {
            push(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::Authorization,
                "csharp-minimal-antiforgery-exemption-review",
                &["CWE-352"],
                &[
                    "aspnet-core",
                    "minimal-api",
                    "antiforgery",
                    "needs-verification",
                    "verify-cookie-authentication-and-origin-controls",
                ],
                "policy",
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if callee.ends_with(".RequireAntiforgery") {
            push(
                path,
                &invocation,
                EvidenceKind::Guard,
                Capability::Authorization,
                "csharp-minimal-antiforgery-control",
                &["CWE-352"],
                &[
                    "aspnet-core",
                    "minimal-api",
                    "antiforgery",
                    "endpoint-guard",
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

fn add_cors_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for invocation in invocations(root) {
        if !invocation.field("function").is_some_and(|function| {
            compact(function.text().as_ref()).ends_with(".AllowCredentials")
        }) {
            continue;
        }
        let text = compact(invocation.text().as_ref());
        if text.contains("SetIsOriginAllowed") && literal_true_lambda(&text) {
            push(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::HttpRequestHandling,
                "csharp-credentialed-cors-review",
                &["CWE-942"],
                &[
                    "aspnet-core",
                    "cors",
                    "credentials",
                    "arbitrary-origin",
                    "needs-verification",
                    "verify-effective-origin-policy-at-app-or-gateway",
                ],
                "policy",
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if text.contains("WithOrigins(") && !text.contains("AllowAnyOrigin()") {
            push(
                path,
                &invocation,
                EvidenceKind::Validation,
                Capability::HttpRequestHandling,
                "csharp-credentialed-cors-control",
                &["CWE-942"],
                &["aspnet-core", "cors", "credentials", "explicit-origins"],
                "policy",
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn add_forwarded_headers_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for declarator in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
    {
        let Some(name_node) = declarator.field("name") else {
            continue;
        };
        let name = name_node.text();
        if !declarator.dfs().any(|node| {
            node.kind().as_ref() == "object_creation_expression"
                && node.field("type").is_some_and(|kind| {
                    short_type(kind.text().as_ref()) == "ForwardedHeadersOptions"
                })
        }) {
            continue;
        }
        let scope = declarator
            .ancestors()
            .find(|node| {
                matches!(
                    node.kind().as_ref(),
                    "method_declaration" | "global_statement"
                )
            })
            .unwrap_or_else(|| root.clone());
        let scope_text = compact(scope.text().as_ref());
        let networks_clear = scope_text.contains(&format!("{name}.KnownNetworks.Clear()"));
        let proxies_clear = scope_text.contains(&format!("{name}.KnownProxies.Clear()"));
        let trusted = scope_text.contains(&format!("{name}.KnownNetworks.Add("))
            || scope_text.contains(&format!("{name}.KnownProxies.Add("));
        if networks_clear && proxies_clear && !trusted {
            push(
                path,
                &declarator,
                EvidenceKind::SecurityConfiguration,
                Capability::HttpRequestHandling,
                "csharp-forwarded-headers-trust-review",
                &["CWE-346"],
                &[
                    "aspnet-core",
                    "forwarded-headers",
                    "proxy-trust",
                    "needs-verification",
                    "verify-known-proxies-networks-and-ingress-filtering",
                ],
                "policy",
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if trusted {
            push(
                path,
                &declarator,
                EvidenceKind::Validation,
                Capability::HttpRequestHandling,
                "csharp-forwarded-headers-trust-control",
                &["CWE-346"],
                &["aspnet-core", "forwarded-headers", "explicit-trusted-proxy"],
                "policy",
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn add_authorization_policy<'tree>(
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
        let Some(left) = assignment.field("left") else {
            continue;
        };
        let left = compact(left.text().as_ref());
        let policy_name = if left.ends_with(".FallbackPolicy") {
            "fallback"
        } else if left.ends_with(".DefaultPolicy") {
            "default"
        } else {
            continue;
        };
        let right = assignment
            .field("right")
            .map(|node| compact(node.text().as_ref()))
            .unwrap_or_default();
        if right == "null" {
            push(
                path,
                &assignment,
                EvidenceKind::SecurityConfiguration,
                Capability::Authorization,
                if policy_name == "fallback" {
                    "csharp-null-fallback-authorization-review"
                } else {
                    "csharp-null-default-authorization-review"
                },
                &["CWE-862"],
                &[
                    "aspnet-core",
                    "authorization",
                    if policy_name == "fallback" {
                        "fallback-policy"
                    } else {
                        "default-policy"
                    },
                    "needs-verification",
                    "verify-default-deny-and-endpoint-coverage",
                ],
                "policy",
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if right.contains("RequireAuthenticatedUser()") {
            push(
                path,
                &assignment,
                EvidenceKind::Guard,
                Capability::Authorization,
                if policy_name == "fallback" {
                    "csharp-fallback-authorization-control"
                } else {
                    "csharp-default-authorization-control"
                },
                &["CWE-862"],
                &[
                    "aspnet-core",
                    "authorization",
                    if policy_name == "fallback" {
                        "fallback-policy"
                    } else {
                        "default-policy"
                    },
                    "authenticated-user-required",
                ],
                "policy",
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    for attribute in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "attribute")
    {
        let text = compact(attribute.text().as_ref());
        if text.starts_with("AllowAnonymous") {
            let state_changing = attribute
                .ancestors()
                .find(|ancestor| ancestor.kind().as_ref() == "method_declaration")
                .is_some_and(|method| state_changing_method(&method));
            if state_changing {
                push(
                    path,
                    &attribute,
                    EvidenceKind::SecurityConfiguration,
                    Capability::Authorization,
                    "csharp-anonymous-state-change-review",
                    &["CWE-306", "CWE-862"],
                    &[
                        "aspnet-core",
                        "allow-anonymous",
                        "state-changing-endpoint",
                        "needs-verification",
                        "verify-public-intent-and-operation-authorization",
                    ],
                    "policy",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        } else if text.starts_with("Authorize") {
            push(
                path,
                &attribute,
                EvidenceKind::Guard,
                Capability::Authorization,
                "csharp-authorize-attribute-control",
                &["CWE-862"],
                &["aspnet-core", "authorization", "endpoint-guard"],
                "policy",
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    for invocation in invocations(root) {
        let callee = invocation
            .field("function")
            .map(|function| compact(function.text().as_ref()))
            .unwrap_or_default();
        if callee.ends_with(".AllowAnonymous") && contains_state_changing_map(&callee) {
            push(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::Authorization,
                "csharp-minimal-anonymous-state-change-review",
                &["CWE-306", "CWE-862"],
                &[
                    "aspnet-core",
                    "minimal-api",
                    "allow-anonymous",
                    "state-changing-endpoint",
                    "needs-verification",
                    "verify-public-intent-and-operation-authorization",
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

fn add_middleware_ordering<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let mut calls = invocations(root)
        .into_iter()
        .filter_map(|node| {
            let function = compact(node.field("function")?.text().as_ref());
            let method = function.rsplit('.').next()?;
            matches!(
                method,
                "UseForwardedHeaders"
                    | "UseAuthentication"
                    | "UseAuthorization"
                    | "MapControllers"
                    | "MapGet"
                    | "MapPost"
                    | "MapPut"
                    | "MapDelete"
                    | "MapPatch"
            )
            .then_some((node.range().start, method.to_string(), node))
        })
        .collect::<Vec<_>>();
    calls.sort_by_key(|(offset, _, _)| *offset);
    let position = |name: &str| {
        calls
            .iter()
            .find(|(_, method, _)| method == name)
            .map(|(offset, _, _)| *offset)
    };
    let authn = position("UseAuthentication");
    let authz = position("UseAuthorization");
    let first_map = calls
        .iter()
        .find(|(_, method, _)| method.starts_with("Map"))
        .map(|(offset, _, _)| *offset);
    let forwarded = position("UseForwardedHeaders");
    let bad = match (authn, authz) {
        (Some(authentication), Some(authorization)) => authentication > authorization,
        _ => false,
    } || first_map
        .is_some_and(|map| authz.is_some_and(|authorization| map < authorization));
    if bad {
        if let Some((_, _, node)) = calls
            .iter()
            .find(|(_, method, _)| method == "UseAuthorization")
        {
            push(
                path,
                node,
                EvidenceKind::SecurityConfiguration,
                Capability::Authentication,
                "csharp-auth-middleware-order-review",
                &["CWE-306", "CWE-862"],
                &[
                    "aspnet-core",
                    "middleware-order",
                    "authentication",
                    "authorization",
                    "needs-verification",
                    "verify-effective-pipeline-and-endpoint-routing",
                ],
                "pipeline",
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    } else if authn.is_some_and(|authentication| {
        authz.is_some_and(|authorization| {
            authentication < authorization && first_map.is_none_or(|map| authorization < map)
        })
    }) && let Some((_, _, node)) = calls
        .iter()
        .find(|(_, method, _)| method == "UseAuthorization")
    {
        push(
            path,
            node,
            EvidenceKind::Validation,
            Capability::Authentication,
            "csharp-auth-middleware-order-control",
            &["CWE-306", "CWE-862"],
            &[
                "aspnet-core",
                "middleware-order",
                "authentication-before-authorization",
            ],
            "pipeline",
            comments,
            conditional,
            literals,
            evidence,
        );
    }
    if let (Some(forwarded), Some(authentication)) = (forwarded, authn)
        && forwarded > authentication
        && let Some((_, _, node)) = calls
            .iter()
            .find(|(_, method, _)| method == "UseForwardedHeaders")
    {
        push(
            path,
            node,
            EvidenceKind::SecurityConfiguration,
            Capability::HttpRequestHandling,
            "csharp-forwarded-headers-order-review",
            &["CWE-346"],
            &[
                "aspnet-core",
                "forwarded-headers",
                "middleware-order",
                "needs-verification",
                "verify-proxy-derived-values-before-security-consumers",
            ],
            "pipeline",
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn invocations<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "invocation_expression")
        .collect()
}

fn state_changing_method(method: &Node<'_, StrDoc<SupportLang>>) -> bool {
    method
        .dfs()
        .filter(|node| node.kind().as_ref() == "attribute")
        .map(|node| compact(node.text().as_ref()))
        .any(|attribute| {
            ["HttpPost", "HttpPut", "HttpPatch", "HttpDelete"]
                .iter()
                .any(|verb| attribute.starts_with(verb))
        })
}

fn contains_state_changing_map(text: &str) -> bool {
    [".MapPost(", ".MapPut(", ".MapPatch(", ".MapDelete("]
        .iter()
        .any(|verb| text.contains(verb))
}

fn contains_antiforgery_map(text: &str) -> bool {
    [".MapPost(", ".MapPut(", ".MapPatch("]
        .iter()
        .any(|verb| text.contains(verb))
}

fn literal_true_lambda(text: &str) -> bool {
    text.contains("=>true") || text.contains("=>{returntrue;}")
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
fn push<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    cwes: &[&str],
    tags: &[&str],
    capture_role: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if comments.is_in_comment(node.range()) {
        return;
    }
    evidence.push(Evidence {
        id: evidence_id(rule_id, path, node.range().start, node.range().end),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures: BTreeMap::from([(
            capture_role.to_string(),
            Capture {
                text: node.text().into_owned(),
                location: location(path, node),
            },
        )]),
        cwe_candidates: cwes.iter().map(|cwe| (*cwe).to_string()).collect(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
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

fn evidence_id(rule_id: &str, path: &str, start: usize, end: usize) -> String {
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}
