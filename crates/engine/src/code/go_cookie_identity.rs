//! A visible cookie issuer and a decoded, consumed database selector.
//! This relationship is review work, not proof of authentication or bypass.
use super::{
    comments::CommentRanges, conditional::ConditionalRegions, literals::LiteralEnvironment,
};
use ast_grep_core::{AstGrep, Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Provenance,
    Resolution,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

type N<'a> = Node<'a, StrDoc<SupportLang>>;
const RULE: &str = "go-reversible-cookie-identity-review";

#[derive(Clone, Debug)]
struct Issuer {
    path: String,
    package: String,
    imports: Vec<String>,
    name: String,
    flavor: String,
    input: Capture,
    encoding: Capture,
    cookie: Capture,
    delivery: Capture,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CookieIdentityContext {
    issuers: Vec<Issuer>,
}

impl CookieIdentityContext {
    pub(crate) fn from_sources<'a>(sources: impl Iterator<Item = (&'a str, &'a str)>) -> Self {
        let mut issuers = Vec::new();
        for (path, source) in
            sources.filter(|(_, s)| s.contains("encoding/base64") && s.contains("SetCookie"))
        {
            let Ok(doc) = StrDoc::try_new(source, SupportLang::Go) else {
                continue;
            };
            let ast = AstGrep::doc(doc);
            let root = ast.root();
            for call in root.dfs().filter(|n| n.kind() == "call_expression") {
                if !owned(&root, &call, "net/http", "http", "SetCookie") {
                    continue;
                }
                let args = arguments(&call);
                if args.len() != 2 {
                    continue;
                }
                let Some(value) = origin(&args[1], 4) else {
                    continue;
                };
                let value = if value.kind() == "unary_expression"
                    && value.field("operator").is_some_and(|n| n.text() == "&")
                {
                    let Some(n) = value.field("operand") else {
                        continue;
                    };
                    n
                } else {
                    value
                };
                if value.kind() != "composite_literal" {
                    continue;
                }
                let Some(ty) = value.field("type") else {
                    continue;
                };
                if !qualifiers(&root, "net/http", "http")
                    .iter()
                    .any(|q| ty.text() == format!("{q}.Cookie") && !shadowed(&root, &call, q))
                {
                    continue;
                }
                if escaped_cookie(&args[1], &value, &call) {
                    continue;
                }
                let (Some(name), Some(payload)) =
                    (literal_field(&value, "Name"), field_value(&value, "Value"))
                else {
                    continue;
                };
                let Some(encoded) = origin(&payload, 4) else {
                    continue;
                };
                let Some(flavor) = encoding_flavor(&root, &encoded, "EncodeToString") else {
                    continue;
                };
                let encoded_args = arguments(&encoded);
                if encoded_args.len() != 1 {
                    continue;
                }
                let Some(text) = conversion(&encoded_args[0], "[]byte") else {
                    continue;
                };
                let Some(input) = origin(&text, 4) else {
                    continue;
                };
                if !(request_form(&root, &input) || string_parameter(&input)) {
                    continue;
                }
                issuers.push(Issuer {
                    path: path.into(),
                    package: package(&root),
                    imports: imports(&root),
                    name: literal(&name).unwrap(),
                    flavor,
                    input: capture(path, &input),
                    encoding: capture(path, &encoded),
                    cookie: capture(path, &value),
                    delivery: capture(path, &call),
                });
            }
        }
        Self { issuers }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_observations<'a>(
        &self,
        path: &str,
        root: &N<'a>,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        if self.issuers.is_empty()
            || qualifiers(root, "encoding/base64", "base64").is_empty()
            || qualifiers(root, "database/sql", "sql").is_empty()
        {
            return;
        }
        for query in root.dfs().filter(|n| n.kind() == "call_expression") {
            let Some(function) = query.field("function") else {
                continue;
            };
            if function.kind() != "selector_expression"
                || !function
                    .field("field")
                    .is_some_and(|n| n.text() == "QueryRow")
            {
                continue;
            }
            let Some(receiver) = function.field("operand").and_then(|n| origin(&n, 4)) else {
                continue;
            };
            if !owned(root, &receiver, "database/sql", "sql", "Open") {
                continue;
            }
            let Some(selector) = query.parent().filter(|n| {
                n.kind() == "selector_expression"
                    && n.field("field").is_some_and(|n| n.text() == "Scan")
            }) else {
                continue;
            };
            let Some(scan) = selector.parent().filter(|n| n.kind() == "call_expression") else {
                continue;
            };
            let scan_args = arguments(&scan);
            if scan_args.is_empty() || comments.is_in_comment(query.range()) {
                continue;
            }
            for parameter in arguments(&query).iter().skip(1) {
                let Some(mut decoded) = origin(parameter, 4) else {
                    continue;
                };
                if let Some(bytes) = conversion(&decoded, "string") {
                    let Some(n) = origin(&bytes, 4) else { continue };
                    decoded = n;
                }
                let Some(flavor) = encoding_flavor(root, &decoded, "DecodeString") else {
                    continue;
                };
                let args = arguments(&decoded);
                if args.len() != 1
                    || args[0].kind() != "selector_expression"
                    || !args[0].field("field").is_some_and(|n| n.text() == "Value")
                {
                    continue;
                }
                let Some(cookie) = args[0].field("operand").and_then(|n| origin(&n, 4)) else {
                    continue;
                };
                let Some((request, method)) = method_receiver(&cookie) else {
                    continue;
                };
                if method != "Cookie" || !request_parameter(root, &request) {
                    continue;
                }
                let names = arguments(&cookie);
                if names.len() != 1 {
                    continue;
                }
                let Some(name) = literal(&names[0]) else {
                    continue;
                };
                let compatible = self
                    .issuers
                    .iter()
                    .filter(|i| {
                        i.name == name && i.flavor == flavor && associated(i, path, &package(root))
                    })
                    .collect::<Vec<_>>();
                if compatible.is_empty() {
                    continue;
                }
                let id = format!(
                    "{path}:{}:{}:{RULE}",
                    query.range().start,
                    query.range().end
                );
                if evidence.iter().any(|e| e.id == id) {
                    continue;
                }
                let mut captures = BTreeMap::from([
                    ("cookie_name".into(), capture(path, &names[0])),
                    ("cookie_read".into(), capture(path, &cookie)),
                    ("credential_decode".into(), capture(path, &decoded)),
                    ("record_lookup".into(), capture(path, &query)),
                    ("lookup_result".into(), capture(path, &scan_args[0])),
                ]);
                for (index, issuer) in compatible.iter().take(4).enumerate() {
                    for (role, value) in [
                        ("issuer_input", &issuer.input),
                        ("issuer_encoding", &issuer.encoding),
                        ("issuer_cookie", &issuer.cookie),
                        ("issuer_delivery", &issuer.delivery),
                    ] {
                        captures.insert(format!("{role}_{index}"), value.clone());
                    }
                }
                evidence.push(Evidence {
                    id,
                    kind: EvidenceKind::SensitiveOperation,
                    capability: Capability::Authentication,
                    location: super::matcher::location(path, &query),
                    enclosing_symbol: super::context::enclosing_symbol(&query),
                    captures,
                    cwe_candidates: vec!["CWE-287".into()],
                    tags: vec![
                        "credential".into(),
                        "reversible-cookie".into(),
                        "visible-issuer-consumer".into(),
                        "review-independent-proof-and-effect".into(),
                        "review-origin:decision-critical".into(),
                    ],
                    confidence: Confidence::Medium,
                    provenance: Provenance {
                        resolution: Resolution::Ast,
                        engine: "mehscan bounded-go-cookie-selector 1".into(),
                        rule_version: 1,
                    },
                    context: EvidenceContext {
                        comment: false,
                        reachability: Some(super::reachability::classify(&query, literals)),
                        availability: Some(conditional.availability_for(query.range())),
                        ..Default::default()
                    },
                    symbol_resolution: None,
                    rule_id: RULE.into(),
                    related_evidence: Vec::new(),
                });
            }
        }
    }
}

fn arguments<'a>(n: &N<'a>) -> Vec<N<'a>> {
    n.field("arguments")
        .map(|a| a.children().filter(|n| n.is_named()).collect())
        .unwrap_or_default()
}
fn owner<'a>(n: &N<'a>) -> Option<N<'a>> {
    n.ancestors().find(|n| {
        matches!(
            n.kind().as_ref(),
            "function_declaration" | "method_declaration" | "func_literal"
        )
    })
}
fn qualifiers(root: &N<'_>, path: &str, default: &str) -> BTreeSet<String> {
    super::go_policy::go_import_qualifiers(root, path, default)
}
fn owned(root: &N<'_>, n: &N<'_>, path: &str, default: &str, suffix: &str) -> bool {
    n.field("function").is_some_and(|f| {
        qualifiers(root, path, default)
            .iter()
            .any(|q| f.text() == format!("{q}.{suffix}") && !shadowed(root, n, q))
    })
}
fn encoding_flavor(root: &N<'_>, n: &N<'_>, method: &str) -> Option<String> {
    [
        "StdEncoding",
        "RawStdEncoding",
        "URLEncoding",
        "RawURLEncoding",
    ]
    .into_iter()
    .find(|f| {
        owned(
            root,
            n,
            "encoding/base64",
            "base64",
            &format!("{f}.{method}"),
        )
    })
    .map(str::to_string)
}
fn names(n: &N<'_>, field: &str) -> Vec<String> {
    n.field(field)
        .map(|l| {
            l.children()
                .filter(|n| n.kind() == "identifier")
                .map(|n| n.text().into_owned())
                .collect()
        })
        .unwrap_or_default()
}
fn shadowed(root: &N<'_>, at: &N<'_>, name: &str) -> bool {
    let scope = owner(at);
    root.dfs().any(|n| {
        let local = scope
            .as_ref()
            .is_some_and(|s| owner(&n).is_some_and(|o| o.range() == s.range()));
        (local
            && n.kind() == "short_var_declaration"
            && names(&n, "left").iter().any(|x| x == name))
            || ((local || owner(&n).is_none())
                && matches!(
                    n.kind().as_ref(),
                    "parameter_declaration"
                        | "var_spec"
                        | "const_spec"
                        | "type_spec"
                        | "function_declaration"
                )
                && n.field("name").is_some_and(|v| v.text() == name))
    })
}
fn origin<'a>(n: &N<'a>, depth: usize) -> Option<N<'a>> {
    if n.kind() != "identifier" {
        return Some(n.clone());
    }
    if depth == 0 {
        return None;
    }
    let scope = owner(n)?;
    if scope.range().len() > 64 * 1024 {
        return None;
    }
    let candidates = scope
        .dfs()
        .filter(|d| {
            d.kind() == "short_var_declaration"
                && names(d, "left")
                    .first()
                    .is_some_and(|s| s == n.text().as_ref())
                && d.range().end <= n.range().start
                && owner(d).is_some_and(|o| o.range() == scope.range())
                && d.ancestors()
                    .find(|p| p.kind() == "block")
                    .is_some_and(|b| b.range().contains(&n.range().start))
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        if scope.dfs().any(|w| {
            w.range().start < n.range().start
                && w.kind() == "assignment_statement"
                && w.field("left")
                    .is_some_and(|l| l.children().any(|v| v.text() == n.text()))
        }) {
            return None;
        }
        return Some(n.clone());
    }
    if candidates.len() != 1 {
        return None;
    }
    let decl = &candidates[0];
    if !decl.parent().is_some_and(|p| p.kind() == "statement_list") {
        return None;
    }
    let name = n.text();
    if scope.dfs().any(|w| {
        w.range().start >= decl.range().end
            && w.range().start < n.range().start
            && owner(&w).is_some_and(|o| o.range() == scope.range())
            && ((w.kind() == "assignment_statement"
                && w.field("left").is_some_and(|l| {
                    l.children()
                        .any(|x| x.text() == name || x.text().starts_with(&format!("{name}.")))
                }))
                || (w.kind() == "unary_expression" && w.text() == format!("&{name}")))
    }) {
        return None;
    }
    let right = decl.field("right")?;
    let mut values = right.children().filter(|n| n.is_named());
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    origin(&value, depth - 1)
}
fn conversion<'a>(n: &N<'a>, ty: &str) -> Option<N<'a>> {
    if n.kind() == "type_conversion_expression"
        && n.field("type")
            .is_some_and(|t| t.text().replace(' ', "") == ty)
    {
        return n.field("operand");
    }
    if n.kind() == "call_expression"
        && n.field("function")
            .is_some_and(|f| f.text().replace(' ', "") == ty)
    {
        let mut args = arguments(n);
        return (args.len() == 1).then(|| args.remove(0));
    }
    None
}
fn method_receiver<'a>(n: &N<'a>) -> Option<(N<'a>, String)> {
    let f = n.field("function")?;
    Some((f.field("operand")?, f.field("field")?.text().into_owned()))
}
fn request_parameter(root: &N<'_>, n: &N<'_>) -> bool {
    let Some(f) = owner(n) else { return false };
    let Some(params) = f.field("parameters") else {
        return false;
    };
    params.dfs().any(|p| {
        p.kind() == "parameter_declaration"
            && p.field("name").is_some_and(|x| x.text() == n.text())
            && p.field("type").is_some_and(|t| {
                qualifiers(root, "net/http", "http").iter().any(|q| {
                    t.text().replace(' ', "") == format!("*{q}.Request") && !shadowed(root, n, q)
                })
            })
    })
}
fn request_form(root: &N<'_>, n: &N<'_>) -> bool {
    method_receiver(n).is_some_and(|(r, m)| m == "FormValue" && request_parameter(root, &r))
}
fn string_parameter(n: &N<'_>) -> bool {
    n.kind() == "identifier"
        && owner(n)
            .and_then(|f| f.field("parameters"))
            .is_some_and(|p| {
                p.dfs().any(|p| {
                    p.kind() == "parameter_declaration"
                        && p.field("name").is_some_and(|v| v.text() == n.text())
                        && p.field("type").is_some_and(|t| t.text() == "string")
                })
            })
}
fn field_value<'a>(n: &N<'a>, field: &str) -> Option<N<'a>> {
    n.field("body")?
        .children()
        .find(|n| n.kind() == "keyed_element" && n.field("key").is_some_and(|k| k.text() == field))?
        .field("value")
        .and_then(|v| v.children().find(|n| n.is_named()))
}
fn literal_field<'a>(n: &N<'a>, field: &str) -> Option<N<'a>> {
    field_value(n, field).filter(|v| literal(v).is_some())
}
fn literal(n: &N<'_>) -> Option<String> {
    matches!(
        n.kind().as_ref(),
        "interpreted_string_literal" | "raw_string_literal"
    )
    .then(|| n.text()[1..n.text().len() - 1].to_string())
    .filter(|s| !s.contains('\\'))
}
fn package(n: &N<'_>) -> String {
    n.children()
        .find(|n| n.kind() == "package_clause")
        .and_then(|p| p.children().find(|n| n.is_named()))
        .map(|n| n.text().into_owned())
        .unwrap_or_default()
}
fn imports(n: &N<'_>) -> Vec<String> {
    n.dfs()
        .filter(|n| n.kind() == "import_spec")
        .filter(|n| {
            !n.field("name")
                .is_some_and(|v| matches!(v.text().as_ref(), "_" | "."))
        })
        .filter_map(|n| n.field("path").and_then(|p| literal(&p)))
        .collect()
}
fn directory(path: &str) -> String {
    Path::new(path)
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .to_string_lossy()
        .replace('\\', "/")
}
fn associated(i: &Issuer, path: &str, package: &str) -> bool {
    let target = directory(path);
    (directory(&i.path) == target && i.package == package)
        || (!target.is_empty() && i.imports.iter().any(|p| p.ends_with(&format!("/{target}"))))
}
fn escaped_cookie(arg: &N<'_>, cookie: &N<'_>, delivery: &N<'_>) -> bool {
    if arg.kind() != "identifier" {
        return false;
    }
    let Some(scope) = owner(delivery) else {
        return true;
    };
    scope.dfs().any(|n| {
        n.kind() == "call_expression"
            && n.range().start > cookie.range().end
            && n.range().start < delivery.range().start
            && arguments(&n).iter().any(|a| a.text() == arg.text())
    })
}
fn capture(path: &str, n: &N<'_>) -> Capture {
    Capture {
        text: n.text().into_owned(),
        location: super::matcher::location(path, n),
    }
}
