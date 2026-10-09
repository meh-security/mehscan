//! Legacy request factories are context; owned initiation methods are effects.
use super::*;
type N<'a> = Node<'a, StrDoc<SupportLang>>;

#[allow(clippy::too_many_arguments)]
pub(super) fn add<'a>(
    path: &str,
    root: &N<'a>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let calls = root
        .dfs()
        .filter(|n| n.kind().as_ref() == "invocation_expression")
        .collect::<Vec<_>>();
    let producers = evidence
        .iter()
        .enumerate()
        .filter_map(|(i, e)| {
            if e.rule_id != "csharp-outbound-http" {
                return None;
            }
            calls
                .iter()
                .find(|n| n.range() == (e.location.start.byte_offset..e.location.end.byte_offset))
                .map(|n| (i, n.clone()))
        })
        .collect::<Vec<_>>();
    let imported = root.dfs().any(|n| {
        n.kind().as_ref() == "using_directive"
            && matches!(
                compact(&n.text()).as_str(),
                "usingSystem.Net;" | "globalusingSystem.Net;"
            )
    });
    let aliases = root
        .dfs()
        .filter(|n| n.kind().as_ref() == "using_directive")
        .filter_map(|n| {
            let text = compact(&n.text());
            let text = text.trim_start_matches("global").strip_prefix("using")?;
            let (name, ty) = text.trim_end_matches(';').split_once('=')?;
            Some((name.to_owned(), ty.to_owned()))
        })
        .collect::<Vec<_>>();
    for call in &calls {
        if comments.is_in_comment(call.range()) {
            continue;
        }
        let Some(function) = call.field("function") else {
            continue;
        };
        let Some(receiver) = function.field("expression") else {
            continue;
        };
        let Some(method) = function.field("name") else {
            continue;
        };
        let method = method.text();
        let arity = invocation_arguments(call).len();
        if !match method.as_ref() {
            "GetResponse" | "GetResponseAsync" | "GetRequestStream" | "GetRequestStreamAsync" => {
                arity == 0
            }
            "BeginGetResponse" | "BeginGetRequestStream" => arity == 2,
            _ => false,
        } {
            continue;
        }
        let canonical_type = |ty: &str| {
            let ty = ty
                .trim()
                .trim_end_matches('?')
                .trim_start_matches("global::");
            let alias = aliases
                .iter()
                .find(|(name, _)| name == ty)
                .map(|(_, ty)| ty.as_str());
            let ty = alias.unwrap_or(ty).trim_start_matches("global::");
            let shadowed = call.ancestors().any(|p| {
                p.children().any(|n| {
                    n.kind().as_ref() == "type_parameter_list"
                        && n.dfs().any(|t| {
                            t.kind().as_ref() == "type_parameter"
                                && t.field("name").is_some_and(|name| name.text() == ty)
                        })
                })
            });
            [
                "WebRequest",
                "HttpWebRequest",
                "FtpWebRequest",
                "FileWebRequest",
            ]
            .iter()
            .any(|name| {
                ty == format!("System.Net.{name}")
                    || ty == *name
                        && alias.is_none()
                        && imported
                        && !shadowed
                        && !declares_type(root, name)
            })
        };
        let declared = binding_type(root, &receiver).is_some_and(|ty| canonical_type(&ty));
        let cast = receiver.kind().as_ref() == "cast_expression"
            && receiver
                .field("type")
                .is_some_and(|ty| canonical_type(&ty.text()));
        let origin = super::super::outbound_cleanup::origin(root, &receiver, &producers, 8);
        let helper = helper_type(root, &receiver).is_some_and(|ty| canonical_type(&ty));
        if !declared && !cast && origin.is_none() && !helper {
            continue;
        }
        push_call_sink(
            path,
            call,
            &receiver,
            "request",
            "csharp-webrequest-dispatch",
            Capability::OutboundNetworkRequest,
            "CWE-918",
            &[
                "http",
                "network",
                "legacy-webrequest",
                "outbound-request:dispatch",
            ],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn binding<'a>(root: &N<'a>, site: &N<'a>) -> Option<N<'a>> {
    let text = site.text();
    let explicit = text.starts_with("this.");
    let symbol = text.strip_prefix("this.").unwrap_or(&text);
    simple_identifier(symbol)?;
    let owner = super::super::context::enclosing_type_start(site);
    let mut fields = Vec::new();
    let mut locals = Vec::new();
    for n in root
        .dfs()
        .filter(|n| matches!(n.kind().as_ref(), "parameter" | "variable_declarator"))
    {
        if n.field("name").is_none_or(|n| n.text() != symbol) {
            continue;
        }
        let field = n
            .ancestors()
            .find(|p| p.kind().as_ref() == "field_declaration");
        if field.is_some() && super::super::context::enclosing_type_start(&n) == owner {
            fields.push(n);
        } else if !explicit
            && n.range().end <= site.range().start
            && (super::super::context::lexical_declaration_visible_at(&n, site)
                || n.kind().as_ref() == "parameter"
                    && scope_range(&n, root) == scope_range(site, root))
        {
            locals.push(n);
        }
    }
    locals.sort_by_key(|n| n.range().start);
    locals.pop().or_else(|| fields.into_iter().next())
}

pub(super) fn binding_type<'a>(root: &N<'a>, site: &N<'a>) -> Option<String> {
    let n = binding(root, site)?;
    n.field("type")
        .or_else(|| n.parent()?.field("type"))
        .map(|ty| ty.text().into_owned())
}

fn helper_type<'a>(root: &N<'a>, site: &N<'a>) -> Option<String> {
    // A unique same-type helper signature can establish return ownership, never
    // its destination. No overload/virtual dispatch or cross-file inference.
    let binding = binding(root, site)?;
    if binding_type(root, site).as_deref() != Some("var") {
        return None;
    }
    let call = binding
        .field("value")
        .or_else(|| binding.children().filter(|n| n.is_named()).last())?;
    let function = call.field("function")?;
    if function.kind().as_ref() != "identifier" {
        return None;
    }
    let owner = super::super::context::enclosing_type_start(site);
    let methods = root
        .dfs()
        .filter(|n| {
            n.kind().as_ref() == "method_declaration"
                && super::super::context::enclosing_type_start(n) == owner
                && n.field("name")
                    .is_some_and(|name| name.text() == function.text())
        })
        .collect::<Vec<_>>();
    if methods.len() != 1 {
        return None;
    }
    methods[0]
        .field("returns")
        .or_else(|| methods[0].field("type"))
        .map(|ty| ty.text().into_owned())
}
