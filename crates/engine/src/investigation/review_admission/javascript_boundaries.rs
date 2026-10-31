//! Handler identity and lexical membership only; no guard or effect proof.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct RouteInvocation {
    pub(super) possible_route: bool,
    pub(super) end_line: usize,
}

pub(super) struct Boundaries {
    pub(super) decorated: BTreeMap<usize, ServerMutationMarker>,
    pub(super) mutation_members: BTreeSet<usize>,
    pub(super) route_invocations: BTreeMap<usize, RouteInvocation>,
    pub(super) comments: Vec<std::ops::Range<usize>>,
}

pub(super) fn inspect(file: &SourceFile, spans: &[(usize, usize)]) -> Option<Boundaries> {
    if !matches!(
        file.language,
        Some(Language::Javascript | Language::Typescript | Language::Tsx)
    ) || !((file.source.contains("Mutation") && file.source.contains(": async"))
        || file.source.contains("@Mutation(")
        || ["@Post(", "@Put(", "@Patch(", "@Delete("]
            .iter()
            .any(|s| file.source.contains(s))
        || file.source.contains(".route(")
        || file.source.lines().any(javascript_http_mutation_route))
    {
        return None;
    }
    let ast = AstGrep::doc(StrDoc::try_new(&file.source, parser_language(file.language?)).ok()?);
    let root = ast.root();
    if root.dfs().any(|n| n.is_error() || n.is_missing()) {
        return None;
    }
    let mut result = Boundaries {
        decorated: BTreeMap::new(),
        mutation_members: BTreeSet::new(),
        comments: Vec::new(),
        route_invocations: BTreeMap::new(),
    };
    for node in root.dfs() {
        if node.kind().as_ref() == "comment" {
            result.comments.push(node.range());
        }
        if node.kind().as_ref() == "call_expression" {
            if let Some(function) = node.field("function").filter(|function| {
                function.kind().as_ref() == "member_expression"
                    && function.field("property").is_some_and(|property| {
                        matches!(
                            property.text().to_ascii_lowercase().as_str(),
                            "post" | "put" | "patch" | "delete"
                        )
                    })
            }) {
                let chained = function.field("object").is_some_and(|object| {
                    object.kind().as_ref() == "call_expression"
                        && object
                            .field("function")
                            .and_then(|f| f.field("property"))
                            .is_some_and(|property| property.text().as_ref() == "route")
                });
                if !chained && !javascript_http_mutation_route(&format!("{}(", function.text())) {
                    continue;
                }
                if let Some(arguments) = node.field("arguments") {
                    let arguments = arguments
                        .children()
                        .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
                        .collect::<Vec<_>>();
                    // Supported HTTP shorthand registrations have a path and
                    // handler(s). A lone object is not that invocation contract:
                    // e.g. a nested model named `app` with delete({where: ...}).
                    // Chained route methods already bind their path separately.
                    // Keep spreads, variable paths and callable references;
                    // this is a syntax veto, not framework/type resolution.
                    let lone_object =
                        arguments.len() == 1 && arguments[0].kind().as_ref() == "object";
                    // An object explicitly carrying a handler can be a custom
                    // registration wrapper. Its contract is unresolved, not a
                    // proven non-route; keep it available for review.
                    let handler_config = lone_object
                        && arguments[0].children().any(|property| {
                            let key = property
                                .field("key")
                                .or_else(|| property.field("name"))
                                .map(|key| key.text().into_owned())
                                .unwrap_or_else(|| property.text().into_owned());
                            matches!(key.trim_matches(['\'', '"']), "handler" | "handlers")
                        });
                    let possible_route = chained || !lone_object || handler_config;
                    let anchor_line = if chained {
                        function
                            .field("object")
                            .and_then(|object| object.field("function"))
                            .and_then(|route| route.field("property"))
                    } else {
                        function.field("property")
                    }
                    .map(|property| property.start_pos().line())
                    .unwrap_or(function.start_pos().line());
                    result
                        .route_invocations
                        .entry(anchor_line)
                        .and_modify(|accepted| {
                            accepted.possible_route |= possible_route;
                            accepted.end_line = accepted.end_line.max(node.end_pos().line());
                        })
                        .or_insert(RouteInvocation {
                            possible_route,
                            end_line: node.end_pos().line(),
                        });
                }
            }
        }
        if node.kind().as_ref() == "method_definition" {
            let Some(name) = node.field("name") else {
                continue;
            };
            let Some(body) = node.field("body") else {
                continue;
            };
            for decorator in node
                .prev_all()
                .filter(|n| n.is_named())
                .take_while(|n| n.kind().as_ref() == "decorator")
            {
                let Some(call) = decorator
                    .children()
                    .find(|n| n.kind().as_ref() == "call_expression")
                else {
                    continue;
                };
                if call.field("function").is_none_or(|n| {
                    !matches!(
                        n.text().as_ref(),
                        "Post" | "Put" | "Patch" | "Delete" | "Mutation"
                    )
                }) {
                    continue;
                }
                let start_index = decorator.start_pos().line();
                let end_index = node.end_pos().line().min(spans.len().saturating_sub(1));
                let excerpt = &file.source[spans[start_index].0..spans[end_index].1];
                let Some(effect) = mutation_effect(excerpt) else {
                    continue;
                };
                let symbol = name.text().into_owned();
                if is_authorization_bootstrap_operation(&symbol) {
                    continue;
                }
                result.decorated.insert(
                    start_index,
                    ServerMutationMarker {
                        start_index,
                        end_index,
                        related_handlers: terminal_call_identifiers(&body.text(), &symbol),
                        symbol,
                        effect,
                    },
                );
            }
        }
        if node.kind().as_ref() != "pair"
            || node
                .field("key")
                .is_none_or(|n| n.text().trim_matches(['\'', '"']) != "Mutation")
        {
            continue;
        }
        let Some(object) = node
            .field("value")
            .filter(|n| n.kind().as_ref() == "object")
        else {
            continue;
        };
        for member in object.children().filter(|n| n.kind().as_ref() == "pair") {
            if member.field("value").is_some_and(|n| {
                matches!(n.kind().as_ref(), "arrow_function" | "function_expression")
            }) {
                result.mutation_members.insert(member.start_pos().line());
            }
        }
    }
    Some(result)
}
