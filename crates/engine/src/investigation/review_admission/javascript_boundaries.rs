//! Handler identity and lexical membership only; no guard or effect proof.
use super::*;

pub(super) struct Boundaries {
    pub(super) decorated: BTreeMap<usize, ServerMutationMarker>,
    pub(super) mutation_members: BTreeSet<usize>,
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
            .any(|s| file.source.contains(s)))
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
    };
    for node in root.dfs() {
        if node.kind().as_ref() == "comment" {
            result.comments.push(node.range());
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
