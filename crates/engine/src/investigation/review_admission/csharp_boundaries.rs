//! Associate HTTP attributes with their owning method, not annotation calls.
//! The bounded mutation excerpt remains a review lead, not proof of persistence.
use super::*;

pub(super) fn inspect(
    file: &SourceFile,
    spans: &[(usize, usize)],
) -> BTreeMap<usize, ServerMutationMarker> {
    let mut markers = BTreeMap::new();
    if file.language != Some(Language::Csharp)
        || !["HttpPost", "HttpPut", "HttpPatch", "HttpDelete"]
            .iter()
            .any(|name| file.source.contains(name))
    {
        return markers;
    }
    let Ok(document) = StrDoc::try_new(&file.source, parser_language(Language::Csharp)) else {
        return markers;
    };
    let ast = AstGrep::doc(document);
    let root = ast.root();
    for method in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_declaration")
    {
        let (Some(name), Some(_body)) = (method.field("name"), method.field("body")) else {
            continue;
        };
        let symbol = name.text().into_owned();
        if is_authorization_bootstrap_operation(&symbol) {
            continue;
        }
        let definition_index = name.start_pos().line();
        let end_index = method
            .end_pos()
            .line()
            .min(definition_index + 119)
            .min(spans.len().saturating_sub(1));
        for attributes in method
            .children()
            .filter(|node| node.kind().as_ref() == "attribute_list")
        {
            let http_mutation = attributes.children().any(|attribute| {
                attribute.kind().as_ref() == "attribute"
                    && attribute.field("name").is_some_and(|name| {
                        let text = name.text();
                        matches!(
                            text.strip_suffix("Attribute").unwrap_or(&text),
                            "HttpPost" | "HttpPut" | "HttpPatch" | "HttpDelete"
                        )
                    })
            });
            if !http_mutation {
                continue;
            }
            let start_index = attributes.start_pos().line();
            // Correct ownership without broadening the existing admission gate.
            // A form/filter action mentioning an editor update is not new work
            // merely because the AST can now identify its declaration.
            let boundary = file.source[spans[start_index].0..spans[start_index].1].trim();
            if !["[HttpPost", "[HttpPut", "[HttpPatch", "[HttpDelete"]
                .iter()
                .any(|prefix| boundary.starts_with(prefix))
                || marker_after_boundary(file, spans, start_index, 8).is_none()
            {
                continue;
            }
            let excerpt = &file.source[spans[start_index].0..spans[end_index].1];
            let Some(effect) = mutation_effect(excerpt) else {
                continue;
            };
            markers.insert(
                start_index,
                ServerMutationMarker {
                    start_index,
                    end_index,
                    symbol: symbol.clone(),
                    effect,
                    related_handlers: terminal_call_identifiers(excerpt, &symbol),
                    credential_effect: None,
                },
            );
        }
    }
    markers
}
