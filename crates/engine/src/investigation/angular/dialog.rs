//! Imported Material dialog receiver/data navigation, not runtime object flow.
use super::*;
use registry::{Declaration, Registry, bounded_fact, core_imports};

pub(super) fn receiver(
    registry: &Registry,
    decl: &Declaration,
    call: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let Some(receiver) = call.field("function").and_then(|n| n.field("object")) else {
        return false;
    };
    let text = receiver.text();
    let Some(name) = text.strip_prefix("this.") else {
        return false;
    };
    let root = registry.documents[&decl.path].root();
    let inject = core_imports(&root, "inject");
    registry.owner(decl).dfs().any(|field| {
        if !field
            .ancestors()
            .find(|n| n.kind().as_ref() == "class_declaration")
            .is_some_and(|n| n.range() == decl.range)
        {
            return false;
        }
        if !field
            .field("name")
            .or_else(|| field.field("pattern"))
            .is_some_and(|n| n.text() == name)
        {
            return false;
        }
        if field.kind().as_ref() == "public_field_definition" {
            if let Some(value) = field.field("value")
                && value
                    .field("function")
                    .is_some_and(|n| inject.contains(n.text().as_ref()))
                && let Some(arg) = value
                    .field("arguments")
                    .and_then(|n| n.children().find(|n| n.is_named()))
            {
                return registry.imported(
                    &decl.path,
                    arg.text().as_ref(),
                    "@angular/material/dialog",
                    "MatDialog",
                );
            }
        } else if !matches!(
            field.kind().as_ref(),
            "required_parameter" | "optional_parameter"
        ) || !field
            .ancestors()
            .find(|n| n.kind().as_ref() == "method_definition")
            .is_some_and(|n| n.field("name").is_some_and(|n| n.text() == "constructor"))
        {
            return false;
        }
        if !field
            .children()
            .any(|n| n.kind().as_ref() == "accessibility_modifier" || n.text() == "readonly")
        {
            return false;
        }
        field.field("type").is_some_and(|n| {
            registry.imported(
                &decl.path,
                n.text().trim_start_matches(':').trim(),
                "@angular/material/dialog",
                "MatDialog",
            )
        })
    })
}

pub(super) fn data(
    registry: &Registry,
    sources: &RepositorySources,
    decl: &Declaration,
) -> Vec<(String, ReviewNeighborhoodFact)> {
    let root = registry.documents[&decl.path].root();
    let inject = core_imports(&root, "inject");
    let decorators = core_imports(&root, "Inject");
    let file = sources.file(&decl.path).unwrap();
    let mut result = Vec::new();
    for field in registry.owner(decl).dfs().filter(|n| {
        matches!(
            n.kind().as_ref(),
            "public_field_definition" | "required_parameter" | "optional_parameter"
        ) && n
            .ancestors()
            .find(|n| n.kind().as_ref() == "class_declaration")
            .is_some_and(|n| n.range() == decl.range)
    }) {
        let Some(name) = field.field("name").or_else(|| field.field("pattern")) else {
            continue;
        };
        let direct = field.field("value").is_some_and(|n| {
            n.field("function")
                .is_some_and(|n| inject.contains(n.text().as_ref()))
                && n.field("arguments")
                    .and_then(|n| n.children().find(|n| n.is_named()))
                    .is_some_and(|n| {
                        registry.imported(
                            &decl.path,
                            n.text().as_ref(),
                            "@angular/material/dialog",
                            "MAT_DIALOG_DATA",
                        )
                    })
        });
        let parameter_property = field.kind().as_ref() == "public_field_definition"
            || (field
                .children()
                .any(|n| n.kind().as_ref() == "accessibility_modifier" || n.text() == "readonly")
                && field
                    .ancestors()
                    .find(|n| n.kind().as_ref() == "method_definition")
                    .is_some_and(|n| n.field("name").is_some_and(|n| n.text() == "constructor")));
        let decorated = parameter_property
            && field
                .children()
                .filter(|n| n.kind().as_ref() == "decorator")
                .flat_map(|n| n.children().collect::<Vec<_>>())
                .any(|n| {
                    n.field("function")
                        .is_some_and(|n| decorators.contains(n.text().as_ref()))
                        && n.field("arguments")
                            .and_then(|n| n.children().find(|n| n.is_named()))
                            .is_some_and(|n| {
                                registry.imported(
                                    &decl.path,
                                    n.text().as_ref(),
                                    "@angular/material/dialog",
                                    "MAT_DIALOG_DATA",
                                )
                            })
                });
        if direct || decorated {
            result.push((
                name.text().to_string(),
                bounded_fact(
                    file,
                    &field,
                    "frontend_dialog_data_context",
                    name.text().as_ref(),
                )
                .0,
            ));
        }
    }
    result
}
