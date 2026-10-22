//! Exact imported callable bodies and bounded module setup, never safety proof.
use super::*;

pub(super) fn append(
    sources: &RepositorySources,
    documents: &mut BTreeMap<String, Option<AstGrep<StrDoc<SupportLang>>>>,
    context: &mut FrontendContext,
) {
    for (id, (facts, partial)) in &mut context.packets {
        let seeds = facts.clone();
        let mut imported = BTreeSet::new();
        let mut added = Vec::new();
        for seed in seeds.iter().filter(|f| {
            matches!(
                f.role.as_str(),
                "frontend_output_producer_context"
                    | "frontend_output_dependency_context"
                    | "frontend_prop_producer_context"
                    | "frontend_prop_value_context"
                    | "frontend_state_writer_context"
            )
        }) {
            let Ok(file) = sources.file(&seed.location.path) else {
                continue;
            };
            let Some(ast) = documents
                .entry(file.path.clone())
                .or_insert_with(|| parse(file))
                .as_ref()
            else {
                continue;
            };
            let root = ast.root();
            // Save owned targets before mutably accessing the document cache.
            let targets: Vec<_> = root
                .dfs()
                .filter(|n| {
                    n.kind().as_ref() == "call_expression"
                        && valid(n)
                        && n.range().start >= seed.location.start.byte_offset
                        && n.range().end <= seed.location.end.byte_offset
                })
                .filter_map(|call| {
                    let callee = call.field("function")?;
                    if callee.kind().as_ref() != "identifier"
                        || shadowed(&call, callee.text().trim())
                    {
                        return None;
                    }
                    imported_target(file, &root, callee.text().trim(), sources)
                })
                .collect();
            for (path, export) in targets {
                if !imported.insert((path.clone(), export.clone())) {
                    continue;
                }
                if imported.len() > 2 {
                    *partial = true;
                    continue;
                }
                let Ok(helper_file) = sources.file(&path) else {
                    continue;
                };
                let Some(ast) = documents
                    .entry(path.clone())
                    .or_insert_with(|| parse(helper_file))
                    .as_ref()
                else {
                    *partial = true;
                    continue;
                };
                let root = ast.root();
                let definitions = exported_callable(&root, &export);
                if definitions.len() != 1 {
                    *partial = true;
                    continue;
                }
                let definition = &definitions[0];
                if !valid(definition) || definition.range().len() > MAX_FACT_BYTES {
                    *partial = true;
                    continue;
                }
                added.push(fact(
                    helper_file,
                    definition,
                    "frontend_imported_helper_context",
                    &export,
                    id,
                ));
                dependencies(
                    helper_file,
                    &root,
                    vec![definition.clone()],
                    &mut added,
                    partial,
                    id,
                    "frontend_helper_dependency_context",
                );
                // Include module-level effects on the actual referenced local
                // instances/options. Hooks or assignments can change behavior.
                // These are candidate effects, not execution/order guarantees.
                let names: BTreeSet<_> = added
                    .iter()
                    .filter(|f| f.location.path == path)
                    .filter_map(|f| {
                        root.dfs().find(|n| {
                            n.range().start == f.location.start.byte_offset
                                && n.range().end == f.location.end.byte_offset
                        })
                    })
                    .filter(|n| n.kind().as_ref() == "variable_declarator")
                    .filter_map(|n| n.field("name").map(|n| n.text().to_string()))
                    .collect();
                for statement in root.children().filter(|n| {
                    n.kind().as_ref() == "expression_statement"
                        && valid(n)
                        && n.dfs().any(|n| {
                            n.kind().as_ref() == "identifier" && names.contains(n.text().as_ref())
                        })
                }) {
                    if added
                        .iter()
                        .filter(|f| f.role == "frontend_helper_setup_context")
                        .count()
                        == 2
                        || statement.range().len() > MAX_FACT_BYTES
                    {
                        *partial = true;
                        continue;
                    }
                    added.push(fact(
                        helper_file,
                        &statement,
                        "frontend_helper_setup_context",
                        "candidate module effect on helper inputs",
                        id,
                    ));
                    dependencies(
                        helper_file,
                        &root,
                        vec![statement],
                        &mut added,
                        partial,
                        id,
                        "frontend_helper_dependency_context",
                    );
                }
                context
                    .imports
                    .entry(path.clone())
                    .or_insert_with(|| import_bindings(helper_file, &root));
            }
        }
        // Bound all imported-helper additions together, not per source/ID hop.
        let mut bytes = 0;
        for f in added {
            if facts.iter().any(|old| old.location == f.location) {
                continue;
            }
            if bytes + f.excerpt.len() > 4096
                || f.location.end.line.saturating_sub(f.location.start.line) >= 40
            {
                *partial = true;
                continue;
            }
            bytes += f.excerpt.len();
            facts.push(f);
        }
    }
}

fn imported_target(
    file: &SourceFile,
    root: &Node<'_, StrDoc<SupportLang>>,
    local: &str,
    sources: &RepositorySources,
) -> Option<(String, String)> {
    let mut targets = Vec::new();
    for import in root
        .children()
        .filter(|n| n.kind().as_ref() == "import_statement" && valid(n))
    {
        if import.text().trim_start().starts_with("import type ") {
            continue;
        }
        let module = import
            .field("source")?
            .text()
            .trim_matches(['\'', '"'])
            .to_string();
        // The shared resolver admits selected application sources only. A
        // workspace package or tsconfig alias can own the same helper contract
        // as a relative import; external dependencies still return no source.
        let path = if sources.node_modules.is_empty() {
            resolve_relative_typescript_module(&file.path, &module, sources)
        } else {
            match sources.node_modules.resolve_review_source(
                &file.path,
                &module,
                crate::code::node_modules::ImportMode::Import,
            ) {
                crate::code::node_modules::ModuleTarget::Source(path) => Some(path),
                _ => None,
            }
        };
        let Some(path) = path else {
            continue;
        };
        for spec in import.dfs().filter(|n| {
            n.kind().as_ref() == "import_specifier" && !n.text().trim_start().starts_with("type ")
        }) {
            if spec
                .field("alias")
                .or_else(|| spec.field("name"))
                .is_some_and(|n| n.text() == local)
            {
                targets.push((path.clone(), spec.field("name")?.text().to_string()));
            }
        }
        for clause in import
            .children()
            .filter(|n| n.kind().as_ref() == "import_clause")
        {
            if clause
                .children()
                .any(|n| n.kind().as_ref() == "identifier" && n.text() == local)
            {
                targets.push((path.clone(), "default".to_string()));
            }
        }
    }
    (targets.len() == 1).then(|| targets.remove(0))
}

fn exported_callable<'a>(
    root: &Node<'a, StrDoc<SupportLang>>,
    export: &str,
) -> Vec<Node<'a, StrDoc<SupportLang>>> {
    let mut locals = BTreeSet::new();
    let mut direct = Vec::new();
    for statement in root
        .children()
        .filter(|n| n.kind().as_ref() == "export_statement" && valid(n))
    {
        if statement.field("source").is_some() {
            continue;
        } // No barrel guesses.
        if statement.text().trim_start().starts_with("export default ") {
            if export != "default" {
                continue;
            }
            for value in statement.children().filter(|n| n.is_named()) {
                if value.kind().as_ref() == "identifier" {
                    locals.insert(value.text().to_string());
                } else if callable(&value) {
                    direct.push(value);
                }
            }
        } else {
            for spec in statement
                .dfs()
                .filter(|n| n.kind().as_ref() == "export_specifier")
            {
                if spec
                    .field("alias")
                    .or_else(|| spec.field("name"))
                    .is_some_and(|n| n.text() == export)
                {
                    if let Some(name) = spec.field("name") {
                        locals.insert(name.text().to_string());
                    }
                }
            }
            for declaration in statement.children().filter(|n| n.is_named()) {
                if declaration
                    .field("name")
                    .is_some_and(|n| n.text() == export)
                {
                    locals.insert(export.to_string());
                }
                for binding in declaration
                    .children()
                    .filter(|n| n.kind().as_ref() == "variable_declarator")
                {
                    if binding.field("name").is_some_and(|n| n.text() == export) {
                        locals.insert(export.to_string());
                    }
                }
            }
        }
    }
    for declaration in root.children().flat_map(|n| {
        if n.kind().as_ref() == "export_statement" {
            n.children().collect::<Vec<_>>()
        } else {
            vec![n]
        }
    }) {
        if declaration.kind().as_ref() == "function_declaration"
            && declaration
                .field("name")
                .is_some_and(|n| locals.contains(n.text().as_ref()))
        {
            direct.push(declaration);
        } else if declaration.kind().as_ref() == "lexical_declaration"
            && declaration.text().trim_start().starts_with("const ")
        {
            for binding in declaration
                .children()
                .filter(|n| n.kind().as_ref() == "variable_declarator")
            {
                if binding
                    .field("name")
                    .is_some_and(|n| locals.contains(n.text().as_ref()))
                    && binding.field("value").is_some_and(|n| callable(&n))
                {
                    direct.push(binding);
                }
            }
        }
    }
    direct.sort_by_key(|n| n.range().start);
    direct.dedup_by_key(|n| n.range().start);
    direct
}
