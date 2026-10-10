//! Explicit component/template navigation for existing Angular trust reviews.
use super::*;

const MAX_FACT_BYTES: usize = 2048;

pub(super) fn template_facts(
    sources: &RepositorySources,
    paths: &BTreeSet<&str>,
    existing: &[ReviewNeighborhoodFact],
    precise_fields: Option<&BTreeSet<String>>,
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    let mut facts = Vec::new();
    let mut partial = false;
    for path in paths {
        let relevant: Vec<_> = existing
            .iter()
            .filter(|f| f.location.path == *path && f.excerpt.contains("bypassSecurityTrust"))
            .collect();
        if relevant.is_empty() {
            continue;
        }
        let Ok(file) = sources.file(path) else {
            continue;
        };
        if file.language != Some(Language::Typescript)
            || file.source.len() > MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES
        {
            continue;
        }
        let Ok(doc) = StrDoc::try_new(&file.source, parser_language(Language::Typescript)) else {
            continue;
        };
        let ast = AstGrep::doc(doc);
        let root = ast.root();
        let components = component_imports(&root);
        for owner in root
            .dfs()
            .filter(|n| n.kind().as_ref() == "class_declaration")
        {
            let mut names = BTreeSet::new();
            let mut methods = BTreeSet::new();
            for call in owner
                .dfs()
                .filter(|n| n.kind().as_ref() == "call_expression")
            {
                if !call.field("function").is_some_and(|f| {
                    f.kind().as_ref() == "member_expression"
                        && f.field("property")
                            .is_some_and(|p| p.text().starts_with("bypassSecurityTrust"))
                }) || !relevant.iter().any(|f| {
                    f.location.start.byte_offset <= call.range().start
                        && call.range().end <= f.location.end.byte_offset
                }) || call
                    .ancestors()
                    .find(|a| a.kind().as_ref() == "class_declaration")
                    .is_none_or(|a| a.range() != owner.range())
                {
                    continue;
                }
                for parent in call.ancestors().take_while(|a| a.range() != owner.range()) {
                    match parent.kind().as_ref() {
                        "assignment_expression" => {
                            if let Some(left) = parent.field("left") {
                                if let Some(name) = left.field("property").or_else(|| {
                                    (left.kind().as_ref() == "identifier").then(|| left.clone())
                                }) {
                                    names.insert(name.text().to_string());
                                }
                            }
                            break;
                        }
                        "pair" => {
                            if let Some(key) = parent.field("key") {
                                if is_plain_identifier(key.text().as_ref()) {
                                    names.insert(key.text().to_string());
                                }
                            }
                            break;
                        }
                        "public_field_definition" => {
                            if let Some(name) = parent.field("name") {
                                if is_plain_identifier(name.text().as_ref()) {
                                    names.insert(name.text().to_string());
                                }
                            }
                            break;
                        }
                        "return_statement" => {
                            if let Some(method) = parent
                                .ancestors()
                                .take_while(|a| a.range() != owner.range())
                                .find(|a| {
                                    matches!(
                                        a.kind().as_ref(),
                                        "method_definition"
                                            | "arrow_function"
                                            | "function_expression"
                                    )
                                })
                                && method.kind().as_ref() == "method_definition"
                            {
                                if let Some(name) = method.field("name") {
                                    methods.insert(name.text().to_string());
                                }
                            }
                            break;
                        }
                        _ => {}
                    }
                }
            }
            if let Some(precise) = precise_fields {
                names.retain(|n| precise.contains(n));
            }
            names.extend(methods);
            if names.is_empty() {
                continue;
            }
            // Decorators can belong to the class or its containing export statement.
            let decorators: Vec<_> = owner
                .children()
                .chain(
                    owner
                        .parent()
                        .into_iter()
                        .filter(|p| p.kind().as_ref() == "export_statement")
                        .flat_map(|p| p.children().collect::<Vec<_>>()),
                )
                .filter(|n| n.kind().as_ref() == "decorator")
                .collect();
            let metadata: Vec<_> = decorators
                .iter()
                .flat_map(|n| n.children())
                .filter(|n| {
                    n.kind().as_ref() == "call_expression"
                        && n.field("function")
                            .is_some_and(|f| components.contains(f.text().as_ref()))
                })
                .collect();
            if metadata.len() != 1 {
                partial = true;
                continue;
            }
            let metadata = &metadata[0];
            let Some(args) = metadata.field("arguments") else {
                partial = true;
                continue;
            };
            let objects: Vec<_> = args.children().filter(|n| n.is_named()).collect();
            if objects.len() != 1
                || objects[0].kind().as_ref() != "object"
                || objects[0]
                    .children()
                    .any(|n| n.kind().as_ref() == "spread_element")
            {
                partial = true;
                continue;
            }
            let pairs: Vec<_> = objects[0]
                .children()
                .filter(|n| {
                    n.kind().as_ref() == "pair"
                        && n.field("key").is_some_and(|k| {
                            matches!(
                                k.text().trim_matches(['\'', '"']),
                                "template" | "templateUrl"
                            )
                        })
                })
                .collect();
            if pairs.len() != 1 {
                partial = true;
                continue;
            }
            let Some(value) = pairs[0].field("value") else {
                partial = true;
                continue;
            };
            let Some(text) = static_literal(&value) else {
                partial = true;
                continue;
            };
            let external = pairs[0]
                .field("key")
                .unwrap()
                .text()
                .trim_matches(['\'', '"'])
                == "templateUrl";
            let (template_path, template, offset) = if external {
                let Some((path, source)) = external_template(sources, path, &text) else {
                    partial = true;
                    continue;
                };
                (path, source, 0)
            } else {
                (file.path.clone(), text, value.range().start + 1)
            };
            let consumers = binding_ranges(&template, &names);
            if metadata.range().len() > MAX_FACT_BYTES || !valid(metadata) {
                partial = true;
                continue;
            }
            // Retain explicit metadata even with no matched consumer: no match is not no consumer.
            if facts.len() == limit {
                return (facts, true);
            }
            facts.push(fact(
                file,
                metadata.range().start,
                metadata.range().end,
                "frontend_component_template_context",
                "Component",
            ));
            for (start, end, name) in consumers {
                if facts.len() == limit {
                    return (facts, true);
                }
                if end - start > MAX_FACT_BYTES {
                    partial = true;
                    continue;
                }
                let source = if external { &template } else { &file.source };
                facts.push(ReviewNeighborhoodFact {
                    role: "frontend_template_binding_context".into(), symbol: name,
                    location: location_from_offsets(&template_path, source, offset + start, offset + end),
                    excerpt: source[offset + start..offset + end].into(), evidence_id: None,
                    provenance: textual_provenance("explicit Angular component template; bounded lexical binding navigation, not reaching-value, actor or sanitization proof 1"),
                });
            }
        }
    }
    (facts, partial)
}

fn component_imports(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.children()
        .filter(|n| {
            n.kind().as_ref() == "import_statement"
                && n.field("source")
                    .is_some_and(|s| s.text().trim_matches(['\'', '"']) == "@angular/core")
        })
        .flat_map(|n| {
            n.dfs()
                .filter(|n| n.kind().as_ref() == "import_specifier")
                .collect::<Vec<_>>()
        })
        .filter(|n| n.field("name").is_some_and(|n| n.text() == "Component"))
        .filter_map(|n| n.field("alias").or_else(|| n.field("name")))
        .map(|n| n.text().to_string())
        .collect()
}

fn static_literal(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    if !matches!(node.kind().as_ref(), "string" | "template_string")
        || !valid(node)
        || node
            .dfs()
            .any(|n| n.kind().as_ref() == "template_substitution")
    {
        return None;
    }
    let text = node.text();
    // Cooked escapes require a source-offset map; keep those as follow-ups.
    if text.len() < 2 || text.contains('\\') {
        return None;
    }
    Some(text[1..text.len() - 1].to_string())
}

fn external_template(
    sources: &RepositorySources,
    component: &str,
    name: &str,
) -> Option<(String, String)> {
    if name.is_empty() || name.starts_with('/') || name.contains(['\\', ':']) {
        return None;
    }
    let mut parts: Vec<_> = component.split('/').collect();
    parts.pop()?;
    for part in name.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            value => parts.push(value),
        }
    }
    let relative = parts.join("/");
    if let Ok(file) = sources.file(&relative) {
        return (file.source.len() <= MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES)
            .then(|| (relative, file.source.clone()));
    }
    let root = fs::canonicalize(&sources.root).ok()?;
    let absolute = fs::canonicalize(root.join(Path::new(component).parent()?).join(name)).ok()?;
    if !absolute.starts_with(&root) {
        return None;
    }
    let path = display_path(absolute.strip_prefix(&root).ok()?);
    let source = fs::read_to_string(absolute).ok()?;
    (source.len() <= MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES).then_some((path, source))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sources(source: &str, templates: &[(&str, &str)]) -> RepositorySources {
        let mut files = BTreeMap::from([(
            "view.ts".into(),
            SourceFile {
                path: "view.ts".into(),
                language: Some(Language::Typescript),
                source: source.into(),
            },
        )]);
        for (path, text) in templates {
            files.insert(
                (*path).into(),
                SourceFile {
                    path: (*path).into(),
                    language: None,
                    source: (*text).into(),
                },
            );
        }
        RepositorySources {
            root: "fixture".into(),
            files,
        }
    }

    fn collect(
        sources: &RepositorySources,
        precise: Option<&BTreeSet<String>>,
        limit: usize,
    ) -> (Vec<ReviewNeighborhoodFact>, bool) {
        let source = &sources.files["view.ts"].source;
        let context = ReviewNeighborhoodFact {
            role: "sink_context".into(),
            symbol: "bypassSecurityTrustHtml".into(),
            location: location_from_offsets("view.ts", source, 0, source.len()),
            excerpt: source.clone(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        };
        template_facts(
            sources,
            &BTreeSet::from(["view.ts"]),
            &[context],
            precise,
            limit,
        )
    }

    #[test]
    fn explicit_external_template_replaces_filename_guess_and_ignores_comments() {
        let source = "import { Component as View } from '@angular/core';\n@View({ templateUrl: './actual.html' })\nexport class A { set(v: string) { this.html = this.s.bypassSecurityTrustHtml(v); } }";
        let sources = sources(
            source,
            &[
                (
                    "actual.html",
                    "<!-- <div [innerHTML]=\"html\"></div> -->\n<div\n [innerHTML] = \"html\"></div>",
                ),
                ("view.component.html", "<div [innerHTML]=\"wrong\"></div>"),
            ],
        );
        let (facts, cut) = collect(&sources, None, 3);
        assert!(!cut);
        assert_eq!(facts.len(), 2, "{facts:#?}");
        assert_eq!(facts[1].location.path, "actual.html");
        assert_eq!(facts[1].excerpt, "<div\n [innerHTML] = \"html\">");
        assert_eq!(facts[1].location.start.line, 2);
    }

    #[test]
    fn inline_method_consumer_preserves_original_unicode_offsets() {
        let source = "import { Component } from '@angular/core';\n@Component({ template: `é<div [innerHTML]=\"render()\"></div>` })\nexport class A { render() { return this.s.bypassSecurityTrustHtml(this.value); } }";
        let (facts, cut) = collect(&sources(source, &[]), None, 3);
        assert!(!cut);
        assert_eq!(facts.len(), 2, "{facts:#?}");
        let binding = &facts[1];
        assert_eq!(binding.location.path, "view.ts");
        assert_eq!(binding.location.start.line, 2);
        assert_eq!(binding.excerpt, "<div [innerHTML]=\"render()\">");
        assert_eq!(
            &source[binding.location.start.byte_offset..binding.location.end.byte_offset],
            binding.excerpt
        );
    }

    #[test]
    fn rejects_foreign_dynamic_duplicate_and_outside_templates() {
        for metadata in [
            "import { Component } from 'other'; @Component({ template: '<div [innerHTML]=\"html\"></div>' })",
            "import { Component } from '@angular/core'; @Component({ templateUrl: getTemplate() })",
            "import { Component } from '@angular/core'; @Component({ templateUrl: '../outside.html' })",
            "import { Component } from '@angular/core'; @Component({ template: `<div>${markup}</div>` })",
            "import { Component } from '@angular/core'; @Component({ ...options, template: '<div [innerHTML]=\"html\"></div>' })",
            "import { Component } from '@angular/core'; @Component({ template: '<div></div>', templateUrl: './actual.html' })",
        ] {
            let source = format!(
                "{metadata}\nexport class A {{ set(v: string) {{ this.html = this.s.bypassSecurityTrustHtml(v); }} }}"
            );
            let (facts, cut) = collect(&sources(&source, &[]), None, 3);
            assert!(facts.is_empty(), "{metadata}: {facts:#?}");
            assert!(
                cut,
                "unsupported metadata must remain a follow-up: {metadata}"
            );
        }
    }

    #[test]
    fn does_not_attach_other_class_template_or_unrelated_field() {
        let source = "import { Component } from '@angular/core';\n@Component({ template: '<div [innerHTML]=\"html\"></div>' }) export class B {}\n@Component({ template: '<div [innerHTML]=\"unrelated\"></div>' }) export class A { set(v: string) { this.html = this.s.bypassSecurityTrustHtml(v); } }";
        let (facts, cut) = collect(&sources(source, &[]), None, 3);
        assert!(!cut);
        assert_eq!(facts.len(), 1);
        assert!(facts[0].excerpt.contains("unrelated"));
    }

    #[test]
    fn precise_field_and_consumer_limit_remain_bounded() {
        let source = "import { Component } from '@angular/core';\n@Component({ template: '<div [innerHTML]=\"a\"></div><div [innerHTML]=\"b\"></div><div [innerHTML]=\"a\"></div>' }) export class A { set(v: string) { this.a = this.s.bypassSecurityTrustHtml(v); this.b = this.s.bypassSecurityTrustHtml(v); } }";
        let (facts, cut) = collect(
            &sources(source, &[]),
            Some(&BTreeSet::from(["b".into()])),
            3,
        );
        assert!(!cut);
        assert_eq!(facts.len(), 2);
        assert_eq!(facts[1].symbol, "b");
        let (facts, cut) = collect(&sources(source, &[]), None, 2);
        assert!(cut);
        assert_eq!(facts.len(), 2);
    }

    #[test]
    fn ignores_property_spelling_in_text_or_quoted_attributes() {
        let names = BTreeSet::from(["html".into()]);
        let source = "é [innerHTML]=\"html\" <div title='[innerHTML]=\"html\"' [innerHTML]=\"other\"></div><div [innerHTML]=\"'html'\"></div><p [innerHTML]=\"html\"></p>";
        let ranges = binding_ranges(source, &names);
        assert_eq!(ranges.len(), 1);
        assert_eq!(
            &source[ranges[0].0..ranges[0].1],
            "<p [innerHTML]=\"html\">"
        );
    }
}

fn valid(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    !node.dfs().any(|n| n.is_error() || n.is_missing())
}

fn fact(
    file: &SourceFile,
    start: usize,
    end: usize,
    role: &str,
    symbol: &str,
) -> ReviewNeighborhoodFact {
    ReviewNeighborhoodFact {
        role: role.into(),
        symbol: symbol.into(),
        location: location_from_offsets(&file.path, &file.source, start, end),
        excerpt: file.source[start..end].into(),
        evidence_id: None,
        provenance: QueryProvenance {
            resolution: Resolution::Ast,
            engine: "explicit imported Angular Component metadata; navigation only 1".into(),
        },
    }
}

// Read only bracketed property attributes inside tags, ignoring comments and
// quoted unrelated attributes. Angular expression identity remains a reviewer check.
fn binding_ranges(source: &str, names: &BTreeSet<String>) -> Vec<(usize, usize, String)> {
    let bytes = source.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;
    let mut in_tag = false;
    let mut tag_start = 0;
    while i < bytes.len() {
        if source[i..].starts_with("<!--") {
            i = source[i + 4..]
                .find("-->")
                .map_or(bytes.len(), |end| i + 4 + end + 3);
            continue;
        }
        match bytes[i] {
            b'<' => {
                in_tag = true;
                tag_start = i;
                i += 1;
            }
            b'>' => {
                in_tag = false;
                i += 1;
            }
            b'\'' | b'"' if in_tag => {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                i += usize::from(i < bytes.len());
            }
            b'[' if in_tag && i > 0 && bytes[i - 1].is_ascii_whitespace() => {
                let Some(close) = source[i..].find(']') else {
                    break;
                };
                let property = &source[i + 1..i + close];
                if !matches!(
                    property.to_ascii_lowercase().as_str(),
                    "innerhtml" | "srcdoc" | "href" | "src"
                ) {
                    i += 1;
                    continue;
                }
                i += close + 1;
                while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                if bytes.get(i) != Some(&b'=') {
                    continue;
                }
                i += 1;
                while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                if !matches!(bytes.get(i), Some(b'\'' | b'"')) {
                    continue;
                }
                let quote = bytes[i];
                i += 1;
                let value_start = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                if i == bytes.len() {
                    break;
                }
                let expression = &source[value_start..i];
                if let Some(name) = names.iter().find(|n| mentions_binding(expression, n))
                    && let Some(end) = tag_end(source, tag_start)
                {
                    result.push((tag_start, end, name.clone()));
                }
                i += 1;
            }
            _ => {
                i += source[i..].chars().next().unwrap().len_utf8();
            }
        }
    }
    result
}

fn mentions_binding(expression: &str, name: &str) -> bool {
    let mut code = String::new();
    let mut chars = expression.chars();
    let mut quote = None;
    while let Some(ch) = chars.next() {
        if let Some(delimiter) = quote {
            if ch == '\\' {
                chars.next();
            } else if ch == delimiter {
                quote = None;
            }
            code.push(' ');
        } else if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            code.push(' ');
        } else {
            code.push(ch);
        }
    }
    contains_identifier(&code, name)
}

fn tag_end(source: &str, start: usize) -> Option<usize> {
    let mut quote = None;
    for (offset, ch) in source[start..].char_indices() {
        match (quote, ch) {
            (Some(delimiter), ch) if delimiter == ch => quote = None,
            (None, '\'' | '"') => quote = Some(ch),
            (None, '>') => return Some(start + offset + 1),
            _ => {}
        }
    }
    None
}
