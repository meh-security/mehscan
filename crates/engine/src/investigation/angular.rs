//! Explicit component/template navigation for existing Angular trust reviews.
use super::*;

const MAX_FACT_BYTES: usize = 2048;

mod dialog;
mod packets;
mod registry;
mod templates;
pub(super) use packets::AngularContext;

#[cfg(test)]
mod completion_tests;

#[cfg(test)]
pub(super) fn template_facts(
    sources: &RepositorySources,
    paths: &BTreeSet<&str>,
    existing: &[ReviewNeighborhoodFact],
    precise: Option<&BTreeSet<String>>,
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    AngularContext::build(sources).facts(sources, paths, existing, precise, limit, None)
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
    // Metadata names and paths stay literal; inline HTML has its own source map.
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
    if fs::metadata(&absolute).ok()?.len() > MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES as u64 {
        return None;
    }
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
            assert!(
                facts
                    .iter()
                    .all(|f| f.role == "frontend_component_template_context"),
                "no fabricated binding for {metadata}: {facts:#?}"
            );
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
        assert!(
            cut,
            "an unrelated template does not close the missing consumer"
        );
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
#[cfg(test)]
fn binding_ranges(source: &str, names: &BTreeSet<String>) -> Vec<(usize, usize, String)> {
    templates::bindings(source)
        .into_iter()
        .filter(|b| b.output())
        .filter_map(|b| {
            names
                .iter()
                .find(|n| mentions_binding(&b.expression, n))
                .map(|n| (b.start, b.end, n.clone()))
        })
        .collect()
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
