//! Same-project startup and one-hop inherited policy navigation. Not an
//! effective authorization assertion; the reviewer reads the actual source.
use super::*;

pub(super) fn facts(
    sources: &RepositorySources,
    file: &SourceFile,
    anchor: &Location,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if file.language != Some(Language::Csharp) {
        return (Vec::new(), false);
    }
    if file.source.len() > MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES {
        return (Vec::new(), true);
    }
    let scopes = sources
        .files
        .values()
        .filter(|f| f.path.to_ascii_lowercase().ends_with(".csproj"))
        .map(|f| path_directory(&f.path))
        .collect::<BTreeSet<_>>();
    let scope = nearest_framework_scope(&file.path, &scopes);
    let mut facts = Vec::new();
    for name in ["Program.cs", "Startup.cs"] {
        let path = if scope.is_empty() {
            name.to_string()
        } else {
            format!("{scope}/{name}")
        };
        if let Some(startup) = sources.files.get(&path)
            && !is_nonproduction_review_context_path(&path)
            && startup.source.len() <= MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES
        {
            facts.push(lead(
                startup,
                0,
                startup.source.len(),
                "application_policy_context",
                name,
            ));
        }
    }
    let Ok(doc) = StrDoc::try_new(&file.source, parser_language(Language::Csharp)) else {
        return (facts, true);
    };
    let ast = AstGrep::doc(doc);
    let root = ast.root();
    let Some(class) = root
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "class_declaration"
                && node.range().start <= anchor.start.byte_offset
                && anchor.end.byte_offset <= node.range().end
        })
        .min_by_key(|node| node.range().len())
    else {
        return (facts, false);
    };
    let bases = class
        .children()
        .find(|child| child.kind().as_ref() == "base_list")
        .map(|list| {
            list.children()
                .filter(|child| child.is_named())
                .map(|child| child.text().into_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let candidates = sources
        .files
        .values()
        .filter(|candidate| {
            candidate.language == Some(Language::Csharp)
                && candidate.source.len() <= MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES
                && !is_nonproduction_review_context_path(&candidate.path)
                && nearest_framework_scope(&candidate.path, &scopes) == scope
        })
        .collect::<Vec<_>>();
    if candidates.len() > 128 {
        return (facts, true);
    }
    for base in bases.iter().take(2) {
        // Qualified/generic/ambiguous names need semantic research. A unique
        // short name is a navigation opportunity, never inherited enforcement.
        if !base.chars().all(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let mut matches = Vec::new();
        for candidate in &candidates {
            let Ok(doc) = StrDoc::try_new(&candidate.source, parser_language(Language::Csharp))
            else {
                continue;
            };
            let ast = AstGrep::doc(doc);
            for declaration in ast.root().dfs().filter(|node| {
                node.kind().as_ref() == "class_declaration"
                    && node
                        .field("name")
                        .is_some_and(|name| name.text().trim() == base)
            }) {
                matches.push(lead(
                    candidate,
                    declaration.range().start,
                    declaration.range().end,
                    "inherited_policy_context",
                    base,
                ));
            }
        }
        if matches.len() == 1 {
            facts.append(&mut matches);
        }
    }
    (facts, bases.len() > 2)
}

fn lead(
    file: &SourceFile,
    start: usize,
    end: usize,
    role: &str,
    symbol: &str,
) -> ReviewNeighborhoodFact {
    // Location ends are exclusive byte coordinates, while source lookups use
    // inclusive lines and Rust str::lines omits a final empty LF line.
    let mut end = end;
    if end == file.source.len() && file.source.ends_with('\n') {
        end -= 1;
        if end > start && file.source.as_bytes()[end - 1] == b'\r' {
            end -= 1;
        }
    }
    ReviewNeighborhoodFact {
        role: role.into(),
        symbol: symbol.into(),
        location: location_from_offsets(&file.path, &file.source, start, end),
        excerpt: String::new(),
        evidence_id: None,
        provenance: textual_provenance(
            "same-project C# startup or unique lexical base-class navigation; effective policy and runtime activation unproved; location-only review lead 1",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(files: &[(&str, &str)]) -> RepositorySources {
        RepositorySources {
            node_modules: Default::default(),
            root: ".".into(),
            files: files
                .iter()
                .map(|(path, text)| {
                    (
                        path.to_string(),
                        SourceFile {
                            path: path.to_string(),
                            language: path.ends_with(".cs").then_some(Language::Csharp),
                            source: text.to_string(),
                        },
                    )
                })
                .collect(),
        }
    }
    #[test]
    fn selects_same_project_startup_and_unique_base_without_borrowing_sibling_policy() {
        let sources = fixture(&[
            ("app/App.csproj", "<Project />"),
            ("other/Other.csproj", "<Project />"),
            (
                "app/Program.cs",
                "builder.Services.AddControllers();\napp.MapControllers();\n",
            ),
            ("other/Program.cs", "app.RequireAuthorization();"),
            (
                "app/Base.cs",
                "[Authorize] class DemoBase : ControllerBase {}",
            ),
            (
                "app/Controller.cs",
                "class Controller : DemoBase { public void Reset() {} }",
            ),
        ]);
        let file = &sources.files["app/Controller.cs"];
        let anchor = location_from_offsets(
            &file.path,
            &file.source,
            file.source.find("public").unwrap(),
            file.source.find("public").unwrap() + 6,
        );
        let (facts, limited) = super::facts(&sources, file, &anchor);
        assert!(!limited);
        assert_eq!(facts.len(), 2);
        assert!(
            facts
                .iter()
                .any(|fact| fact.role == "application_policy_context"
                    && fact.location.path == "app/Program.cs"
                    && fact.location.end.line == 2)
        );
        assert!(
            facts
                .iter()
                .any(|fact| fact.role == "inherited_policy_context"
                    && fact.location.path == "app/Base.cs")
        );
        assert!(
            facts
                .iter()
                .all(|fact| fact.location.path.starts_with("app/") && fact.excerpt.is_empty())
        );
    }
    #[test]
    fn ambiguous_base_is_not_presented_as_inherited_policy() {
        let sources = fixture(&[
            ("App.csproj", "<Project />"),
            (
                "Controller.cs",
                "class Controller : Base { public void Reset() {} }",
            ),
            ("One.cs", "namespace One { [Authorize] class Base {} }"),
            ("Two.cs", "namespace Two { [AllowAnonymous] class Base {} }"),
        ]);
        let file = &sources.files["Controller.cs"];
        let anchor = location_from_offsets(&file.path, &file.source, 30, 36);
        assert!(super::facts(&sources, file, &anchor).0.is_empty());
    }
}
