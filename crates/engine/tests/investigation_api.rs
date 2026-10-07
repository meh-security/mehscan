use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceFilter, EvidenceKind, Language, Resolution};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/aliases")
}

fn top_level_fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/investigation")
}

fn native_investigation_fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/native-investigation")
}

#[test]
fn symbol_queries_preserve_later_definitions_and_scope_parse_work() {
    use mehscan_engine::investigation::{find_imports, find_symbol};
    let root = std::env::temp_dir().join(format!("mehscan-symbols-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    for (path, source) in [
        ("a-broken.php", "<?php function needle( {"),
        ("b-broken.py", "import subprocess\ndef needle(\n"),
        ("c-valid.php", "<?php function needle($v) { return $v; }"),
        (
            "d-valid.py",
            "import subprocess\ndef needle(value):\n    return value\n",
        ),
        ("e-valid.js", "export { needle };"),
        ("f-valid.rs", "fn needle() {}"),
        (
            "g-valid.kt",
            "class Holder {\n    companion  object {\n        fun member(): Int { return 1 }\n    }\n}\n",
        ),
        ("h-irrelevant.php", "<?php function unrelated( {"),
    ] {
        std::fs::write(root.join(path), source).unwrap();
    }
    let broad = find_symbol(&root, "needle", None, None).unwrap();
    assert!(broad.truncated); // Relevant parse failures remain explicit.
    assert_eq!(broad.results.len(), 3); // Later PHP, Python and Rust definitions survive.
    assert_eq!(broad.skipped_files, ["a-broken.php", "b-broken.py"]);
    let scoped = find_symbol(&root, "needle", Some("c-valid.php"), None).unwrap();
    assert_eq!(scoped.results.len(), 1);
    assert!(!scoped.truncated);
    assert!(scoped.skipped_files.is_empty());
    assert!(find_symbol(&root, "needle", Some("../outside.php"), None).is_err());
    assert!(find_symbol(&root, "needle", Some("missing.php"), None).is_err());
    let limited = find_symbol(&root, "needle", None, Some(1)).unwrap();
    assert!(limited.truncated);
    assert_eq!(limited.results.len(), 1);
    let imports = find_imports(&root, "subprocess", None).unwrap();
    assert!(imports.truncated);
    assert_eq!(imports.skipped_files, ["b-broken.py"]);
    assert!(
        imports
            .results
            .iter()
            .any(|symbol| symbol.location.path == "d-valid.py")
    );
    // Synthetic labels need not occur verbatim in source; keep their AST path.
    assert_eq!(
        find_symbol(&root, "exports", Some("e-valid.js"), None)
            .unwrap()
            .results
            .len(),
        1
    );
    assert_eq!(
        find_symbol(&root, "companion object", Some("g-valid.kt"), None)
            .unwrap()
            .results
            .len(),
        1
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn directory_references_find_template_producers_without_crossing_scope() {
    use mehscan_engine::investigation::find_text_references;
    let root = std::env::temp_dir().join(format!("mehscan-producer-scope-{}", std::process::id()));
    std::fs::create_dir_all(root.join("app/views/private")).unwrap();
    std::fs::create_dir_all(root.join("app-other")).unwrap();
    std::fs::write(root.join(".gitignore"), "app/views/private/\n").unwrap();
    for (path, source) in [
        ("app/client.ts", "const url = node.dataset.apiUrl;\n"),
        (
            "app/views/index.cshtml",
            "<div data-api-url='@Url.Content(\"~/api/items\")'></div>\n",
        ),
        (
            "app/views/index.php",
            "<div data-api-url='/api/items'></div>\n",
        ),
        (
            "app/views/index.ejs",
            "<div data-api-url='<%= endpoint %>'></div>\n",
        ),
        ("app/views/index.pug", "div(data-api-url=endpoint)\n"),
        (
            "app/views/index.html",
            "<div data-api-url='/api/items'></div>\n",
        ),
        (
            "app/views/index.vue",
            "<template><div data-api-url='/api/items'></div></template>\n",
        ),
        (
            "app/views/index.jinja2",
            "<div data-api-url='{{ endpoint }}'></div>\n",
        ),
        (
            "app/views/index.twig",
            "<div data-api-url='{{ endpoint }}'></div>\n",
        ),
        (
            "app/views/private/hidden.cshtml",
            "<div data-api-url='hidden'></div>\n",
        ),
        (
            "app-other/copy.cshtml",
            "<div data-api-url='outside'></div>\n",
        ),
    ] {
        std::fs::write(root.join(path), source).unwrap();
    }
    let broad = find_text_references(&root, "data-api-url", None, None, Some(200)).unwrap();
    let scoped =
        find_text_references(&root, "data-api-url", None, Some("app/views/"), Some(200)).unwrap();
    let expected: Vec<_> = broad
        .results
        .into_iter()
        .filter(|row| row.location.path.starts_with("app/views/"))
        .collect();
    assert_eq!(scoped.results, expected);
    assert_eq!(scoped.results.len(), 8);
    let templates =
        mehscan_engine::investigation::find_source_paths(&root, "index.html", None).unwrap();
    assert_eq!(templates.results, ["app/views/index.html"]);
    assert!(!scoped.truncated);
    assert_eq!(scoped.provenance.resolution, Resolution::Textual);
    assert!(
        !scoped
            .results
            .iter()
            .any(|row| row.location.path.contains("private"))
    );
    let limited = find_text_references(&root, "data-api-url", None, Some("app"), Some(1)).unwrap();
    assert_eq!(limited.results.len(), 1);
    assert!(limited.truncated);
    for prefix in [
        "../outside",
        "app/../../outside",
        "C:/outside",
        "/outside",
        "missing",
        "app/client.ts",
        "",
    ] {
        assert!(
            find_text_references(&root, "data-api-url", None, Some(prefix), None).is_err(),
            "prefix {prefix}"
        );
    }
    assert!(
        find_text_references(&root, "apiUrl", Some("app/client.ts"), Some("app"), None).is_err()
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn supports_bounded_ai_investigation_workflow() {
    let root = fixture_root();

    let outline = mehscan_engine::investigation::get_file_outline(&root, "python/aliases.py")
        .expect("outline should succeed");
    assert_eq!(outline.provenance.resolution, Resolution::Ast);
    assert!(
        outline
            .results
            .symbols
            .iter()
            .any(|symbol| symbol.name == "review" && symbol.symbol_type == "function")
    );

    let source = mehscan_engine::investigation::get_source(&root, "python/aliases.py", 5, 7)
        .expect("source retrieval should succeed");
    assert_eq!(source.provenance.resolution, Resolution::Textual);
    assert_eq!(
        source.results.text,
        "def review(command):\n    sp.Popen(command)\n    launch(command)\n"
    );

    let enclosing = mehscan_engine::investigation::get_enclosing_at(&root, "python/aliases.py", 6)
        .expect("known location should have an enclosing symbol");
    assert_eq!(enclosing.results.symbol.unwrap().name, "review");

    let evidence = mehscan_engine::investigation::find_evidence(
        &root,
        EvidenceFilter {
            kind: Some(EvidenceKind::Sink),
            capability: Some(Capability::ProcessExecution),
            language: Some(Language::Python),
            path: Some("python/aliases.py".to_string()),
        },
        None,
    )
    .expect("evidence lookup should succeed");
    assert_eq!(evidence.results.evidence.len(), 2);

    let enclosing = mehscan_engine::investigation::get_enclosing_symbol(
        &root,
        &evidence.results.evidence[0].id,
    )
    .expect("enclosing lookup should succeed");
    assert_eq!(
        enclosing
            .results
            .symbol
            .expect("function should enclose sink")
            .name,
        "review"
    );

    let symbols = mehscan_engine::investigation::find_symbol(&root, "review", None, None)
        .expect("symbol lookup should succeed");
    assert!(symbols.results.len() >= 5);

    let imports = mehscan_engine::investigation::find_imports(&root, "subprocess", None)
        .expect("import lookup should succeed");
    assert_eq!(imports.results.len(), 2);
    assert!(imports.results.iter().all(|item| item.is_import));

    let references =
        mehscan_engine::investigation::find_text_references(&root, "launch", None, None, None)
            .expect("reference lookup should succeed");
    assert_eq!(references.provenance.resolution, Resolution::Textual);
    assert_eq!(references.results.len(), 2);

    let paths = mehscan_engine::investigation::find_source_paths(&root, "aliases.py", None)
        .expect("path navigation should succeed");
    assert_eq!(paths.results, vec!["python/aliases.py"]);
    assert!(
        mehscan_engine::investigation::find_source_paths(&root, "missing-view.pug", None)
            .expect("missing path search should succeed")
            .results
            .is_empty()
    );

    let scoped = mehscan_engine::investigation::find_text_references(
        &root,
        "launch",
        Some("python/aliases.py"),
        None,
        None,
    )
    .expect("scoped reference search should succeed");
    assert!(!scoped.results.is_empty());
    assert!(
        scoped
            .results
            .iter()
            .all(|item| item.location.path == "python/aliases.py")
    );

    let structural = mehscan_engine::investigation::run_structural_query(
        &root,
        Language::Python,
        "sp.Popen($COMMAND)",
        Some("python/aliases.py"),
        None,
    )
    .expect("structural query should succeed");
    assert_eq!(structural.results.len(), 2);
    assert_eq!(structural.results[0].text, "sp.Popen(command)");

    let job = mehscan_engine::investigation::build_investigation_job(
        &root,
        EvidenceFilter {
            kind: Some(EvidenceKind::Sink),
            capability: Some(Capability::ProcessExecution),
            language: Some(Language::Python),
            path: Some("python/aliases.py".to_string()),
        },
        Some(2),
        Some(5),
    )
    .expect("investigation job should succeed");
    assert_eq!(job.units.len(), 1, "two sinks should group by function");
    let unit = &job.units[0];
    assert_eq!(
        unit.anchor.symbol.as_ref().expect("AST anchor").name,
        "review"
    );
    assert_eq!(unit.selected_evidence_ids.len(), 2);
    assert_eq!(unit.evidence.len(), 2);
    assert_eq!(unit.imports.len(), 2);
    assert_eq!(unit.ai_guidance.len(), 3);
    assert_eq!(unit.provenance.grouping.resolution, Resolution::Ast);
    assert!(!unit.context_truncated);

    let repeated = mehscan_engine::investigation::build_investigation_job(
        &root,
        job.filter.clone(),
        Some(2),
        Some(5),
    )
    .expect("repeated job should succeed");
    assert_eq!(job, repeated, "job assembly must be deterministic");
}

#[test]
fn exposes_bounded_native_call_inventory_without_flow_claims() {
    let root = top_level_fixture_root();

    let calls = mehscan_engine::investigation::find_native_call_sites(
        &root,
        "consume",
        Some("native.cpp"),
        None,
    )
    .expect("native call inventory should succeed");
    assert_eq!(calls.results.matches.len(), 1);
    assert_eq!(calls.results.matches[0].call_kind, "bare_identifier");
    assert_eq!(calls.results.matches[0].text, "consume(packet.length)");
    assert_eq!(calls.results.matches[0].arguments[0].text, "packet.length");
    assert_eq!(
        calls.results.matches[0]
            .expression
            .as_ref()
            .expect("statement context")
            .ast_kind,
        "expression_statement"
    );
    assert!(
        calls.results.matches[0]
            .ambiguity
            .contains(&"semantic_target_not_resolved".to_string())
    );
}

#[test]
fn native_syntax_inventory_retains_local_matches_during_parse_recovery() {
    let calls = mehscan_engine::investigation::find_native_call_sites(
        &native_investigation_fixture_root(),
        "consume",
        Some("recovered.cpp"),
        None,
    )
    .expect("recovered native call inventory should succeed");
    assert_eq!(calls.results.matches.len(), 1);
    assert_eq!(
        calls.results.parse_recovered_files,
        vec!["recovered.cpp".to_string()]
    );
    assert!(calls.results.skipped_files.is_empty());
    assert!(
        calls.results.matches[0]
            .ambiguity
            .contains(&"macro_origin_unknown".to_string())
    );
}

#[test]
fn rejects_unbounded_or_out_of_root_requests() {
    let root = fixture_root();
    assert!(mehscan_engine::investigation::get_source(&root, "../planv1.md", 1, 2).is_err());
    assert!(
        mehscan_engine::investigation::find_symbol(&root, "review", None, Some(1_001)).is_err()
    );
    assert!(mehscan_engine::investigation::get_source(&root, "python/aliases.py", 0, 1).is_err());
    assert!(
        mehscan_engine::investigation::build_investigation_job(
            &root,
            EvidenceFilter::default(),
            Some(101),
            None,
        )
        .is_err()
    );
    assert!(
        mehscan_engine::investigation::build_investigation_job(
            &root,
            EvidenceFilter::default(),
            None,
            Some(101),
        )
        .is_err()
    );
    assert!(
        mehscan_engine::investigation::build_investigation_job(
            &root,
            EvidenceFilter {
                path: Some("../outside.py".to_string()),
                ..EvidenceFilter::default()
            },
            None,
            None,
        )
        .is_err()
    );
}

#[test]
fn selected_source_reads_keep_repository_ignore_rules() {
    let root = std::env::temp_dir().join(format!("mehscan-selected-source-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src/private")).unwrap();
    std::fs::write(root.join(".gitignore"), "src/private/\n").unwrap();
    std::fs::write(
        root.join("src/public.ts"),
        "export const publicValue = 1;\n",
    )
    .unwrap();
    std::fs::write(root.join("src/template.html"), "<h1>{{ value }}</h1>\n").unwrap();
    std::fs::write(
        root.join("src/private/hidden.ts"),
        "export const secret = 1;\n",
    )
    .unwrap();
    let public = mehscan_engine::investigation::get_source(&root, "src/public.ts", 1, 1)
        .expect("admitted source should be readable");
    assert_eq!(public.results.text, "export const publicValue = 1;\n");
    let template = mehscan_engine::investigation::get_source(&root, "src/template.html", 1, 1)
        .expect("explicit template source should be readable");
    assert_eq!(template.results.text, "<h1>{{ value }}</h1>\n");
    assert!(
        mehscan_engine::investigation::get_source(&root, "src/private/hidden.ts", 1, 1).is_err()
    );
    assert!(
        mehscan_engine::investigation::find_text_references(
            &root,
            "secret",
            Some("src/private/hidden.ts"),
            None,
            None,
        )
        .is_err()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn groups_top_level_related_evidence_with_textual_provenance() {
    let job = mehscan_engine::investigation::build_investigation_job(
        &top_level_fixture_root(),
        EvidenceFilter {
            kind: None,
            capability: Some(Capability::ProcessExecution),
            language: Some(Language::Javascript),
            path: Some("top_level.js".to_string()),
        },
        Some(2),
        None,
    )
    .expect("top-level job should succeed");
    assert_eq!(job.units.len(), 1);
    let unit = &job.units[0];
    assert!(unit.anchor.symbol.is_none());
    assert_eq!(unit.provenance.grouping.resolution, Resolution::Textual);
    assert_eq!(unit.selected_evidence_ids.len(), 1);
    assert_eq!(
        unit.evidence.len(),
        2,
        "the nearby outbound request should be included as related evidence"
    );
    assert_eq!(unit.capabilities.len(), 2);
}
