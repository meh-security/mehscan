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

    let symbols = mehscan_engine::investigation::find_symbol(&root, "review", None)
        .expect("symbol lookup should succeed");
    assert!(symbols.results.len() >= 5);

    let imports = mehscan_engine::investigation::find_imports(&root, "subprocess", None)
        .expect("import lookup should succeed");
    assert_eq!(imports.results.len(), 2);
    assert!(imports.results.iter().all(|item| item.is_import));

    let references = mehscan_engine::investigation::find_text_references(&root, "launch", None)
        .expect("reference lookup should succeed");
    assert_eq!(references.provenance.resolution, Resolution::Textual);
    assert_eq!(references.results.len(), 2);

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
fn rejects_unbounded_or_out_of_root_requests() {
    let root = fixture_root();
    assert!(mehscan_engine::investigation::get_source(&root, "../planv1.md", 1, 2).is_err());
    assert!(mehscan_engine::investigation::find_symbol(&root, "review", Some(1_001)).is_err());
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
