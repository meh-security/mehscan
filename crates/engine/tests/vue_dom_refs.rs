use mehscan_core::{Capability, EvidenceKind};
use std::path::PathBuf;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/vue-dom-ref-review")
}

#[test]
fn vue_ref_packets_include_the_actual_operand_control_import_and_native_binding() {
    let root = fixture();
    let jobs =
        mehscan_engine::investigation::build_path_review_jobs(&root, Some(3), Some(50)).unwrap();
    let review = jobs
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence.iter().any(|e| {
                e.location.path == "Controlled.vue"
                    && e.kind == EvidenceKind::Sink
                    && e.capability == Capability::HtmlOutput
            })
        })
        .expect("controlled DOM operation must have a review");
    for role in [
        "frontend_dom_ref_template_context",
        "frontend_dom_ref_declaration_context",
        "frontend_output_producer_context",
        "frontend_import_binding_context",
    ] {
        assert!(
            review.facts.iter().any(|f| f.role == role),
            "missing {role}"
        );
    }
    assert!(review.facts.iter().any(
        |f| f.role == "frontend_output_producer_context" && f.excerpt.contains("ALLOWED_TAGS")
    ));
    assert!(review.facts.iter().any(|f|f.role=="frontend_import_binding_context" && f.excerpt.contains("dompurify")));
    for fact in review
        .facts
        .iter()
        .filter(|f| f.role.starts_with("frontend_"))
    {
        let source = std::fs::read_to_string(root.join(&fact.location.path)).unwrap();
        assert_eq!(
            &source[fact.location.start.byte_offset..fact.location.end.byte_offset],
            fact.excerpt
        );
    }
}

#[test]
fn vue_native_refs_locate_dynamic_effects_and_exclude_unowned_or_static_writes() {
    let root = fixture();
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.scanned, 6, "{:?}", scan.diagnostics);
    let sinks: Vec<_> = scan
        .evidence
        .iter()
        .filter(|e| e.kind == EvidenceKind::Sink && e.capability == Capability::HtmlOutput)
        .collect();
    assert_eq!(
        sinks
            .iter()
            .filter(|e| e.location.path == "Refs.vue")
            .count(),
        4
    );
    assert_eq!(
        sinks
            .iter()
            .filter(|e| e.location.path == "Shadow.vue")
            .count(),
        1
    );
    assert_eq!(
        sinks
            .iter()
            .filter(|e| e.location.path == "Controlled.vue")
            .count(),
        1
    );
    assert_eq!(sinks.len(), 6);
    for e in sinks {
        assert!(e.tags.iter().any(|t| t == "vue-dom-ref"));
        assert!(e.captures.contains_key("vue_dom_ref_template"));
        assert!(e.captures.contains_key("vue_dom_ref_declaration"));
        let source = std::fs::read_to_string(root.join(&e.location.path)).unwrap();
        for capture in e.captures.values() {
            assert_eq!(
                &source[capture.location.start.byte_offset..capture.location.end.byte_offset],
                capture.text
            );
        }
    }
}
