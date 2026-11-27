use mehscan_core::{Capability, EvidenceKind};
use std::path::PathBuf;

#[test]
fn infers_real_archive_entries_without_relabeling_cleanup_or_lookalikes() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/v2-csharp-archive-inferred");
    let inventory = mehscan_engine::investigation::build_review_inventory(&root, false).unwrap();
    let sinks = inventory
        .scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "csharp-zip-entry-extract-to-file")
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 3);
    for symbol in ["Parameter", "Open", "Construct"] {
        let sink = sinks
            .iter()
            .find(|e| e.enclosing_symbol.as_deref() == Some(symbol))
            .unwrap();
        assert_eq!(sink.kind, EvidenceKind::Sink);
        assert_eq!(sink.capability, Capability::FilesystemWrite);
        assert!(
            sink.captures["path"].text.contains("path")
                || sink.captures["path"].text.contains("Path.Combine")
        );
        assert!(
            inventory.entries.iter().any(|entry| entry
                .identity
                .as_ref()
                .is_some_and(|identity| identity.anchor_id == sink.id)),
            "extraction lost its own native identity"
        );
    }
    assert!(
        !sinks
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("Unknown"))
    );
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .any(|e| e.rule_id == "csharp-zip-entry-full-name"
                && e.enclosing_symbol.as_deref() == Some("Open"))
    );
    let cleanup = inventory
        .scan
        .evidence
        .iter()
        .find(|e| {
            e.rule_id == "csharp-filesystem-write" && e.captures.values().any(|v| v.text == "file")
        })
        .unwrap();
    assert!(
        sinks
            .iter()
            .all(|e| e.id != cleanup.id && e.location.start.line != cleanup.location.start.line)
    );
}
