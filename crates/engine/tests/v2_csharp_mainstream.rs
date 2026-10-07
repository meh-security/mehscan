use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-mainstream")
}

#[test]
fn covers_mainstream_csharp_sinks_and_keeps_safe_siblings_out_of_paths() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 2);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let rules = result
        .evidence
        .iter()
        .filter(|item| {
            item.kind == EvidenceKind::Sink
                && item
                    .provenance
                    .engine
                    .starts_with("mehscan csharp-mainstream-summary")
        })
        .fold(BTreeMap::new(), |mut counts, item| {
            *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
            counts
        });

    for rule in [
        "csharp-jsonnet-typename-deserialization",
        "csharp-xmlreader-external-entity",
        "csharp-powershell-addscript",
        "csharp-filestream-read",
        "csharp-filestream-write",
        "csharp-file-copy-source",
        "csharp-file-copy-destination",
        "csharp-file-move-source",
        "csharp-file-move-destination",
    ] {
        assert_eq!(rules[rule], 1, "unexpected count for {rule}");
    }
    assert_eq!(rules["csharp-process-start-info"], 2);
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| {
                item.kind == EvidenceKind::Sink
                    && item.rule_id == "csharp-zip-entry-extract-to-file"
                    && item.provenance.engine == "mehscan bounded-csharp-archive 1"
            })
            .count(),
        1
    );

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.steps
                .last()
                .is_some_and(|step| step.location.path == "positive/Mainstream.cs")
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 11);
    assert!(paths.iter().all(|path| {
        path.state == SecurityPathState::Propagated
            && path
                .uncertainty_reasons
                .iter()
                .any(|reason| reason == "aspnet_parameter_binding_is_syntactic")
    }));
    assert!(!result.security_paths.iter().any(|path| {
        path.steps
            .iter()
            .any(|step| step.location.path == "negative/SafeAndLookalike.cs")
    }));
    for rule in [
        "csharp-filesystem-write",
        "csharp-outbound-http",
        "csharp-hash-algorithm-selection",
    ] {
        assert!(!result.evidence.iter().any(|item| {
            item.location.path == "negative/SafeAndLookalike.cs"
                && item.enclosing_symbol.as_deref() == Some("LocalFactory")
                && item.rule_id == rule
        }));
    }

    let capabilities = paths.iter().fold(BTreeMap::new(), |mut counts, path| {
        *counts.entry(path.capability).or_insert(0usize) += 1;
        counts
    });
    assert_eq!(capabilities[&Capability::Deserialization], 1);
    assert_eq!(capabilities[&Capability::XmlParsing], 1);
    assert_eq!(capabilities[&Capability::DynamicCodeExecution], 1);
    assert_eq!(capabilities[&Capability::ProcessExecution], 1);
    assert_eq!(capabilities[&Capability::FilesystemRead], 3);
    assert_eq!(capabilities[&Capability::FilesystemWrite], 4);
}

#[test]
fn binds_named_filesystem_arguments_and_deduplicates_copy_paths() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/csharp-filesystem-operands");
    let scan = mehscan_engine::scan_path(root).unwrap();
    let capture = |method: &str, rule: &str, role: &str| {
        scan.evidence
            .iter()
            .find(|e| e.enclosing_symbol.as_deref() == Some(method) && e.rule_id == rule)
            .unwrap()
            .captures[role]
            .text
            .as_str()
    };
    assert_eq!(
        capture("NamedCopy", "csharp-filesystem-read", "path"),
        "Console.ReadLine()"
    );
    assert_eq!(
        capture("NamedCopy", "csharp-file-copy-source", "path"),
        "Console.ReadLine()"
    );
    assert_eq!(
        capture("NamedCopy", "csharp-file-copy-destination", "path"),
        "\"known.txt\""
    );
    assert_eq!(
        capture("NamedMove", "csharp-file-move-source", "path"),
        "\"known.txt\""
    );
    assert_eq!(
        capture("NamedMove", "csharp-file-move-destination", "path"),
        "Console.ReadLine()"
    );
    assert_eq!(
        capture("NamedDirectoryMove", "csharp-filesystem-write", "path"),
        "Console.ReadLine()"
    );
    assert_eq!(
        capture("NamedDirectoryMove", "csharp-filesystem-write", "source"),
        "\"known\""
    );
    assert_eq!(
        capture("NamedStream", "csharp-filestream-write", "path"),
        "Console.ReadLine()"
    );
    let source = scan
        .evidence
        .iter()
        .find(|e| {
            e.enclosing_symbol.as_deref() == Some("NamedCopy")
                && e.rule_id == "csharp-file-copy-source"
        })
        .unwrap();
    assert_eq!(
        scan.security_paths
            .iter()
            .filter(|p| p.sink_evidence_id == source.id)
            .count(),
        1
    );
    assert!(!scan.security_paths.iter().any(|p| {
        scan.evidence.iter().any(|e| {
            e.id == p.sink_evidence_id
                && e.enclosing_symbol.as_deref() == Some("NamedCopy")
                && e.rule_id == "csharp-filesystem-read"
        })
    }));
}
