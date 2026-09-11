use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-c15")
}

#[test]
fn limits_legacy_serializers_by_exact_type_and_runtime_applicability() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 7);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let legacy_sinks = result
        .evidence
        .iter()
        .filter(|item| {
            item.kind == EvidenceKind::Sink
                && item.capability == Capability::Deserialization
                && item.tags.iter().any(|tag| tag == "dangerous-object-graph")
        })
        .collect::<Vec<_>>();
    assert_eq!(legacy_sinks.len(), 7);
    let by_rule = legacy_sinks
        .iter()
        .fold(BTreeMap::new(), |mut counts, item| {
            *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(by_rule["csharp-binaryformatter-deserialization"], 3);
    assert_eq!(by_rule["csharp-soapformatter-deserialization"], 1);
    assert_eq!(
        by_rule["csharp-netdatacontractserializer-deserialization"],
        1
    );
    assert_eq!(by_rule["csharp-losformatter-deserialization"], 1);
    assert_eq!(by_rule["csharp-objectstateformatter-deserialization"], 1);
    assert!(legacy_sinks.iter().all(|item| {
        item.cwe_candidates == ["CWE-502"]
            && (item.location.path.starts_with("framework/")
                || item.location.path.starts_with("compat/")
                || item.location.path.starts_with("net8-optin/"))
    }));

    let nonexecuting = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "csharp-legacy-deserializer-nonexecuting-runtime-context")
        .collect::<Vec<_>>();
    assert_eq!(nonexecuting.len(), 3);
    assert!(nonexecuting.iter().all(|item| {
        item.kind == EvidenceKind::SecurityConfiguration
            && item.cwe_candidates.is_empty()
            && (item.location.path == "modern/NonExecuting.cs"
                || item.location.path == "net8-disabled/Disabled.cs")
            && item
                .tags
                .iter()
                .any(|tag| tag == "runtime-applicability:non-executing")
    }));

    let typed_json = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "csharp-system-text-json-typed-deserialization-context")
        .collect::<Vec<_>>();
    assert_eq!(typed_json.len(), 1);
    assert_eq!(typed_json[0].kind, EvidenceKind::Validation);
    assert!(typed_json[0].cwe_candidates.is_empty());

    // A sink remains useful evidence without manufacturing a path from an
    // ordinary method parameter that is not a recognized request boundary.
    assert_eq!(result.security_paths.len(), 6);
    assert!(result.security_paths.iter().all(|path| {
        path.capability == Capability::Deserialization
            && path.cwe_candidates == ["CWE-502"]
            && (path
                .steps
                .last()
                .unwrap()
                .location
                .path
                .starts_with("framework/")
                || path
                    .steps
                    .last()
                    .unwrap()
                    .location
                    .path
                    .starts_with("compat/")
                || path
                    .steps
                    .last()
                    .unwrap()
                    .location
                    .path
                    .starts_with("net8-optin/"))
    }));
    assert!(!result.evidence.iter().any(|item| {
        item.location.path.starts_with("shadow/")
            && item.capability == Capability::Deserialization
            && item.kind == EvidenceKind::Sink
    }));
}
