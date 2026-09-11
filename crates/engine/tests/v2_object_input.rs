use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-object-input")
}

#[test]
fn reports_only_bounded_nosql_mass_assignment_and_prototype_write_shapes() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 17);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let custom = result
        .evidence
        .iter()
        .filter(|item| {
            item.provenance
                .engine
                .ends_with("bounded-node-object-input")
        })
        .collect::<Vec<_>>();
    let sinks = custom
        .iter()
        .filter(|item| item.kind == EvidenceKind::Sink)
        .collect::<Vec<_>>();
    eprintln!(
        "object-input sinks: {:#?}",
        sinks
            .iter()
            .map(|item| (
                &item.location.path,
                item.location.start.line,
                &item.cwe_candidates
            ))
            .collect::<Vec<_>>()
    );
    assert_eq!(sinks.len(), 7);
    assert!(
        sinks
            .iter()
            .all(|item| item.location.path.starts_with("positive/"))
    );
    assert_eq!(
        sinks
            .iter()
            .filter(|item| item.cwe_candidates == ["CWE-943"])
            .count(),
        2
    );
    assert_eq!(
        sinks
            .iter()
            .filter(|item| item.cwe_candidates == ["CWE-915"])
            .count(),
        3
    );
    assert_eq!(
        sinks
            .iter()
            .filter(|item| item.cwe_candidates == ["CWE-1321"])
            .count(),
        2
    );

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            matches!(
                path.cwe_candidates.as_slice(),
                [cwe] if matches!(cwe.as_str(), "CWE-943" | "CWE-915" | "CWE-1321")
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 7);
    assert!(
        paths
            .iter()
            .all(|path| path.state == SecurityPathState::Unknown)
    );
    assert!(paths.iter().all(|path| {
        path.uncertainty_reasons
            .iter()
            .any(|reason| reason == "node_object_input_relationship_is_syntactic")
    }));
    assert!(paths.iter().any(|path| {
        path.capability == Capability::DatabaseQuery && path.cwe_candidates == ["CWE-943"]
    }));
    assert!(paths.iter().any(|path| {
        path.capability == Capability::ResourceAccess && path.cwe_candidates == ["CWE-915"]
    }));
    assert!(paths.iter().any(|path| {
        path.capability == Capability::ResourceAccess && path.cwe_candidates == ["CWE-1321"]
    }));

    let generated = sinks
        .iter()
        .find(|item| item.location.path == "positive/generated-mass.ts")
        .expect("generated user resource should be bounded");
    assert!(
        generated
            .tags
            .iter()
            .any(|tag| tag == "route:POST /api/Users")
    );
    assert!(
        generated
            .tags
            .iter()
            .any(|tag| tag == "sensitive-fields:isActive,role")
    );
}

#[test]
#[ignore = "requires the optional local Juice Shop corpus"]
fn juice_shop_object_input_targets_are_exact() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("juice-shop");
    let result = mehscan_engine::scan_path(root).expect("Juice Shop should scan");

    let custom = result
        .evidence
        .iter()
        .filter(|item| {
            item.provenance
                .engine
                .ends_with("bounded-node-object-input")
        })
        .collect::<Vec<_>>();
    let sinks = custom
        .iter()
        .filter(|item| item.kind == EvidenceKind::Sink)
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 8, "{sinks:#?}");
    assert_eq!(
        sinks
            .iter()
            .filter(|item| item.cwe_candidates == ["CWE-943"])
            .count(),
        7
    );
    assert_eq!(
        sinks
            .iter()
            .filter(|item| item.cwe_candidates == ["CWE-915"])
            .count(),
        1
    );
    assert!(sinks.iter().all(|item| item.cwe_candidates != ["CWE-1321"]));

    let expected = [
        ("routes/showProductReviews.ts", 36, "CWE-943"),
        ("routes/trackOrder.ts", 18, "CWE-943"),
        ("routes/updateProductReviews.ts", 17, "CWE-943"),
        ("routes/likeProductReviews.ts", 25, "CWE-943"),
        ("routes/likeProductReviews.ts", 35, "CWE-943"),
        ("routes/likeProductReviews.ts", 43, "CWE-943"),
        ("routes/likeProductReviews.ts", 50, "CWE-943"),
        ("server.ts", 501, "CWE-915"),
    ];
    for (path, line, cwe) in expected {
        assert!(
            sinks.iter().any(|item| {
                item.location.path == path
                    && item.location.start.line == line
                    && item.cwe_candidates == [cwe]
            }),
            "missing {cwe} at {path}:{line}"
        );
    }

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            matches!(
                path.cwe_candidates.as_slice(),
                [cwe] if matches!(cwe.as_str(), "CWE-943" | "CWE-915" | "CWE-1321")
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 8, "{paths:#?}");
    assert!(
        paths
            .iter()
            .all(|path| path.state == SecurityPathState::Unknown)
    );
}
