use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState, SymbolConfidence};

#[test]
#[ignore = "requires the optional local OrchardCore corpus"]
fn optional_orchardcore_c23_baseline_matches_when_requested() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("apps/OrchardCore");
    assert!(
        root.join("src/OrchardCore.Cms.Web/OrchardCore.Cms.Web.csproj")
            .is_file()
    );

    let result = mehscan_engine::scan_path(root).expect("OrchardCore should scan");
    assert_eq!(result.coverage.totals.scanned, 7_145);
    assert_eq!(result.coverage.totals.parse_failed, 2);
    assert_eq!(result.evidence.len(), 1_718);
    assert_eq!(result.security_paths.len(), 6);

    assert_eq!(
        result
            .security_paths
            .iter()
            .filter(|path| {
                path.capability == Capability::Redirect
                    && path.state == SecurityPathState::Protected
            })
            .count(),
        5
    );
    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::BrowserNavigation
            && path.state == SecurityPathState::Propagated
            && path.steps.last().is_some_and(|step| {
                step.location.path
                    == "src/OrchardCore.Modules/OrchardCore.OpenApi/Assets/openapi-ui-auth/src/openapi-ui-auth.ts"
                    && step.location.start.line == 298
            })
            && path
                .uncertainty_reasons
                .iter()
                .any(|reason| reason == "browser_storage_writer_origin_unverified")
    }));
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "csharp-identity-role-assignment-review")
            .count(),
        1
    );
    assert!(result.security_paths.iter().all(|path| {
        result
            .evidence
            .iter()
            .find(|item| item.id == path.sink_evidence_id)
            .is_none_or(|sink| sink.rule_id != "csharp-request-controlled-role-assignment")
    }));
    assert!(result.evidence.iter().all(|item| {
        item.symbol_resolution
            .as_ref()
            .is_none_or(|resolution| resolution.confidence != SymbolConfidence::Ambiguous)
    }));
    assert!(result.evidence.iter().all(|item| {
        item.location.path
            != "src/OrchardCore.Modules/OrchardCore.Workflows/Controllers/ActivityController.cs"
            || item.location.start.line != 77
            || ![
                "csharp-filesystem-write",
                "csharp-outbound-http",
                "csharp-hash-algorithm-selection",
            ]
            .contains(&item.rule_id.as_str())
    }));
}
