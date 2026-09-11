use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState, SecurityPathStepKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-object-property-flow")
}

#[test]
fn follows_only_recognized_evaluator_and_request_property_through_vm_context() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 6);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.capability == Capability::DynamicCodeExecution && path.cwe_candidates == ["CWE-94"]
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 3);
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Propagated)
            .count(),
        2
    );
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Unknown)
            .count(),
        1
    );
    let uncertain = paths
        .iter()
        .find(|path| path.state == SecurityPathState::Unknown)
        .expect("control-flow path should be retained as unknown");
    assert!(
        uncertain
            .uncertainty_reasons
            .iter()
            .any(|reason| reason == "control_flow_context_not_modeled")
    );
    assert!(
        uncertain
            .uncertainty_reasons
            .iter()
            .any(|reason| reason == "embedded_program_resolution_is_syntactic")
    );
    assert!(result.evidence.iter().any(|item| {
        item.location.path == "positive/object-flow.ts"
            && item.enclosing_symbol.as_deref() == Some("evaluateOrder")
            && item
                .provenance
                .engine
                .ends_with("bounded-express-type-boundary")
    }));
    assert!(paths.iter().all(|path| {
        path.steps
            .iter()
            .any(|step| step.symbol.as_deref() == Some("sandbox.orderData"))
            && path
                .steps
                .iter()
                .any(|step| step.symbol.as_deref() == Some("safeEval(orderData)"))
            && path.steps.first().is_some_and(|step| {
                step.kind == SecurityPathStepKind::Source
                    && step.location.path.starts_with("positive/")
            })
            && path.steps.last().is_some_and(|step| {
                step.kind == SecurityPathStepKind::Sink
                    && step.location.path.starts_with("positive/")
            })
    }));
    assert!(paths.iter().all(|path| {
        path.steps
            .iter()
            .all(|step| !step.location.path.starts_with("negative/"))
    }));
}
