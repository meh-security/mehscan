use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState, SecurityPathStepKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-redirect-precision")
}

#[test]
fn models_controller_dtos_and_preserves_proven_local_redirect_context() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    let model_sources = result
        .evidence
        .iter()
        .filter(|item| {
            item.rule_id == "csharp-aspnet-controller-parameter-source"
                && item.tags.iter().any(|tag| tag == "from_model")
        })
        .count();
    assert_eq!(model_sources, 5);

    let controls = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::RedirectDestinationValidation)
        .collect::<Vec<_>>();
    assert!(
        controls
            .iter()
            .any(|item| item.rule_id == "csharp-local-url-generation")
    );
    assert!(
        controls
            .iter()
            .any(|item| item.rule_id == "csharp-local-redirect-helper-summary")
    );

    let paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::Redirect)
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 7);
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        4
    );
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Unknown)
            .count(),
        3
    );
    assert!(paths.iter().any(|path| {
        path.state == SecurityPathState::Unknown
            && path
                .steps
                .last()
                .is_some_and(|step| step.location.start.line == 13)
            && path.steps.iter().any(|step| {
                step.kind == SecurityPathStepKind::IneffectiveProtection
                    && step
                        .symbol
                        .as_deref()
                        .is_some_and(|symbol| symbol.contains("does not constrain redirect"))
            })
    }));
    assert!(paths.iter().any(|path| {
        path.state == SecurityPathState::Unknown
            && path
                .steps
                .last()
                .is_some_and(|step| step.location.start.line == 45)
    }));
}
