use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-python-p3c")
}

#[test]
fn distinguishes_django_output_contexts_and_summarizes_one_unique_helper() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let template_sinks = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "python-django-template-unsafe-output")
        .collect::<Vec<_>>();
    assert_eq!(template_sinks.len(), 2);
    assert!(
        template_sinks
            .iter()
            .any(|item| item.captures["template_expression"].text.ends_with(":safe"))
    );
    assert!(template_sinks.iter().any(|item| {
        item.captures["template_expression"]
            .text
            .ends_with(":javascript-context")
    }));
    assert!(
        !template_sinks
            .iter()
            .any(|item| item.captures["template"].text == "escaped.html")
    );

    let helper_summaries = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "python-file-local-parameter-sink-summary")
        .collect::<Vec<_>>();
    assert_eq!(helper_summaries.len(), 1);
    assert_eq!(helper_summaries[0].location.path, "views.py");
    assert_eq!(helper_summaries[0].captures["helper"].text, "command_out");

    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::ProcessExecution
            && path
                .steps
                .first()
                .is_some_and(|step| step.location.path == "views.py")
    }));
    assert_eq!(
        result
            .security_paths
            .iter()
            .filter(|path| path.capability == Capability::HtmlOutput)
            .count(),
        4
    );
    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::HtmlOutput && path.state == SecurityPathState::Protected
    }));
}
