use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState, SecurityPathStepKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-aspnet-ingress")
}

#[test]
fn inventories_aspnet_bound_parameters_and_builds_bounded_paths() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 2);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let sources = result
        .evidence
        .iter()
        .filter(|item| {
            matches!(
                item.rule_id.as_str(),
                "csharp-aspnet-controller-parameter-source"
                    | "csharp-aspnet-minimal-parameter-source"
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(sources.len(), 14);
    assert!(sources.iter().all(|item| {
        item.kind == EvidenceKind::Source && item.capability == Capability::HttpRequestData
    }));

    let positive_sources = sources
        .iter()
        .copied()
        .filter(|item| item.location.path == "positive/AspNetIngress.cs")
        .collect::<Vec<_>>();
    assert_eq!(positive_sources.len(), 11);
    let by_binding = positive_sources
        .iter()
        .fold(BTreeMap::new(), |mut counts, item| {
            let binding = [
                "from_query",
                "from_route",
                "from_body",
                "from_form",
                "from_header",
            ]
            .into_iter()
            .find(|binding| item.tags.iter().any(|tag| tag == binding))
            .expect("source should identify its binding");
            *counts.entry(binding).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(by_binding["from_query"], 3);
    assert_eq!(by_binding["from_route"], 2);
    assert_eq!(by_binding["from_body"], 2);
    assert_eq!(by_binding["from_form"], 2);
    assert_eq!(by_binding["from_header"], 2);

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.uncertainty_reasons
                .iter()
                .any(|reason| reason == "aspnet_parameter_binding_is_syntactic")
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 12);
    let positive_paths = paths
        .iter()
        .copied()
        .filter(|path| {
            path.steps
                .first()
                .is_some_and(|step| step.location.path == "positive/AspNetIngress.cs")
        })
        .collect::<Vec<_>>();
    assert_eq!(positive_paths.len(), 11);
    assert!(positive_paths.iter().all(|path| {
        matches!(
            path.state,
            SecurityPathState::Propagated | SecurityPathState::Protected
        ) && path.steps.first().is_some_and(|step| {
            step.kind == SecurityPathStepKind::Source
                && step.location.path == "positive/AspNetIngress.cs"
        }) && path.steps.iter().any(|step| {
            step.kind
                == if path.state == SecurityPathState::Protected {
                    SecurityPathStepKind::Protection
                } else {
                    SecurityPathStepKind::Alias
                }
        }) && path
            .steps
            .last()
            .is_some_and(|step| step.kind == SecurityPathStepKind::Sink)
    }));
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        1
    );

    let negative_sources = sources
        .iter()
        .filter(|item| item.location.path == "negative/SafeControls.cs")
        .collect::<Vec<_>>();
    assert_eq!(negative_sources.len(), 3);
    assert_eq!(
        negative_sources
            .iter()
            .map(|source| source.location.start.line)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([9, 37, 45])
    );
    let conventional_path = paths
        .iter()
        .find(|path| {
            path.steps.first().is_some_and(|step| {
                step.location.path == "negative/SafeControls.cs" && step.location.start.line == 9
            }) && path
                .steps
                .last()
                .is_some_and(|step| step.location.start.line == 11)
        })
        .expect("public conventional controller action should bind its simple parameter");
    assert_eq!(conventional_path.state, SecurityPathState::Propagated);
    assert!(paths.iter().all(|path| {
        !path.steps.first().is_some_and(|step| {
            step.location.path == "negative/SafeControls.cs"
                && matches!(step.location.start.line, 37 | 45)
        })
    }));
}
