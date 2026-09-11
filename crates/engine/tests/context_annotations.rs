use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{AvailabilityState, Confidence, ReachabilityReason, ReachabilityState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/context")
}

#[test]
fn comments_are_preserved_but_not_emitted_as_code_evidence() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("context fixture should scan");
    let comments_file = result
        .evidence
        .iter()
        .filter(|evidence| evidence.location.path == "comments.js")
        .collect::<Vec<_>>();
    assert_eq!(
        comments_file.len(),
        1,
        "line and block comments contain two lookalikes, but only executable code is evidence"
    );
    assert_eq!(comments_file[0].location.start.line, 6);
    assert!(!comments_file[0].context.comment);
}

#[test]
fn annotates_only_syntactically_certain_unreachable_code() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("context fixture should scan");
    let by_symbol: BTreeMap<_, _> = result
        .evidence
        .iter()
        .filter(|evidence| evidence.location.path == "reachability.js")
        .map(|evidence| {
            (
                evidence
                    .enclosing_symbol
                    .as_deref()
                    .expect("named function"),
                evidence,
            )
        })
        .collect();

    for (symbol, reason) in [
        ("afterReturn", ReachabilityReason::AfterReturn),
        ("afterThrow", ReachabilityReason::AfterThrow),
        (
            "afterTerminatingIf",
            ReachabilityReason::AfterTerminatingConditional,
        ),
        ("falseBranch", ReachabilityReason::ConditionAlwaysFalse),
        ("trueAlternative", ReachabilityReason::ConditionAlwaysTrue),
        ("afterContinue", ReachabilityReason::AfterContinue),
        ("afterBreak", ReachabilityReason::AfterBreak),
    ] {
        let reachability = by_symbol[symbol]
            .context
            .reachability
            .as_ref()
            .expect("reachability context");
        assert_eq!(
            reachability.state,
            ReachabilityState::Unreachable,
            "{symbol}"
        );
        assert_eq!(reachability.reason, Some(reason), "{symbol}");
    }

    assert_eq!(
        by_symbol["afterOneBranch"]
            .context
            .reachability
            .as_ref()
            .expect("reachability context")
            .state,
        ReachabilityState::Reachable,
        "one terminating branch must not make following code unreachable"
    );

    let python = result
        .evidence
        .iter()
        .find(|evidence| evidence.location.path == "reachability.py")
        .expect("Python raise fixture");
    assert_eq!(
        python
            .context
            .reachability
            .as_ref()
            .expect("context")
            .reason,
        Some(ReachabilityReason::AfterRaise)
    );
}

#[test]
fn conditional_compilation_is_availability_not_reachability() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("context fixture should scan");
    let csharp = result
        .evidence
        .iter()
        .filter(|evidence| evidence.location.path == "Conditional.cs")
        .collect::<Vec<_>>();
    assert_eq!(csharp.len(), 3);

    let expected = [
        (AvailabilityState::Excluded, "false"),
        (AvailabilityState::Always, "true"),
        (AvailabilityState::Conditional, "DEBUG"),
    ];
    for (evidence, (state, condition)) in csharp.into_iter().zip(expected) {
        let availability = evidence
            .context
            .availability
            .as_ref()
            .expect("availability");
        assert_eq!(availability.state, state);
        assert_eq!(availability.condition.as_deref(), Some(condition));
        assert_eq!(
            evidence
                .context
                .reachability
                .as_ref()
                .expect("reachability")
                .state,
            ReachabilityState::Reachable
        );
        assert_eq!(
            evidence.confidence,
            Confidence::High,
            "context must not downgrade the underlying observation"
        );
    }
}
