use std::path::PathBuf;

use mehscan_core::{
    Evidence, LiteralEvaluation, LiteralState, LiteralValue, ReachabilityReason, ReachabilityState,
};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/literals")
}

fn evidence<'a>(items: &'a [Evidence], path: &str, capture_text: &str) -> &'a Evidence {
    items
        .iter()
        .find(|evidence| {
            evidence.location.path == path
                && evidence
                    .captures
                    .values()
                    .any(|capture| capture.text == capture_text)
        })
        .unwrap_or_else(|| panic!("missing evidence for {path}: {capture_text}"))
}

fn literal<'a>(evidence: &'a Evidence, capture: &str) -> &'a LiteralEvaluation {
    evidence
        .context
        .literals
        .get(capture)
        .unwrap_or_else(|| panic!("missing literal context for {capture}"))
}

#[test]
fn annotates_capture_literals_across_supported_languages() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("literal fixture should scan");

    for (path, text) in [
        ("Literals.cs", "Command"),
        ("Literals.java", "command"),
        ("literals.go", "command"),
        ("literals.js", "COMMAND"),
        ("literals.py", "\"safe/\" + \"tool\""),
        ("literals.ts", "`safe/${TOOL}`"),
        ("literals.tsx", "`safe/${TOOL}`"),
    ] {
        let evaluation = literal(evidence(&result.evidence, path, text), "command");
        assert_eq!(evaluation.state, LiteralState::Known, "{path}: {text}");
        assert_eq!(
            evaluation.value,
            Some(LiteralValue::String("safe/tool".to_string())),
            "{path}: {text}"
        );
    }

    assert_eq!(
        literal(
            evidence(&result.evidence, "Literals.cs", "ToolMode.Safe"),
            "command"
        )
        .value,
        Some(LiteralValue::Enum("ToolMode.Safe".to_string()))
    );

    for (text, value) in [
        ("true", LiteralValue::Boolean(true)),
        ("7", LiteralValue::Number("7".to_string())),
        ("-7", LiteralValue::Number("-7".to_string())),
        ("null", LiteralValue::Null),
    ] {
        assert_eq!(
            literal(evidence(&result.evidence, "literals.js", text), "code").value,
            Some(value),
            "{text}"
        );
    }
}

#[test]
fn preserves_partial_and_unknown_values_and_reuses_known_boole() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("literal fixture should scan");

    let partial = literal(
        evidence(
            &result.evidence,
            "literals.js",
            "`prefix/${dynamicCommand}/suffix`",
        ),
        "command",
    );
    assert_eq!(partial.state, LiteralState::Partial);
    assert_eq!(partial.constant_fragments, ["prefix/", "/suffix"]);
    assert_eq!(partial.references, ["dynamicCommand"]);
    assert!(partial.value.is_none());

    let unknown = literal(
        evidence(&result.evidence, "literals.js", "dynamicCommand"),
        "command",
    );
    assert_eq!(unknown.state, LiteralState::Unknown);
    assert_eq!(unknown.references, ["dynamicCommand"]);
    assert!(unknown.value.is_none());

    let dead = evidence(&result.evidence, "literals.js", "\"dead\"");
    let reachability = dead
        .context
        .reachability
        .as_ref()
        .expect("reachability context");
    assert_eq!(reachability.state, ReachabilityState::Unreachable);
    assert_eq!(
        reachability.reason,
        Some(ReachabilityReason::ConditionAlwaysFalse)
    );
}
