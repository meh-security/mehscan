use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{
    AvailabilityState, Capability, Confidence, EvidenceKind, LiteralState, LiteralValue,
    ReachabilityState,
};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/web-surfaces")
}

#[test]
fn enumerates_web_output_redirect_and_upload_surfaces() {
    let result =
        mehscan_engine::scan_path(fixture_root()).expect("web surface fixture should scan");

    assert_eq!(result.schema_version, "2.1");
    assert_eq!(result.coverage.totals.scanned, 14);
    assert_eq!(result.evidence.len(), 21);
    assert!(
        result
            .evidence
            .iter()
            .all(|evidence| evidence.location.path.starts_with("positive/"))
    );

    let counts = result
        .evidence
        .iter()
        .fold(BTreeMap::new(), |mut counts, evidence| {
            *counts.entry(evidence.capability).or_insert(0) += 1;
            counts
        });
    assert_eq!(counts[&Capability::HtmlOutput], 7);
    assert_eq!(counts[&Capability::Redirect], 7);
    assert_eq!(counts[&Capability::FileUpload], 7);

    for evidence in &result.evidence {
        assert_eq!(evidence.confidence, Confidence::High);
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
            evidence
                .context
                .availability
                .as_ref()
                .expect("availability")
                .state,
            AvailabilityState::Always
        );
        match evidence.capability {
            Capability::HtmlOutput => {
                assert_eq!(evidence.kind, EvidenceKind::Sink);
                let content = evidence
                    .context
                    .literals
                    .get("content")
                    .expect("content capture");
                assert_eq!(content.state, LiteralState::Unknown);
                assert_eq!(content.references, ["html"]);
            }
            Capability::Redirect => {
                assert_eq!(evidence.kind, EvidenceKind::Sink);
                let location = evidence
                    .context
                    .literals
                    .get("location")
                    .expect("location capture");
                assert_eq!(location.state, LiteralState::Unknown);
                assert_eq!(location.references, ["location"]);
            }
            Capability::FileUpload => {
                assert_eq!(evidence.kind, EvidenceKind::Source);
                if let Some(field) = evidence.context.literals.get("field") {
                    assert_eq!(field.state, LiteralState::Known);
                    assert_eq!(
                        field.value,
                        Some(LiteralValue::String("upload".to_string()))
                    );
                }
            }
            capability => panic!("unexpected capability: {capability:?}"),
        }
    }
}

#[test]
fn exposes_three_new_web_cwe_families_for_every_language() {
    let result =
        mehscan_engine::scan_path(fixture_root()).expect("web surface fixture should scan");
    let coverage: BTreeMap<_, _> = result
        .coverage
        .cwe
        .iter()
        .map(|item| (item.cwe.as_str(), item))
        .collect();
    assert_eq!(coverage["CWE-79"].supported_languages.len(), 9);
    assert_eq!(coverage["CWE-601"].supported_languages.len(), 8);
    assert_eq!(coverage["CWE-434"].supported_languages.len(), 7);
}
