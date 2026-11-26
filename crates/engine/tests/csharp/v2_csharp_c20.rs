use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::Capability;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-c20")
}

#[test]
fn models_dynamic_xml_cookie_identity_legacy_web_and_wcf_boundaries() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("C20 fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("C20 fixture should rescan");
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    assert_eq!(result.coverage.totals.scanned, 5);
    assert_eq!(result.coverage.totals.parse_failed, 0);

    let counts = result
        .evidence
        .iter()
        .fold(BTreeMap::new(), |mut counts, item| {
            *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(counts["csharp-request-xml-type-selector"], 1);
    assert_eq!(
        counts["csharp-xmlserializer-dynamic-type-deserialization"],
        1
    );
    assert_eq!(counts["csharp-sso-cookie-identity-source"], 1);
    assert_eq!(counts["csharp-unverified-sso-cookie-token-issuance"], 1);
    assert_eq!(counts["csharp-webforms-client-script-include"], 1);
    assert_eq!(counts["csharp-webforms-request-data"], 1);
    assert_eq!(counts["csharp-webforms-request-files"], 1);
    assert_eq!(counts["csharp-webforms-upload-stream"], 1);
    assert_eq!(counts["csharp-wcf-operation-parameter-source"], 1);

    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::Deserialization && path.cwe_candidates == ["CWE-502"]
    }));
    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::Authentication && path.cwe_candidates == ["CWE-345"]
    }));
    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::ResourceAccess
            && path.steps.iter().any(|step| step.location.start.line == 93)
    }));
    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::ProcessExecution
            && path
                .steps
                .iter()
                .any(|step| step.location.path == "WcfService.cs")
    }));
    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::HtmlOutput
            && path
                .steps
                .iter()
                .any(|step| step.location.path == "LegacyWebForms.cs")
    }));
    assert!(!result.security_paths.iter().any(|path| {
        path.steps.iter().any(|step| {
            step.location.path == "DynamicTrustShapes.cs" && step.location.start.line == 102
        })
    }));

    let reviews =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), true)
            .expect("C20 review material should build");
    let sso = reviews
        .reviews
        .iter()
        .find(|review| {
            review.candidate.sink.rule_id == "csharp-unverified-sso-cookie-token-issuance"
        })
        .expect("SSO identity path should be reviewable");
    assert!(sso.open_questions.iter().any(|question| {
        question.contains("server-held integrity key") && question.contains("Base64")
    }));
}
