use std::path::PathBuf;

#[test]
fn sibling_and_cross_method_bindings_do_not_prove_framework_receivers() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/specialized-identity-scope");
    let result = mehscan_engine::scan_path(root).expect("identity scope fixture should scan");

    assert_eq!(result.coverage.totals.scanned, 4);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert!(
        result.evidence.is_empty(),
        "out-of-scope framework bindings created evidence: {:#?}",
        result.evidence
    );
    assert!(result.security_paths.is_empty());
}

#[test]
fn remaining_specialized_analyzers_reject_out_of_scope_receiver_bindings() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/specialized-identity-remaining");
    let result = mehscan_engine::scan_path(root).expect("remaining identity fixture should scan");

    assert_eq!(result.coverage.totals.scanned, 6);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let forbidden = [
        "java-spring-multipart-transfer-to-filesystem",
        "java-spring-multipart-file-storage",
        "java-jsp-writer-html-output",
        "java-insecure-security-randomness",
        "csharp-security-token-weak-randomness",
        "csharp-xmldocument-external-resolver",
        "csharp-jsonnet-typename-deserialization",
        "csharp-streamed-upload-file-copy",
    ];
    let leaked = result
        .evidence
        .iter()
        .filter(|item| forbidden.contains(&item.rule_id.as_str()))
        .collect::<Vec<_>>();
    assert!(
        leaked.is_empty(),
        "out-of-scope bindings created specialized evidence: {leaked:#?}"
    );
}
