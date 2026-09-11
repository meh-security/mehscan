use std::path::PathBuf;

use mehscan_core::Capability;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/v2-rust-r8")
}

#[test]
fn inventories_exact_rust_protection_and_configuration_shapes() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("Rust R8 fixture should scan");
    assert_eq!(result.coverage.totals.scanned, 2);
    assert_eq!(result.coverage.totals.parse_failed, 0);

    for (capability, expected) in [
        (Capability::ProcessArgumentSeparation, 2),
        (Capability::UrlParsing, 1),
        (Capability::UrlDestinationValidation, 2),
        (Capability::PathCanonicalization, 2),
        (Capability::PathContainmentCheck, 1),
        (Capability::TlsConfiguration, 2),
    ] {
        assert_eq!(
            result
                .evidence
                .iter()
                .filter(|item| item.capability == capability)
                .count(),
            expected,
            "unexpected {capability:?} inventory"
        );
    }

    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| {
                item.location.path.ends_with("negative/lookalikes.rs")
                    && matches!(
                        item.capability,
                        Capability::ProcessArgumentSeparation
                            | Capability::UrlParsing
                            | Capability::TlsConfiguration
                    )
            })
            .count(),
        0,
        "same-name lookalikes must not become framework evidence"
    );
}
