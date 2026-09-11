use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, RuntimeEnvironment};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-typescript-express")
}

#[test]
fn resolves_typed_express_request_aliases_and_destructuring_without_name_lookalikes() {
    let result =
        mehscan_engine::scan_path(fixture_root()).expect("Express type fixture should scan");
    assert_eq!(result.coverage.totals.scanned, 7);
    assert_eq!(result.coverage.totals.parse_failed, 0);

    let typed = result
        .evidence
        .iter()
        .filter(|item| {
            item.provenance
                .engine
                .ends_with("bounded-express-type-boundary")
        })
        .collect::<Vec<_>>();
    assert!(!typed.is_empty());
    assert!(typed.iter().all(|item| {
        item.location.path.starts_with("positive/")
            && item.context.runtime_environment == Some(RuntimeEnvironment::Server)
            && item
                .symbol_resolution
                .as_ref()
                .is_some_and(|resolution| resolution.canonical == "express.Request")
    }));

    let sources_by_symbol = typed.iter().fold(BTreeMap::new(), |mut counts, item| {
        *counts
            .entry(item.enclosing_symbol.as_deref().unwrap_or("<none>"))
            .or_insert(0usize) += 1;
        counts
    });
    assert_eq!(sources_by_symbol["renamed"], 1);
    assert_eq!(sources_by_symbol["parameterDestructure"], 3);
    assert_eq!(sources_by_symbol["localDestructure"], 2);
    assert_eq!(sources_by_symbol["uploaded"], 1);
    assert_eq!(sources_by_symbol["ExpressionPreview"], 1);
    assert_eq!(sources_by_symbol["contextual"], 1);

    let upload = typed
        .iter()
        .find(|item| item.enclosing_symbol.as_deref() == Some("uploaded"))
        .expect("renamed typed upload source");
    assert_eq!(upload.capability, Capability::UploadedFileContent);

    let dynamic_paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::DynamicCodeExecution)
        .collect::<Vec<_>>();
    assert_eq!(dynamic_paths.len(), 8);
    assert!(dynamic_paths.iter().all(|path| {
        path.steps
            .first()
            .is_some_and(|step| step.location.path.starts_with("positive/"))
            && path
                .steps
                .last()
                .is_some_and(|step| step.location.path.starts_with("positive/"))
    }));
}
