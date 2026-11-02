use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use mehscan_core::{AvailabilityState, Capability};

#[test]
fn source_configuration_is_retained_without_assuming_manifest_defaults_or_host_target() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-rust-configuration-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("Cargo.toml"), "[package]\nname='configuration'\nversion='0.1.0'\n[features]\ndefault=['server']\nserver=[]\n").unwrap();
    fs::write(
        root.join("lib.rs"),
        r#"
        #[cfg(feature = "server")]
        #[cfg(unix)]
        fn configured(cmd: &str) { std::process::Command::new(cmd).status(); }
        fn ordinary(cmd: &str) { std::process::Command::new(cmd).status(); }
        #[cfg(any())]
        fn excluded(cmd: &str) { std::process::Command::new(cmd).status(); }
        mod fixture {
            #![cfg(test)]
            fn test_only(cmd: &str) { std::process::Command::new(cmd).status(); }
        }
    "#,
    )
    .unwrap();
    let result = mehscan_engine::scan_path(&root).expect("scan configured source");
    let sinks = result
        .evidence
        .iter()
        .filter(|e| e.capability == Capability::ProcessExecution)
        .collect::<Vec<_>>();
    let configured = sinks
        .iter()
        .find(|e| e.enclosing_symbol.as_deref() == Some("configured"))
        .expect("conditional source remains visible");
    let availability = configured.context.availability.as_ref().unwrap();
    assert_eq!(availability.state, AvailabilityState::Conditional);
    let condition = availability.condition.as_deref().unwrap();
    assert!(
        condition.contains("server") && condition.contains("unix"),
        "{condition}"
    );
    let ordinary = sinks
        .iter()
        .find(|e| e.enclosing_symbol.as_deref() == Some("ordinary"))
        .unwrap();
    assert_eq!(
        ordinary.context.availability.as_ref().unwrap().state,
        AvailabilityState::Always
    );
    assert!(
        !sinks
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("test_only"))
    );
    assert!(
        sinks
            .iter()
            .filter(|e| e.enclosing_symbol.as_deref() == Some("excluded"))
            .all(|e| e.context.availability.as_ref().unwrap().state == AvailabilityState::Excluded)
    );
    fs::remove_dir_all(root).unwrap();
}
