use mehscan_core::SecurityPathState;
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str, source: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("mehscan-url-limits-{name}-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("app.php"), source).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn component_parsing_keeps_native_identity_and_never_proves_destination_safety() {
    let fixture = Fixture::new(
        "identity",
        r#"<?php
function whole($v) { return parse_url($v); }
function component($v) { return parse_url($v, PHP_URL_SCHEME); }
function qualified($v) { return \parse_url($v, PHP_URL_HOST); }
function custom($v) { return Custom\parse_url($v, PHP_URL_SCHEME); }
function named($v) { return parse_url(url: $v, component: PHP_URL_SCHEME); }
function unpacked($v) { return parse_url(...$v); }
function extra($v) { return parse_url($v, PHP_URL_SCHEME, true); }
function destination() { $v = $_GET['url']; parse_url($v, PHP_URL_SCHEME); return file_get_contents($v); }
"#,
    );
    fs::write(fixture.0.join("custom.php"), "<?php namespace Local; function parse_url($v, $c) { return $v; } function shadow($v) { return parse_url($v, PHP_URL_SCHEME); }").unwrap();
    fs::write(fixture.0.join("alias.php"), "<?php namespace App; use function parse_url as parts; function alias($v) { return parts($v, PHP_URL_HOST); }").unwrap();
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let parsers = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "php-url-parsing")
        .collect::<Vec<_>>();
    for symbol in ["whole", "component", "qualified", "alias", "destination"] {
        let evidence = parsers
            .iter()
            .find(|e| e.enclosing_symbol.as_deref() == Some(symbol))
            .expect(symbol);
        assert!(evidence.captures.contains_key("value"));
        if symbol != "whole" {
            assert!(evidence.captures.contains_key("component"));
        }
    }
    for symbol in ["custom", "named", "unpacked", "extra", "shadow"] {
        assert!(
            !parsers
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some(symbol)),
            "{symbol}"
        );
    }
    assert_eq!(parsers.len(), 5);
    assert!(
        scan.security_paths
            .iter()
            .any(|path| path.capability == mehscan_core::Capability::OutboundNetworkRequest),
        "The request-selected outbound path must exist"
    );
    for path in &scan.security_paths {
        assert_ne!(
            path.state,
            SecurityPathState::Protected,
            "Parsing is not authorization"
        );
    }
}
