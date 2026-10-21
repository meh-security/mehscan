use mehscan_core::{Capability, EvidenceKind};
use mehscan_engine::investigation::build_review_inventory;

#[test]
fn a_fixed_browser_prefix_does_not_close_an_expression_that_returns_another_destination() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-navigation-literals-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("environment.js"),
        "export const environment = {hostServer:'.'};",
    )
    .unwrap();
    for extension in ["js", "ts", "tsx"] {
        std::fs::write(
            root.join(format!("navigation.{extension}")),
            r#"
import {environment as appEnvironment} from './environment.js';
export function expression(destination) {
  window.location.replace(appEnvironment.hostServer + '/inside' && destination || '/fallback');
}
export function fixed() {
  window.location.replace(appEnvironment.hostServer + '/profile');
}
"#,
        )
        .unwrap();
    }
    let inventory = build_review_inventory(&root, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    for extension in ["js", "ts", "tsx"] {
        let path = format!("navigation.{extension}");
        assert!(
            inventory.entries.iter().any(|e| e.path == path
                && e.symbol.as_deref() == Some("expression")
                && e.capability == Capability::BrowserNavigation),
            "dynamic expression excluded as a fixed destination in {path}"
        );
        assert!(
            inventory
                .scan
                .evidence
                .iter()
                .any(|e| e.location.path == path
                    && e.enclosing_symbol.as_deref() == Some("fixed")
                    && e.kind == EvidenceKind::Sink
                    && e.capability == Capability::BrowserNavigation)
        );
        assert!(
            !inventory.entries.iter().any(|e| e.path == path
                && e.symbol.as_deref() == Some("fixed")
                && e.capability == Capability::BrowserNavigation),
            "actual fixed navigation regressed in {path}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn code_relative_paths_require_a_literal_leaf_not_expressions_between_quotes() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-filesystem-literals-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("paths.py"),
        r#"
import os
def concatenated(key):
    base = os.path.dirname(__file__)
    target = os.path.join(base, 'pre' + key + 'post')
    return open(target).read()
def conditional(key, allowed):
    base = os.path.dirname(__file__)
    target = os.path.join(base, 'first' if allowed else key + 'tail')
    return open(target).read()
def written(key, content):
    base = os.path.dirname(__file__)
    target = os.path.join(base, 'pre' + key + 'post')
    return open(target, 'w').write(content)
def fixed():
    base = os.path.dirname(__file__)
    target = os.path.join(base, 'payload.txt')
    return open(target).read()
def escaped():
    base = os.path.dirname(__file__)
    target = os.path.join(base, 'can\'t.txt')
    return open(target).read()
def dollars():
    base = os.path.dirname(__file__)
    target = os.path.join(base, "$literal.txt")
    return open(target).read()
"#,
    )
    .unwrap();
    let inventory = build_review_inventory(&root, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    let filesystem = |capability| {
        matches!(
            capability,
            Capability::FilesystemRead | Capability::FilesystemWrite
        )
    };
    for name in ["concatenated", "conditional", "written"] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some(name) && filesystem(e.capability)),
            "dynamic path excluded: {name}"
        );
    }
    for name in ["fixed", "escaped", "dollars"] {
        assert!(
            inventory
                .scan
                .evidence
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some(name)
                    && e.kind == EvidenceKind::Sink
                    && filesystem(e.capability)),
            "missing raw fixed-path effect: {name}"
        );
        assert!(
            !inventory
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some(name) && filesystem(e.capability)),
            "fixed-path exclusion regressed: {name}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
