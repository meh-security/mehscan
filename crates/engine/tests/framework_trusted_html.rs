use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::Capability;

#[test]
fn inventories_explicit_framework_html_trust_boundaries() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/framework-trusted-html");
    let result = mehscan_engine::scan_path(root).expect("trusted HTML fixture should scan");

    let sinks = result
        .evidence
        .iter()
        .filter(|item| {
            item.capability == Capability::HtmlOutput
                && item.location.path == "positive.tsx"
                && item
                    .tags
                    .iter()
                    .any(|tag| tag == "review-origin:decision-critical")
        })
        .collect::<Vec<_>>();
    let rules = sinks
        .iter()
        .map(|item| item.rule_id.as_str())
        .collect::<BTreeSet<_>>();
    for expected in [
        "tsx-angular-html-trust-bypass",
        "tsx-lit-unsafe-html-output",
        "tsx-vue-inner-html-output",
        "tsx-solid-inner-html-output",
        "tsx-react-dangerous-html-output",
        "tsx-browser-dom-html-output",
        "tsx-jquery-html-output",
    ] {
        assert!(rules.contains(expected), "missing {expected}: {rules:#?}");
    }
    assert!(
        sinks
            .iter()
            .all(|item| item.captures.contains_key("content"))
    );
    assert_eq!(
        sinks
            .iter()
            .filter(|item| item.rule_id == "tsx-solid-inner-html-output")
            .count(),
        1,
        "custom-component props are not intrinsic DOM innerHTML sinks"
    );
    assert_eq!(
        sinks
            .iter()
            .filter(|item| item.rule_id == "tsx-jquery-html-output")
            .count(),
        2,
        "jQuery receiver ownership follows the latest same-scope assignment"
    );
    assert!(result.evidence.iter().all(|item| {
        item.location.path != "lookalikes.tsx"
            || !matches!(
                item.rule_id.as_str(),
                "tsx-lit-unsafe-html-output"
                    | "tsx-vue-inner-html-output"
                    | "tsx-solid-inner-html-output"
                    | "tsx-jquery-html-output"
                    | "tsx-angular-html-trust-bypass"
            )
    }));
    assert!(sinks.iter().any(|item| {
        item.rule_id == "tsx-browser-dom-html-output"
            && item
                .tags
                .iter()
                .any(|tag| tag == "html-boundary:dom-insertion")
            && item
                .tags
                .iter()
                .any(|tag| tag == "browser-interpretation:html-markup")
    }));
}

#[test]
fn requires_exact_python_trusted_markup_ownership() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-python-trusted-markup-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("owned.py"),
        "from django.utils.safestring import mark_safe as trust\nfrom markupsafe import Markup as SafeMarkup\ndef render(content):\n    trust(content)\n    return SafeMarkup(content)\n",
    )
    .unwrap();
    std::fs::write(
        root.join("lookalike.py"),
        "def mark_safe(value):\n    return value\ndef render(content):\n    return mark_safe(content)\n",
    )
    .unwrap();

    let result = mehscan_engine::scan_path(&root).expect("trusted markup fixture should scan");
    let sinks = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "python-trusted-markup-bypass")
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 2, "only import-owned helpers should match");
    assert!(sinks.iter().all(|item| {
        item.location.path == "owned.py"
            && item
                .tags
                .iter()
                .any(|tag| tag == "review-origin:decision-critical")
            && item
                .tags
                .iter()
                .any(|tag| tag == "html-boundary:trusted-markup")
    }));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn treats_interpolated_trusted_markup_as_dynamic() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-interpolated-trusted-markup-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("view.ts"),
        "import { DomSanitizer } from '@angular/platform-browser';\nclass View { constructor(private sanitizer: DomSanitizer) {} render(user: any) { return this.sanitizer.bypassSecurityTrustHtml(`<small>${user.name}</small>`); } }\n",
    )
    .unwrap();

    let result = mehscan_engine::scan_path(&root).expect("interpolation fixture should scan");
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "typescript-angular-html-trust-bypass"
            && item
                .tags
                .iter()
                .any(|tag| tag == "review-origin:decision-critical")
    }));

    std::fs::remove_dir_all(root).unwrap();
}
