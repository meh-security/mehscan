use mehscan_core::Capability;
use mehscan_engine::investigation::build_review_inventory;
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str, source: &str, extension: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("mehscan-bucket-{label}-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(format!("app.{extension}")), source).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn redirect_origin_questions_do_not_override_the_comprehensive_impact_lane() {
    let fixture = Fixture::new(
        "redirect",
        "from django.shortcuts import redirect\ndef navigate(request):\n    return redirect(request.GET['next'])\n",
        "py",
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    let redirects = inventory
        .entries
        .iter()
        .filter(|entry| entry.capability == Capability::Redirect)
        .collect::<Vec<_>>();
    assert!(!redirects.is_empty(), "lost unresolved redirect research");
    assert!(redirects.iter().all(|entry| {
        entry
            .value_hint
            .as_ref()
            .is_some_and(|hint| hint.reason == "medium_impact_relationship")
    }));
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .any(|item| item.capability == Capability::Redirect
                && item
                    .tags
                    .iter()
                    .any(|tag| tag == "review-origin:decision-critical")),
        "the origin question must remain available"
    );
}

#[test]
fn fixed_padding_leaves_both_queues_without_dropping_raw_html_or_formatting() {
    let fixture = Fixture::new(
        "padding",
        r#"from django.utils.safestring import mark_safe
def padding(depth):
    return mark_safe("&nbsp;" * 4 * depth)
def raw(value):
    return mark_safe(value)
def mixed(value, depth):
    return mark_safe(("&nbsp;" + value) * depth)
def interpolated(value):
    return mark_safe(f" {value}")
def formatted(value):
    return mark_safe(" %s" % value)
def escaped_bytes(depth):
    return mark_safe("&nbsp;\x3cscript>" * depth)
"#,
        "py",
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(inventory.scan.evidence.iter().any(|item| {
        item.enclosing_symbol.as_deref() == Some("padding")
            && item
                .tags
                .iter()
                .any(|tag| tag == "html-origin:fixed-padding")
    }));
    assert!(
        !inventory
            .entries
            .iter()
            .any(|entry| entry.symbol.as_deref() == Some("padding"))
    );
    for symbol in ["raw", "mixed", "interpolated", "formatted", "escaped_bytes"] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|entry| entry.symbol.as_deref() == Some(symbol)
                    && entry.capability == Capability::HtmlOutput),
            "lost dynamic HTML {symbol}"
        );
    }
}

#[test]
fn jsx_props_are_not_browser_sinks_and_link_research_does_not_defer_unsafe_construction() {
    let fixture = Fixture::new(
        "links",
        r#"import React from 'react';
function Custom(url) { return <SafeLink href={url}/>; }
function Namespaced(url) { return <ui.SafeLink href={url}/>; }
function Ordinary(url) { return <a href={url}>link</a>; }
function Area(url) { return <area href={url}/>; }
function Resource(url) { return <base href={url}/>; }
function Constructed(value) { const url = `javascript:${value}`; return <a href={url}>link</a>; }
function Mutated(url, value) { url = `javascript:${value}`; return <a href={url}>link</a>; }
function Default(value, url = `javascript:${value}`) { return <a href={url}>link</a>; }
function Raw(value) { return <div dangerouslySetInnerHTML={{__html:value}}/>; }
function Input() { return <a href={window.location.hash}>link</a>; }
"#,
        "tsx",
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    assert!(!inventory.scan.evidence.iter().any(|item| {
        item.rule_id.ends_with("react-url-attribute-output")
            && matches!(
                item.enclosing_symbol.as_deref(),
                Some("Custom" | "Namespaced")
            )
    }));
    for symbol in ["Ordinary", "Area"] {
        let entry = inventory
            .entries
            .iter()
            .find(|entry| {
                entry.symbol.as_deref() == Some(symbol)
                    && entry.rule_id.ends_with("react-url-attribute-output")
            })
            .expect("link research retained");
        assert_eq!(
            entry.value_hint.as_ref().map(|hint| hint.reason.as_str()),
            Some("unconnected_browser_link_destination")
        );
    }
    for symbol in [
        "Resource",
        "Constructed",
        "Mutated",
        "Default",
        "Raw",
        "Input",
    ] {
        let entries = inventory
            .entries
            .iter()
            .filter(|entry| {
                entry.symbol.as_deref() == Some(symbol)
                    && entry.capability == Capability::HtmlOutput
            })
            .collect::<Vec<_>>();
        assert!(!entries.is_empty(), "lost meaningful boundary {symbol}");
        assert!(
            entries.iter().all(|entry| entry.value_hint.is_none()),
            "unexpected deferral for {symbol}"
        );
    }
}
