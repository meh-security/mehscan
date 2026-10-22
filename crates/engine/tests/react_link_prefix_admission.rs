use mehscan_core::Capability;
use mehscan_engine::investigation::build_review_inventory;
use std::fs;

#[test]
fn native_link_prefixes_close_only_the_selected_xss_operand() {
    let root =
        std::env::temp_dir().join(format!("mehscan-react-link-prefix-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let cases = [
        ("mail", "`mailto:${value}`", true),
        ("tel", "'tel:' + value", true),
        ("https", "`https://${value}/path`", true),
        ("fragment", "`#${value}`", true),
        (
            "branches",
            "choice ? `mailto:${value}` : `https://${value}`",
            true,
        ),
        ("whole", "value", false),
        ("suffix", "value + '/safe'", false),
        ("mixed", "choice ? `mailto:${value}` : value", false),
        ("javascript", "`javascript:${value}`", false),
        ("data", "`data:text/html,${value}`", false),
        ("encoded", "decodeURIComponent(value)", false),
    ];
    for (name, expression, _) in cases {
        fs::write(root.join(format!("{name}.tsx")), format!("import React from 'react'; export function View({{value,choice}}:any){{return <a href={{{expression}}}>link</a>;}}")).unwrap();
    }
    fs::write(root.join("alias.tsx"), "import React from 'react'; export function View({value}:any){const url=`mailto:${value}`;return <a href={url}>link</a>;}").unwrap();
    fs::write(root.join("mutated.tsx"), "import React from 'react'; export function View({value}:any){let url=`mailto:${value}`;url=value;return <a href={url}>link</a>;}").unwrap();
    fs::write(root.join("raw.tsx"), "import React from 'react'; export function View({value}:any){return <div dangerouslySetInnerHTML={{__html:`<a href=\"mailto:${value}\">link</a>`}}/>;}").unwrap();
    fs::write(root.join("resource.tsx"), "import React from 'react'; export function View({value}:any){return <svg><use href={`https://${value}`}/></svg>;}").unwrap();
    fs::write(root.join("spread.tsx"), "import React from 'react'; export function View({value,props}:any){return <a href={`mailto:${value}`} {...props}>link</a>;}").unwrap();
    fs::write(root.join("custom.tsx"), "/** @jsx custom */ import React from 'react'; export function View({value}:any){return <a href={`mailto:${value}`}>link</a>;}").unwrap();
    let inventory = build_review_inventory(&root, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    for (name, _, closed) in cases.into_iter().chain([
        ("alias", "", true),
        ("mutated", "", false),
        ("raw", "", false),
        ("resource", "", false),
        ("spread", "", false),
        ("custom", "", false),
    ]) {
        let path = format!("{name}.tsx");
        let sinks = inventory
            .scan
            .evidence
            .iter()
            .filter(|e| e.location.path == path && e.capability == Capability::HtmlOutput)
            .collect::<Vec<_>>();
        assert!(!sinks.is_empty(), "missing evidence: {path}");
        assert_eq!(
            sinks.iter().any(|e| e
                .tags
                .iter()
                .any(|t| t == "html-url:non-executable-link-prefix")),
            closed,
            "wrong fact: {path}"
        );
        if closed {
            assert!(
                !inventory
                    .entries
                    .iter()
                    .any(|e| e.path == path && e.capability == Capability::HtmlOutput),
                "wrong admission: {path}"
            );
        } else if matches!(name, "javascript" | "data" | "raw" | "resource") {
            assert!(
                inventory
                    .entries
                    .iter()
                    .any(|e| e.path == path && e.capability == Capability::HtmlOutput),
                "lost dangerous/contextual output: {path}"
            );
        }
    }
    fs::remove_dir_all(root).unwrap();
}
