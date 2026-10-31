use std::path::PathBuf;

#[test]
fn workspace_and_tsconfig_helpers_are_evidence_without_safe_name_inference() {
    use std::fs;
    let root =
        std::env::temp_dir().join(format!("mehscan-frontend-workspace-{}", std::process::id()));
    fs::create_dir_all(root.join("packages/output")).unwrap();
    fs::write(
        root.join("package.json"),
        r#"{"private":true,"workspaces":["packages/*"]}"#,
    )
    .unwrap();
    fs::write(
        root.join("tsconfig.json"),
        r#"{"compilerOptions":{"baseUrl":".","paths":{"@local/*":["packages/output/*"]}}}"#,
    )
    .unwrap();
    fs::write(
        root.join("packages/output/package.json"),
        r#"{"name":"@workspace/output","exports":{"./clean":"./clean.ts"}}"#,
    )
    .unwrap();
    fs::write(root.join("packages/output/clean.ts"), "import sanitize from 'sanitize-html'; export function clean(html:string){ return sanitize(html); } export function supposedlySafe(html:string){ return html; }").unwrap();
    fs::write(root.join("Views.tsx"), "import React from 'react'; import {clean} from '@workspace/output/clean'; import {supposedlySafe} from '@local/clean'; export function Good({html}:any){return <div dangerouslySetInnerHTML={{__html:clean(html)}}/>;} export function Bad({html}:any){return <div dangerouslySetInnerHTML={{__html:supposedlySafe(html)}}/>;}").unwrap();
    fs::create_dir_all(root.join("apps/web")).unwrap();
    fs::write(
        root.join("apps/web/tsconfig.json"),
        r#"{"extends":"@uninstalled/config/base.json"}"#,
    )
    .unwrap();
    fs::write(root.join("apps/web/WorkspaceView.tsx"), "import React from 'react'; import {clean} from '@workspace/output/clean'; export function WorkspaceView({html}:any){return <div dangerouslySetInnerHTML={{__html:clean(html)}}/>;}").unwrap();
    let jobs =
        mehscan_engine::investigation::build_path_review_jobs(&root, Some(3), Some(100)).unwrap();
    for (symbol, body) in [
        ("Good", "return sanitize(html)"),
        ("Bad", "return html"),
        ("WorkspaceView", "return sanitize(html)"),
    ] {
        let review = jobs
            .observation_reviews
            .iter()
            .find(|r| {
                r.evidence.iter().any(|e| {
                    e.enclosing_symbol.as_deref() == Some(symbol)
                        && e.capability == mehscan_core::Capability::HtmlOutput
                })
            })
            .unwrap();
        assert!(
            review
                .facts
                .iter()
                .any(|f| f.role == "frontend_imported_helper_context"
                    && f.location.path == "packages/output/clean.ts"
                    && f.excerpt.contains(body)),
            "missing actual helper for {symbol}"
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn dependency_reuse_controls_preserve_distinct_transformations_and_decoded_callers() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/frontend-dependency-reuse");
    let jobs =
        mehscan_engine::investigation::build_path_review_jobs(&root, Some(3), Some(100)).unwrap();
    assert_eq!(jobs.observation_reviews.len(), 5);
    for (line, transformation) in [
        (3, "cleaner.sanitize(html)"),
        (5, "cleaner.sanitize(html, STRICT)"),
        (7, "cleaner.sanitize(html) + html"),
        (9, "decodeURIComponent(cleaner.sanitize(html))"),
        (11, "=> html"),
    ] {
        let review = jobs
            .observation_reviews
            .iter()
            .find(|r| {
                r.evidence
                    .iter()
                    .any(|e| e.location.path == "Views.tsx" && e.location.start.line == line)
            })
            .unwrap();
        assert!(review.facts.iter().any(|f| {
            f.role == "frontend_imported_helper_context" && f.excerpt.contains(transformation)
        }));
        assert!(review.facts.iter().any(|f| {
            f.role == "frontend_prop_producer_context"
                && f.location.path == "Source.tsx"
                && f.excerpt.contains("URLSearchParams")
                && f.excerpt.contains(".get('html')")
        }));
        if line == 5 {
            assert!(
                review
                    .facts
                    .iter()
                    .any(|f| f.excerpt.contains("ALLOWED_TAGS"))
            );
        }
    }
}

#[test]
fn imported_frontend_callables_include_options_instance_hooks_and_actual_imports() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/frontend-imported-helpers");
    let jobs =
        mehscan_engine::investigation::build_path_review_jobs(&root, Some(3), Some(100)).unwrap();
    for (path, line) in [("Page.tsx", 5), ("Rich.vue", 6)] {
        let review = jobs
            .observation_reviews
            .iter()
            .find(|r| {
                r.evidence
                    .iter()
                    .any(|e| e.location.path == path && e.location.start.line == line)
            })
            .unwrap();
        for text in [
            "clean = (html",
            "OPTIONS =",
            "cleaner =",
            "addHook",
            "ATTRS =",
            "from 'dompurify'",
        ] {
            assert!(
                review
                    .facts
                    .iter()
                    .any(|f| f.role.starts_with("frontend_") && f.excerpt.contains(text)),
                "{path}: missing {text}"
            );
        }
        let additions: Vec<_> = review
            .facts
            .iter()
            .filter(|f| {
                f.role.starts_with("frontend_helper_")
                    || f.role == "frontend_imported_helper_context"
            })
            .collect();
        assert!(additions.iter().map(|f| f.excerpt.len()).sum::<usize>() <= 4096);
    }
    for fact in jobs
        .observation_reviews
        .iter()
        .flat_map(|r| &r.facts)
        .filter(|f| f.role.starts_with("frontend_"))
    {
        let source = std::fs::read_to_string(root.join(&fact.location.path)).unwrap();
        assert_eq!(
            &source[fact.location.start.byte_offset..fact.location.end.byte_offset],
            fact.excerpt
        );
    }
}

#[test]
fn names_do_not_prove_sanitization_and_shadowed_imports_are_not_followed() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/frontend-imported-helpers");
    let jobs =
        mehscan_engine::investigation::build_path_review_jobs(&root, Some(3), Some(100)).unwrap();
    let at = |line| {
        jobs.observation_reviews
            .iter()
            .find(|r| {
                r.evidence
                    .iter()
                    .any(|e| e.location.path == "Page.tsx" && e.location.start.line == line)
            })
            .unwrap()
    };
    for line in [5, 8] {
        assert!(at(line).facts.iter().any(|f| {
            f.role == "frontend_prop_caller_context"
                && f.location.path == "Source.tsx"
                && f.excerpt.contains("html={payload}")
        }));
        assert!(at(line).facts.iter().any(|f| {
            f.role == "frontend_prop_producer_context"
                && f.location.path == "Source.tsx"
                && f.excerpt.contains("URLSearchParams")
                && f.excerpt.contains(".get('html')")
        }));
    }
    assert!(
        at(8)
            .facts
            .iter()
            .any(|f| f.role == "frontend_imported_helper_context" && f.excerpt.contains("=> html"))
    );
    assert!(
        at(10)
            .facts
            .iter()
            .any(|f| f.role == "frontend_imported_helper_context"
                && f.excerpt.contains("DOMPurify.sanitize"))
    );
    assert!(
        !at(12)
            .facts
            .iter()
            .any(|f| f.role == "frontend_imported_helper_context")
    );
    let controls: Vec<_> = jobs
        .observation_reviews
        .iter()
        .filter(|r| r.evidence.iter().any(|e| e.location.path == "Controls.tsx"))
        .collect();
    assert_eq!(controls.len(), 3);
    assert!(controls.iter().all(|r| {
        !r.facts
            .iter()
            .any(|f| f.role == "frontend_imported_helper_context")
    }));
    assert!(
        controls
            .iter()
            .find(|r| r.evidence.iter().any(|e| e.location.start.line == 5))
            .unwrap()
            .context_truncated
    );
}
