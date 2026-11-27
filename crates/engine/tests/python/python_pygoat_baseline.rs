use std::path::PathBuf;

use mehscan_core::Capability;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn pygoat_introduction_root() -> PathBuf {
    std::env::var_os("MEHSCAN_PYGOAT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("apps/python/pygoat/introduction"))
}

#[test]
#[ignore = "requires the optional local PyGoat corpus"]
fn optional_python_p5_pygoat_baseline_matches_when_requested() {
    let corpus = pygoat_introduction_root();
    assert!(
        corpus.is_dir(),
        "optional corpus is missing: {}",
        corpus.display()
    );

    let result = mehscan_engine::scan_path(&corpus).expect("PyGoat should scan");
    assert_eq!(result.coverage.totals.discovered, 181);
    assert_eq!(result.coverage.totals.scanned, 25);
    assert_eq!(result.coverage.totals.ignored, 156);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence.len(), 329);
    assert_eq!(result.security_paths.len(), 16);
    assert_eq!(
        result
            .security_paths
            .iter()
            .filter(|path| path.capability == Capability::DynamicCodeExecution)
            .count(),
        2
    );
    assert_eq!(
        result
            .security_paths
            .iter()
            .filter(|path| {
                path.capability == Capability::FilesystemWrite
                    && path.cwe_candidates.iter().any(|cwe| cwe == "CWE-94")
            })
            .count(),
        3
    );
    assert_eq!(
        result
            .security_paths
            .iter()
            .filter(|path| path.capability == Capability::Deserialization)
            .count(),
        2
    );
    assert_eq!(
        result
            .security_paths
            .iter()
            .filter(|path| path.capability == Capability::ProcessExecution)
            .count(),
        2
    );
    assert_eq!(
        result
            .security_paths
            .iter()
            .filter(|path| path.capability == Capability::HtmlOutput)
            .count(),
        4
    );
    assert!(
        result
            .security_paths
            .iter()
            .any(|path| path.capability == Capability::XmlParsing)
    );
    assert!(!result.security_paths.iter().any(|path| {
        path.capability == Capability::ResourceAccess
            && path.cwe_candidates.iter().any(|cwe| cwe == "CWE-639")
    }));

    let reviews =
        mehscan_engine::investigation::build_all_path_review_jobs(&corpus, Some(8), false)
            .expect("PyGoat review admission should build");
    assert_eq!(reviews.reviews.len(), 16);
    assert_eq!(reviews.observation_reviews.len(), 12);
    assert_eq!(reviews.total_reviews, 28);
    let csrf_reviews = reviews
        .observation_reviews
        .iter()
        .filter(|review| {
            review.evidence.iter().any(|evidence| {
                review.anchor_evidence_ids.contains(&evidence.id)
                    && evidence.rule_id == "python-django-csrf-exempt-handler"
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(csrf_reviews.len(), 6);
    assert!(csrf_reviews.iter().all(|review| {
        review
            .facts
            .iter()
            .any(|fact| fact.role == "python_csrf_handler_context")
    }));
    assert!(reviews.observation_reviews.iter().all(|review| {
        review.evidence.iter().all(|evidence| {
            evidence.capability != Capability::ProcessExecution
                && evidence.capability != Capability::Redirect
                && evidence.location.path != "playground/A6/soln.py"
        })
    }));
}
