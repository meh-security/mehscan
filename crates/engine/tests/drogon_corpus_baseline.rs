use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState};

fn corpus_root() -> PathBuf {
    std::env::var_os("MEHSCAN_DROGON_CORPUS").map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../mehscan-internal/corpus-cache/apps/c-cpp/orgchartapi")
        },
        PathBuf::from,
    )
}

#[test]
#[ignore = "requires the optional pinned orgChartApi Drogon corpus"]
fn optional_drogon_corpus_keeps_authentication_and_ownership_separate() {
    let root = corpus_root();
    assert!(
        root.is_dir(),
        "optional Drogon corpus is missing: {}",
        root.display()
    );
    let result = mehscan_engine::scan_path(&root).expect("Drogon corpus should scan");
    let repeated = mehscan_engine::scan_path(&root).expect("Drogon corpus should rescan");
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    assert_eq!(result.coverage.totals.scanned, 22);
    assert_eq!(result.coverage.totals.parse_failed, 5);
    assert_eq!(result.evidence.len(), 79);
    assert_eq!(result.security_paths.len(), 26);

    let count = |cwe: &str, state: SecurityPathState| {
        result
            .security_paths
            .iter()
            .filter(|path| path.cwe_candidates == [cwe] && path.state == state)
            .count()
    };
    assert_eq!(count("CWE-306", SecurityPathState::Protected), 10);
    assert_eq!(count("CWE-306", SecurityPathState::Unknown), 5);
    assert_eq!(count("CWE-639", SecurityPathState::Propagated), 5);
    assert_eq!(count("CWE-639", SecurityPathState::Unknown), 6);
    assert!(
        result
            .security_paths
            .iter()
            .filter(|path| {
                path.capability == Capability::ResourceAccess && path.cwe_candidates == ["CWE-639"]
            })
            .all(|path| path.protection_evidence_ids.is_empty())
    );

    let mut unknown_authentication = result
        .security_paths
        .iter()
        .filter(|path| {
            path.cwe_candidates == ["CWE-306"] && path.state == SecurityPathState::Unknown
        })
        .map(|path| {
            let sink = result
                .evidence
                .iter()
                .find(|item| item.id == path.sink_evidence_id)
                .expect("path sink evidence");
            (sink.location.path.as_str(), sink.location.start.line)
        })
        .collect::<Vec<_>>();
    unknown_authentication.sort_unstable();
    assert_eq!(
        unknown_authentication,
        [
            ("controllers/DepartmentsController.h", 13),
            ("controllers/PersonsController.h", 15),
            ("controllers/PersonsController.h", 17),
            ("controllers/PersonsController.h", 18),
            ("controllers/PersonsController.h", 19),
        ]
    );

    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(100), true)
        .expect("Drogon corpus review jobs");
    let repeated_reviews =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(100), true)
            .expect("Drogon corpus repeated review jobs");
    assert_eq!(reviews, repeated_reviews);
    assert_eq!(reviews.reviews.len(), 26);
    assert!(reviews.reviews.iter().any(|review| {
        review.candidate.cwe_candidates == ["CWE-639"]
            && review.open_questions.iter().any(|question| {
                question.contains("Token verification establishes identity")
                    && question.contains("not resource authorization")
            })
    }));
}
