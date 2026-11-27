use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::Capability;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-node-mongo-dao")
}

#[test]
fn bounds_legacy_commonjs_mongo_dao_roles() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 4);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            matches!(
                path.cwe_candidates.as_slice(),
                [cwe] if matches!(cwe.as_str(), "CWE-639" | "CWE-916" | "CWE-943")
            )
        })
        .collect::<Vec<_>>();
    let counts = paths.iter().fold(BTreeMap::new(), |mut counts, path| {
        *counts
            .entry(path.cwe_candidates[0].as_str())
            .or_insert(0usize) += 1;
        counts
    });
    assert_eq!(counts.get("CWE-639"), Some(&2));
    assert_eq!(counts.get("CWE-916"), Some(&1));
    assert_eq!(counts.get("CWE-943"), Some(&1));
    assert!(paths.iter().all(|path| {
        path.steps
            .iter()
            .all(|step| step.location.path.starts_with("positive/"))
            && path
                .uncertainty_reasons
                .iter()
                .any(|reason| reason == "node_parameter_sink_summary_is_syntactic")
    }));
    assert!(paths.iter().any(|path| {
        path.capability == Capability::DatabaseQuery && path.cwe_candidates == ["CWE-943"]
    }));
    assert!(paths.iter().any(|path| {
        path.capability == Capability::CryptographicHash && path.cwe_candidates == ["CWE-916"]
    }));

    let reviews =
        mehscan_engine::investigation::build_path_review_jobs(&fixture_root(), Some(6), Some(100))
            .expect("review jobs should build");
    let password = reviews
        .reviews
        .iter()
        .find(|review| review.candidate.cwe_candidates == ["CWE-916"])
        .expect("password review");
    assert!(password.open_questions.iter().any(|question| {
        question.contains("password KDF") && question.contains("commented example")
    }));
    assert!(password.facts.iter().any(|fact| {
        fact.role == "helper_definition_context"
            && fact.location.path == "positive/dao.js"
            && fact.excerpt.contains("users.insert")
    }));
    let nosql = reviews
        .reviews
        .iter()
        .find(|review| review.candidate.cwe_candidates == ["CWE-943"])
        .expect("NoSQL review");
    assert!(
        nosql
            .open_questions
            .iter()
            .any(|question| question.contains("MongoDB $where"))
    );
}
