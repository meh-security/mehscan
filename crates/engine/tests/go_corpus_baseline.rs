use std::path::{Path, PathBuf};

use mehscan_core::{ScanResult, SecurityPathState};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn assert_path_count(result: &ScanResult, state: SecurityPathState, cwe: &str, expected: usize) {
    let actual = result
        .security_paths
        .iter()
        .filter(|path| path.state == state && path.cwe_candidates == [cwe])
        .count();
    assert_eq!(actual, expected, "unexpected {state:?} {cwe} path count");
}

fn scan(root: &Path, relative: &str) -> ScanResult {
    let corpus = root.join(relative);
    assert!(
        corpus.is_dir(),
        "optional corpus is missing: {}",
        corpus.display()
    );
    mehscan_engine::scan_path(corpus).expect("optional Go corpus should scan")
}

#[test]
#[ignore = "requires the optional local GoVWA, Not Going Anywhere, and vuLnDAP corpora"]
fn optional_go_g7_cross_corpus_baselines_match_when_requested() {
    let root = workspace_root();

    let govwa = scan(&root, "apps/govwa");
    assert_eq!(govwa.coverage.totals.discovered, 71);
    assert_eq!(govwa.coverage.totals.scanned, 23);
    assert_eq!(govwa.coverage.totals.ignored, 48);
    assert_eq!(govwa.coverage.totals.parse_failed, 0);
    assert_eq!(govwa.evidence.len(), 112);
    assert_eq!(govwa.security_paths.len(), 11);
    assert_path_count(&govwa, SecurityPathState::Unknown, "CWE-639", 4);
    assert_path_count(&govwa, SecurityPathState::Unknown, "CWE-89", 2);
    assert_path_count(&govwa, SecurityPathState::Unknown, "CWE-352", 2);
    assert_path_count(&govwa, SecurityPathState::Unknown, "CWE-79", 2);
    assert_path_count(&govwa, SecurityPathState::Direct, "CWE-916", 1);

    let not_going_anywhere = scan(&root, "apps/not-going-anywhere");
    assert_eq!(not_going_anywhere.coverage.totals.discovered, 51);
    assert_eq!(not_going_anywhere.coverage.totals.scanned, 14);
    assert_eq!(not_going_anywhere.coverage.totals.ignored, 37);
    assert_eq!(not_going_anywhere.coverage.totals.parse_failed, 0);
    assert_eq!(not_going_anywhere.evidence.len(), 91);
    assert_eq!(not_going_anywhere.security_paths.len(), 14);
    assert_path_count(
        &not_going_anywhere,
        SecurityPathState::Protected,
        "CWE-89",
        3,
    );
    assert_path_count(
        &not_going_anywhere,
        SecurityPathState::Propagated,
        "CWE-89",
        3,
    );
    assert_path_count(&not_going_anywhere, SecurityPathState::Direct, "CWE-89", 2);
    assert_path_count(&not_going_anywhere, SecurityPathState::Unknown, "CWE-89", 1);
    assert_path_count(
        &not_going_anywhere,
        SecurityPathState::Unknown,
        "CWE-601",
        3,
    );
    assert_path_count(
        &not_going_anywhere,
        SecurityPathState::Propagated,
        "CWE-79",
        1,
    );
    assert_path_count(
        &not_going_anywhere,
        SecurityPathState::Unknown,
        "CWE-639",
        1,
    );

    let vulndap = scan(&root, "apps/vuLnDAP");
    assert_eq!(vulndap.coverage.totals.discovered, 18);
    assert_eq!(vulndap.coverage.totals.scanned, 5);
    assert_eq!(vulndap.coverage.totals.ignored, 13);
    assert_eq!(vulndap.coverage.totals.parse_failed, 0);
    assert_eq!(vulndap.evidence.len(), 74);
    assert_eq!(vulndap.security_paths.len(), 17);
    assert_path_count(&vulndap, SecurityPathState::Unknown, "CWE-79", 14);
    assert_path_count(&vulndap, SecurityPathState::Unknown, "CWE-90", 2);
    assert_path_count(&vulndap, SecurityPathState::Protected, "CWE-90", 1);

    let heading_paths = vulndap
        .security_paths
        .iter()
        .filter(|path| {
            path.steps.last().is_some_and(|sink| {
                sink.location.path == "web_server.go" && sink.location.start.line == 145
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        heading_paths.len(),
        1,
        "the request cn is shadowed before the line 145 heading; only LDAP-derived cn may reach it"
    );
    let heading_source = vulndap
        .evidence
        .iter()
        .find(|item| item.id == heading_paths[0].source_evidence_id)
        .expect("the retained line 145 path should reference its LDAP source evidence");
    assert_eq!(heading_source.rule_id, "go-ldap-result-value-source");
}
