use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use mehscan_core::{Capability, HttpRouteAccess};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-go-g2-breadth")
}

#[test]
fn adds_httprouter_sql_helper_and_cookie_policy_context() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    assert_eq!(result.security_paths.len(), 3);
    assert_eq!(
        result
            .security_paths
            .iter()
            .filter(|path| path.cwe_candidates == ["CWE-639"])
            .count(),
        2
    );
    assert!(
        result
            .evidence
            .iter()
            .any(|item| item.rule_id == "go-cookie-helper-source")
    );

    let unsafe_query = result
        .evidence
        .iter()
        .find(|item| item.rule_id == "go-sql-parameter-query-summary")
        .expect("unsafe helper should become a caller-side sink");
    assert_eq!(unsafe_query.capability, Capability::DatabaseQuery);
    assert!(unsafe_query.context.http_routes.iter().any(|route| {
        route.method == "GET"
            && route.path == "/unsafe"
            && route.access == HttpRouteAccess::Unknown
            && !route.guards.is_empty()
    }));

    let safe = result
        .evidence
        .iter()
        .find(|item| item.rule_id == "go-sql-parameterization-summary-control")
        .expect("prepared helper should remain a caller-side control");
    assert_eq!(safe.capability, Capability::SqlParameterization);
    assert!(
        safe.context
            .http_routes
            .iter()
            .any(|route| route.path == "/safe")
    );

    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "go-cookie-security-policy-review")
            .count(),
        2
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "go-cookie-security-policy-control")
            .count(),
        1
    );

    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), false)
            .expect("Go SQL reviews should build");
    let parameterized = jobs
        .observation_reviews
        .iter()
        .find(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id == "go-dynamic-sql-prepare")
        })
        .expect("parameterized SQL observation");
    assert!(parameterized.decision_facts.unresolved.is_empty());
    assert_eq!(parameterized.decision_facts.effective_controls.len(), 1);
}

#[test]
fn unix_exec_is_not_reported_as_a_database_query() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-go-unix-exec-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create Go unix.Exec fixture");
    fs::write(
        root.join("main.go"),
        r#"package main

import "golang.org/x/sys/unix"

func replaceProcess(executable string, arguments []string, environment []string) error {
    return unix.Exec(executable, arguments, environment)
}
"#,
    )
    .expect("write Go unix.Exec fixture");

    let result = mehscan_engine::scan_path(&root).expect("scan Go unix.Exec fixture");
    assert!(result.evidence.iter().all(|item| {
        !matches!(
            item.rule_id.as_str(),
            "go-database-query"
                | "go-sql-parameterization"
                | "go-sql-parameter-query-summary"
                | "go-sql-parameterization-summary-control"
        )
    }));
    fs::remove_dir_all(&root).expect("remove Go unix.Exec fixture");
}

#[test]
fn keeps_discarded_repository_reads_as_context_and_prefers_the_exact_sql_sink() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-go-discarded-repository-read-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create Go repository fixture");
    fs::write(
        root.join("app.go"),
        r#"package app
import (
    "fmt"
    "net/http"
)
func findUser(name string) { db.Query(fmt.Sprintf("SELECT * FROM users WHERE name='%s'", name)) }
func userService(name string) { findUser(name) }
func handler(w http.ResponseWriter, r *http.Request) { userService(r.URL.Query().Get("name")) }
"#,
    )
    .expect("write Go repository fixture");

    let scan = mehscan_engine::scan_path(&root).expect("scan Go repository fixture");
    assert!(
        scan.evidence
            .iter()
            .any(|item| item.rule_id == "go-sql-parameter-query-summary")
    );
    assert!(
        scan.evidence
            .iter()
            .any(|item| item.rule_id == "go-sql-resource-filter-summary")
    );

    let jobs = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(8), false)
        .expect("build Go reviews");
    assert_eq!(
        jobs.observation_reviews
            .iter()
            .filter(|review| review.evidence.iter().any(|item| {
                item.capability == Capability::DatabaseQuery
                    && item.cwe_candidates.iter().any(|cwe| cwe == "CWE-89")
            }))
            .count(),
        1
    );
    assert!(jobs.observation_reviews.iter().all(|review| {
        !review
            .evidence
            .iter()
            .any(|item| item.rule_id == "go-sql-resource-filter-summary")
    }));
    let sql = jobs
        .observation_reviews
        .iter()
        .find(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id == "go-database-query")
        })
        .expect("exact dynamic SQL review");
    assert!(sql.decision_facts.unresolved.is_empty());

    fs::remove_dir_all(&root).expect("remove Go repository fixture");
}
