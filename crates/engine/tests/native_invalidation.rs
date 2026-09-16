use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use mehscan_core::SecurityPathState;

fn fixture_root(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-invalidation-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create invalidation fixture");
    root
}

fn assert_language(extension: &str) {
    let root = fixture_root(extension);
    fs::write(
        root.join(format!("contract.{extension}")),
        r#"
typedef struct session session;
#define DEAD 0
#define LIVE 1

/* Runs pending work. The function returns DEAD if the session is no longer valid. */
int run_pending(session *s) { return LIVE; }

/* This mentions a freed session but does not document a return status. */
int unrelated(session *s) { return LIVE; }

/* Returns DEAD if either session was freed. */
int ambiguous(session *left, session *right) { return LIVE; }
"#,
    )
    .expect("write contract source");
    fs::write(
        root.join(format!("callers.{extension}")),
        r#"
typedef struct session { int flags; } session;
#define DEAD 0
int run_pending(session *s);
int unrelated(session *s);
int ambiguous(session *left, session *right);
void consume(session *s);

void vulnerable(session *s) {
    run_pending(s);
    if (s->flags) consume(s);
}

void protected_direct(session *s) {
    if (run_pending(s) == DEAD) {
        cleanup_metrics();
        return;
    }
    consume(s);
}

void protected_stored(session *s) {
    int status = run_pending(s);
    if (DEAD == status) return;
    consume(s);
}

void protected_continue(session *s) {
    while (next_session(&s)) {
        if (run_pending(s) == DEAD) continue;
        consume(s);
    }
}

void nonterminating_guard(session *s) {
    if (run_pending(s) == DEAD) log_dead();
    consume(s);
}

void late_guard(session *s) {
    int status = run_pending(s);
    consume(s);
    if (status == DEAD) return;
}

void reassigned(session *s, session *replacement) {
    run_pending(s);
    s = replacement;
    consume(s);
}

void no_post_use(session *s) { run_pending(s); }
void undocumented(session *s) { unrelated(s); consume(s); }
void ambiguous_contract(session *a, session *b) { ambiguous(a, b); consume(a); }
"#,
    )
    .expect("write caller source");

    let result = mehscan_engine::scan_path(&root).expect("scan invalidation fixture");
    let repeated = mehscan_engine::scan_path(&root).expect("repeat invalidation fixture");
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.provenance.engine == "mehscan c-family documented-invalidation relationship 1"
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 6);
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        3
    );
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Unknown)
            .count(),
        3
    );
    assert!(paths.iter().all(|path| path.cwe_candidates == ["CWE-416"]));
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "c-family-invalidating-return-call")
            .count(),
        6,
        "reassignment, no-use, undocumented, and ambiguous contracts stay excluded"
    );
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "c-family-invalidating-return-call"
            && item
                .captures
                .get("contract_definition")
                .is_some_and(|capture| {
                    capture
                        .location
                        .path
                        .ends_with(&format!("contract.{extension}"))
                })
    }));
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(30), true)
        .expect("invalidation reviews");
    assert!(reviews.reviews.iter().any(|review| {
        review
            .candidate
            .cwe_candidates
            .contains(&"CWE-416".to_string())
            && review.open_questions.iter().any(|question| {
                question.contains("documented invalid status")
                    && question.contains("exact pointer argument")
                    && question.contains("post-call use")
            })
    }));

    fs::remove_dir_all(&root).expect("remove invalidation fixture");
}

#[test]
fn documented_invalidating_status_controls_post_call_pointer_use_in_c() {
    assert_language("c");
}

#[test]
fn documented_invalidating_status_controls_post_call_pointer_use_in_cpp() {
    assert_language("cpp");
}
