use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use mehscan_core::{Capability, SecurityPathState};

fn fixture_root(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-remaining-input-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create fixture");
    root
}

fn assert_language(extension: &str) {
    let root = fixture_root(extension);
    fs::write(
        root.join(format!("parser.{extension}")),
        r#"
void CopyFrom(const unsigned char *source, unsigned length);
unsigned decode_length(const unsigned char *source);

void wrapping_check(const unsigned char *buf, unsigned total, unsigned pos) {
    unsigned item_len = decode_length(buf);
    if (pos + item_len > total) return;
    CopyFrom(buf + pos, item_len);
}

void protected_check(const unsigned char *buf, unsigned total, unsigned pos) {
    unsigned item_len = decode_length(buf);
    if (pos > total) return;
    if (item_len > total - pos) return;
    CopyFrom(buf + pos, item_len);
}

void subtraction_without_cursor_bound(const unsigned char *buf, unsigned total, unsigned pos) {
    unsigned item_len = decode_length(buf);
    if (item_len > total - pos) return;
    CopyFrom(buf + pos, item_len);
}

void compound_protected(const unsigned char *buf, unsigned total, unsigned pos) {
    unsigned item_len = decode_length(buf);
    if (pos > total || item_len > total - pos) return;
    CopyFrom(buf + pos, item_len);
}

void advanced_cursor_protected(const unsigned char *buf, unsigned total) {
    unsigned pos = 12;
    if (total < 12) return;
    unsigned first_len = decode_length(buf);
    if (first_len > total - pos) return;
    pos += first_len;
    unsigned item_len = decode_length(buf + pos);
    if (item_len > total - pos) return;
    CopyFrom(buf + pos, item_len);
}

void nonterminating(const unsigned char *buf, unsigned total, unsigned pos) {
    unsigned item_len = decode_length(buf);
    if (pos + item_len > total) log_bad_length();
    CopyFrom(buf + pos, item_len);
}

void late_check(const unsigned char *buf, unsigned total, unsigned pos) {
    unsigned item_len = decode_length(buf);
    CopyFrom(buf + pos, item_len);
    if (pos + item_len > total) return;
}

void wrong_length(const unsigned char *buf, unsigned total, unsigned pos, unsigned other) {
    unsigned item_len = decode_length(buf);
    if (pos + item_len > total) return;
    CopyFrom(buf + pos, other);
}

void reassigned_cursor(const unsigned char *buf, unsigned total, unsigned pos) {
    unsigned item_len = decode_length(buf);
    if (pos + item_len > total) return;
    pos = trusted_position();
    CopyFrom(buf + pos, item_len);
}

void no_cursor_source(const unsigned char *buf, unsigned total, unsigned pos) {
    unsigned item_len = decode_length(buf);
    if (pos + item_len > total) return;
    CopyFrom(buf, item_len);
}

void unrelated_consumer(const unsigned char *buf, unsigned total, unsigned pos) {
    unsigned item_len = decode_length(buf);
    if (pos + item_len > total) return;
    record_value(buf + pos, item_len);
}

void plain_parameter(const unsigned char *buf, unsigned total, unsigned pos, unsigned item_len) {
    if (pos + item_len > total) return;
    CopyFrom(buf + pos, item_len);
}
"#,
    )
    .expect("write fixture");

    let result = mehscan_engine::scan_path(&root).expect("scan fixture");
    let repeated = mehscan_engine::scan_path(&root).expect("repeat fixture");
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    let paths = result
        .security_paths
        .iter()
        .filter(|path| path.provenance.engine == "mehscan c-family remaining-input relationship 1")
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 5);
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
        2
    );
    assert!(paths.iter().all(|path| {
        path.capability == Capability::RemainingInputRead
            && path.cwe_candidates == ["CWE-190", "CWE-125"]
    }));
    assert!(paths.iter().any(|path| {
        path.steps
            .iter()
            .any(|step| step.kind == mehscan_core::SecurityPathStepKind::IneffectiveProtection)
    }));
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(50), true)
        .expect("reviews");
    assert!(reviews.reviews.iter().any(|review| {
        review.candidate.capability == Capability::RemainingInputRead
            && review.open_questions.iter().any(|question| {
                question.contains("authoritative remaining input")
                    && question.contains("offset-plus-length wrapping")
            })
    }));
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn decoded_extents_are_related_to_remaining_input_in_c() {
    assert_language("c");
}

#[test]
fn decoded_extents_are_related_to_remaining_input_in_cpp() {
    assert_language("cpp");
}
