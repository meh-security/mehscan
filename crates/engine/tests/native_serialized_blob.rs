use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use mehscan_core::SecurityPathState;

fn fixture_root(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-serialized-blob-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create serialized-blob fixture");
    root
}

fn assert_language(extension: &str) {
    let root = fixture_root(extension);
    fs::write(
        root.join(format!("model.{extension}")),
        r#"
#include <stddef.h>
#define NULL ((void *)0)
void *allocate_bytes(size_t size);
void release_bytes(void *value);
char *read_model_buffer(void *input, size_t *length);
char *parse_model(void *input, size_t *length);
void *memcpy(void *destination, const void *source, size_t size);

struct model { float *matrix; };

void vulnerable(struct model *value, void *input, size_t rows, size_t columns) {
    size_t matrix_size = sizeof(float) * rows * columns;
    char *blob = read_model_buffer(input, NULL);
    value->matrix = allocate_bytes(matrix_size);
    memcpy(value->matrix, blob, matrix_size);
}

void protected_copy(struct model *value, void *input, size_t rows, size_t columns) {
    size_t matrix_size = sizeof(float) * rows * columns;
    size_t blob_length = 0;
    char *blob = read_model_buffer(input, &blob_length);
    if (blob_length != matrix_size) {
        release_bytes(blob);
        return;
    }
    value->matrix = allocate_bytes(matrix_size);
    memcpy(value->matrix, blob, matrix_size);
}

void nonterminating_guard(struct model *value, void *input, size_t rows, size_t columns) {
    size_t matrix_size = sizeof(float) * rows * columns;
    size_t blob_length = 0;
    char *blob = read_model_buffer(input, &blob_length);
    if (blob_length != matrix_size) release_bytes(blob);
    value->matrix = allocate_bytes(matrix_size);
    memcpy(value->matrix, blob, matrix_size);
}

void late_guard(struct model *value, void *input, size_t rows, size_t columns) {
    size_t matrix_size = sizeof(float) * rows * columns;
    size_t blob_length = 0;
    char *blob = read_model_buffer(input, &blob_length);
    value->matrix = allocate_bytes(matrix_size);
    memcpy(value->matrix, blob, matrix_size);
    if (blob_length != matrix_size) return;
}

void wrong_length_guard(struct model *value, void *input, size_t rows, size_t columns) {
    size_t matrix_size = sizeof(float) * rows * columns;
    size_t blob_length = 0;
    size_t other_length = 0;
    char *blob = read_model_buffer(input, &blob_length);
    if (other_length != matrix_size) return;
    value->matrix = allocate_bytes(matrix_size);
    memcpy(value->matrix, blob, matrix_size);
}

void reassigned_blob(struct model *value, void *input, size_t rows, size_t columns) {
    size_t matrix_size = sizeof(float) * rows * columns;
    char *blob = read_model_buffer(input, NULL);
    blob = replacement_blob();
    value->matrix = allocate_bytes(matrix_size);
    memcpy(value->matrix, blob, matrix_size);
}

void reassigned_extent(struct model *value, void *input, size_t rows, size_t columns) {
    size_t matrix_size = sizeof(float) * rows * columns;
    char *blob = read_model_buffer(input, NULL);
    matrix_size = trusted_size();
    value->matrix = allocate_bytes(matrix_size);
    memcpy(value->matrix, blob, matrix_size);
}

void no_dimension_product(struct model *value, void *input, size_t rows) {
    size_t matrix_size = sizeof(float) * rows;
    char *blob = read_model_buffer(input, NULL);
    value->matrix = allocate_bytes(matrix_size);
    memcpy(value->matrix, blob, matrix_size);
}

void different_allocation_extent(struct model *value, void *input, size_t rows, size_t columns) {
    size_t matrix_size = sizeof(float) * rows * columns;
    char *blob = read_model_buffer(input, NULL);
    value->matrix = allocate_bytes(rows);
    memcpy(value->matrix, blob, matrix_size);
}

void non_buffer_parser(struct model *value, void *input, size_t rows, size_t columns) {
    size_t matrix_size = sizeof(float) * rows * columns;
    char *blob = parse_model(input, NULL);
    value->matrix = allocate_bytes(matrix_size);
    memcpy(value->matrix, blob, matrix_size);
}
"#,
    )
    .expect("write serialized-blob source");

    let result = mehscan_engine::scan_path(&root).expect("scan serialized-blob fixture");
    let repeated = mehscan_engine::scan_path(&root).expect("repeat serialized-blob fixture");
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.provenance.engine == "mehscan c-family serialized-blob extent relationship 1"
        })
        .collect::<Vec<_>>();
    assert_eq!(
        paths.len(),
        5,
        "lookalikes and mutated values stay excluded"
    );
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        1
    );
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Unknown)
            .count(),
        4
    );
    assert!(paths.iter().all(|path| {
        path.cwe_candidates == ["CWE-20", "CWE-125"]
            && path.capability == mehscan_core::Capability::SerializedBlobCopy
    }));
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "c-family-serialized-blob-length-validation")
            .count(),
        1,
        "only an exact, terminating, pre-copy mismatch guard protects the copy"
    );
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(50), true)
        .expect("serialized-blob reviews");
    assert!(reviews.reviews.iter().any(|review| {
        review.candidate.capability == mehscan_core::Capability::SerializedBlobCopy
            && review.open_questions.iter().any(|question| {
                question.contains("loader-reported blob length")
                    && question.contains("fixed-layout copy extent")
                    && question.contains("multiplication-overflow invariant")
            })
    }));

    fs::remove_dir_all(&root).expect("remove serialized-blob fixture");
}

#[test]
fn serialized_blob_extent_validation_controls_fixed_layout_copy_in_c() {
    assert_language("c");
}

#[test]
fn serialized_blob_extent_validation_controls_fixed_layout_copy_in_cpp() {
    assert_language("cpp");
}
