use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use mehscan_core::{Capability, SecurityPathState};

fn fixture_root(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-loaded-extent-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create fixture");
    root
}

fn assert_language(extension: &str) {
    let root = fixture_root(extension);
    fs::write(
        root.join(format!("extent.{extension}")),
        r#"
#include <stddef.h>
#include <stdint.h>
#define SIZE_MAX ((size_t)-1)
uint32_t decode_u32(void *reader);
void *allocate_bytes(size_t size);
void *memcpy(void *dst, const void *src, size_t size);

void vulnerable(void *reader, void *src, uint32_t columns) {
    uint32_t rows = decode_u32(reader);
    size_t extent = sizeof(float) * rows * columns;
    void *dst = allocate_bytes(extent);
    memcpy(dst, src, extent);
}

void protected_extent(void *reader, void *src, uint32_t columns) {
    uint32_t rows = decode_u32(reader);
    if (rows == 0 || columns == 0) return;
    size_t max_rows = SIZE_MAX / (sizeof(float) * columns);
    if (rows > max_rows) return;
    size_t extent = sizeof(float) * rows * columns;
    void *dst = allocate_bytes(extent);
    memcpy(dst, src, extent);
}

void missing_zero_proof(void *reader, void *src, uint32_t columns) {
    uint32_t rows = decode_u32(reader);
    size_t max_rows = SIZE_MAX / (sizeof(float) * columns);
    if (rows > max_rows) return;
    size_t extent = sizeof(float) * rows * columns;
    void *dst = allocate_bytes(extent);
    memcpy(dst, src, extent);
}

void nonterminating_guard(void *reader, void *src, uint32_t columns) {
    uint32_t rows = decode_u32(reader);
    if (rows == 0 || columns == 0) log_invalid();
    size_t max_rows = SIZE_MAX / (sizeof(float) * columns);
    if (rows > max_rows) log_invalid();
    size_t extent = sizeof(float) * rows * columns;
    void *dst = allocate_bytes(extent);
    memcpy(dst, src, extent);
}

void late_guard(void *reader, void *src, uint32_t columns) {
    uint32_t rows = decode_u32(reader);
    size_t extent = sizeof(float) * rows * columns;
    if (rows == 0 || columns == 0) return;
    size_t max_rows = SIZE_MAX / (sizeof(float) * columns);
    if (rows > max_rows) return;
    void *dst = allocate_bytes(extent);
    memcpy(dst, src, extent);
}

void reassigned_input(void *reader, void *src, uint32_t columns) {
    uint32_t rows = decode_u32(reader);
    rows = trusted_rows();
    size_t extent = sizeof(float) * rows * columns;
    void *dst = allocate_bytes(extent);
    memcpy(dst, src, extent);
}

void no_scalar_loader(void *src, uint32_t rows, uint32_t columns) {
    size_t extent = sizeof(float) * rows * columns;
    void *dst = allocate_bytes(extent);
    memcpy(dst, src, extent);
}

void wrong_allocation(void *reader, void *src, uint32_t columns) {
    uint32_t rows = decode_u32(reader);
    size_t extent = sizeof(float) * rows * columns;
    void *dst = allocate_bytes(columns);
    memcpy(dst, src, extent);
}

void no_copy(void *reader, uint32_t columns) {
    uint32_t rows = decode_u32(reader);
    size_t extent = sizeof(float) * rows * columns;
    allocate_bytes(extent);
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
        .filter(|path| {
            path.provenance.engine == "mehscan c-family loaded-memory-extent relationship 1"
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 5);
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
        path.capability == Capability::LoadedMemoryExtent
            && path.cwe_candidates == ["CWE-190", "CWE-680", "CWE-122"]
    }));
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(50), true)
        .expect("reviews");
    assert!(reviews.reviews.iter().any(|review| {
        review.candidate.capability == Capability::LoadedMemoryExtent
            && review.open_questions.iter().any(|question| {
                question.contains("effective C/C++ types")
                    && question.contains("zero")
                    && question.contains("SIZE_MAX")
            })
    }));
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn loaded_scalars_control_memory_extents_in_c() {
    assert_language("c");
}

#[test]
fn loaded_scalars_control_memory_extents_in_cpp() {
    assert_language("cpp");
}
