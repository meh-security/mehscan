use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use mehscan_core::SecurityPathState;

#[test]
fn image_copy_regions_require_both_axes_before_the_write() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-region-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create destination-region fixture");
    let source = r#"
typedef unsigned int u32;
int freerdp_image_copy_no_overlap(void*, u32, u32, u32, u32, u32, u32,
                                   void*, u32, u32, u32, u32, void*, u32);

void vulnerable(void *d, void *s, u32 f, u32 stride, u32 x, u32 y,
                u32 w, u32 h, u32 dw, u32 dh) {
  if (x > dw) return; if (y > dh) return;
  freerdp_image_copy_no_overlap(d, f, stride, x, y, w, h, s, f, 0, 0, 0, 0, 0);
}
void protected_copy(void *d, void *s, u32 f, u32 stride, u32 x, u32 y,
                    u32 w, u32 h, u32 dw, u32 dh) {
  if (x > dw) return; if (y > dh) return;
  u32 cw = w; if (1ull * x + w > dw) cw = dw - x;
  u32 ch = h; if (1ull * y + h > dh) ch = dh - y;
  freerdp_image_copy_no_overlap(d, f, stride, x, y, cw, ch, s, f, 0, 0, 0, 0, 0);
}
void one_axis(void *d, void *s, u32 x, u32 y, u32 w, u32 h, u32 dw, u32 dh) {
  if (x > dw) return; if (y > dh) return;
  u32 cw = w; if (x + w > dw) cw = dw - x;
  freerdp_image_copy_no_overlap(d, 0, 0, x, y, cw, h, s, 0, 0, 0, 0, 0, 0);
}
void late_clamp(void *d, void *s, u32 x, u32 y, u32 w, u32 h, u32 dw, u32 dh) {
  if (x > dw) return; if (y > dh) return;
  u32 cw = w; u32 ch = h;
  freerdp_image_copy_no_overlap(d, 0, 0, x, y, cw, ch, s, 0, 0, 0, 0, 0, 0);
  if (x + w > dw) cw = dw - x; if (y + h > dh) ch = dh - y;
}
void reassigned(void *d, void *s, u32 x, u32 y, u32 w, u32 h,
                u32 dw, u32 dh, u32 other) {
  if (x > dw) return; if (y > dh) return;
  u32 cw = w; if (x + w > dw) cw = dw - x;
  u32 ch = h; if (y + h > dh) ch = dh - y; cw = other;
  freerdp_image_copy_no_overlap(d, 0, 0, x, y, cw, ch, s, 0, 0, 0, 0, 0, 0);
}
void wrapping_checks(void *d, void *s, u32 x, u32 y, u32 w, u32 h,
                     u32 dw, u32 dh) {
  if (x > dw) return; if (y > dh) return;
  u32 cw = w; if (x + w > dw) cw = dw - x;
  u32 ch = h; if (y + h > dh) ch = dh - y;
  freerdp_image_copy_no_overlap(d, 0, 0, x, y, cw, ch, s, 0, 0, 0, 0, 0, 0);
}
void unguarded(void *d, void *s, u32 x, u32 y, u32 w, u32 h) {
  freerdp_image_copy_no_overlap(d, 0, 0, x, y, w, h, s, 0, 0, 0, 0, 0, 0);
}
void different_api(void *d, void *s, u32 x, u32 y, u32 w, u32 h, u32 dw, u32 dh) {
  if (x > dw) return; if (y > dh) return;
  image_copy_no_overlap(d, 0, 0, x, y, w, h, s);
}
"#;
    fs::write(root.join("regions.c"), source).expect("write C fixture");
    fs::write(root.join("regions.cpp"), source).expect("write C++ fixture");

    let result = mehscan_engine::scan_path(&root).expect("scan destination regions");
    let repeated = mehscan_engine::scan_path(&root).expect("repeat destination regions");
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.provenance.engine == "mehscan c-family destination-region relationship 1"
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 12);
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        2
    );
    assert!(paths.iter().all(|path| {
        path.cwe_candidates.contains(&"CWE-787".to_string())
            && path.cwe_candidates.contains(&"CWE-122".to_string())
    }));
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "c-family-image-copy-operation")
            .count(),
        12,
        "unguarded and differently named lookalikes stay excluded"
    );
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(30), true)
        .expect("destination-region reviews");
    assert!(reviews.reviews.iter().any(|review| {
        review
            .candidate
            .cwe_candidates
            .contains(&"CWE-787".to_string())
            && review.open_questions.iter().any(|question| {
                question.contains("destination offset")
                    && question.contains("authoritative")
                    && question.contains("both axes")
            })
    }));
    fs::remove_dir_all(&root).expect("remove destination-region fixture");
}
