use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn capacity_and_termination_require_the_consumed_array_binding() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-buffer-owner-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let source = r#"#include <string.h>
void sibling(char *dst, const char *src) {
    { char dst[64]; }
    strncpy(dst, src, 32); dst[63] = 0;
}
void shadow(char *external, const char *src) {
    char dst[64];
    { char *dst = external; strncpy(dst, src, 32); dst[63] = 0; }
}
void wrong_terminator(char *external, const char *src) {
    char dst[64]; strncpy(dst, src, 32);
    { char *dst = external; dst[63] = 0; }
}
void excluded(char *dst, const char *src) {
#if 0
    char dst[64];
#endif
    strncpy(dst, src, 32); dst[63] = 0;
}
void actual(const char *src) {
    char dst[64]; strncpy(dst, src, 32); dst[63] = 0;
}
void conditional_safe(const char *src) {
#if FEATURE
    char dst[64]; strncpy(dst, src, 32); dst[63] = 0;
#endif
}
"#;
    for extension in ["c", "cpp"] {
        fs::write(root.join(format!("input.{extension}")), source).unwrap();
    }
    let scan = mehscan_engine::scan_path(&root).unwrap();
    fs::remove_dir_all(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    for extension in ["c", "cpp"] {
        let validations = scan
            .evidence
            .iter()
            .filter(|item| {
                item.location.path == format!("input.{extension}")
                    && matches!(
                        item.rule_id.as_str(),
                        "c-family-local-buffer-capacity" | "c-family-local-string-termination"
                    )
            })
            .collect::<Vec<_>>();
        assert_eq!(validations.len(), 4, "{extension}: {validations:#?}");
        assert!(validations.iter().all(|item| matches!(
            item.enclosing_symbol.as_deref(),
            Some("actual" | "conditional_safe")
        )));
        for symbol in ["sibling", "shadow", "wrong_terminator", "excluded"] {
            assert!(
                scan.evidence
                    .iter()
                    .any(|item| item.location.path == format!("input.{extension}")
                        && item.enclosing_symbol.as_deref() == Some(symbol)
                        && item.capability == mehscan_core::Capability::BufferWrite),
                "{extension} {symbol}: retain operation"
            );
        }
    }
}
