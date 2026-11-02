use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use mehscan_core::Capability;

fn scan_source(label: &str, extension: &str, source: &str) -> mehscan_core::ScanResult {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-buffer-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join(format!("input.{extension}")), source).unwrap();
    let result = mehscan_engine::scan_path(&root).unwrap();
    fs::remove_dir_all(root).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    result
}

#[test]
fn qualified_buffer_operations_keep_the_standard_copy_and_termination_contracts() {
    let source = r#"
namespace runtime = std;
using std::strncpy;
void unclosed(const char *src) { char dst[8]; std::strncpy(dst,src,sizeof(dst)); }
void qualified(const char *src) { char dst[8]; std::strncpy(dst,src,sizeof(dst)); dst[7]=0; }
void global_call(const char *src) { char dst[8]; ::strncpy(dst,src,sizeof(dst)); dst[7]=0; }
void root_std(const char *src) { char dst[8]; ::std::strncpy(dst,src,sizeof(dst)); dst[7]=0; }
void alias(const char *src) { char dst[8]; runtime::strncpy(dst,src,sizeof(dst)); dst[7]=0; }
void imported(const char *src) { char dst[8]; strncpy(dst,src,sizeof(dst)); dst[7]=0; }
void pointer(const char *src) { char dst[8]; const auto copy = std::strncpy; copy(dst,src,sizeof(dst)); dst[7]=0; }
void memory(const char *src) { char dst[8]; std::memcpy(dst,src,sizeof(dst)); }
void move(const char *src) { char dst[8]; ::memmove(dst,src,sizeof(dst)); }
void append(const char *src) { char dst[8]=""; runtime::strncat(dst,src,sizeof(dst)); dst[7]=0; }
void unbounded(const char *src) { char dst[8]; std::strcpy(dst,src); runtime::strcat(dst,src); }
void lookalike(const char *src) { char dst[8]; project::strncpy(dst,src,8); object.strncpy(dst,src,8); }
"#;
    let result = scan_source("qualified", "cpp", source);
    let writes = result
        .evidence
        .iter()
        .filter(|e| e.capability == Capability::BufferWrite)
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 12, "{writes:#?}");
    let sufficient = writes
        .iter()
        .filter(|e| {
            e.tags
                .iter()
                .any(|tag| tag == "buffer-capacity:proven-sufficient")
        })
        .map(|e| e.enclosing_symbol.as_deref().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(sufficient.len(), 8, "{sufficient:#?}");
    for symbol in [
        "qualified",
        "global_call",
        "root_std",
        "alias",
        "imported",
        "pointer",
        "memory",
        "move",
    ] {
        assert!(sufficient.contains(&symbol), "{symbol}: {sufficient:#?}");
    }
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|e| e.capability == Capability::StringTerminationValidation)
            .count(),
        6
    );
    for item in &result.evidence {
        for capture in item.captures.values() {
            assert_eq!(
                &source[capture.location.start.byte_offset..capture.location.end.byte_offset],
                capture.text
            );
        }
    }
}

#[test]
fn custom_functions_callbacks_members_and_macros_never_gain_capacity_proofs() {
    let source = r#"
namespace app {
void strncpy(char *dst, const char *src, unsigned requested) {
    for (unsigned i=0; i<64; ++i) dst[i]=src[i];
}
void copy(const char *src) { char dst[8]; strncpy(dst,src,8); dst[7]=0; }
}
namespace declared { void memcpy(void*,const void*,unsigned); }
namespace declared { void run(const char *src) { char dst[8]; memcpy(dst,src,8); } }
struct Custom {
    void run(const char *src) { char dst[8]; strncpy(dst,src,8); dst[7]=0; }
    void strncpy(char*,const char*,unsigned);
};
void callback(const char *src, void (*strncpy)(char*,const char*,unsigned)) { char dst[8]; strncpy(dst,src,8); dst[7]=0; }
void dynamic(const char *src) { char dst[8]; auto strncpy = choose_copy(); strncpy(dst,src,8); dst[7]=0; }
#define strncpy(a,b,c) replacement(a,b,c)
void macro_copy(const char *src) { char dst[8]; strncpy(dst,src,8); dst[7]=0; }
"#;
    let result = scan_source("shadows", "cpp", source);
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|e| e.capability == Capability::BufferWrite)
            .count(),
        6
    );
    assert!(!result.evidence.iter().any(|e| matches!(
        e.capability,
        Capability::BufferCapacityValidation | Capability::StringTerminationValidation
    )));
    assert!(!result.evidence.iter().any(|e| {
        e.tags
            .iter()
            .any(|tag| tag == "buffer-capacity:proven-sufficient")
    }));
}

#[test]
fn mutable_function_pointer_with_const_parameters_does_not_close_a_buffer_copy() {
    let result = scan_source(
        "pointer-storage",
        "cpp",
        r#"#include <cstring>
struct Adapter {
    Adapter(decltype(&std::strncpy)) {}
    char *operator()(char *dst,const char *src,std::size_t ignored) const {
        for(unsigned i=0;i<64;++i) dst[i]=src[i];
        return dst;
    }
};
char *replacement(char *dst,const char *src,std::size_t ignored) {
    for(unsigned i=0;i<64;++i) dst[i]=src[i];
    return dst;
}
void mutable_copy(const char *src) {
    char dst[8]; char *(*copy)(char*,const char*,std::size_t)=std::strncpy;
    copy=replacement; copy(dst,src,8); dst[7]=0;
}
void constant_copy(const char *src) {
    char dst[8]; char *(* const copy)(char*,const char*,std::size_t)=std::strncpy;
    copy(dst,src,8); dst[7]=0;
}
void constant_object(const char *src) {
    char dst[8]; const Adapter copy=std::strncpy;
    copy(dst,src,8); dst[7]=0;
}
namespace application {
namespace detail { void helper(); }
using namespace detail;
void unrelated_import(const char *src) {
    char dst[5]; memcpy(dst,src,4); dst[4]=0;
}
}
"#,
    );
    let copies = result
        .evidence
        .iter()
        .filter(|item| {
            matches!(
                item.capability,
                Capability::BufferWrite
                    | Capability::BufferCapacityValidation
                    | Capability::StringTerminationValidation
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(copies.len(), 5, "{copies:#?}");
    assert!(copies.iter().all(|item| matches!(
        item.enclosing_symbol.as_deref(),
        Some("constant_copy" | "unrelated_import")
    )));
    assert_eq!(
        copies
            .iter()
            .filter(|item| item.enclosing_symbol.as_deref() == Some("constant_copy"))
            .count(),
        3
    );
    assert_eq!(
        copies
            .iter()
            .filter(|item| item.enclosing_symbol.as_deref() == Some("unrelated_import"))
            .count(),
        2
    );
}

#[test]
fn termination_requires_a_positive_extent_and_uninterrupted_straight_line_use() {
    let source = r#"
void zero(const char *src) { char dst[0]; strncpy(dst,src,sizeof(dst)); dst[0]=0; }
void variable(const char *src, unsigned n) { char dst[n]; strncpy(dst,src,sizeof(dst)); dst[sizeof(dst)-1]=0; }
void branch(const char *src, int enabled) { char dst[8]; strncpy(dst,src,8); if (enabled) dst[7]=0; }
void read_before(const char *src) { char dst[8]; strncpy(dst,src,8); consume(dst); dst[7]=0; }
void unreachable(const char *src) { char dst[8]; strncpy(dst,src,8); return; dst[7]=0; }
void comma(const char *src) { char dst[8]; strncpy(dst,src,8), consume(dst); dst[7]=0; }
void octal(const char *src) { char dst[010]; strncpy(dst,src,9); dst[7]=0; }
void real_octal(const char *src) { char dst[010]; strncpy(dst,src,010); dst[7]=0; }
void actual(const char *src) { char dst[8]; strncpy(dst,src,8); dst[7]=0; }
void excluded_shadow(const char *src) { char dst[8];
#if 0
char dst[0];
#endif
strncpy(dst,src,8); dst[7]=0; }
void excluded_effect(const char *src) { char dst[8]; strncpy(dst,src,8);
#if 0
consume(dst);
#endif
dst[7]=0; }
"#;
    for extension in ["c", "cpp"] {
        let result = scan_source("termination", extension, source);
        let protected = result
            .evidence
            .iter()
            .filter(|e| e.capability == Capability::BufferCapacityValidation)
            .map(|e| e.enclosing_symbol.as_deref().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(protected.len(), 4, "{extension}: {protected:#?}");
        for symbol in ["real_octal", "actual", "excluded_shadow", "excluded_effect"] {
            assert!(
                protected.contains(&symbol),
                "{extension} {symbol}: {protected:#?}"
            );
        }
        assert!(result.evidence.iter().any(|e| {
            e.enclosing_symbol.as_deref() == Some("octal")
                && e.tags
                    .iter()
                    .any(|tag| tag == "buffer-capacity:known-insufficient")
        }));
        assert_eq!(
            result
                .evidence
                .iter()
                .filter(|e| e.capability == Capability::BufferWrite)
                .count(),
            11
        );
    }
}

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
