use mehscan_core::{Capability, OperandFactKind};
use std::fs;

const SOURCE: &str = r#"
unsigned decode_length(const unsigned char *source);
void CopyFrom(const unsigned char *source, unsigned length);
static void single(const unsigned char *buf, unsigned total, unsigned pos) {
    unsigned length = decode_length(buf);
    if (pos + length > total) return;
    CopyFrom(buf + pos, length);
}
void entry(const unsigned char *buf) { single(buf, 16, 0); }
static void changed(const unsigned char *buf, unsigned total, unsigned pos) {
    unsigned length = decode_length(buf);
    pos += length;
    if (pos + length > total) return;
    CopyFrom(buf + pos, length);
}
void change_entry(const unsigned char *buf) { changed(buf, 16, 0); }
static void escaped(const unsigned char *buf, unsigned total, unsigned pos) {
    unsigned length = decode_length(buf);
    adjust(pos);
    if (pos + length > total) return;
    CopyFrom(buf + pos, length);
}
void escape_entry(const unsigned char *buf) { escaped(buf, 16, 0); }
static void multiple(const unsigned char *buf, unsigned total, unsigned pos) {
    unsigned length = decode_length(buf);
    if (pos + length > total) return;
    CopyFrom(buf + pos, length);
}
void two(const unsigned char *buf) { multiple(buf, 16, 0); multiple(buf, 16, 1); }
static void address_taken(const unsigned char *buf, unsigned total, unsigned pos) {
    unsigned length = decode_length(buf);
    if (pos + length > total) return;
    CopyFrom(buf + pos, length);
}
void pointer_entry(const unsigned char *buf) { auto_ptr = address_taken; address_taken(buf, 16, 0); }
void external(const unsigned char *buf, unsigned total, unsigned pos) {
    unsigned length = decode_length(buf);
    if (pos + length > total) return;
    CopyFrom(buf + pos, length);
}
void external_entry(const unsigned char *buf) { external(buf, 16, 0); }
void loaded(void *reader, void *source, unsigned columns) {
    unsigned rows = decode_length(reader);
    size_t extent = sizeof(float) * rows * columns;
    void *dst = allocate_bytes(extent);
    memcpy(dst, source, extent);
}
unsigned long pos;
void loop_shadow(const unsigned char *buf, unsigned total) {
    for (unsigned pos = 0; pos < 1; ++pos) {}
    unsigned length = decode_length(buf);
    if (pos + length > total) return;
    CopyFrom(buf + pos, length);
}
"#;

#[test]
fn scalar_declarations_and_one_caller_stay_navigation_facts_in_c_and_cpp() {
    for extension in ["c", "cpp"] {
        let root = std::env::temp_dir().join(format!(
            "mehscan-native-operands-{extension}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(format!("Review.{extension}")), SOURCE).unwrap();
        let inventory = mehscan_engine::investigation::build_review_inventory(&root, true).unwrap();
        let sink = |name: &str| {
            let start = SOURCE.find(&format!("void {name}(")).unwrap();
            let end = start + SOURCE[start..].find("\n}").unwrap();
            inventory
                .scan
                .evidence
                .iter()
                .find(|e| {
                    e.location.start.byte_offset > start
                        && e.location.start.byte_offset < end
                        && e.capability == Capability::RemainingInputRead
                })
                .unwrap_or_else(|| panic!("missing {name} in {}", extension))
        };
        let single = sink("single");
        for name in ["length", "pos", "total"] {
            let fact = single
                .context
                .operand_facts
                .iter()
                .find(|f| f.value == name && f.kind == OperandFactKind::NativeOperandDeclaration)
                .unwrap();
            let text = &SOURCE[fact.location.start.byte_offset..fact.location.end.byte_offset];
            assert!(text.contains("unsigned") && text.contains(name), "{text}");
            assert!(!fact.remaining_checks.is_empty());
        }
        let caller = single
            .context
            .operand_facts
            .iter()
            .filter(|f| f.kind == OperandFactKind::LocalCallArgument)
            .collect::<Vec<_>>();
        assert_eq!(caller.len(), 2);
        for fact in caller {
            let expected = if fact.value == "pos" { "0" } else { "16" };
            assert_eq!(
                &SOURCE[fact.location.start.byte_offset..fact.location.end.byte_offset],
                expected
            );
            assert!(!fact.remaining_checks.is_empty());
        }
        for name in ["changed", "escaped"] {
            let item = sink(name);
            assert!(
                !item
                    .context
                    .operand_facts
                    .iter()
                    .any(|f| f.kind == OperandFactKind::LocalCallArgument && f.value == "pos")
            );
            assert!(
                item.context
                    .operand_facts
                    .iter()
                    .any(|f| f.kind == OperandFactKind::OperandBoundary && f.value == "pos")
            );
            let boundary = item
                .context
                .operand_facts
                .iter()
                .find(|f| f.kind == OperandFactKind::OperandBoundary && f.value == "pos")
                .unwrap();
            let text =
                &SOURCE[boundary.location.start.byte_offset..boundary.location.end.byte_offset];
            assert!(text.contains(if name == "changed" {
                "pos += length"
            } else {
                "adjust(pos)"
            }));
        }
        for name in ["multiple", "address_taken", "external"] {
            let item = sink(name);
            assert!(
                !item
                    .context
                    .operand_facts
                    .iter()
                    .any(|f| f.kind == OperandFactKind::LocalCallArgument),
                "{name}"
            );
            assert!(
                item.context
                    .operand_facts
                    .iter()
                    .any(|f| f.kind == OperandFactKind::OperandBoundary),
                "{name}"
            );
        }
        let loaded = inventory
            .scan
            .evidence
            .iter()
            .find(|e| e.capability == Capability::LoadedMemoryExtent)
            .unwrap();
        for name in ["extent", "rows", "columns"] {
            assert!(loaded.context.operand_facts.iter().any(|f| f.kind == OperandFactKind::NativeOperandDeclaration && f.value == name), "{name}");
        }
        let shadow = sink("loop_shadow");
        assert!(
            !shadow
                .context
                .operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::NativeOperandDeclaration && f.value == "pos")
        );
        assert!(
            shadow
                .context
                .operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::OperandBoundary && f.value == "pos")
        );
        assert!(inventory.entries.iter().all(|e| e.value_hint.is_none()));
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn unsupported_scalar_shapes_and_overloaded_helpers_do_not_borrow_arguments() {
    let root =
        std::env::temp_dir().join(format!("mehscan-native-ambiguity-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let source = r#"
unsigned decode_length(const unsigned char *);
void CopyFrom(const unsigned char *, unsigned);
static void read(const unsigned char *buf, unsigned total, unsigned &pos) {
    unsigned length = decode_length(buf);
    if (pos + length > total) return;
    CopyFrom(buf + pos, length);
}
static void read(int) {}
void entry(const unsigned char *buf, unsigned pos) { read(buf, 16, pos); }
"#;
    fs::write(root.join("Review.cpp"), source).unwrap();
    let scan = mehscan_engine::scan_path(&root).unwrap();
    let sink = scan
        .evidence
        .iter()
        .find(|e| e.capability == Capability::RemainingInputRead)
        .unwrap();
    assert!(
        !sink
            .context
            .operand_facts
            .iter()
            .any(|f| f.kind == OperandFactKind::LocalCallArgument)
    );
    assert!(
        !sink
            .context
            .operand_facts
            .iter()
            .any(|f| f.kind == OperandFactKind::NativeOperandDeclaration && f.value == "pos")
    );
    assert!(
        sink.context
            .operand_facts
            .iter()
            .any(|f| f.kind == OperandFactKind::OperandBoundary && f.value == "pos")
    );
    fs::remove_dir_all(root).unwrap();
}
