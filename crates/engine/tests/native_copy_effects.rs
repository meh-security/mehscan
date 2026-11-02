use mehscan_core::{Capability, SecurityPathState};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn typed_constructor_copies_keep_subtraction_and_other_buffer_invariants_separate() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-copy-effects-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("buffer.hpp"),
        r#"
        #pragma once
        #include <algorithm>
        #include <cstddef>
        #include <vector>
        namespace codec {
            class Frame {
            public: Frame(const unsigned char*, std::size_t);
            private: std::vector<unsigned char> storage_;
            };
            class NonCopy { public: NonCopy(const unsigned char*, std::size_t); };
        }
    "#,
    )
    .unwrap();
    fs::write(root.join("buffer.cpp"), r#"
        #include "buffer.hpp"
        namespace codec {
            Frame::Frame(const unsigned char* input, std::size_t count) : storage_(count) {
                std::copy_n(input, count, storage_.begin());
            }
            NonCopy::NonCopy(const unsigned char* input, std::size_t count) {}
            void require(bool ok) { if (!ok) { throw 0; } }
            template<class Error> void require_impl(bool ok, int code) { if (!ok) { throw Error{}; } }
            void forwarded(bool ok, int code) { require_impl<int>(ok, code); }
            void log_only(bool ok) { if (!ok) { log_error(); } }
            void sometimes(bool ok, bool flag) { if (!ok) { if(flag) throw 0; return; } }
            void overloaded(bool ok) { if(!ok)throw 0; }
            void overloaded(bool ok, int code) { log_error(); }
            void cycle_b(bool ok);
            void cycle_a(bool ok) { cycle_b(ok); }
            void cycle_b(bool ok) { cycle_a(ok); }
            #ifdef OPTIONAL_REJECTION
            void configured(bool ok) { if(!ok)throw 0; }
            #else
            void configured(bool ok) {}
            #endif
            namespace inner { void require(bool ok) {} }
        }
    "#).unwrap();
    let cases = [
        (
            "plain",
            "",
            "return {input+7, count-7};",
            Some(SecurityPathState::Unknown),
        ),
        (
            "direct_guard",
            "if(count<7)throw 0;",
            "return {input+7, count-7};",
            Some(SecurityPathState::Protected),
        ),
        (
            "defined_guard",
            "require(count>=7);",
            "return {input+7, count-7};",
            Some(SecurityPathState::Protected),
        ),
        (
            "forwarded_guard",
            "forwarded(count>=7,0);",
            "return {input+7, count-7};",
            Some(SecurityPathState::Protected),
        ),
        (
            "wrong_value",
            "if(other<7)throw 0;",
            "return {input+7, count-7};",
            Some(SecurityPathState::Unknown),
        ),
        (
            "weak_guard",
            "require(count>=6);",
            "return {input+7, count-7};",
            Some(SecurityPathState::Unknown),
        ),
        (
            "or_guard",
            "require(count>=7 || enabled);",
            "return {input+7, count-7};",
            Some(SecurityPathState::Unknown),
        ),
        (
            "logging",
            "log_only(count>=7);",
            "return {input+7, count-7};",
            Some(SecurityPathState::Unknown),
        ),
        (
            "conditional_rejection",
            "sometimes(count>=7, enabled);",
            "return {input+7, count-7};",
            Some(SecurityPathState::Unknown),
        ),
        (
            "shadowed_guard",
            "auto require=[](bool){}; require(count>=7);",
            "return {input+7, count-7};",
            Some(SecurityPathState::Unknown),
        ),
        (
            "changed_count",
            "require(count>=7); count=0;",
            "return {input+7, count-7};",
            Some(SecurityPathState::Unknown),
        ),
        (
            "unknown_guard_configuration",
            "configured(count>=7);",
            "return {input+7, count-7};",
            Some(SecurityPathState::Unknown),
        ),
        (
            "nonrejecting_overload",
            "overloaded(count>=7);",
            "return {input+7, count-7};",
            Some(SecurityPathState::Unknown),
        ),
        (
            "forwarding_cycle",
            "cycle_a(count>=7);",
            "return {input+7, count-7};",
            Some(SecurityPathState::Unknown),
        ),
        (
            "nested_guard",
            "if(enabled){require(count>=7);}",
            "return {input+7, count-7};",
            Some(SecurityPathState::Unknown),
        ),
        ("no_subtraction", "", "return {input, count};", None),
    ];
    let mut source = String::from("#include \"buffer.hpp\"\nnamespace codec {\n");
    for (name, guard, effect, _) in &cases {
        source.push_str(&format!("Frame {name}(const unsigned char* input, std::size_t count, std::size_t other, bool enabled) {{ {guard} {effect} }}\n"));
    }
    source.push_str("NonCopy unrelated(const unsigned char* input, std::size_t count) { return {input+7, count-7}; }\n");
    source.push_str("namespace inner { Frame wrong_namespace(const unsigned char* input, std::size_t count){ require(count>=7); return {input+7, count-7}; } }\n}\n");
    fs::write(root.join("caller.cpp"), source).unwrap();
    let result = mehscan_engine::scan_path(&root).expect("scan defined copy effects");
    let paths = result
        .security_paths
        .iter()
        .filter(|p| p.capability == Capability::SubtractedMemoryExtent)
        .collect::<Vec<_>>();
    for (name, _, _, expected) in &cases {
        let selected = paths
            .iter()
            .filter(|p| {
                result.evidence.iter().any(|e| {
                    e.id == p.sink_evidence_id && e.enclosing_symbol.as_deref() == Some(name)
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            selected.len(),
            usize::from(expected.is_some()),
            "{name}: paths={paths:?}"
        );
        if let Some(expected) = expected {
            assert_eq!(selected[0].state, *expected, "{name}");
        }
    }
    assert!(!paths.iter().any(|p| {
        result.evidence.iter().any(|e| {
            e.id == p.sink_evidence_id && e.enclosing_symbol.as_deref() == Some("unrelated")
        })
    }));
    let wrong_namespace = paths
        .iter()
        .find(|p| {
            result.evidence.iter().any(|e| {
                e.id == p.sink_evidence_id
                    && e.enclosing_symbol.as_deref() == Some("wrong_namespace")
            })
        })
        .expect("inner caller");
    assert_eq!(wrong_namespace.state, SecurityPathState::Unknown);
    let contracts = result
        .evidence
        .iter()
        .filter(|e| e.capability == Capability::MemoryCopyContract)
        .collect::<Vec<_>>();
    assert!(
        contracts
            .iter()
            .all(|e| e.captures["definition"].location.path == "buffer.cpp"
                && e.captures["defined_copy"].text.contains("std::copy_n"))
    );
    assert!(contracts.iter().all(|e| {
        e.tags
            .iter()
            .any(|t| t == "copy-effect:member-initializer-effects-unresolved")
    }));
    assert_eq!(
        result
            .evidence
            .iter()
            .map(|e| &e.id)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        result.evidence.len()
    );
    let jobs = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(20), false)
        .expect("copy review jobs");
    let reviews = jobs
        .reviews
        .iter()
        .filter(|r| r.candidate.capability == Capability::SubtractedMemoryExtent)
        .collect::<Vec<_>>();
    assert_eq!(
        reviews.len(),
        paths
            .iter()
            .filter(|p| p.state == SecurityPathState::Unknown)
            .count()
    );
    assert!(reviews.iter().all(|r| {
        r.candidate.state == SecurityPathState::Unknown
            && r.open_questions
                .iter()
                .any(|q| q.contains("subtracting this offset"))
    }));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn integer_comparisons_follow_literal_bases_signedness_and_binding() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-copy-literals-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let cases = [
        (
            "decimal",
            "int",
            "if(count<9)return;",
            "9",
            SecurityPathState::Protected,
        ),
        (
            "unsigned_guard",
            "int",
            "if(count<9u)return;",
            "9",
            SecurityPathState::Unknown,
        ),
        (
            "signed_positive",
            "int",
            "if(count>=9)",
            "9",
            SecurityPathState::Protected,
        ),
        (
            "octal_weak",
            "unsigned",
            "if(count<010)return;",
            "9",
            SecurityPathState::Unknown,
        ),
        (
            "octal_offset",
            "unsigned",
            "if(count<8)return;",
            "010",
            SecurityPathState::Protected,
        ),
        (
            "binary_offset",
            "unsigned",
            "if(count<9)return;",
            "0b1001",
            SecurityPathState::Protected,
        ),
        (
            "octal_signed",
            "int",
            "if(count<011)return;",
            "9",
            SecurityPathState::Protected,
        ),
        (
            "unsigned_zero",
            "unsigned",
            "if(count==0)return;",
            "1",
            SecurityPathState::Protected,
        ),
        (
            "signed_zero",
            "int",
            "if(count==0)return;",
            "1",
            SecurityPathState::Unknown,
        ),
        (
            "unsigned_truth",
            "unsigned",
            "if(!count)return;",
            "1",
            SecurityPathState::Protected,
        ),
    ];
    for extension in ["c", "cpp"] {
        let op = if extension == "cpp" {
            "std::memcpy"
        } else {
            "memcpy"
        };
        let mut source = String::new();
        for (name, ty, guard, offset, _) in cases {
            source.push_str(&format!("void {name}(char* dst,const char* src,{ty} count) {{ {guard} {op}(dst,src,count-{offset}); }}\n"));
        }
        if extension == "cpp" {
            source.push_str("void shadowed(char* dst,const char* src,unsigned count) { if(unsigned count=10; count<9)return; std::memcpy(dst,src,count-9); }\n");
        }
        let file = root.join(format!("literals.{extension}"));
        fs::write(&file, source).unwrap();
        let result = mehscan_engine::scan_path(&file).expect("scan literal guards");
        for (name, _, _, _, expected) in cases {
            let sink = result
                .evidence
                .iter()
                .find(|e| {
                    e.capability == Capability::SubtractedMemoryExtent
                        && e.enclosing_symbol.as_deref() == Some(name)
                })
                .expect(name);
            let path = result
                .security_paths
                .iter()
                .find(|p| p.sink_evidence_id == sink.id)
                .unwrap();
            assert_eq!(path.state, expected, "{extension}:{name}");
        }
        if extension == "cpp" {
            let sink = result
                .evidence
                .iter()
                .find(|e| {
                    e.capability == Capability::SubtractedMemoryExtent
                        && e.enclosing_symbol.as_deref() == Some("shadowed")
                })
                .unwrap();
            assert_eq!(
                result
                    .security_paths
                    .iter()
                    .find(|p| p.sink_evidence_id == sink.id)
                    .unwrap()
                    .state,
                SecurityPathState::Unknown
            );
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn namespace_imports_aliases_and_declared_overloads_keep_constructor_identity() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-copy-lookup-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("blocks.cpp"), r#"
        namespace wire {
            class Block { public: Block(const char*, unsigned); };
            Block::Block(const char* source, unsigned count) { std::copy_n(source,count,destination); }
            void reject(bool ok) { if(!ok)throw 0; }
        }
        namespace other {
            class Block { public: Block(const char*, unsigned); };
            Block::Block(const char* source, unsigned count) {}
        }
        namespace ambiguous {
            class Block { public: Block(const char*,unsigned); Block(char*,unsigned); };
            Block::Block(const char* source,unsigned count) { std::copy_n(source,count,destination); }
        }
        namespace conditional {
            class Block { public: Block(const char*,unsigned); };
            #ifdef OPTIONAL_COPY
            Block::Block(const char* source,unsigned count) { std::copy_n(source,count,destination); }
            #else
            Block::Block(const char* source,unsigned count) {}
            #endif
        }
        namespace {
            using namespace wire;
            Block imported(const char* source,unsigned count) { return {source+3,count-3}; }
            Block imported_guard(const char* source,unsigned count) { reject(count>=3); return {source+3,count-3}; }
        }
        namespace named {
            using wire::Block;
            Block named_import(const char* source,unsigned count) { return {source+3,count-3}; }
        }
        namespace short_name {
            namespace format = wire;
            using Result = format::Block;
            Result aliased(const char* source,unsigned count) { return {source+3,count-3}; }
        }
        namespace competing {
            using namespace wire;
            using namespace other;
            Block conflicting(const char* source,unsigned count) { return {source+3,count-3}; }
        }
        ambiguous::Block unknown_overload(const char* source,unsigned count) { return {source+3,count-3}; }
        conditional::Block unknown_configuration(const char* source,unsigned count) { return {source+3,count-3}; }
        wire::Block return_type_bound_before_body(const char* source,unsigned count) {
            using namespace other;
            return {source+3,count-3};
        }
    "#).unwrap();
    let scan = mehscan_engine::scan_path(&root).expect("scan C++ name bindings");
    let sinks = scan
        .evidence
        .iter()
        .filter(|e| e.capability == Capability::SubtractedMemoryExtent)
        .collect::<Vec<_>>();
    for expected in [
        "imported",
        "imported_guard",
        "named_import",
        "aliased",
        "return_type_bound_before_body",
    ] {
        assert!(
            sinks
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some(expected)),
            "{expected}"
        );
    }
    for excluded in ["conflicting", "unknown_overload", "unknown_configuration"] {
        assert!(
            !sinks
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some(excluded)),
            "{excluded}"
        );
    }
    let guarded = sinks
        .iter()
        .find(|e| e.enclosing_symbol.as_deref() == Some("imported_guard"))
        .unwrap();
    assert_eq!(
        scan.security_paths
            .iter()
            .find(|p| p.sink_evidence_id == guarded.id)
            .unwrap()
            .state,
        SecurityPathState::Protected
    );
    assert!(
        scan.evidence
            .iter()
            .filter(|e| e.capability == Capability::MemoryCopyContract)
            .all(|e| e.captures.contains_key("binding_0"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn helpers_preserve_parameter_roles_and_do_not_certify_argument_side_effects() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-copy-helpers-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("foreign.hpp"),
        "namespace foreign { struct uint32_t { unsigned operator-(int)const; }; struct size_t { operator unsigned()const; }; }\n",
    )
    .unwrap();
    fs::write(root.join("helpers.cpp"), r#"
        namespace wire {
            void copy_bytes(const char* src, unsigned count, char* dst) { std::memcpy(dst,src,count); }
            void replaced_count(const char* src, unsigned count, char* dst) { count=0; std::memcpy(dst,src,count); }
            void correct(char* dst,const char* src,unsigned count) { if(count<3)return; copy_bytes(src,count-3,dst); }
            void missing(char* dst,const char* src,unsigned count) { copy_bytes(src,count-3,dst); }
            void sanitized(char* dst,const char* src,unsigned count) { replaced_count(src,count-3,dst); }
            const char* change(unsigned& count) { count=0; return nullptr; }
            void callback(char* dst,unsigned count) { if(count<3)return; std::memcpy(dst,change(count),count-3); }
            struct Proxy { unsigned& count; operator void*() { count=0;return nullptr; } };
            void conversion(const char* src,unsigned count) { Proxy proxy{count}; if(count<3)return; std::memcpy(proxy,src,count-3); }
            void shadowed_lambda(char* dst,const char* src,unsigned count) { if(count<3)return; auto run=[](char* dst,const char* src,unsigned count) { std::memcpy(dst,src,count-3); }; run(dst,src,0); }
            void shadowed_block(char* dst,const char* src,unsigned count) { if(count<3)return; { unsigned count=0; std::memcpy(dst,src,count-3); } }
            struct uint32_t { unsigned operator-(int)const; };
            void nominal(char* dst,const char* src,uint32_t count) { std::memcpy(dst,src,count-3); }
        }
        namespace foreign {
            void cross_file_nominal(char* dst,const char* src,uint32_t count) { std::memcpy(dst,src,count-3); }
            void nominal_count(const char* src,size_t count,char* dst) { std::memcpy(dst,src,count); }
            void foreign_count_helper(char* dst,const char* src,unsigned count) { nominal_count(src,count-3,dst); }
        }
    "#).unwrap();
    let scan = mehscan_engine::scan_path(&root).unwrap();
    let lookup = |name| {
        let sink = scan.evidence.iter().find(|e| {
            e.capability == Capability::SubtractedMemoryExtent
                && e.enclosing_symbol.as_deref() == Some(name)
        })?;
        scan.security_paths
            .iter()
            .find(|p| p.sink_evidence_id == sink.id)
    };
    assert_eq!(
        lookup("correct").unwrap().state,
        SecurityPathState::Protected
    );
    for name in [
        "missing",
        "callback",
        "conversion",
        "shadowed_lambda",
        "shadowed_block",
    ] {
        assert_eq!(
            lookup(name).unwrap().state,
            SecurityPathState::Unknown,
            "{name}"
        );
    }
    for name in [
        "sanitized",
        "nominal",
        "cross_file_nominal",
        "foreign_count_helper",
    ] {
        assert!(lookup(name).is_none(), "{name}");
    }
    fs::remove_dir_all(root).unwrap();
}
