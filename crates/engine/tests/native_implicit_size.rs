mod support;
use std::fs;

use mehscan_core::{Capability, SecurityPathState};

#[test]
fn one_nonnegative_guard_can_protect_multiple_operations_without_duplicate_ids() {
    let root = support::temp_dir("native-shared-size-guard");
    fs::write(root.join("app.c"), "#include <stdlib.h>\n#include <string.h>\nvoid operation(int count,const char*src){if(count<0)return;char*dst=malloc((size_t)count);memcpy(dst,src,(size_t)count);}").unwrap();
    let inventory = mehscan_engine::investigation::build_review_inventory(&root, false).unwrap();
    let guards = inventory
        .scan
        .evidence
        .iter()
        .filter(|e| e.capability == Capability::NonnegativeSizeValidation)
        .collect::<Vec<_>>();
    assert_eq!(guards.len(), 1);
    assert_eq!(guards[0].related_evidence.len(), 2);
    let protected = inventory
        .scan
        .security_paths
        .iter()
        .filter(|p| {
            p.capability == Capability::SignedSizeMemoryOperation
                && p.state == SecurityPathState::Protected
        })
        .collect::<Vec<_>>();
    assert_eq!(protected.len(), 2);
    assert!(
        protected
            .iter()
            .all(|p| p.protection_evidence_ids == [guards[0].id.clone()])
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn implicit_standard_counts_require_a_visible_signed_scalar_and_unchanged_guard() {
    let root = support::temp_dir("native-implicit-size");
    fs::create_dir_all(&root).unwrap();
    let cases = [
        (
            "implicit",
            "COPY(dst,src,count);",
            Some(SecurityPathState::Unknown),
        ),
        (
            "guarded",
            "if(count<0)return; COPY(dst,src,count);",
            Some(SecurityPathState::Protected),
        ),
        (
            "inner_signed",
            "if(count<0)return; {int count=-1; COPY(dst,src,count);}",
            Some(SecurityPathState::Unknown),
        ),
        (
            "volatile_count",
            "volatile int amount=count; if(amount<0)return; COPY(dst,src,amount);",
            Some(SecurityPathState::Unknown),
        ),
        (
            "volatile_alias",
            "typedef volatile int Counter; typedef Counter Amount; Amount amount=count; if(amount<0)return; COPY(dst,src,amount);",
            Some(SecurityPathState::Unknown),
        ),
        (
            "conditional_exit",
            "if(count<0){if(enabled)return;} COPY(dst,src,count);",
            Some(SecurityPathState::Unknown),
        ),
        (
            "reassigned",
            "if(count<0)return; count=other; COPY(dst,src,count);",
            Some(SecurityPathState::Unknown),
        ),
        (
            "escaped",
            "if(count<0)return; mutate(&count); COPY(dst,src,count);",
            Some(SecurityPathState::Unknown),
        ),
        (
            "inner_unsigned",
            "{unsigned count=1; COPY(dst,src,count);}",
            None,
        ),
        (
            "nested_guard",
            "if(enabled){if(count<0)return;} COPY(dst,src,count);",
            Some(SecurityPathState::Unknown),
        ),
        (
            "signed_alias",
            "Count amount=count; COPY(dst,src,amount);",
            Some(SecurityPathState::Unknown),
        ),
        (
            "unsigned_alias",
            "UnsignedCount amount=other; COPY(dst,src,amount);",
            None,
        ),
        (
            "nominal_only",
            "print_context amount; COPY(dst,src,amount);",
            None,
        ),
        ("pointer", "int *amount=&count; COPY(dst,src,amount);", None),
        (
            "changed_in_branch",
            "if(count>=0){count=other; COPY(dst,src,count);}",
            Some(SecurityPathState::Unknown),
        ),
        (
            "nonrejecting",
            "if(count<0)log_invalid(); COPY(dst,src,count);",
            Some(SecurityPathState::Unknown),
        ),
        (
            "bypassed_guard",
            "if(enabled)goto consume; if(count<0)return; consume: COPY(dst,src,count);",
            Some(SecurityPathState::Unknown),
        ),
        (
            "other_assignment",
            "if(count<0)return; other=count; COPY(dst,src,count);",
            Some(SecurityPathState::Protected),
        ),
        ("count_wrong_role", "COPY(count,src,8);", None),
        (
            "return_logging",
            "if(count<0)return log_error(count); COPY(dst,src,count);",
            Some(SecurityPathState::Protected),
        ),
        (
            "terminating_logging",
            "if(count<0){log_error(count);return;} if(count==0){log_error(count);return;} COPY(dst,src,count);",
            Some(SecurityPathState::Protected),
        ),
        (
            "cleanup_label",
            "if(count<0)return; COPY(dst,src,count); if(enabled)goto cleanup; cleanup: return;",
            Some(SecurityPathState::Protected),
        ),
        (
            "backward_bypass",
            "if(count<0)return; consume: COPY(dst,src,count); count=-1; if(enabled)goto consume;",
            Some(SecurityPathState::Unknown),
        ),
        (
            "overflow_after_guard",
            "if(count>0){count++; COPY(dst,src,count);}",
            Some(SecurityPathState::Unknown),
        ),
        (
            "condition_mutates",
            "if(count<0 || mutate(&count))return; COPY(dst,src,count);",
            Some(SecurityPathState::Unknown),
        ),
        (
            "later_loop_change",
            "if(count<0)return; while(enabled){COPY(dst,src,count); count=-1;}",
            Some(SecurityPathState::Unknown),
        ),
        (
            "unchanged_loop",
            "if(count<0)return; while(enabled){COPY(dst,src,count);}",
            Some(SecurityPathState::Protected),
        ),
        (
            "refreshed_loop_guard",
            "while(enabled){if(count<0)return; COPY(dst,src,count); count=-1;}",
            Some(SecurityPathState::Protected),
        ),
    ];
    for extension in ["c", "cpp"] {
        let operation = if extension == "cpp" {
            "std::memcpy"
        } else {
            "memcpy"
        };
        let mut source = String::from(
            "typedef int Count; typedef unsigned int UnsignedCount; typedef unsigned long size_t;\n",
        );
        for (name, body, _) in &cases {
            source.push_str(&format!(
                "void {name}(char *dst,const char *src,int count,int other,int enabled){{ {} }}\n",
                body.replace("COPY", operation)
            ));
        }
        let file = root.join(format!("counts.{extension}"));
        fs::write(&file, source).unwrap();
        let result = mehscan_engine::scan_path(&file).expect("scan signed counts");
        for (name, _, expected) in &cases {
            let paths = result
                .security_paths
                .iter()
                .filter(|path| {
                    path.capability == Capability::SignedSizeMemoryOperation
                        && result.evidence.iter().any(|e| {
                            e.id == path.sink_evidence_id
                                && e.enclosing_symbol.as_deref() == Some(name)
                        })
                })
                .collect::<Vec<_>>();
            assert_eq!(
                paths.len(),
                usize::from(expected.is_some()),
                "{extension}:{name}"
            );
            if let Some(expected) = expected {
                assert_eq!(&paths[0].state, expected, "{extension}:{name}");
                let source = result
                    .evidence
                    .iter()
                    .find(|e| e.id == paths[0].source_evidence_id)
                    .unwrap();
                assert!(
                    source
                        .tags
                        .iter()
                        .any(|t| t == "signed-size:implicit-standard-count-conversion")
                );
                if *name == "signed_alias" {
                    assert_eq!(
                        source.captures["source_type_definition"].text,
                        "typedef int Count;"
                    );
                }
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}
