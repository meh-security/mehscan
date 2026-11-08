mod support;
use std::fs;
fn assess(source: &str) -> Vec<String> {
    let root = support::temp_dir("thread-safety-obligations");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname=\"thread_obligations\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), source).unwrap();
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, false).unwrap();
    let mut out = Vec::new();
    for r in &jobs.observation_reviews {
        for e in r
            .evidence
            .iter()
            .filter(|e| e.rule_id == "rust-thread-safety-implementation-review")
        {
            assert_eq!(
                r.review_basis.as_ref().unwrap().relationship,
                "bounded_rust_thread_safety_review"
            );
            for c in e.captures.values() {
                assert_eq!(
                    &source.as_bytes()[c.location.start.byte_offset..c.location.end.byte_offset],
                    c.text.as_bytes()
                );
            }
            out.push(e.enclosing_symbol.clone().unwrap());
        }
    }
    fs::remove_dir_all(root).unwrap();
    out.sort();
    out
}
#[test]
fn generic_fields_and_interior_mutability_keep_bounds_for_review() {
    let source = r#"
pub struct Loose<T>{pub value:T}
unsafe impl<T> Send for Loose<T>{}
pub struct Bounded<T>{pub value:T}
unsafe impl<T:Send> Send for Bounded<T>{}
pub struct Shared{pub value:std::cell::Cell<u32>}
unsafe impl Sync for Shared{}
pub struct Fixed{pub value:u32}
unsafe impl Send for Fixed{}
"#;
    assert_eq!(assess(source), ["Bounded<T>", "Loose<T>", "Shared"]);
}
#[test]
fn foreign_traits_and_excluded_or_unrelated_storage_do_not_borrow_standard_identity() {
    assert!(
        assess(
            r#"
unsafe trait Send{}pub struct Holder<T>{pub value:T}unsafe impl<T> Send for Holder<T>{}
"#
        )
        .is_empty()
    );
    assert!(assess(r#"
#[cfg(test)]pub struct Test<T>{pub value:T}#[cfg(test)]unsafe impl<T> std::marker::Send for Test<T>{}
struct Other<T>{value:T}struct Plain{value:u32}unsafe impl std::marker::Sync for Plain{}
"#).is_empty());
    assert_eq!(
        assess(
            "use std::marker::Sync as Share;pub struct Cell{value:std::cell::UnsafeCell<u32>}unsafe impl Share for Cell{}"
        ),
        ["Cell"]
    );
}
