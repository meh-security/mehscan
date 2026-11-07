mod support;
use std::fs;
fn assess(source: &str) -> Vec<String> {
    let root = support::temp_dir("panic-cleanup-obligation");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname=\"panic_cleanup\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), source).unwrap();
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, false).unwrap();
    let mut out = Vec::new();
    for r in &jobs.observation_reviews {
        for e in r.evidence.iter().filter(|e| {
            matches!(
                e.rule_id.as_str(),
                "rust-panic-cleanup-metadata-review" | "rust-panic-cleanup-helper-review"
            )
        }) {
            assert_eq!(
                r.review_basis.as_ref().unwrap().relationship,
                "bounded_rust_panic_cleanup_review"
            );
            assert!(e.captures.contains_key("owner_destructor"));
            if e.rule_id == "rust-panic-cleanup-helper-review" {
                for name in [
                    "guard_destructor",
                    "destruction_helper",
                    "metadata_assignment_00",
                    "cleanup_binding_00",
                ] {
                    assert!(e.captures.contains_key(name), "missing {name}");
                }
            }
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
fn same_owner_raw_destruction_preserves_metadata_order_and_drop() {
    let source = r#"
pub struct Store<T>{data:*mut T,live:usize}
impl<T> Store<T>{pub fn late(&mut self){unsafe{std::ptr::drop_in_place(self.data);}self.live=0;}
pub fn early(&mut self){self.live=0;unsafe{std::ptr::drop_in_place(self.data);}}}
impl<T> Drop for Store<T>{fn drop(&mut self){if self.live>0{unsafe{std::ptr::drop_in_place(self.data);}}}}
"#;
    assert_eq!(assess(source), ["early", "late"]);
}
#[test]
fn unrelated_metadata_and_custom_drop_spellings_do_not_supply_the_obligation() {
    let source = r#"
pub struct Store<T>{data:*mut T,live:usize}
impl<T> Store<T>{pub fn foreign(&mut self){custom::drop_in_place(self.data);self.live=0;}
pub fn different(&mut self,other:*mut T){unsafe{std::ptr::drop_in_place(other);}self.live=0;}}
impl<T> Drop for Store<T>{fn drop(&mut self){}}
mod custom{pub fn drop_in_place<T>(_:*mut T){}}
"#;
    assert!(assess(source).is_empty());
}

#[test]
fn scoped_destruction_helper_connects_late_updates_to_safe_callers() {
    let source = r#"
use core::{mem::MaybeUninit, ptr};
struct Part<T> { live: usize, items: [MaybeUninit<T>; 4] }
struct Queue<T> { storage: Part<T>, other: Part<T> }
impl<T> Queue<T> {
    unsafe fn release(&mut self, end: usize) {
        struct Hold<'a, T>(&'a mut [MaybeUninit<T>]);
        impl<T> Drop for Hold<'_, T> {
            fn drop(&mut self) { unsafe { ptr::drop_in_place(self.0.assume_init_mut()); } }
        }
        let (slice, _other) = if end > 0 {
            (&mut self.storage.items[..end], 0)
        } else {
            (&mut self.storage.items[..0], 0)
        };
        let _hold = Hold(slice);
    }
    fn truncate(&mut self) {
        let end = self.storage.live;
        unsafe { self.release(end) };
        self.storage.live = 0;
    }
    fn clear(&mut self) { self.truncate(); }
    fn refill(&mut self) { self.clear(); }
    fn other(&mut self) {
        let end = self.other.live;
        unsafe { self.release(end) };
        self.other.live = 0;
    }
}
impl<T> Drop for Queue<T> { fn drop(&mut self) { self.clear(); } }
"#;
    assert_eq!(assess(source), ["clear", "refill", "truncate"]);
    for control in [
        source.replace(
            "let _hold = Hold(slice);",
            "self.storage.live = 0; let _hold = Hold(slice);",
        ),
        source.replace(
            "let _hold = Hold(slice);",
            "let hold = Hold(slice); core::mem::forget(hold);",
        ),
        source.replace(
            "ptr::drop_in_place(self.0.assume_init_mut());",
            "if false { ptr::drop_in_place(self.0.assume_init_mut()); }",
        ),
    ] {
        assert!(assess(&control).is_empty());
    }
}
