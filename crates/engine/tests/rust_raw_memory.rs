mod support;
use std::{fs, path::PathBuf};
struct Project(PathBuf);
impl Project {
    fn new(source: &str) -> Self {
        let root = support::temp_dir("rust-raw-memory");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname=\"raw_memory\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), source).unwrap();
        Self(root)
    }
    fn rules(&self) -> Vec<String> {
        mehscan_engine::investigation::build_review_inventory(&self.0, false)
            .unwrap()
            .entries
            .into_iter()
            .map(|e| e.rule_id)
            .filter(|r| {
                r.starts_with("rust-vector-")
                    || r.starts_with("rust-safe-raw-")
                    || r.starts_with("rust-owned-buffer-")
                    || r.starts_with("rust-raw-copy-")
            })
            .collect()
    }
}
impl Drop for Project {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
const VECTOR: &str = r#"
pub fn transfer(mut source:std::vec::Vec<u8>)->std::vec::Vec<u8>{
 let pointer=source.as_mut_ptr();let length=source.len();let capacity=source.capacity();
 unsafe { std::vec::Vec::from_raw_parts(pointer,length,capacity) }
}
"#;
#[test]
fn reconstructed_vector_roles_and_ownership_are_distinct_questions() {
    let p = Project::new(VECTOR);
    let rules = p.rules();
    assert!(
        rules.contains(&"rust-vector-metadata-review".into()),
        "{rules:?}"
    );
    assert!(
        rules.contains(&"rust-vector-ownership-review".into()),
        "{rules:?}"
    );
    let fixed = Project::new(&VECTOR.replace(" unsafe {", " std::mem::forget(source);\n unsafe {"));
    assert!(
        fixed
            .rules()
            .contains(&"rust-vector-metadata-review".into())
    );
    assert!(
        !fixed
            .rules()
            .contains(&"rust-vector-ownership-review".into())
    );
}
#[test]
fn standard_aliases_work_and_shadowed_sdk_names_do_not_supply_an_operation() {
    let alias = VECTOR
        .replace("pub fn", "use std::vec::Vec as Buffer;pub fn")
        .replace("std::vec::Vec", "Buffer")
        .replacen("use Buffer as Buffer;", "use std::vec::Vec as Buffer;", 1);
    assert_eq!(Project::new(&alias).rules().len(), 2);
    for source in [
        VECTOR.replace("std::vec::Vec::from_raw_parts", "Foreign::from_raw_parts"),
        format!("mod std{{pub mod vec{{pub struct Vec<T>(T);}}}}\n{VECTOR}"),
        VECTOR.replace(" unsafe {", " return source;\n unsafe {"),
        format!("#[cfg(any())]\n{VECTOR}"),
        format!("#[cfg(test)] mod hidden {{{VECTOR}}}"),
    ] {
        assert!(Project::new(&source).rules().is_empty(), "{source}");
    }
}
#[test]
fn safe_pointer_and_slice_boundaries_keep_checks_for_review_and_unsafe_contracts_separate() {
    for source in [
        "pub fn read<'a>(p:*const u8,n:usize)->&'a[u8]{unsafe{std::slice::from_raw_parts(p,n)}}",
        "pub fn read(s:&[u8],n:usize)->&[u8]{unsafe{std::slice::from_raw_parts(s.as_ptr(),n)}}",
        "pub fn read(s:&[u8],n:usize)->&[u8]{if n>s.len(){return &[];}unsafe{std::slice::from_raw_parts(s.as_ptr(),n)}}",
    ] {
        assert_eq!(
            Project::new(source).rules(),
            vec!["rust-safe-raw-memory-boundary-review"],
            "{source}"
        );
    }
    assert!(
        Project::new(
            "pub unsafe fn read<'a>(p:*const u8,n:usize)->&'a[u8]{std::slice::from_raw_parts(p,n)}"
        )
        .rules()
        .is_empty()
    );
}
#[test]
fn raw_copy_extent_and_owned_value_copy_have_separate_obligations() {
    let ranges = "pub fn copy(s:&[u8],d:&mut[u8],n:usize){unsafe{std::ptr::copy_nonoverlapping(s.as_ptr(),d.as_mut_ptr(),n)}}";
    assert_eq!(
        Project::new(ranges).rules(),
        vec!["rust-raw-copy-range-review"]
    );
    let owned = "pub fn duplicate<T>(source:Vec<T>,mut target:Vec<T>)->Vec<T>{unsafe{std::ptr::copy_nonoverlapping(source.as_ptr(),target.as_mut_ptr(),source.len());target.set_len(source.len());}target}";
    assert!(
        Project::new(owned)
            .rules()
            .contains(&"rust-owned-buffer-copy-review".into())
    );
    assert!(
        !Project::new(&owned.replace(
            "std::ptr::copy_nonoverlapping",
            "foreign::copy_nonoverlapping"
        ))
        .rules()
        .contains(&"rust-owned-buffer-copy-review".into())
    );
}
#[test]
fn generic_retyping_keeps_layout_and_manually_dropped_owner_evidence() {
    let source = "pub fn bytes<T:Copy>(source:Vec<T>)->Vec<u8>{let mut source=std::mem::ManuallyDrop::new(source);unsafe{Vec::from_raw_parts(source.as_mut_ptr() as *mut u8,source.len()*std::mem::size_of::<T>(),source.capacity()*std::mem::size_of::<T>())}}";
    let rules = Project::new(source).rules();
    assert!(
        rules.contains(&"rust-vector-metadata-review".into()),
        "{rules:?}"
    );
    assert!(
        rules.contains(&"rust-vector-layout-review".into()),
        "{rules:?}"
    );
    assert!(
        !rules.contains(&"rust-vector-ownership-review".into()),
        "{rules:?}"
    );
}
#[test]
fn source_coordinates_and_bytes_survive_unicode_crlf_and_context_pooling() {
    let source = VECTOR.replace("source", "données").replace('\n', "\r\n");
    let p = Project::new(&source);
    let job = mehscan_engine::investigation::build_all_path_review_jobs(&p.0, None, false).unwrap();
    let mut captures = 0;
    for review in job.observation_reviews {
        for fact in review
            .evidence
            .into_iter()
            .filter(|e| e.capability == mehscan_core::Capability::RustRawMemoryReview)
        {
            for capture in fact.captures.values() {
                let bytes = fs::read(p.0.join(&capture.location.path)).unwrap();
                assert_eq!(
                    &bytes[capture.location.start.byte_offset..capture.location.end.byte_offset],
                    capture.text.as_bytes()
                );
                captures += 1;
            }
        }
    }
    assert!(captures >= 4);
}

#[test]
fn ownership_suppression_follows_the_original_binding_across_moves_and_rebinding() {
    for insertion in [
        "let source=std::vec::Vec::<u8>::new();std::mem::forget(source);",
        "source=std::vec::Vec::<u8>::new();std::mem::forget(source);",
        "let other=std::vec::Vec::<u8>::new();let source=std::mem::ManuallyDrop::new(other);",
        "let mut holder=std::mem::ManuallyDrop::new(source);unsafe{std::mem::ManuallyDrop::drop(&mut holder);}",
    ] {
        let source = VECTOR.replace(" unsafe {", &format!(" {insertion}\n unsafe {{"));
        assert!(
            Project::new(&source)
                .rules()
                .contains(&"rust-vector-ownership-review".into()),
            "{source}"
        );
    }
    for insertion in [
        "let moved=source;std::mem::forget(moved);",
        "let holder=std::mem::ManuallyDrop::new(source);",
    ] {
        let source = VECTOR.replace(" unsafe {", &format!(" {insertion}\n unsafe {{"));
        assert!(
            !Project::new(&source)
                .rules()
                .contains(&"rust-vector-ownership-review".into()),
            "{source}"
        );
    }
}

#[test]
fn local_standard_constructors_are_bound_and_dead_or_foreign_uses_are_not() {
    let source = "pub fn clone_owner()->Vec<u8>{let mut data=Vec::<u8>::with_capacity(8);unsafe{Vec::from_raw_parts(data.as_mut_ptr(),0,data.capacity())}}";
    assert!(
        Project::new(source)
            .rules()
            .contains(&"rust-vector-ownership-review".into())
    );
    let conditional = "pub fn read<'a>(p:*const u8,n:usize)->&'a[u8]{if false{unsafe{std::slice::from_raw_parts(p,n)}}else{&[]}}";
    assert!(Project::new(conditional).rules().is_empty());
    let shadow = VECTOR
        .replace("pub fn", "struct Foreign;pub fn")
        .replace("source:std::vec::Vec<u8>", "source:Foreign")
        .replace(
            " let pointer",
            " if false{let source:std::vec::Vec<u8>=std::vec::Vec::new();}\n let pointer",
        );
    assert!(Project::new(&shadow).rules().is_empty());
}

#[test]
fn copy_helper_binding_and_drop_identity_are_required() {
    let source = r#"
fn duplicate(value:&[u8])->*mut u8{let p=std::ptr::null_mut();unsafe{std::ptr::copy_nonoverlapping(value.as_ptr(),p,value.len());}p}
struct Storage{pointer:*mut u8}
impl Storage{fn new(value:std::boxed::Box<[u8]>)->Self{let p=duplicate(&value);Self{pointer:p}}}
impl Drop for Storage{fn drop(&mut self){}}
"#;
    assert!(
        Project::new(source)
            .rules()
            .contains(&"rust-owned-buffer-copy-review".into())
    );
    for variant in [
        source.replace(
            "fn new(value:std::boxed::Box<[u8]>)",
            "fn new(value:std::boxed::Box<[u8]>,duplicate:fn(&[u8])->*mut u8)",
        ),
        source.replace(
            "let p=duplicate(&value);",
            "let duplicate=external;let p=duplicate(&value);",
        ),
        format!("#![no_implicit_prelude]\n{source}"),
        format!("use foreign::*;\n{source}"),
        source.replace(
            "impl Drop for Storage{fn drop(&mut self){}}",
            "mod another{struct Storage;impl Drop for Storage{fn drop(&mut self){}}}",
        ),
    ] {
        assert!(
            !Project::new(&variant)
                .rules()
                .contains(&"rust-owned-buffer-copy-review".into()),
            "{variant}"
        );
    }
}
