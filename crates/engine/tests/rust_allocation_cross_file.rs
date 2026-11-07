mod support;
use std::{fs, path::PathBuf};

const MANIFEST: &str = "[package]\nname=\"module_witness\"\nversion=\"0.1.0\"\nedition=\"2021\"\n";

struct Fixture(PathBuf);
impl Fixture {
    fn new(files: &[(&str, &str)]) -> Self {
        let root = support::temp_dir("allocation-module-witness");
        fs::write(root.join("Cargo.toml"), MANIFEST).unwrap();
        for (path, source) in files {
            let file = root.join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, source).unwrap();
        }
        Self(root)
    }
    fn symbols(&self) -> Vec<String> {
        let inventory =
            mehscan_engine::investigation::build_review_inventory(&self.0, false).unwrap();
        let mut symbols = inventory
            .entries
            .into_iter()
            .filter(|e| e.rule_id == "rust-allocation-extent-review")
            .filter_map(|e| e.symbol)
            .collect::<Vec<_>>();
        symbols.sort();
        symbols
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn declared_modules_follow_reexported_fields_helpers_and_impl_owners() {
    let repo = Fixture::new(&[
        ("src/lib.rs", "mod buffers; mod api; pub mod operations;"),
        (
            "src/buffers.rs",
            "pub use std::vec::Vec as Storage;pub type Bytes=Storage<u8>;pub struct Decoder{pub pending:Bytes}pub fn make()->Bytes{Vec::new()}",
        ),
        (
            "src/api.rs",
            "pub use super::buffers::{Decoder as Shared,make as create};",
        ),
        (
            "src/operations.rs",
            r#"
use crate::api::{Shared as Decoder,create as buffer};
pub fn field(d:&mut Decoder,n:usize){d.pending.reserve(n);}
pub fn helper(n:usize){let mut v=buffer();v.resize(n,0);}
impl crate::buffers::Decoder {pub fn own(&mut self,n:usize){let _=self.pending.try_reserve(n);}}
pub fn bounded(d:&mut Decoder,n:usize){if n>32{return;}d.pending.reserve(n);}
struct Foreign;impl Foreign{fn reserve(&mut self,_:usize){}}
struct Other{pending:Foreign}
fn different(d:&mut Other,n:usize){d.pending.reserve(n);}
"#,
        ),
    ]);
    assert_eq!(repo.symbols(), ["bounded", "field", "helper", "own"]);
}

#[test]
fn nested_files_inline_modules_and_logical_super_keep_their_actual_parent() {
    let repo = Fixture::new(&[
        (
            "src/lib.rs",
            r#"mod outer;mod facade{pub mod storage;}pub struct Root{pub bytes:Vec<u8>}
pub fn inline(v:&mut facade::storage::Bytes,n:usize){v.reserve(n);}"#,
        ),
        (
            "src/outer.rs",
            "pub mod nested;pub fn child(s:&mut nested::State,n:usize){s.bytes.reserve(n);}",
        ),
        (
            "src/outer/nested/mod.rs",
            "pub struct State{pub bytes:Vec<u8>}pub fn ancestor(s:&mut super::super::Root,n:usize){s.bytes.reserve(n);}",
        ),
        ("src/facade/storage.rs", "pub type Bytes=Vec<u8>;"),
    ]);
    assert_eq!(repo.symbols(), ["ancestor", "child", "inline"]);
}

#[test]
fn custom_target_and_literal_path_bind_physical_files_to_logical_names() {
    let manifest = format!("{MANIFEST}\n[lib]\npath=\"entry/root.rs\"\n");
    let repo = Fixture::new(&[
        ("Cargo.toml", &manifest),
        (
            "entry/root.rs",
            r#"#[path="impls/real state.rs"] mod model;
pub fn grow(s:&mut crate::model::Owner,n:usize){s.bytes.reserve(n);}"#,
        ),
        (
            "entry/impls/real state.rs",
            "mod types;pub struct Owner{pub bytes:self::types::Bytes}",
        ),
        ("entry/impls/types.rs", "pub type Bytes=Vec<u8>;"),
        ("entry/model.rs", "pub struct Owner{pub bytes:u8}"),
    ]);
    assert_eq!(repo.symbols(), ["grow"]);
}

#[test]
fn binary_and_neighbor_package_roots_do_not_borrow_library_types() {
    let repo = Fixture::new(&[
        (
            "src/lib.rs",
            "pub mod lib_ops;pub struct State{pub bytes:Vec<u8>}",
        ),
        (
            "src/lib_ops.rs",
            "pub fn library(s:&mut crate::State,n:usize){s.bytes.reserve(n);}",
        ),
        (
            "src/main.rs",
            "mod bin_ops;pub struct State{pub bytes:Foreign}pub struct Foreign;impl Foreign{pub fn reserve(&mut self,_:usize){}}fn main(){}",
        ),
        (
            "src/bin_ops.rs",
            "pub fn binary(s:&mut crate::State,n:usize){s.bytes.reserve(n);}",
        ),
        ("neighbor/Cargo.toml", MANIFEST),
        (
            "neighbor/src/lib.rs",
            "pub mod ops;pub struct State{pub bytes:Other}pub struct Other;impl Other{pub fn reserve(&mut self,_:usize){}}",
        ),
        (
            "neighbor/src/ops.rs",
            "pub fn sibling(s:&mut crate::State,n:usize){s.bytes.reserve(n);}",
        ),
    ]);
    assert_eq!(repo.symbols(), ["library"]);
}

#[test]
fn explicit_route_can_select_a_shared_file_but_an_ambiguous_caller_cannot() {
    let repo = Fixture::new(&[
        (
            "src/lib.rs",
            "mod shared;pub struct State{pub bytes:Vec<u8>}pub fn explicit(s:&mut shared::Record,n:usize){s.bytes.reserve(n);}",
        ),
        (
            "src/main.rs",
            "mod shared;pub struct State{pub bytes:Foreign}pub struct Foreign;impl Foreign{pub fn reserve(&mut self,_:usize){}}fn main(){}",
        ),
        (
            "src/shared.rs",
            "pub struct Record{pub bytes:Vec<u8>}pub fn ambiguous(s:&mut crate::State,n:usize){s.bytes.reserve(n);}",
        ),
    ]);
    assert_eq!(repo.symbols(), ["explicit"]);
}

#[test]
fn unresolved_duplicate_disabled_and_transformed_modules_never_guess_by_filename() {
    let repo = Fixture::new(&[
        (
            "src/lib.rs",
            r#"
mod duplicate;
#[cfg_attr(feature="other",path="other.rs")] mod opaque;
#[cfg(any())] mod disabled;
#[path="lib.rs"] mod cycle;
#[path=concat!("orphan.rs")] mod generated;
pub type Bytes=Vec<u8>;
pub fn double(v:&mut duplicate::Bytes,n:usize){v.reserve(n);}
pub fn conditional_path(v:&mut opaque::Bytes,n:usize){v.reserve(n);}
pub fn excluded(v:&mut disabled::Bytes,n:usize){v.reserve(n);}
pub fn cyclic(v:&mut cycle::Bytes,n:usize){v.reserve(n);}
pub fn missing(v:&mut orphan::Bytes,n:usize){v.reserve(n);}
pub fn transformed(v:&mut generated::Bytes,n:usize){v.reserve(n);}
"#,
        ),
        ("src/duplicate.rs", "pub type Bytes=Vec<u8>;"),
        ("src/duplicate/mod.rs", "pub type Bytes=Vec<u8>;"),
        ("src/opaque.rs", "pub type Bytes=Vec<u8>;"),
        ("src/other.rs", "pub type Bytes=Vec<u8>;"),
        ("src/disabled.rs", "pub type Bytes=Vec<u8>;"),
        ("src/orphan.rs", "pub type Bytes=Vec<u8>;"),
    ]);
    assert!(repo.symbols().is_empty());
}

#[test]
fn local_patterns_hide_a_cross_file_receiver_until_an_inner_rebinding() {
    let repo = Fixture::new(&[
        ("src/lib.rs", "mod buffers;pub mod operations;"),
        ("src/buffers.rs", "pub fn create()->Vec<u8>{Vec::new()}"),
        (
            "src/operations.rs",
            r#"
use crate::buffers::create;
struct Foreign;impl Foreign{fn reserve(&mut self,_:usize){}}
pub fn for_shadow(n:usize){let v=create();for mut v in [Foreign]{v.reserve(n);}}
pub fn if_shadow(n:usize){let v=create();if let Some(mut v)=Some(Foreign){v.reserve(n);}}
pub fn match_shadow(n:usize){let v=create();match Some(Foreign){Some(mut v)=>v.reserve(n),None=>{}}}
pub fn rebound(n:usize){let v=create();for mut v in [Foreign]{let mut v=create();v.reserve(n);}}
pub fn else_branch(n:usize){let mut v=create();if let Some(mut v)=None::<Foreign>{v.reserve(n);}else{v.reserve(n);}}
"#,
        ),
    ]);
    assert_eq!(repo.symbols(), ["else_branch", "rebound"]);
}

#[test]
fn cross_file_proof_keeps_conditions_and_original_bytes_in_bundles() {
    let repo = Fixture::new(&[
        (
            "src/lib.rs",
            "#[cfg(feature=\"buffers\")] mod storage;\r\npub mod operations;\r\n",
        ),
        (
            "src/storage.rs",
            "pub type Bytes=Vec<u8>;\r\npub fn create()->Bytes{Vec::new()}\r\n",
        ),
        (
            "src/operations.rs",
            "use crate::storage::create as storage;\r\npub fn grow(données:usize){\r\nif données>64{return;}\r\nstorage().reserve(données);\r\n}\r\n",
        ),
    ]);
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&repo.0, None, false).unwrap();
    let review = job
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence
                .iter()
                .any(|e| e.rule_id == "rust-allocation-extent-review")
        })
        .unwrap();
    let evidence = review
        .evidence
        .iter()
        .find(|e| e.rule_id == "rust-allocation-extent-review")
        .unwrap();
    assert_eq!(evidence.location.path, "src/operations.rs");
    assert_eq!(
        evidence.context.availability.as_ref().unwrap().state,
        mehscan_core::AvailabilityState::Conditional
    );
    assert!(
        evidence
            .context
            .configuration_dependencies
            .iter()
            .any(|d| d.declaration.text.contains("buffers"))
    );
    let support = evidence
        .captures
        .iter()
        .filter(|(k, _)| k.starts_with("allocation_type_support_"))
        .map(|(_, v)| v)
        .collect::<Vec<_>>();
    for (path, text) in [
        ("src/lib.rs", "mod storage;"),
        ("src/storage.rs", "pub fn create()->Bytes{Vec::new()}"),
        (
            "src/operations.rs",
            "use crate::storage::create as storage;",
        ),
    ] {
        assert!(
            support
                .iter()
                .any(|c| c.location.path == path && c.text == text),
            "missing {path}: {text}"
        );
    }
    assert!(support.iter().any(|c| c.location.path == "Cargo.toml"));
    for c in evidence.captures.values() {
        let bytes = fs::read(repo.0.join(&c.location.path)).unwrap();
        assert_eq!(
            &bytes[c.location.start.byte_offset..c.location.end.byte_offset],
            c.text.as_bytes()
        );
    }
    let bundle = mehscan_engine::investigation::build_path_review_bundles(&job, None).unwrap();
    assert!(bundle.bundles.iter().any(|b| {
        b.review_playbooks
            .get(&review.id)
            .is_some_and(|p| p.bucket == "resource_boundary")
    }));
}
