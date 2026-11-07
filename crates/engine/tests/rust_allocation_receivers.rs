mod support;
use std::fs;

fn review(source: &str) -> Vec<String> {
    let root = support::temp_dir("allocation-receivers");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname=\"receiver_cases\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), source).unwrap();
    let inventory = mehscan_engine::investigation::build_review_inventory(&root, false).unwrap();
    let mut result = inventory
        .entries
        .into_iter()
        .filter(|e| e.rule_id == "rust-allocation-extent-review")
        .filter_map(|e| e.symbol)
        .collect::<Vec<_>>();
    result.sort();
    fs::remove_dir_all(root).unwrap();
    result
}

#[test]
fn named_fields_self_aliases_and_nested_records_witness_vector_growth() {
    assert_eq!(
        review(
            r#"
use std::vec::Vec as Storage;
type Payload = Storage<u8>;
pub struct Decoder { pending: Payload }
pub struct Envelope { decoder: Decoder }
impl Decoder {
 pub fn own(&mut self, n:usize) { self.pending.reserve(n); }
 pub fn guarded(&mut self, n:usize) { if n>1024{return;} self.pending.resize(n,0); }
}
pub fn field(d:&mut Decoder,n:usize) { d.pending.try_reserve(n); }
pub fn renamed(d:&mut Decoder,n:usize) { let x=d; x.pending.reserve_exact(n); }
pub fn nested(e:&mut Envelope,n:usize) { e.decoder.pending.resize_with(n,||0); }
pub fn referenced(d:&mut Decoder,n:usize) { (&mut d.pending).reserve(n); }
pub fn fixed(d:&mut Decoder,_n:usize) { d.pending.reserve(16); }
"#
        ),
        ["field", "guarded", "nested", "own", "referenced", "renamed"]
    );
}

#[test]
fn explicit_free_helper_return_types_survive_local_bindings_and_field_access() {
    assert_eq!(
        review(
            r#"
type Bytes = Vec<u8>;
pub struct State { bytes: Bytes }
fn create() -> Bytes { Vec::new() }
fn borrow(v:&mut Bytes) -> &mut Bytes { v }
fn state() -> State { State { bytes:Vec::new() } }
pub fn direct(n:usize) { create().reserve(n); }
pub fn local(n:usize) { let mut v=create(); v.reserve(n); }
pub fn returned_field(n:usize) { state().bytes.reserve(n); }
pub fn borrowed(v:&mut Bytes,n:usize) { borrow(v).resize(n,0); }
pub fn typed(n:usize) { let mut v:Bytes=Default::default(); v.reserve(n); }
pub fn local_helper(n:usize) { fn allocate()->Vec<u8>{Vec::new()} allocate().reserve(n); }
"#
        ),
        [
            "borrowed",
            "direct",
            "local",
            "local_helper",
            "returned_field",
            "typed"
        ]
    );
}

#[test]
fn inline_module_import_aliases_and_reexports_keep_the_declared_owner() {
    assert_eq!(
        review(
            r#"
mod model {
 pub use std::vec::Vec as Storage;
 pub type Bytes = Storage<u8>;
 pub struct State { pub bytes: Bytes }
 pub fn make() -> Bytes { Vec::new() }
 pub mod inner {
  use super::State as Parent;
  pub fn child(s:&mut Parent,n:usize) { s.bytes.reserve(n); }
 }
}
use crate::model::{State as Decoder, make as create};
pub fn outer(s:&mut Decoder,n:usize) { s.bytes.reserve(n); }
pub fn imported(n:usize) { create().reserve(n); }
pub fn reexport(v:&mut model::Storage<u8>,n:usize) { v.reserve(n); }
mod other {
 pub struct State { pub bytes: Foreign }
 pub struct Foreign;
 impl Foreign { pub fn reserve(&mut self,_:usize){} }
 pub fn foreign(s:&mut State,n:usize) { s.bytes.reserve(n); }
}
"#
        ),
        ["child", "imported", "outer", "reexport"]
    );
}

#[test]
fn foreign_fields_closures_generics_deref_and_async_do_not_borrow_vector_types() {
    assert_eq!(
        review(
            r#"
pub struct Foreign;
impl Foreign { pub fn reserve(&mut self,_:usize){} }
pub struct State<T> { pub bytes:T }
fn create()->Vec<u8>{Vec::new()}
pub fn field(s:&mut State<Foreign>,n:usize){s.bytes.reserve(n);}
pub fn generic<T>(s:&mut State<T>,n:usize){s.bytes.reserve(n);}
pub fn closure(n:usize){let create=||Foreign;create().reserve(n);}
pub fn argument(create:fn()->Foreign,n:usize){create().reserve(n);}
pub fn destructured(n:usize){let (create,)=(||Foreign,);create().reserve(n);}
pub struct Owner { bytes:Vec<u8> }
pub fn deref(s:&mut Box<Owner>,n:usize){s.bytes.reserve(n);}
pub async fn deferred()->Vec<u8>{Vec::new()}
pub async fn future(n:usize){let mut v=deferred().await;v.reserve(n);}
pub fn reassigned(n:usize){let mut v=create();v=Vec::new();v.reserve(n);}
"#
        ),
        Vec::<String>::new()
    );
}

#[test]
fn nearer_scopes_and_duplicate_or_cyclic_aliases_stay_unresolved() {
    assert_eq!(
        review(
            r#"
use std::vec::Vec as Buffer;
struct Foreign;
impl Foreign{fn reserve(&mut self,_:usize){}}
pub fn block(n:usize){type Buffer=Foreign;let mut v:Buffer=Foreign;v.reserve(n);}
mod inner {
 pub struct Buffer;
 impl Buffer { pub fn reserve(&mut self,_:usize){} }
 pub fn make()->Buffer{Buffer}
 pub fn shadow(n:usize){make().reserve(n);}
}
type CycleA=CycleB;
type CycleB=CycleA;
pub fn cycle(v:&mut CycleA,n:usize){v.reserve(n);}
#[cfg(feature="one")] type Both=Vec<u8>;
#[cfg(not(feature="one"))] type Both=Foreign;
pub fn ambiguous(v:&mut Both,n:usize){v.reserve(n);}
#[cfg(any())] use std::vec::Vec as Disabled;
pub fn excluded(v:&mut Disabled<u8>,n:usize){v.reserve(n);}
pub fn excluded_constructor(n:usize){let mut v=Disabled::<u8>::new();v.reserve(n);}
"#
        ),
        Vec::<String>::new()
    );
}

#[test]
fn field_and_helper_configuration_is_retained_and_excluded_definitions_are_not_used() {
    assert_eq!(
        review(
            r#"
pub struct State { #[cfg(any())] bytes:Vec<u8> }
pub fn disabled_field(s:&mut State,n:usize){s.bytes.reserve(n);}
#[cfg(any())] fn disabled()->Vec<u8>{Vec::new()}
pub fn disabled_helper(n:usize){disabled().reserve(n);}
#[cfg(feature="buffers")] type Bytes=Vec<u8>;
pub fn conditional(v:&mut Bytes,n:usize){v.reserve(n);}
#[cfg(test)] fn only_test()->Vec<u8>{Vec::new()}
pub fn test_helper(n:usize){only_test().reserve(n);}
"#
        ),
        ["conditional"]
    );
}

#[test]
fn a_nested_file_named_lib_does_not_lend_its_record_to_the_crate_root() {
    let root = support::temp_dir("allocation-crate-owner");
    fs::create_dir_all(root.join("src/nested")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname=\"crate_owner\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), "pub mod nested;pub struct State{pub bytes:Foreign}pub struct Foreign;impl Foreign{pub fn reserve(&mut self,_:usize){}}\n").unwrap();
    fs::write(root.join("src/nested.rs"), "pub mod lib;\n").unwrap();
    fs::write(root.join("src/nested/lib.rs"), "pub struct State{pub bytes:Vec<u8>}pub fn grow(s:&mut crate::State,n:usize){s.bytes.reserve(n);}\n").unwrap();
    let inventory = mehscan_engine::investigation::build_review_inventory(&root, false).unwrap();
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| e.rule_id == "rust-allocation-extent-review")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn receiver_declaration_conditions_gate_the_allocation_question() {
    let root = support::temp_dir("allocation-type-configuration");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname=\"receiver_configuration\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), "#[cfg(feature=\"buffers\")] type Bytes=Vec<u8>;\nstruct State{bytes:Bytes}\npub fn grow(s:&mut State,n:usize){s.bytes.reserve(n);}\n").unwrap();
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, false).unwrap();
    let evidence = job
        .observation_reviews
        .iter()
        .flat_map(|r| &r.evidence)
        .find(|e| e.rule_id == "rust-allocation-extent-review")
        .unwrap();
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
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn provenance_captures_are_original_bytes_and_reach_the_review_bundle() {
    let root = support::temp_dir("allocation-type-evidence");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname=\"receiver_evidence\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    let source = "use std::vec::Vec as Storage;\r\ntype Bytes=Storage<u8>;\r\nfn create()->Bytes { Vec::new() }\r\npub fn grow(données:usize) {\r\nif données>1024{return;}\r\nlet mut pending=create();pending.reserve(données);\r\n}\r\n";
    fs::write(root.join("src/lib.rs"), source).unwrap();
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, false).unwrap();
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
    assert_eq!(evidence.captures["allocation_receiver"].text, "pending");
    let support = evidence
        .captures
        .iter()
        .filter(|(k, _)| k.starts_with("allocation_type_support_"))
        .map(|(_, v)| v.text.as_str())
        .collect::<Vec<_>>();
    for expected in [
        "use std::vec::Vec as Storage;",
        "type Bytes=Storage<u8>;",
        "fn create()->Bytes { Vec::new() }",
    ] {
        assert!(
            support.contains(&expected),
            "missing {expected}: {support:?}"
        );
    }
    assert!(
        evidence.captures["allocation_definition"]
            .text
            .contains("if données>1024")
    );
    for capture in evidence.captures.values() {
        assert_eq!(capture.location.path, "src/lib.rs");
        assert_eq!(
            &source.as_bytes()
                [capture.location.start.byte_offset..capture.location.end.byte_offset],
            capture.text.as_bytes()
        );
    }
    let bundles = mehscan_engine::investigation::build_path_review_bundles(&job, None).unwrap();
    assert!(bundles.bundles.iter().any(|b| {
        b.review_playbooks
            .get(&review.id)
            .is_some_and(|p| p.bucket == "resource_boundary")
    }));
    fs::remove_dir_all(root).unwrap();
}
