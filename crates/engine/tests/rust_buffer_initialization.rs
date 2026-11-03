use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

const SOURCE: &str = r#"
extern crate std;
pub unsafe trait Region {
 fn valid(&self)->&[u8]; fn reserved(&self)->usize;
 fn address(&mut self)->*mut u8; unsafe fn expose(&mut self, upper:usize);
}
unsafe impl Region for std::vec::Vec<u8> {
 fn valid(&self)->&[u8] { &self[..] }
 fn reserved(&self)->usize { self.capacity() }
 fn address(&mut self)->*mut u8 { self.as_mut_ptr() }
 unsafe fn expose(&mut self,upper:usize) { self.set_len(upper); }
}
pub struct Window<'a,B:Region+?Sized> { bytes:&'a mut B, offset:usize }
struct Raw { target:*mut u8, extent:usize, position:usize }
struct Carrier<'a,'b,B:Region+?Sized> { wire:Raw, owner:&'a mut Window<'b,B> }
impl<'a,B:Region+?Sized> Window<'a,B> {
 pub fn begin(bytes:&'a mut B,offset:usize)->Self {
  if offset>bytes.reserved() { panic!("capacity"); }
  Self { bytes,offset }
 }
 unsafe fn publish(&mut self,new:usize) { self.bytes.expose(new);self.offset=new; }
 fn bridge<'b>(&'b mut self)->Carrier<'b,'a,B> {
  Carrier { wire:Raw { target:self.bytes.address(),extent:self.bytes.reserved(),position:self.offset },owner:self }
 }
}
impl<'a,'b,B:Region+?Sized> Drop for Carrier<'a,'b,B> {
 fn drop(&mut self) { unsafe {self.owner.publish(self.wire.position);} }
}
pub fn flush<B:Region+?Sized>(window:&mut Window<'_,B>) { let _carrier=window.bridge(); }
"#;

struct Project(PathBuf);
impl Project {
    fn new(source: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "mehscan-buffer-prefix-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname=\"buffer_prefix\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), source).unwrap();
        Self(root)
    }
    fn count(&self) -> usize {
        mehscan_engine::investigation::build_review_inventory(&self.0, false)
            .unwrap()
            .entries
            .iter()
            .filter(|entry| entry.rule_id == "rust-buffer-initialized-prefix-review-marker")
            .count()
    }
}
impl Drop for Project {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn source_bound_publication_chain_preserves_the_deciding_initialization_code() {
    for initialize in [false, true] {
        let fill = if initialize {
            "let initialized=bytes.valid().len();if offset>initialized {unsafe {bytes.address().add(initialized).write_bytes(0,offset-initialized);bytes.expose(offset);}}"
        } else {
            ""
        };
        let source = SOURCE.replace(
            "Self { bytes,offset }",
            &format!("{fill}\nSelf {{ bytes,offset }}"),
        );
        let project = Project::new(&source);
        assert_eq!(project.count(), 1, "initialize={initialize}");
        let job =
            mehscan_engine::investigation::build_all_path_review_jobs(&project.0, None, false)
                .unwrap();
        let review = job
            .observation_reviews
            .iter()
            .find(|review| {
                review
                    .evidence
                    .iter()
                    .any(|e| e.rule_id == "rust-buffer-initialized-prefix-review-marker")
            })
            .unwrap();
        let fact = review
            .evidence
            .iter()
            .find(|e| e.rule_id == "rust-buffer-initialized-prefix-review-marker")
            .unwrap();
        assert_eq!(
            fact.capability,
            mehscan_core::Capability::BufferLengthPublication
        );
        assert_eq!(
            fact.captures["helper_definition"]
                .text
                .contains("write_bytes"),
            initialize
        );
        assert!(
            fact.captures["length_effect"]
                .text
                .contains("self.set_len(upper)")
        );
        for capture in fact.captures.values() {
            assert_eq!(
                &source[capture.location.start.byte_offset..capture.location.end.byte_offset],
                capture.text
            );
        }
        assert_eq!(
            review.review_basis.as_ref().unwrap().relationship,
            "bounded_initialized_prefix_publication_review"
        );
        assert!(
            fact.captures["vector_implementation_definition"]
                .text
                .contains("impl Region for std::vec::Vec<u8>")
        );
        let bundles = mehscan_engine::investigation::build_path_review_bundles(&job, None).unwrap();
        assert!(bundles.bundles.iter().any(|bundle| {
            bundle
                .review_playbooks
                .get(&review.id)
                .is_some_and(|playbook| playbook.bucket == "native_memory")
        }));
    }
}

#[test]
fn unrelated_types_methods_positions_and_callers_cannot_supply_the_chain() {
    let cases = [
        SOURCE.replace("std::vec::Vec<u8>", "Foreign<u8>"),
        SOURCE.replace("self.capacity()", "1024"),
        SOURCE.replace("self.set_len(upper)", "self.set_len(0)"),
        SOURCE.replace("position:self.offset", "position:0"),
        SOURCE.replace(
            "self.owner.publish(self.wire.position)",
            "self.owner.publish(0)",
        ),
        SOURCE.replace("pub fn flush", "fn flush"),
        SOURCE.replace("pub fn begin", "pub unsafe fn begin"),
        SOURCE.replace("window.bridge()", "other.bridge()"),
        SOURCE.replace(
            "unsafe impl Region for",
            "#[cfg(any())] unsafe impl Region for",
        ),
        format!("trait Drop {{fn drop(&mut self);}}\n{SOURCE}"),
        format!("mod std {{}}\n{SOURCE}"),
        format!("type u8=();\n{SOURCE}"),
        format!("use foreign::Byte as u8;\n{SOURCE}"),
        format!("use foreign::*;\n{SOURCE}"),
    ];
    for (index, source) in cases.iter().enumerate() {
        assert_eq!(Project::new(source).count(), 0, "case {index}");
    }
}

#[test]
fn shrinking_length_does_not_create_generic_unsafe_warnings() {
    let source = "pub fn untouched(){let mut value=std::vec::Vec::<u8>::with_capacity(12);unsafe{value.set_len(0);}}";
    assert_eq!(
        Project::new(source).count(),
        0,
        "this relationship requires its source-defined position transfer and publisher"
    );
}

#[test]
fn captured_positions_keep_unicode_columns_and_crlf_bytes() {
    let source = format!(
        "// 🦀 λ\n{}",
        SOURCE.replace("Self { bytes,offset }", "Self { bytes,/*🦀*/offset }")
    )
    .replace('\n', "\r\n");
    let project = Project::new(&source);
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&project.0, None, false).unwrap();
    let fact = jobs
        .observation_reviews
        .iter()
        .flat_map(|r| &r.evidence)
        .find(|e| e.rule_id == "rust-buffer-initialized-prefix-review-marker")
        .unwrap();
    for location in
        std::iter::once(&fact.location).chain(fact.captures.values().map(|c| &c.location))
    {
        for point in [&location.start, &location.end] {
            let prefix = &source[..point.byte_offset];
            assert_eq!(
                point.line,
                prefix.bytes().filter(|b| *b == b'\n').count() + 1
            );
            assert_eq!(
                point.column,
                prefix.rsplit('\n').next().unwrap().chars().count() + 1
            );
        }
    }
}

#[test]
fn dead_publication_and_immediately_forgotten_carriers_do_not_supply_a_runtime_chain() {
    for source in [
        SOURCE.replace(
            "unsafe {self.owner.publish(self.wire.position);}",
            "if false {unsafe {self.owner.publish(self.wire.position);}}",
        ),
        SOURCE.replace(
            "self.bytes.expose(new);",
            "if false {self.bytes.expose(new);}",
        ),
        SOURCE.replace(
            "let _carrier=window.bridge();",
            "if false {let _carrier=window.bridge();}",
        ),
        SOURCE.replace(
            "let _carrier=window.bridge();",
            "let carrier=window.bridge();core::mem::forget(carrier);",
        ),
        SOURCE.replace(
            "let _carrier=window.bridge();",
            "return;let _carrier=window.bridge();",
        ),
    ] {
        assert_eq!(Project::new(&source).count(), 0);
    }
    // An intervening operation can unwind before forget and publish the prefix.
    let source = SOURCE.replace(
        "let _carrier=window.bridge();",
        "let carrier=window.bridge();possibly_panicking();core::mem::forget(carrier);",
    );
    assert_eq!(Project::new(&source).count(), 1);
    let source = SOURCE.replace(
        "unsafe {self.owner.publish(self.wire.position);}",
        "if unknown() {unsafe {self.owner.publish(self.wire.position);}}",
    );
    assert_eq!(Project::new(&source).count(), 1);
}

#[test]
fn import_aliases_and_independent_generic_parameter_names_preserve_the_same_effect() {
    let alias = format!(
        "use std::vec::Vec as Bytes;\n{}",
        SOURCE.replace("std::vec::Vec<u8>", "Bytes<u8>")
    );
    assert_eq!(Project::new(&alias).count(), 1);
    assert_eq!(
        Project::new(&format!("use core::primitive::u8;\n{SOURCE}")).count(),
        1
    );
    let (before, rest) = SOURCE
        .split_once("impl<'a,B:Region+?Sized> Window<'a,B> {")
        .unwrap();
    let (body, after) = rest.split_once("impl<'a,'b,B:Region+?Sized> Drop").unwrap();
    let renamed = format!(
        "{before}impl<'a,C:Region+?Sized> Window<'a,C> {{{}impl<'a,'b,B:Region+?Sized> Drop{after}",
        body.replace('B', "C")
    );
    assert_eq!(Project::new(&renamed).count(), 1);
}

#[test]
fn binding_uncertainty_and_test_only_helpers_do_not_borrow_a_standard_effect() {
    for source in [
        SOURCE.replace("extern crate std;", "use foreign::*;"),
        SOURCE.replace(
            "unsafe impl Region for",
            "#[cfg(test)] unsafe impl Region for",
        ),
        SOURCE.replace(
            "let _carrier=window.bridge();",
            "let window=make_other_window();let _carrier=window.bridge();",
        ),
    ] {
        assert_eq!(Project::new(&source).count(), 0);
    }
    let source=SOURCE.replace("unsafe impl Region for","#[cfg(feature=\"vector\")] #[cfg_attr(feature=\"docs\",doc(cfg(feature=\"vector\")))] unsafe impl Region for");
    let project = Project::new(&source);
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&project.0, false).unwrap();
    let entry = inventory
        .entries
        .iter()
        .find(|entry| entry.rule_id == "rust-buffer-initialized-prefix-review-marker")
        .unwrap();
    let condition = entry
        .source_configuration
        .as_ref()
        .unwrap()
        .condition
        .as_ref()
        .unwrap();
    assert!(condition.contains("vector") && !condition.contains("docs"));
    let mut old = inventory.clone();
    old.rust_configuration_revision = Some("source-modules-v2".into());
    assert!(mehscan_engine::investigation::validate_review_inventory(&project.0, &old).is_err());
}
