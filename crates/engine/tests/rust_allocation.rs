mod support;
use std::fs;

fn review(source: &str) -> Vec<String> {
    let root = support::temp_dir("allocation-review");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname=\"extent_review\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), source).unwrap();
    let inventory = mehscan_engine::investigation::build_review_inventory(&root, false).unwrap();
    let symbols = inventory
        .entries
        .into_iter()
        .filter(|e| e.rule_id == "rust-allocation-extent-review")
        .filter_map(|e| e.symbol)
        .collect();
    fs::remove_dir_all(root).unwrap();
    symbols
}

#[test]
fn allocation_extents_preserve_input_and_guarded_controls_as_questions() {
    let source = r#"
pub fn direct(n:usize)->Vec<u8>{Vec::with_capacity(n)}
pub fn qualified(n:usize)->Vec<u8>{std::vec::Vec::with_capacity(n)}
pub fn decoded(input:&[u8])->Vec<u8>{let n=u32::from_be_bytes(input[..4].try_into().unwrap()) as usize;Vec::with_capacity(n)}
pub fn bounded(n:usize)->Option<Vec<u8>>{if n>1024{return None;}Some(Vec::with_capacity(n))}
pub fn constant(_:usize)->Vec<u8>{Vec::with_capacity(16)}
pub fn shadow(n:usize)->Vec<u8>{let n=16;Vec::with_capacity(n)}
pub fn nested_shadow(n:usize)->Vec<u8>{{let n=16;return Vec::with_capacity(n);}}
pub fn outside_shadow(n:usize)->Vec<u8>{{let n=16;}Vec::with_capacity(n)}
pub fn mutable(n:usize)->Vec<u8>{let mut size=n;size=16;Vec::with_capacity(size)}
pub fn destructured(n:usize)->Vec<u8>{let (n,)=(16,);Vec::with_capacity(n)}
pub fn loop_shadow(n:usize){for n in [16]{let _:Vec<u8>=Vec::with_capacity(n);}}
pub fn reassigned(mut n:usize)->Vec<u8>{n=16;Vec::with_capacity(n)}
"#;
    let mut symbols = review(source);
    symbols.sort();
    assert_eq!(
        symbols,
        [
            "bounded",
            "decoded",
            "direct",
            "outside_shadow",
            "qualified"
        ]
    );
}

#[test]
fn allocation_identity_and_source_configuration_reject_lookalikes() {
    assert!(
        review(
            r#"
struct Vec;impl Vec{fn with_capacity(_:usize)->Self{Self}}
pub fn foreign(n:usize)->Vec{Vec::with_capacity(n)}
"#
        )
        .is_empty()
    );
    assert!(
        review(
            r#"
#[cfg(test)] pub fn only_test(n:usize)->Vec<u8>{Vec::with_capacity(n)}
#[cfg(any())] pub fn disabled(n:usize)->Vec<u8>{Vec::with_capacity(n)}
pub fn closure(n:usize)->Vec<u8>{let alloc=||Vec::with_capacity(n);alloc()}
pub fn dead(n:usize)->Vec<u8>{if false{return Vec::with_capacity(n);}Vec::new()}
pub fn after_return(n:usize)->Vec<u8>{return Vec::new();Vec::with_capacity(n)}
"#
        )
        .is_empty()
    );
    assert_eq!(
        review(
            r#"
use std::vec::Vec as Buffer;
pub fn alias(n:usize)->Buffer<u8>{Buffer::with_capacity(n)}
"#
        ),
        ["alias"]
    );
}

#[test]
fn allocation_reviews_deliver_guards_exact_source_and_resource_guidance() {
    let root = support::temp_dir("allocation-evidence");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname=\"extent_evidence\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    let source = "pub fn bounded(données:usize)->Option<Vec<u8>>{\r\nif données>1024{return None;}\r\nSome(Vec::with_capacity(données))}\r\n";
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
    assert_eq!(
        review.review_basis.as_ref().unwrap().relationship,
        "bounded_rust_allocation_extent_review"
    );
    let evidence = review
        .evidence
        .iter()
        .find(|e| e.rule_id == "rust-allocation-extent-review")
        .unwrap();
    assert!(
        evidence.captures["allocation_definition"]
            .text
            .contains("if données>1024")
    );
    assert_eq!(evidence.captures["input_parameter"].text, "données:usize");
    for capture in evidence.captures.values() {
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

#[test]
fn repeated_vectors_and_typed_growth_keep_extent_questions() {
    let source = r#"
pub fn repeated(n:usize)->Vec<u8>{vec![0; n]}
pub fn qualified_repeat(n:usize)->Vec<u8>{std::vec![0; n]}
pub fn reader<R:std::io::Read>(mut input:R)->std::io::Result<Vec<u8>>{let mut h=[0;4];input.read_exact(&mut h)?;let n=u32::from_be_bytes(h) as usize;Ok(vec![0;n])}
pub fn reader_method<R:std::io::Read>(mut input:R)->Vec<u8>{let n=input.read_u32() as usize;vec![0;n]}
pub fn generic_reader<R:byteorder::ReadBytesExt>(mut input:R)->std::io::Result<Vec<u8>>{let n=input.read_u32::<byteorder::BigEndian>()? as usize;Ok(vec![0;n])}
pub fn reserve(n:usize){let mut v=Vec::<u8>::new();v.reserve(n);}
pub fn grow(v:&mut Vec<u8>,n:usize){v.resize(n,0);}
pub fn fallible(n:usize){let mut v=std::vec::Vec::<u8>::new();let _=v.try_reserve_exact(n);}
pub fn guarded(n:usize)->Vec<u8>{if n>1024{return Vec::new();}vec![0;n]}
pub fn list(n:usize)->Vec<usize>{vec![n,0]}
pub fn fixed(n:usize)->Vec<u8>{vec![0;16]}
pub fn shadow(n:usize)->Vec<u8>{let n=16;vec![0;n]}
struct Other;impl Other{fn reserve(&mut self,_:usize){}}
pub fn foreign(v:&mut Other,n:usize){v.reserve(n);}
"#;
    let mut found = review(source);
    found.sort();
    assert_eq!(
        found,
        [
            "fallible",
            "generic_reader",
            "grow",
            "guarded",
            "qualified_repeat",
            "reader_method",
            "repeated",
            "reserve"
        ]
    );
    // Header mutation and interprocedural read_exact effects are not modeled.
}

#[test]
fn macro_and_receiver_shadowing_never_borrow_standard_identity() {
    assert!(
        review(
            r#"
macro_rules! vec {($a:expr;$b:expr)=>{Vec::new()}}
pub fn custom(n:usize)->Vec<u8>{vec![0;n]}
pub fn shadow(v:&mut Vec<u8>,n:usize){let mut v=Foreign;v.reserve(n);}
struct Foreign;impl Foreign{fn reserve(&mut self,_:usize){}}
"#
        )
        .is_empty()
    );
}
