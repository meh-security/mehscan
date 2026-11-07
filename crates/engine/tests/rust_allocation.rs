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
}

#[test]
fn read_filled_extent_keeps_only_the_reaching_buffer_and_same_length_guard() {
    let source = r#"
use std::io::{self, Read};
struct Decoder { file: std::fs::File }
fn take<const N: usize>(bytes: &[u8]) -> [u8; N] { bytes[..N].try_into().expect("header") }
impl Decoder {
    fn unchecked(&mut self) -> io::Result<Vec<u8>> {
        let mut head = [0u8; 5]; self.file.read_exact(&mut head).map_err(|err| err)?;
        let length = u32::from_be_bytes(take(&head[1..]));
        let count = usize::try_from(length).map_err(io::Error::other)?;
        Ok(vec![0u8; count])
    }
}
fn guarded<R: Read>(mut reader: R, limit: u32) -> io::Result<Vec<u8>> {
    let mut head = [0u8; 4]; std::io::Read::read_exact(&mut reader, &mut head)?;
    let length = u32::from_be_bytes(head);
    if length > limit { return Err(io::Error::other("limit")); }
    Ok(vec![0u8; length as usize])
}
fn generic(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let payload = {
        let mut head = [0u8; 4]; reader.read_exact(&mut head)?;
        let count = u32::from_be_bytes(head) as usize;
        let unrelated = 0;
        if unrelated > 1024 { return Err(io::Error::other("other length")); }
        vec![0u8; count]
    };
    Ok(payload)
}
fn modified<R: Read>(mut reader: R) -> io::Result<Vec<u8>> {
    let mut head = [0u8; 4]; reader.read_exact(&mut head)?;
    head[0] = 0;
    let count = u32::from_be_bytes(head) as usize;
    Ok(vec![0u8; count])
}
fn conditional<R: Read>(mut reader: R, run: bool) -> io::Result<Vec<u8>> {
    let mut head = [0u8; 4]; if run { reader.read_exact(&mut head)?; }
    let count = u32::from_be_bytes(head) as usize;
    Ok(vec![0u8; count])
}
fn short_width<R: Read>(mut reader: R) -> io::Result<Vec<u8>> {
    let mut head = [0u8; 2]; reader.read_exact(&mut head)?;
    let count = u16::from_be_bytes(head) as usize;
    Ok(vec![0u8; count])
}
fn constant_adapter(_: &[u8]) -> [u8; 4] { [0; 4] }
fn opaque<R: Read>(mut reader: R) -> io::Result<Vec<u8>> {
    let mut head = [0u8; 4]; reader.read_exact(&mut head)?;
    let count = u32::from_be_bytes(constant_adapter(&head)) as usize;
    Ok(vec![0u8; count])
}
struct Foreign;
impl Foreign { fn read_exact(&mut self, _: &mut [u8]) -> io::Result<()> { Ok(()) } }
fn foreign(mut reader: Foreign) -> io::Result<Vec<u8>> {
    let mut head = [0u8; 4]; reader.read_exact(&mut head)?;
    let count = u32::from_be_bytes(head) as usize;
    Ok(vec![0u8; count])
}
"#;
    let root = support::temp_dir("read-filled-allocation");
    fs::write(root.join("lib.rs"), source).unwrap();
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, false).unwrap();
    let mut evidence = job
        .observation_reviews
        .iter()
        .flat_map(|review| &review.evidence)
        .filter(|e| e.rule_id == "rust-allocation-extent-review")
        .collect::<Vec<_>>();
    evidence.sort_by_key(|e| e.enclosing_symbol.as_deref().unwrap());
    assert_eq!(
        evidence
            .iter()
            .map(|e| e.enclosing_symbol.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["generic", "guarded", "unchecked"]
    );
    for e in &evidence {
        assert!(e.captures.contains_key("input_read"));
        assert!(e.captures.contains_key("length_decode"));
    }
    assert_eq!(
        evidence[1].captures["allocation_guard"].text,
        "if length > limit { return Err(io::Error::other(\"limit\")); }"
    );
    assert!(!evidence[0].captures.contains_key("allocation_guard"));
    assert!(!evidence[2].captures.contains_key("allocation_guard"));
    assert!(
        evidence[2]
            .captures
            .values()
            .any(|c| c.text.starts_with("fn take<"))
    );
    fs::remove_dir_all(root).unwrap();
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
