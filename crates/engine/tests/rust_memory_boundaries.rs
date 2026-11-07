mod support;
use std::fs;

fn detect(source: &str) -> Vec<(String, String)> {
    let root = support::temp_dir("safe-memory-boundary");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname=\"safe_memory_boundary\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), source).unwrap();
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, false).unwrap();
    let rules = [
        "rust-unchecked-index-review",
        "rust-vector-length-publication-review",
        "rust-pointer-offset-review",
        "rust-assume-initialized-review",
        "rust-transmute-representation-review",
    ];
    let mut out = Vec::new();
    for r in &jobs.observation_reviews {
        for e in r
            .evidence
            .iter()
            .filter(|e| rules.contains(&e.rule_id.as_str()))
        {
            assert_eq!(
                r.review_basis.as_ref().unwrap().relationship,
                "bounded_rust_raw_memory_invariant_review"
            );
            for c in e.captures.values() {
                assert_eq!(
                    &source.as_bytes()[c.location.start.byte_offset..c.location.end.byte_offset],
                    c.text.as_bytes()
                );
            }
            let bundles =
                mehscan_engine::investigation::build_path_review_bundles(&jobs, None).unwrap();
            assert!(bundles.bundles.iter().any(|b| {
                b.review_playbooks
                    .get(&r.id)
                    .is_some_and(|p| p.bucket == "rust_memory")
            }));
            out.push((e.enclosing_symbol.clone().unwrap(), e.rule_id.clone()));
        }
    }
    fs::remove_dir_all(root).unwrap();
    out.sort();
    out
}
#[test]
fn typed_operations_preserve_vulnerable_and_repaired_boundaries() {
    let source = r#"
pub fn unchecked(input:&[u8],index:usize)->u8{unsafe{*input.get_unchecked(index)}}
pub fn checked(input:&[u8],index:usize)->Option<u8>{if index>=input.len(){return None;}Some(unsafe{*input.get_unchecked(index)})}
pub fn publish(mut input:Vec<u8>,n:usize)->Vec<u8>{unsafe{input.set_len(n);}input}
pub fn shrink(mut input:Vec<u8>)->Vec<u8>{unsafe{input.set_len(0);}input}
pub fn pointer(input:*const u8,n:usize)->*const u8{unsafe{input.add(n)}}
pub fn derived(input:&[u8],n:usize)->*const u8{let ptr=input.as_ptr();unsafe{ptr.offset(n as isize)}}
pub fn uninit()->u8{let value=std::mem::MaybeUninit::<u8>::uninit();unsafe{value.assume_init()}}
pub fn initialized()->u8{let value=std::mem::MaybeUninit::new(7u8);unsafe{value.assume_init()}}
"#;
    assert_eq!(
        detect(source),
        [
            ("checked".into(), "rust-unchecked-index-review".into()),
            ("derived".into(), "rust-pointer-offset-review".into()),
            (
                "initialized".into(),
                "rust-assume-initialized-review".into()
            ),
            ("pointer".into(), "rust-pointer-offset-review".into()),
            (
                "publish".into(),
                "rust-vector-length-publication-review".into()
            ),
            (
                "shrink".into(),
                "rust-vector-length-publication-review".into()
            ),
            ("unchecked".into(), "rust-unchecked-index-review".into()),
            ("uninit".into(), "rust-assume-initialized-review".into()),
        ]
    );
    // Representation conversion is a separate operation; keep each test source
    // within the normal per-file marker page size.
    assert_eq!(
        detect("pub fn convert(x:u8)->bool{unsafe{std::mem::transmute::<u8,bool>(x)}}"),
        [(
            "convert".into(),
            "rust-transmute-representation-review".into()
        )]
    );
}
#[test]
fn foreign_unsafe_declared_shadowed_and_dead_operations_are_not_safe_boundary_questions() {
    let source = r#"
struct Other;impl Other {fn get_unchecked(&self,_:usize)->u8{0}fn set_len(&mut self,_:usize){}fn assume_init(self)->u8{0}}
pub fn foreign(x:&mut Other,n:usize){x.get_unchecked(n);x.set_len(n);}
pub unsafe fn contract(x:&[u8],n:usize)->u8{*x.get_unchecked(n)}
pub fn shadow(x:&[u8],n:usize)->u8{let x=Other;x.get_unchecked(n)}
pub fn destructured(x:&[u8],n:usize)->u8{let (x,)=(Other,);x.get_unchecked(n)}
pub fn dead(x:&[u8],n:usize)->u8{if false{unsafe{*x.get_unchecked(n)}}else{0}}
pub fn nested(x:&[u8],n:usize)->u8{for x in [Other]{x.get_unchecked(n);}0}
#[cfg(test)]pub fn test_scope(x:&[u8],n:usize)->u8{unsafe{*x.get_unchecked(n)}}
"#;
    assert!(detect(source).is_empty());
}
#[test]
fn aliases_arrays_and_unicode_keep_exact_witnesses() {
    let source = "use std::mem::MaybeUninit as Slot;\r\npub fn données(input:&[u8;4],n:usize)->u8{unsafe{*input.get_unchecked(n)}}\r\npub fn slot(value:Slot<u8>)->u8{unsafe{value.assume_init()}}\r\n";
    assert_eq!(
        detect(source),
        [
            ("données".into(), "rust-unchecked-index-review".into()),
            ("slot".into(), "rust-assume-initialized-review".into())
        ]
    );
}
