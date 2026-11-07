mod support;
use std::fs;
#[test]
fn byte_input_panics_retain_guards_and_fallible_or_fixed_controls() {
    let root = support::temp_dir("parser-resource-input");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname=\"parser_resource\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    let source = r#"
pub fn short(input:&[u8])->u32{u32::from_be_bytes(input[..4].try_into().unwrap())}
pub fn guarded(input:&[u8])->Option<u32>{if input.len()<4{return None;}Some(u32::from_be_bytes(input[..4].try_into().unwrap()))}
pub fn option_panic(input:&[u8])->&[u8]{input.get(..4).unwrap()}
pub fn fallible(input:&[u8])->Option<&[u8]>{input.get(..4)}
pub fn fixed(input:&[u8;4])->u8{input[0]}
pub fn unknown(input:&Other)->u8{input[0]}
pub fn shadow(input:&[u8])->u8{let input=[7u8];input[0]}
pub fn dead(input:&[u8])->u8{if false{input[0]}else{0}}
struct Other;impl std::ops::Index<usize>for Other{type Output=u8;fn index(&self,_:usize)->&u8{&7}}
"#;
    fs::write(root.join("src/lib.rs"), source).unwrap();
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, false).unwrap();
    let mut symbols = Vec::new();
    for r in &jobs.observation_reviews {
        for e in r
            .evidence
            .iter()
            .filter(|e| e.rule_id == "rust-input-slice-boundary-review")
        {
            assert_eq!(
                r.review_basis.as_ref().unwrap().relationship,
                "bounded_rust_input_parser_resource_review"
            );
            for c in e.captures.values() {
                assert_eq!(
                    &source.as_bytes()[c.location.start.byte_offset..c.location.end.byte_offset],
                    c.text.as_bytes()
                );
            }
            symbols.push(e.enclosing_symbol.clone().unwrap());
        }
    }
    symbols.sort();
    assert_eq!(symbols, ["guarded", "option_panic", "short"]);
    fs::remove_dir_all(root).unwrap();
}
