mod support;
use std::fs;
#[test]
fn caller_extent_arithmetic_preserves_checked_controls_and_operand_source() {
    let root = support::temp_dir("extent-arithmetic");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname=\"extent_arithmetic\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    let source = r#"
pub fn product(n:usize)->Vec<u8>{let size=n*16;Vec::with_capacity(size)}
pub fn checked(n:usize)->Option<Vec<u8>>{let size=n.checked_mul(16)?;Some(Vec::with_capacity(size))}
pub fn constant(n:usize)->Vec<u8>{Vec::with_capacity(16*2)}
pub fn direct(n:usize)->Vec<u8>{Vec::with_capacity(n)}
"#;
    fs::write(root.join("src/lib.rs"), source).unwrap();
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, false).unwrap();
    let mut symbols = Vec::new();
    for r in &jobs.observation_reviews {
        for e in r
            .evidence
            .iter()
            .filter(|e| e.rule_id == "rust-allocation-extent-arithmetic-review")
        {
            assert_eq!(
                r.review_basis.as_ref().unwrap().relationship,
                "bounded_rust_extent_arithmetic_review"
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
    assert_eq!(symbols, ["checked", "product"]);
    fs::remove_dir_all(root).unwrap();
}
