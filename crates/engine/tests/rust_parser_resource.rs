mod support;
use std::fs;

fn assess(source: &str) -> mehscan_core::PathReviewJob {
    let root = support::temp_dir("parser-resource");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname=\"parser_resource\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), source).unwrap();
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, false).unwrap();
    fs::remove_dir_all(root).unwrap();
    jobs
}

#[test]
fn byte_input_panics_retain_guards_and_fallible_or_fixed_controls() {
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
    let jobs = assess(source);
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
}

#[test]
fn exact_chunk_argument_bounds_only_close_private_local_parsers() {
    let source = r#"
fn decode_short(bytes: &[u8]) -> u8 { bytes[2] }
pub fn records(bytes: &[u8]) -> Vec<u8> {
    bytes.chunks(3).map(|record| decode_short(record)).collect()
}
fn decode_filtered(record: &[u8]) -> u8 { record[2] }
pub fn filtered(bytes: &[u8]) -> Vec<u8> {
    bytes.chunks(4).filter(|part| 3 <= part.len()).map(|row| decode_filtered(row)).collect()
}
fn decode_exact(record: &[u8]) -> u8 { record[3] }
pub fn exact(bytes: &[u8]) -> Vec<u8> {
    bytes.chunks_exact(4).map(|row| decode_exact(row)).collect()
}
pub fn public_entry(record: &[u8]) -> u8 { record[3] }
pub fn full_chunks(bytes: &[u8]) -> Vec<u8> {
    bytes.chunks_exact(4).map(|row| public_entry(row)).collect()
}
fn extra_call(record: &[u8]) -> u8 { record[3] }
pub fn multiple_callers(bytes: &[u8]) -> u8 {
    bytes.chunks_exact(4).map(|row| extra_call(row)).next().unwrap_or(0) ^ extra_call(bytes)
}
fn unrelated_guard(record: &[u8]) -> u8 { record[3] }
pub fn wrong_slice(bytes: &[u8]) -> Vec<u8> {
    bytes.chunks(4).filter(|_row| bytes.len() >= 4).map(|row| unrelated_guard(row)).collect()
}
"#;
    let jobs = assess(source);
    let mut hits = Vec::new();
    for review in &jobs.observation_reviews {
        for evidence in review
            .evidence
            .iter()
            .filter(|e| e.rule_id == "rust-input-slice-boundary-review")
        {
            let symbol = evidence.enclosing_symbol.as_deref().unwrap();
            if symbol == "decode_short" {
                let captures = &evidence.captures;
                assert_eq!(captures["chunk_iterator_00"].text, "bytes.chunks(3)");
                assert_eq!(captures["chunk_caller_00"].text, "decode_short(record)");
            }
            hits.push(symbol);
        }
    }
    hits.sort_unstable();
    assert_eq!(
        hits,
        [
            "decode_short",
            "extra_call",
            "public_entry",
            "unrelated_guard"
        ]
    );
}

#[test]
fn data_selected_chain_growth_respects_a_checked_iteration_budget() {
    let source = r#"
pub fn follow(links: &[usize], payload: &[u8]) -> Vec<u8> {
    let mut current = 0;
    let mut out = Vec::new();
    while current < links.len() {
        out.extend_from_slice(payload);
        current = links[current];
    }
    out
}
pub fn bounded(links: &[usize], payload: &[u8]) -> Vec<u8> {
    let mut current = 0;
    let mut out = Vec::new();
    let mut steps = 0usize;
    while current < links.len() {
        steps += 1;
        if steps > 16 { break; }
        out.extend_from_slice(payload);
        current = links[current];
    }
    out
}
pub fn unrelated_budget(links: &[usize], payload: &[u8], limit: usize) -> Vec<u8> {
    let mut current = 0;
    let mut out = Vec::new();
    while current < links.len() {
        if current >= limit { break; }
        out.extend_from_slice(payload);
        current = links[current];
    }
    out
}
pub fn visited(links: &[usize], payload: &[u8]) -> Vec<u8> {
    let mut current = 0;
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    while current < links.len() {
        if !seen.insert(current) { break; }
        out.extend_from_slice(payload);
        current = links[current];
    }
    out
}
pub fn reset_each_step(links: &[usize], payload: &[u8]) -> Vec<u8> {
    let mut current = 0;
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    while current < links.len() {
        seen.clear();
        if !seen.insert(current) { break; }
        out.extend_from_slice(payload);
        current = links[current];
    }
    out
}
"#;
    let jobs = assess(source);
    let mut hits = Vec::new();
    for review in &jobs.observation_reviews {
        for evidence in review
            .evidence
            .iter()
            .filter(|e| e.rule_id == "rust-input-chain-growth-review")
        {
            assert_eq!(
                review.review_basis.as_ref().unwrap().relationship,
                "bounded_rust_input_chain_growth_review"
            );
            assert_eq!(
                evidence.captures["next_cursor"].text,
                "current = links[current]"
            );
            for capture in evidence.captures.values() {
                assert_eq!(
                    &source.as_bytes()
                        [capture.location.start.byte_offset..capture.location.end.byte_offset],
                    capture.text.as_bytes()
                );
            }
            hits.push(evidence.enclosing_symbol.as_deref().unwrap());
        }
    }
    hits.sort_unstable();
    assert_eq!(hits, ["follow", "reset_each_step", "unrelated_budget"]);
}

#[test]
fn source_owned_glob_must_leave_the_standard_buffer_type_unshadowed() {
    let source = r#"
#[macro_use]
mod helpers { pub fn transform(bytes: &[u8]) -> std::vec::Vec<u8> { bytes.to_vec() } }
use crate::helpers::*;
fn owned_bytes(bytes: &[u8]) -> Vec<u8> { transform(bytes) }
fn parse_record(record: &[u8]) -> u8 { record[1] }
pub fn records(bytes: &[u8]) -> Vec<u8> {
    let data = owned_bytes(bytes);
    data.chunks_exact(2).map(|record| parse_record(record)).collect()
}
"#;
    let review_exists = |source: &str| {
        assess(source).observation_reviews.iter().any(|review| {
            review.evidence.iter().any(|e| {
                e.rule_id == "rust-input-slice-boundary-review"
                    && e.enclosing_symbol.as_deref() == Some("parse_record")
            })
        })
    };
    assert!(!review_exists(source));
    let competing_vec = source
        .replace(
            "mod helpers {",
            r#"mod helpers {
pub struct Vec<T>(std::vec::Vec<T>);
impl Vec<u8> {
    pub fn chunks_exact(&self, _: usize) -> std::slice::Chunks<'_, u8> { self.0.chunks(2) }
}
impl<T> FromIterator<T> for Vec<T> {
    fn from_iter<I: IntoIterator<Item=T>>(iter: I) -> Self { Self(iter.into_iter().collect()) }
}"#,
        )
        .replace("{ transform(bytes) }", "{ Vec(transform(bytes)) }")
        .replace(
            "pub struct Vec<T>(std::vec::Vec<T>);",
            "pub struct Vec<T>(pub std::vec::Vec<T>);",
        );
    assert!(review_exists(&competing_vec));
}
