mod support;

use std::fs;

#[test]
fn decoded_distances_reach_same_output_history_copies() {
    let root = support::temp_dir("decoder-back-reference");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname=\"history\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    let source = r#"
struct Output { bytes: [u8; 32], head: usize }
impl Output {
    fn pos(&self) -> usize { self.head }
    fn extend_from_within(&mut self, start: usize, count: usize) {
        self.bytes.copy_within(start..start + count, self.head);
        self.head += count;
    }
}
fn read_distance(bytes: &[u8]) -> Result<u16, ()> {
    Ok(u16::from_le_bytes(bytes.get(..2).ok_or(())?.try_into().map_err(|_| ())?))
}
fn read_ptr(input: &mut *const u8) -> u16 {
    let mut n: u16 = 0;
    unsafe { core::ptr::copy_nonoverlapping(*input, &mut n as *mut u16 as *mut u8, 2); }
    u16::from_le(n)
}
fn transfer(cursor: &mut *mut u8, from: *const u8, count: usize) {
    unsafe { core::ptr::copy(from, *cursor, count); }
}
fn slice(input: &[u8], output: &mut Output) -> Result<(), ()> {
    let input: &[u8; 2] = input[..2].try_into().unwrap();
    let offset = read_distance(input)? as usize;
    let start = output.pos().saturating_sub(offset);
    output.extend_from_within(start, 3);
    Ok(())
}
fn checked(input: &[u8], output: &mut Output) -> Result<(), ()> {
    let offset = read_distance(input)? as usize;
    let start = output.pos().checked_sub(offset).ok_or(())?;
    output.extend_from_within(start, 3);
    Ok(())
}
fn guarded(input: &[u8], output: &mut Output) -> Result<(), ()> {
    let offset = read_distance(input)? as usize;
    if offset > output.pos() { return Err(()); }
    let start = output.pos().saturating_sub(offset);
    output.extend_from_within(start, 3);
    Ok(())
}
fn different(input: &[u8], output: &mut Output, other: &mut Output) -> Result<(), ()> {
    let offset = read_distance(input)? as usize;
    let start = other.pos().saturating_sub(offset);
    output.extend_from_within(start, 3);
    Ok(())
}
fn constant(output: &mut Output) -> Result<(), ()> {
    let offset = read_distance(&[1, 0])? as usize;
    let start = output.pos().saturating_sub(offset);
    output.extend_from_within(start, 3);
    Ok(())
}
fn pointer(input: &[u8], output: &mut [u8], dictionary: &[u8]) {
    let mut reader = input.as_ptr();
    let offset = read_ptr(&mut reader) as usize;
    let base = output.as_mut_ptr();
    let mut cursor = unsafe { base.add(2) };
    let written = unsafe { cursor.offset_from(base) as usize };
    let offset = offset.min(written + dictionary.len());
    let start = unsafe { cursor.sub(offset) };
    transfer(&mut cursor, start, 3);
}
fn other_pointer(input: &[u8], output: &mut [u8], other: &mut [u8], dictionary: &[u8]) {
    let mut reader = input.as_ptr();
    let offset = read_ptr(&mut reader) as usize;
    let base = output.as_mut_ptr();
    let cursor = unsafe { base.add(2) };
    let written = unsafe { cursor.offset_from(base) as usize };
    let offset = offset.min(written + dictionary.len());
    let start = unsafe { cursor.sub(offset) };
    unsafe { core::ptr::copy(start, other.as_mut_ptr(), 3); }
}
"#;
    fs::write(root.join("src/lib.rs"), source).unwrap();
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, false).unwrap();
    let mut symbols = Vec::new();
    for review in &jobs.observation_reviews {
        for evidence in review
            .evidence
            .iter()
            .filter(|e| e.rule_id == "rust-decoder-back-reference-review")
        {
            assert_eq!(
                review.review_basis.as_ref().unwrap().relationship,
                "bounded_rust_decoder_back_reference_review"
            );
            let symbol = evidence.enclosing_symbol.as_deref().unwrap();
            let captures = &evidence.captures;
            for name in [
                "history_adjustment",
                "initialized_prefix",
                "history_copy",
                "input_parameter",
                "offset_conversion",
            ] {
                assert!(captures.contains_key(name), "missing {name} for {symbol}");
            }
            if symbol == "pointer" {
                for name in ["history_copy_helper", "history_read", "dictionary_extent"] {
                    assert!(captures.contains_key(name), "missing {name}");
                }
            }
            for capture in captures.values() {
                assert_eq!(
                    &source.as_bytes()
                        [capture.location.start.byte_offset..capture.location.end.byte_offset],
                    capture.text.as_bytes()
                );
            }
            symbols.push(symbol);
        }
    }
    symbols.sort_unstable();
    assert_eq!(symbols, ["pointer", "slice"]);
    fs::remove_dir_all(root).unwrap();
}
