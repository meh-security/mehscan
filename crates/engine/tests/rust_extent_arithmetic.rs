mod support;
use std::fs;

#[test]
fn unchecked_view_reuse_binds_the_same_allocation_and_published_extent() {
    let root = support::temp_dir("capacity-reuse");
    let source = r#"
use std::ptr::NonNull;
struct Backing { bytes: Vec<u8> }
struct View { start: NonNull<u8>, remaining: usize }
struct Foreign;
impl Foreign {
    fn capacity(&self) -> usize { 32 }
    fn as_ptr(&self) -> *const u8 { std::ptr::null() }
}
impl View {
    fn reuse(&mut self, backing: *mut Backing, count: usize) {
        unsafe {
            let storage = &mut (*backing).bytes;
            let available = storage.capacity();
            let begin = storage.as_mut_ptr();
            let displacement = self.start.as_ptr().offset_from(begin) as usize;
            if available >= count + displacement { self.remaining = count; }
        }
    }
    fn reversed(&mut self, storage: &Vec<u8>, count: usize) {
        let displacement = unsafe { self.start.as_ptr().offset_from(storage.as_ptr()) as usize };
        let limit = displacement + count;
        if limit <= storage.capacity() { self.remaining = count; }
    }
    fn checked(&mut self, storage: &Vec<u8>, count: usize) {
        let displacement = unsafe { self.start.as_ptr().offset_from(storage.as_ptr()) as usize };
        let limit = match count.checked_add(displacement) { Some(n) => n, None => return };
        if storage.capacity() >= limit { self.remaining = count; }
    }
    fn different_base(&mut self, storage: &Vec<u8>, other: &Vec<u8>, count: usize) {
        let displacement = unsafe { self.start.as_ptr().offset_from(other.as_ptr()) as usize };
        if storage.capacity() >= count + displacement { self.remaining = count; }
    }
    fn shadowed_storage(&mut self, storage: &Vec<u8>, other: &Vec<u8>, count: usize) {
        let displacement = unsafe { self.start.as_ptr().offset_from(storage.as_ptr()) as usize };
        let storage = other;
        if storage.capacity() >= count + displacement { self.remaining = count; }
    }
    fn different_value(&mut self, storage: &Vec<u8>, count: usize) {
        let displacement = unsafe { self.start.as_ptr().offset_from(storage.as_ptr()) as usize };
        if storage.capacity() >= count + displacement { self.remaining = displacement + 1; }
    }
    fn lookalike(&mut self, storage: &Foreign, count: usize) {
        let displacement = unsafe { self.start.as_ptr().offset_from(storage.as_ptr()) as usize };
        if storage.capacity() >= count + displacement { self.remaining = count; }
    }
}
"#;
    fs::write(root.join("source.rs"), source).unwrap();
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, false).unwrap();
    let bundles = mehscan_engine::investigation::build_path_review_bundles(&job, None).unwrap();
    let mut symbols = Vec::new();
    for review in &job.observation_reviews {
        for evidence in review
            .evidence
            .iter()
            .filter(|e| e.rule_id == "rust-capacity-reuse-overflow-review")
        {
            assert_eq!(
                review.review_basis.as_ref().unwrap().relationship,
                "bounded_rust_capacity_reuse_review"
            );
            assert!(bundles.bundles.iter().any(|bundle| {
                bundle
                    .review_playbooks
                    .get(&review.id)
                    .is_some_and(|p| p.bucket == "rust_memory")
            }));
            assert_eq!(
                evidence.captures["extent_publication"].text,
                "self.remaining = count"
            );
            assert!(
                evidence.captures["view_offset"]
                    .text
                    .contains("offset_from")
            );
            for capture in evidence.captures.values() {
                assert_eq!(
                    &source[capture.location.start.byte_offset..capture.location.end.byte_offset],
                    capture.text
                );
            }
            symbols.push(evidence.enclosing_symbol.as_deref().unwrap());
        }
    }
    symbols.sort_unstable();
    assert_eq!(symbols, ["reuse", "reversed"]);
    fs::remove_dir_all(root).unwrap();
}
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
