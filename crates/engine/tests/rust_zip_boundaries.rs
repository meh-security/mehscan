mod support;

use std::fs;

fn review_rules(source: &str) -> Vec<String> {
    let root = support::temp_dir("zip-allocation");
    fs::write(root.join("lib.rs"), source).unwrap();
    let inventory = mehscan_engine::investigation::build_review_inventory(&root, false).unwrap();
    let rules = inventory
        .entries
        .into_iter()
        .filter(|entry| {
            entry.capability == mehscan_core::Capability::RustAllocationReview
                || entry.rule_id == "rust-zip-stream-metadata-permissions-review"
        })
        .map(|entry| entry.rule_id)
        .collect();
    fs::remove_dir_all(root).unwrap();
    rules
}

#[test]
fn checks_indexed_zip_symlink_allocation_and_exact_early_cap() {
    let source = r#"
use std::io::{Read, Seek};
use zip::ZipArchive as Archive;
const LIMIT: u64 = 4096;
pub fn extract<R: Read + Seek>(archive: &mut Archive<R>, unrelated: u64) -> zip::result::ZipResult<()> {
    let mut entry = archive.by_index(0)?;
    if entry.is_symlink() {
        let declared = entry.size();
        let mut payload = Vec::with_capacity(declared as usize);
        entry.read_to_end(&mut payload)?;
    }
    Ok(())
}
"#;
    let rule = "rust-zip-symlink-target-allocation-review";
    assert_eq!(review_rules(source), [rule]);
    let bounded = source.replace(
        "let mut payload",
        "if declared > LIMIT { return Ok(()); }\n        let mut payload",
    );
    assert!(review_rules(&bounded).is_empty());
    assert_eq!(
        review_rules(&bounded.replace("declared > LIMIT", "unrelated > LIMIT")),
        [rule]
    );
    assert_eq!(
        review_rules(&bounded.replace(
            "if declared > LIMIT",
            "let smaller = declared as u8; if smaller > LIMIT as u8"
        )),
        [rule]
    );
    assert_eq!(
        review_rules(&bounded.replace("if declared > LIMIT", "if declared > 4_000_000_000")),
        [rule]
    );
    assert!(
        !review_rules(&source.replace("zip::ZipArchive", "foreign::Archive"))
            .contains(&rule.into())
    );
}

#[test]
fn bounded_zip_visitor_does_not_keep_the_generic_reservation_question() {
    let source = r#"
use std::io::Read;
use zip::read::ZipFile;
pub fn visit<R: Read>(file: &mut ZipFile<'_, R>) -> std::io::Result<()> {
    if file.is_symlink() {
        let len = file.size();
        if len > 4096 { return Ok(()); }
        let mut target = Vec::with_capacity(len as usize);
        file.read_to_end(&mut target)?;
    }
    Ok(())
}
"#;
    assert!(review_rules(source).is_empty());
    assert_eq!(
        review_rules(&source.replace("if len > 4096 { return Ok(()); }", "")),
        ["rust-allocation-extent-review"]
    );
}

#[test]
fn distinguishes_lexical_metadata_destinations_from_checked_outputs() {
    let source = r#"
use std::{fs, path::PathBuf};
use std::os::unix::fs::PermissionsExt;
use zip::unstable::stream::{ZipStreamVisitor as Visitor, ZipStreamFileMetadata as Metadata};
struct Output(PathBuf);
impl Visitor for Output {
    fn visit_additional_metadata(&mut self, metadata: &Metadata) -> zip::result::ZipResult<()> {
        let name = metadata.enclosed_name().ok_or(zip::result::ZipError::FileNotFound)?;
        let output = self.0.join(name);
        if let Some(mode) = metadata.unix_mode() {
            fs::set_permissions(output, fs::Permissions::from_mode(mode))?;
        }
        Ok(())
    }
}
"#;
    assert_eq!(
        review_rules(source),
        ["rust-zip-stream-metadata-permissions-review"]
    );
    let guarded = source.replace(
        "if let Some(mode)",
        "if !fs::canonicalize(&output)?.starts_with(&self.0) { return Ok(()); }\n        if let Some(mode)",
    );
    assert!(review_rules(&guarded).is_empty());
    assert!(review_rules(&source.replace("self.0.join(name)", "self.0.clone()")).is_empty());
    assert!(review_rules(&source.replace("Output(PathBuf)", "Output(CustomRoot)")).is_empty());
    assert!(review_rules(&source.replace("zip::unstable::stream", "other::stream")).is_empty());
}
