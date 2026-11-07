mod support;
use std::fs;

fn reviews(source: &str) -> Vec<(String, String)> {
    let root = support::temp_dir("archive-relationships");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname=\"archive_relationships\"\nversion=\"0.1.0\"\nedition=\"2024\"\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), source).unwrap();
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, false).unwrap();
    let mut result = Vec::new();
    for review in &job.observation_reviews {
        for e in review
            .evidence
            .iter()
            .filter(|e| e.capability == mehscan_core::Capability::RustArchiveExtractionReview)
        {
            assert_eq!(
                review.review_basis.as_ref().unwrap().relationship,
                "bounded_rust_archive_extraction_review"
            );
            for capture in e.captures.values() {
                assert_eq!(
                    &source.as_bytes()
                        [capture.location.start.byte_offset..capture.location.end.byte_offset],
                    capture.text.as_bytes()
                );
            }
            if e.rule_id == "rust-archive-entry-extraction-review" {
                assert!(matches!(
                    e.captures["entry_extraction_method"].text.as_str(),
                    "unpack" | "unpack_in"
                ));
            }
            let bundles =
                mehscan_engine::investigation::build_path_review_bundles(&job, None).unwrap();
            assert!(bundles.bundles.iter().any(|b| {
                b.review_playbooks
                    .get(&review.id)
                    .is_some_and(|p| p.bucket == "resource_boundary")
            }));
            result.push((e.enclosing_symbol.clone().unwrap(), e.rule_id.clone()));
        }
    }
    fs::remove_dir_all(root).unwrap();
    result.sort();
    result
}

#[test]
fn extraction_uses_real_receiver_witnesses_and_preserves_safe_api_questions() {
    let source = r#"
use tar::Archive as Tar;
use zip::ZipArchive as Zip;
pub fn tar<R:std::io::Read>(input:R,root:&std::path::Path){let mut ar=Tar::new(input);ar.unpack(root);}
pub fn zip<R:std::io::Read+std::io::Seek>(input:R,root:&std::path::Path){let mut ar=Zip::new(input).unwrap();ar.extract(root);}
pub fn parameter<R:std::io::Read>(ar:&mut tar::Archive<R>,root:&std::path::Path){ar.unpack(root);}
pub fn inline<R:std::io::Read>(input:R,root:&std::path::Path){tar::Archive::new(input).unpack(root);}
pub fn other(ar:&mut Foreign,root:&std::path::Path){ar.unpack(root);}
pub fn shadow<R:std::io::Read>(input:R,root:&std::path::Path){let ar=Tar::new(input);let mut ar=Foreign;ar.unpack(root);}
struct Foreign;impl Foreign{fn unpack(&mut self,_:&std::path::Path){}}
#[cfg(test)] pub fn test_only<R:std::io::Read>(input:R,root:&std::path::Path){Tar::new(input).unpack(root);}
pub fn dead<R:std::io::Read>(input:R,root:&std::path::Path){if false{Tar::new(input).unpack(root);}}
"#;
    assert_eq!(
        reviews(source)
            .into_iter()
            .map(|(s, _)| s)
            .collect::<Vec<_>>(),
        ["inline", "parameter", "tar", "zip"]
    );
}

#[test]
fn zip_entry_names_connect_to_writes_without_assuming_missing_guards() {
    let source = r#"
use std::fs::{File, write as store};
pub fn raw<R:std::io::Read+std::io::Seek>(input:R,root:&std::path::Path){let mut zip=zip::ZipArchive::new(input).unwrap();let file=zip.by_index(0).unwrap();let path=root.join(file.name());File::create(path);}
pub fn guarded<R:std::io::Read+std::io::Seek>(zip:&mut zip::ZipArchive<R>,root:&std::path::Path){let file=zip.by_index(0).unwrap();let path=root.join(file.name());if !path.starts_with(root){return;}store(path,b"marker");}
pub fn fixed<R:std::io::Read+std::io::Seek>(zip:&mut zip::ZipArchive<R>,root:&std::path::Path){let file=zip.by_index(0).unwrap();std::fs::File::create(root.join("fixed"));}
pub fn foreign(zip:&mut Foreign,root:&std::path::Path){let file=zip.by_index(0);std::fs::File::create(root.join(file.name()));}
struct Foreign;impl Foreign{fn by_index(&self,_:usize)->Self{Foreign}fn name(&self)->&str{"fixed"}}
"#;
    assert_eq!(
        reviews(source),
        [
            ("guarded".into(), "rust-archive-entry-write-review".into()),
            ("raw".into(), "rust-archive-entry-write-review".into())
        ]
    );
}

#[test]
fn tar_loop_entry_paths_reach_writes_and_entry_extraction() {
    let source = r#"
pub fn manual<R:std::io::Read>(ar:&mut tar::Archive<R>,root:&std::path::Path)->std::io::Result<()> {
 for item in ar.entries()? {let mut item=item?;let path=root.join(item.path()?);let mut out=std::fs::File::create(path)?;std::io::copy(&mut item,&mut out)?;}Ok(())
}

pub fn arbitrary<R:std::io::Read>(ar:&mut tar::Archive<R>,root:&std::path::Path)->std::io::Result<()> {
 for result in ar.entries()? {let mut entry=result?;entry.unpack(root.join(entry.path()?))?;}Ok(())
}
pub fn confined<R:std::io::Read>(ar:&mut tar::Archive<R>,root:&std::path::Path)->std::io::Result<()> {
 let entries=ar.entries()?;for result in entries {let mut entry=result?;entry.unpack_in(root)?;}Ok(())
}
pub fn parameter<R:std::io::Read>(entry:&mut tar::Entry<'_,R>,root:&std::path::Path)->std::io::Result<()> {entry.unpack_in(root)?;Ok(())}
pub fn generic<R:std::io::Read>(entry:&mut tar::Entry<'_,R>,root:&std::path::Path)->std::io::Result<()> {entry.unpack_in::<&std::path::Path>(root)?;Ok(())}
pub fn guarded<R:std::io::Read>(ar:&mut tar::Archive<R>,root:&std::path::Path)->std::io::Result<()> {
 for item in ar.entries()? {let item=item?;let name=item.path()?;if name.components().any(|c|!matches!(c,std::path::Component::Normal(_))){continue;}std::fs::write(root.join(name),b"marker")?;}Ok(())
}
"#;
    assert_eq!(
        reviews(source),
        [
            (
                "arbitrary".into(),
                "rust-archive-entry-extraction-review".into()
            ),
            (
                "confined".into(),
                "rust-archive-entry-extraction-review".into()
            ),
            (
                "generic".into(),
                "rust-archive-entry-extraction-review".into()
            ),
            ("guarded".into(), "rust-archive-entry-write-review".into()),
            ("manual".into(), "rust-archive-entry-write-review".into()),
            (
                "parameter".into(),
                "rust-archive-entry-extraction-review".into()
            ),
        ]
    );
}

#[test]
fn tar_entry_provenance_rejects_shadowed_foreign_mutated_and_dead_entries() {
    let source = r#"
struct Other;impl Other{fn path(&self)->&str{"fixed"}fn unpack(&mut self,_:&std::path::Path){}}
pub fn foreign(items:Vec<Other>,root:&std::path::Path){for mut entry in items{entry.unpack(root);std::fs::write(root.join(entry.path()),b"x");}}
pub fn shadow<R:std::io::Read>(ar:&mut tar::Archive<R>,root:&std::path::Path)->std::io::Result<()> {for item in ar.entries()?{let item=item?;let mut item=Other;item.unpack(root);std::fs::write(root.join(item.path()),b"x")?;}Ok(())}
pub fn nested<R:std::io::Read>(ar:&mut tar::Archive<R>,root:&std::path::Path)->std::io::Result<()> {for item in ar.entries()?{let item=item?;for item in [Other]{std::fs::write(root.join(item.path()),b"x")?;}}Ok(())}
pub fn fixed<R:std::io::Read>(ar:&mut tar::Archive<R>,root:&std::path::Path)->std::io::Result<()> {for item in ar.entries()?{let item=item?;std::fs::write(root.join("fixed"),b"x")?;}Ok(())}
pub fn reassigned<'a,R:std::io::Read>(ar:&mut tar::Archive<R>,replacement:tar::Entry<'a,R>,root:&std::path::Path)->std::io::Result<()> {for item in ar.entries()?{let mut item=item?;item=replacement;item.unpack(root)?;break;}Ok(())}
pub fn if_let_shadow<R:std::io::Read>(ar:&mut tar::Archive<R>,root:&std::path::Path)->std::io::Result<()> {for item in ar.entries()?{let item=item?;if let Some(item)=Some(Other){std::fs::write(root.join(item.path()),b"x")?;}}Ok(())}
pub fn dead<R:std::io::Read>(ar:&mut tar::Archive<R>,root:&std::path::Path)->std::io::Result<()> {if false{for item in ar.entries()?{let mut item=item?;item.unpack(root)?;}}Ok(())}
"#;
    assert!(reviews(source).is_empty());
}

#[test]
fn selected_first_tar_entry_keeps_extraction_and_ignores_foreign_iterators() {
    let source = r#"
pub fn first<R:std::io::Read>(archive:&mut tar::Archive<R>,root:&std::path::Path)->std::io::Result<()> {
 if let Some(item)=(archive.entries()?).next(){let mut entry=item?;let out=root.join(entry.path()?);entry.unpack(out)?;}Ok(())
}
pub fn confined<R:std::io::Read>(archive:&mut tar::Archive<R>,root:&std::path::Path)->std::io::Result<()> {
 if let Some(item)=(archive.entries()?).next(){let mut entry=item?;entry.unpack_in(root)?;}Ok(())
}
struct Other;impl Other{fn unpack(&mut self,_:&std::path::Path){}}
pub fn foreign(mut entries:impl Iterator<Item=Other>,root:&std::path::Path) {
 if let Some(item)=entries.next(){let mut entry=item;entry.unpack(root);}
}
"#;
    assert_eq!(
        reviews(source),
        [
            (
                "confined".into(),
                "rust-archive-entry-extraction-review".into()
            ),
            (
                "first".into(),
                "rust-archive-entry-extraction-review".into()
            ),
        ]
    );
}

#[test]
fn directory_permissions_bind_the_following_check_to_the_same_path() {
    let source = r#"
use std::fs as disk;
use std::io::{self, ErrorKind};
use std::path::Path;
fn allow_existing(path: &Path) -> io::Result<()> {
    disk::create_dir(path).or_else(|error| {
        if error.kind() == ErrorKind::AlreadyExists {
            let previous = disk::metadata(path);
            if previous.map(|meta| meta.is_dir()).unwrap_or(false) {
                return Ok(());
            }
        }
        Err(error)
    })
}
fn apply(path: &Path, permissions: disk::Permissions) -> io::Result<()> {
    allow_existing(path)?;
    disk::set_permissions(path, permissions)
}
fn unrelated(path: &Path, other: &Path, permissions: disk::Permissions) -> io::Result<()> {
    allow_existing(other)?;
    disk::set_permissions(path, permissions)
}
fn via_handle(path: &Path, file: &disk::File, permissions: disk::Permissions) -> io::Result<()> {
    allow_existing(path)?;
    file.set_permissions(permissions)
}
"#;
    assert_eq!(
        reviews(source),
        [(
            "allow_existing".into(),
            "rust-directory-symlink-permissions-review".into()
        )],
    );
    assert!(
        reviews(&source.replace("disk::metadata(path)", "disk::symlink_metadata(path)")).is_empty()
    );
    let reject_link = "if disk::symlink_metadata(path)?.file_type().is_symlink() { return Err(io::Error::other(\"link\")); }";
    let guarded = source.replace(
        "allow_existing(path)?;\n    disk::set_permissions",
        &format!("{reject_link}\n    allow_existing(path)?;\n    disk::set_permissions"),
    );
    assert!(reviews(&guarded).is_empty());
    assert_eq!(
        reviews(&guarded.replace(".is_symlink()", ".is_dir()")).len(),
        1
    );
}

#[test]
fn archive_parent_symlink_requires_a_link_and_later_write_under_the_same_root() {
    let source = r#"
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{symlink, OpenOptionsExt as Mode};
use std::path::Path;
use tar::{Archive, Entry, EntryType};
fn prepare(path: &Path, base: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() && parent != base {
        match fs::create_dir_all(parent) {
            Ok(_) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn copy_data<R: Read>(path: &Path, entry: &mut Entry<'_, R>) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create(true).mode(0o600).open(path)?;
    io::copy(entry, &mut file)?;
    Ok(())
}
pub fn restore<R: Read>(reader: R, root: &Path, other: &Path) -> io::Result<()> {
    let mut archive = Archive::new(reader);
    for item in archive.entries().map_err(|error| error)? {
        let mut record = item.map_err(|error| error)?;
        let kind = record.header().entry_type();
        let output = root.join(record.path()?);
        prepare(&output, root)?;
        match kind {
            EntryType::Regular => copy_data(&output, &mut record)?,
            EntryType::Symlink => {
                let target = record.link_name()?.ok_or_else(|| io::Error::other("missing target"))?;
                symlink(&target, &output)?;
            }
            _ => {}
        }
    }
    Ok(())
}
"#;
    let link_count = |source: &str| {
        reviews(source)
            .into_iter()
            .filter(|(_, rule)| rule == "rust-archive-parent-symlink-write-review")
            .count()
    };
    assert_eq!(link_count(source), 1);
    assert_eq!(
        link_count(&source.replace("symlink(&target, &output)", "symlink(&target, other)")),
        0
    );
    assert_eq!(
        link_count(&source.replace("prepare(&output, root)", "prepare(other, root)")),
        0
    );
    assert_eq!(
        link_count(&source.replace("symlink, OpenOptionsExt as Mode", "symlink")),
        0
    );
    let confined = source.replace("match fs::create_dir_all(parent)", "if fs::canonicalize(parent)?.strip_prefix(base).is_err() { return Err(io::Error::other(\"outside\")); }\n        match fs::create_dir_all(parent)");
    assert_eq!(link_count(&confined), 0);
    let reject_outside = "if !fs::canonicalize(output.parent().unwrap())?.starts_with(fs::canonicalize(root)?) { continue; }";
    let guarded = source.replace(
        "prepare(&output, root)?;",
        &format!("{reject_outside}\n        prepare(&output, root)?;"),
    );
    assert_eq!(link_count(&guarded), 0);
    assert_eq!(
        link_count(&guarded.replace("canonicalize(root)?", "canonicalize(other)?")),
        1
    );
}
