mod support;
use mehscan_core::{Capability, EvidenceKind, SecurityPathState};
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str, files: &[(&str, &str)]) -> Self {
        let root = support::temp_dir(&format!("filesystem-{name}"));
        for (path, source) in files {
            fs::write(root.join(path), source).unwrap();
        }
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn file_contents_do_not_upgrade_unconnected_path_observations() {
    let fixture = Fixture::new(
        "source-direction",
        &[(
            "app.rs",
            r#"
fn own_output(path: &str) { let _ = std::fs::read_to_string(path); }
fn unrelated(path: &str) {
    let _content = std::fs::read_to_string("local-config");
    let _ = std::fs::read(path);
}
fn later_output(path: &str) {
    std::fs::remove_file(path);
    let _ = std::fs::read_to_string("local-config");
}
fn content_selects_path() {
    let selected = std::fs::read_to_string("selector").unwrap();
    let _ = std::fs::read(&selected);
}
use axum::extract::Path;
async fn external_path(Path(path): Path<String>) { let _ = std::fs::read(&path); }
"#,
        )],
    );
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, false).unwrap();
    for symbol in ["own_output", "unrelated", "later_output"] {
        let entries = inventory
            .entries
            .iter()
            .filter(|e| e.symbol.as_deref() == Some(symbol))
            .collect::<Vec<_>>();
        assert!(!entries.is_empty(), "lost {symbol}");
        assert!(
            entries.iter().all(|e| e.evidence_strength == "sink"),
            "{symbol}: {entries:?}"
        );
    }
    // Direction correction never erases file content sources or actual consumers.
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .any(|e| e.rule_id == "rust-file-content-input")
    );
    for symbol in ["content_selects_path", "external_path"] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some(symbol)
                    && e.capability == Capability::FilesystemRead
                    && e.value_hint.is_none()),
            "lost {symbol}"
        );
    }
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| e.symbol.as_deref() == Some("external_path") && e.review_kind == "path"),
        "lost actual request-to-path flow"
    );
}

#[test]
fn generated_temporary_selection_is_explicit_research_not_a_safe_verdict() {
    let fixture = Fixture::new(
        "temporary-selection",
        &[
            (
                "app.rs",
                r#"
use tempfile::NamedTempFile as Scratch;
fn editor() -> std::io::Result<()> {
    let file = Scratch::new()?;
    let path = file.into_temp_path();
    std::fs::write(&path, "initial")?;
    let _ = std::fs::read_to_string(&path)?;
    Ok(())
}
fn direct() { let _ = std::fs::read(tempfile::NamedTempFile::new().unwrap().path()); }
fn custom_root(root: &str) {
    let file = Scratch::new_in(root).unwrap();
    let _ = std::fs::read(file.path());
}
fn mutable_path(input: std::path::PathBuf) {
    let file = Scratch::new().unwrap();
    let mut path = file.into_temp_path();
    change(&mut path, input);
    let _ = std::fs::read(&path);
}
fn shadowed(input: std::path::PathBuf) {
    let file = Scratch::new().unwrap();
    let path = file.into_temp_path();
    let path = input;
    let _ = std::fs::read(&path);
}
fn destination(input: &str) {
    let file = Scratch::new().unwrap();
    std::fs::copy(file.path(), input);
    std::fs::rename(file.path(), input);
}
fn custom_extension() {
    let file = Scratch::new().unwrap();
    let _ = std::fs::read(file.path().unwrap());
}
#[cfg(test)]
mod tests { use super::*; struct Scratch; }
"#,
            ),
            (
                "custom.rs",
                r#"
use custom::NamedTempFile;
fn custom() { let file = NamedTempFile::new().unwrap(); let _ = std::fs::read(file.path()); }
"#,
            ),
            (
                "local.rs",
                r#"
mod tempfile { pub struct NamedTempFile; }
fn local() { let file = tempfile::NamedTempFile::new().unwrap(); let _ = std::fs::read(file.path()); }
"#,
            ),
            (
                "nested.rs",
                r#"
use tempfile::NamedTempFile;
fn nested() { use other::NamedTempFile; let file = NamedTempFile::new().unwrap(); let _ = std::fs::read(file.path()); }
"#,
            ),
            (
                "custom_sink.rs",
                r#"
use custom::File;
fn custom_sink() { let file = tempfile::NamedTempFile::new().unwrap(); let _ = File::open(file.path()); }
"#,
            ),
            (
                "crate_alias.rs",
                r#"
extern crate other as tempfile;
fn crate_alias() { let file = tempfile::NamedTempFile::new().unwrap(); let _ = std::fs::read(file.path()); }
"#,
            ),
            (
                "glob.rs",
                r#"
use other::*;
fn glob() { let file = tempfile::NamedTempFile::new().unwrap(); let _ = std::fs::read(file.path()); }
"#,
            ),
            (
                "child.rs",
                r#"
mod child {
    use tempfile::NamedTempFile;
    fn child() { let file = NamedTempFile::new().unwrap(); let _ = std::fs::read(file.path()); }
}
"#,
            ),
        ],
    );
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, false).unwrap();
    for symbol in ["editor", "direct"] {
        let entries = inventory
            .entries
            .iter()
            .filter(|e| e.symbol.as_deref() == Some(symbol))
            .collect::<Vec<_>>();
        assert_eq!(
            entries.len(),
            if symbol == "editor" { 2 } else { 1 },
            "{entries:?}"
        );
        assert!(
            entries.iter().all(|e| e
                .value_hint
                .as_ref()
                .is_some_and(|h| h.reason == "generated_temporary_filesystem_selection")),
            "{entries:?}"
        );
    }
    for symbol in [
        "custom_root",
        "mutable_path",
        "shadowed",
        "destination",
        "custom_extension",
        "custom",
        "local",
        "nested",
        "custom_sink",
        "crate_alias",
        "glob",
        "child",
    ] {
        let entries = inventory
            .entries
            .iter()
            .filter(|e| e.symbol.as_deref() == Some(symbol))
            .collect::<Vec<_>>();
        assert!(!entries.is_empty(), "lost {symbol}");
        assert!(
            entries.iter().all(|e| e.value_hint.is_none()),
            "wrong deferral {symbol}: {entries:?}"
        );
        assert!(
            !inventory
                .scan
                .evidence
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some(symbol)
                    && e.tags
                        .iter()
                        .any(|t| t == "filesystem-path:generated-temporary")),
            "wrong proof {symbol}"
        );
    }
}

#[test]
fn inline_sync_handles_are_inventory_but_readable_handles_and_custom_apis_survive() {
    let fixture = Fixture::new(
        "sync-only",
        &[
            (
                "app.rs",
                r#"
use std::fs::File;
fn sync_directory(path: &std::path::Path) -> std::io::Result<()> { File::open(path)?.sync_all()?; Ok(()) }
fn sync_data(path: &str) -> std::io::Result<()> { std::fs::File::open(path)?.sync_data()?; Ok(()) }
fn result_extension(path: &str) { std::fs::File::open(path).sync_data(); }
fn consumed(path: &str) { let mut file = File::open(path).unwrap(); file.sync_all(); file.read_to_end(&mut Vec::new()); }
fn returned(path: &str) { return File::open(path); }
"#,
            ),
            (
                "custom.rs",
                r#"
use custom::File;
fn custom(path: &str) { File::open(path)?.sync_all()?; }
"#,
            ),
        ],
    );
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, false).unwrap();
    for symbol in ["sync_directory", "sync_data"] {
        assert!(
            inventory
                .scan
                .evidence
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some(symbol)
                    && e.tags.iter().any(|t| t == "filesystem-effect:sync-only")),
            "missing purpose {symbol}"
        );
        assert!(
            !inventory
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some(symbol)),
            "sync is not a content-read job: {symbol}"
        );
    }
    for symbol in ["consumed", "returned", "result_extension", "custom"] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some(symbol)),
            "lost {symbol}"
        );
    }
}

#[test]
fn promise_entrypoints_preserve_filesystem_sinks_without_matching_other_packages() {
    let fixture = Fixture::new(
        "promise-entrypoints",
        &[
            (
                "app.js",
                "const files = require('node:fs/promises'); function read(path){return files.readFile(path);} function remove(path){return files.unlink(path);}",
            ),
            (
                "app.ts",
                "import { readFile as load, unlink as erase } from 'fs/promises'; function read(path:string){return load(path);} function remove(path:string){return erase(path);}",
            ),
            (
                "app.tsx",
                "import files from 'node:fs/promises'; function read(path:string){return files.readFile(path);} function remove(path:string){return files.unlink(path);}",
            ),
            (
                "unrelated.js",
                "const files = require('custom/fs/promises'); function read(path){return files.readFile(path);} function remove(path){return files.unlink(path);}",
            ),
        ],
    );
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, false).unwrap();
    for path in ["app.js", "app.ts", "app.tsx"] {
        for (symbol, capability) in [
            ("read", Capability::FilesystemRead),
            ("remove", Capability::FilesystemWrite),
        ] {
            assert!(
                inventory
                    .scan
                    .evidence
                    .iter()
                    .any(|e| e.location.path == path
                        && e.kind == EvidenceKind::Sink
                        && e.capability == capability
                        && e.enclosing_symbol.as_deref() == Some(symbol)),
                "lost {path}/{symbol}"
            );
        }
    }
    assert!(
        !inventory
            .scan
            .evidence
            .iter()
            .any(|e| e.location.path == "unrelated.js"
                && e.kind == EvidenceKind::Sink
                && matches!(
                    e.capability,
                    Capability::FilesystemRead | Capability::FilesystemWrite
                ))
    );
}

#[test]
fn ordinary_setup_has_no_sink_extraction_but_content_and_recursive_roots_survive() {
    let fixture = Fixture::new(
        "extraction",
        &[
            (
                "app.js",
                "const fs=require('fs'); function setup(path){fs.mkdirSync(path);} function read(path){return fs.readFileSync(path);} function remove(path){fs.unlinkSync(path);}",
            ),
            (
                "app.ts",
                "import * as fs from 'node:fs'; function setup(path:string){fs.mkdirSync(path);} function read(path:string){return fs.readFileSync(path);} function remove(path:string){fs.unlinkSync(path);}",
            ),
            (
                "app.tsx",
                "import * as fs from 'node:fs'; function setup(path:string){fs.mkdirSync(path);} function read(path:string){return fs.readFileSync(path);} function remove(path:string){fs.unlinkSync(path);}",
            ),
            (
                "App.cs",
                "using System.IO; class App { void setup(string path){Directory.CreateDirectory(path);} string[] list(string path){return Directory.GetFiles(path);} string read(string path){return File.ReadAllText(path);} void remove(string path){File.Delete(path);} string[] recursive(string path){return Directory.GetFiles(path,\"*\",SearchOption.AllDirectories);} }",
            ),
            (
                "App.java",
                "import java.nio.file.Files; import java.nio.file.Path; class App { void setup(Path path) throws Exception {Files.createDirectories(path);} Object list(Path path) throws Exception {return Files.list(path);} String read(Path path) throws Exception {return Files.readString(path);} void remove(Path path) throws Exception {Files.delete(path);} Object recursive(Path path) throws Exception {return Files.walk(path);} }",
            ),
            (
                "app.kt",
                "import java.nio.file.Files\nimport java.nio.file.Path\nfun setup(path:Path){Files.createDirectories(path)}\nfun read(path:Path)=Files.readString(path)\nfun remove(path:Path){Files.delete(path)}",
            ),
            (
                "app.go",
                "package app\nimport \"os\"\nfunc setup(path string){os.MkdirAll(path,0755)}\nfunc read(path string){os.ReadFile(path)}\nfunc remove(path string){os.Remove(path)}\nfunc permissions(path string){os.Mkdir(path,0777)}",
            ),
            (
                "app.rs",
                "fn setup(path:&str){std::fs::create_dir_all(path);} fn list(path:&str){std::fs::read_dir(path);} fn read(path:&str){std::fs::read_to_string(path);} fn remove(path:&str){std::fs::remove_file(path);}",
            ),
            (
                "app.php",
                "<?php use function mkdir as make_dir; function setup($path){mkdir($path,0755);make_dir($path);} function read($path){return file_get_contents($path);} function remove($path){unlink($path);}",
            ),
        ],
    );
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, false).unwrap();
    assert!(!inventory.scan.evidence.iter().any(|e| {
        matches!(e.enclosing_symbol.as_deref(), Some("setup" | "list"))
            && matches!(
                e.capability,
                Capability::FilesystemRead | Capability::FilesystemWrite
            )
    }));
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| matches!(e.symbol.as_deref(), Some("setup" | "list")))
    );
    for path in [
        "app.js", "app.ts", "app.tsx", "App.cs", "App.java", "app.kt", "app.go", "app.rs",
        "app.php",
    ] {
        for symbol in ["read", "remove"] {
            assert!(
                inventory
                    .scan
                    .evidence
                    .iter()
                    .any(|e| e.location.path == path
                        && e.kind == EvidenceKind::Sink
                        && e.enclosing_symbol.as_deref() == Some(symbol)),
                "lost {path}/{symbol}"
            );
        }
    }
    for path in ["App.cs", "App.java"] {
        assert!(
            inventory
                .scan
                .evidence
                .iter()
                .any(|e| e.location.path == path
                    && e.enclosing_symbol.as_deref() == Some("recursive")),
            "lost recursive {path}"
        );
        assert!(
            inventory.entries.iter().any(|e| e.path == path
                && e.symbol.as_deref() == Some("recursive")
                && e.value_hint
                    .as_ref()
                    .is_some_and(|h| h.reason == "recursive_filesystem_root_research")),
            "missing Comprehensive recursive root {path}"
        );
    }
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .any(|e| e.rule_id == "go-world-writable-directory-mode")
    );
}

#[test]
fn opens_keep_one_effect_with_effective_modes_and_unknown_mode_evidence() {
    let fixture = Fixture::new(
        "modes",
        &[
            (
                "App.cs",
                "using System.IO; class App { object read(string path){return new FileStream(path,FileMode.Open,FileAccess.Read);} object write(string path){return new FileStream(path,FileMode.Open);} object create(string path){return new FileStream(path,FileMode.OpenOrCreate);} }",
            ),
            (
                "app.go",
                "package app\nimport \"os\"\nfunc read(path string){os.OpenFile(path,os.O_RDONLY,0600)}\nfunc write(path string){os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_TRUNC,0600)}\nfunc unknown(path string,flags int){os.OpenFile(path,flags,0600)}",
            ),
            (
                "app.py",
                "import codecs\ndef read(path):\n return codecs.open(path,'rb')\ndef write(path):\n return codecs.open(path,'wb')\ndef unknown(path,mode):\n return codecs.open(path,mode)\n",
            ),
            (
                "App.java",
                "import java.io.RandomAccessFile; class App { Object read(String path)throws Exception{return new RandomAccessFile(path,\"r\");} Object write(String path)throws Exception{return new RandomAccessFile(path,\"rws\");} Object unknown(String path,String mode)throws Exception{return new RandomAccessFile(path,mode);} }",
            ),
        ],
    );
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    for (symbol, capability) in [
        ("read", Capability::FilesystemRead),
        ("write", Capability::FilesystemWrite),
        ("create", Capability::FilesystemWrite),
    ] {
        let effects = scan
            .evidence
            .iter()
            .filter(|e| {
                e.location.path == "App.cs"
                    && e.enclosing_symbol.as_deref() == Some(symbol)
                    && e.kind == EvidenceKind::Sink
            })
            .collect::<Vec<_>>();
        assert_eq!(effects.len(), 1, "{symbol}: {effects:#?}");
        assert_eq!(effects[0].capability, capability);
    }
    for path in ["app.go", "app.py", "App.java"] {
        for (symbol, capability) in [
            ("read", Capability::FilesystemRead),
            ("write", Capability::FilesystemWrite),
            ("unknown", Capability::FilesystemRead),
        ] {
            let effects = scan
                .evidence
                .iter()
                .filter(|e| {
                    e.location.path == path
                        && e.enclosing_symbol.as_deref() == Some(symbol)
                        && e.kind == EvidenceKind::Sink
                        && matches!(
                            e.capability,
                            Capability::FilesystemRead | Capability::FilesystemWrite
                        )
                })
                .collect::<Vec<_>>();
            assert_eq!(effects.len(), 1, "{path}/{symbol}: {effects:#?}");
            assert_eq!(effects[0].capability, capability);
            if symbol == "unknown" {
                assert!(
                    effects[0]
                        .tags
                        .iter()
                        .any(|t| t == "filesystem-mode:unresolved")
                );
            }
        }
    }
}

#[test]
fn fixed_move_destinations_do_not_hide_affected_sources_in_any_profile() {
    let fixture = Fixture::new(
        "move",
        &[
            (
                "app.js",
                "const fs=require('fs'); function move(req){fs.renameSync(req.query.source,'fixed');}",
            ),
            (
                "app.ts",
                "import * as fs from 'fs'; function move(req){fs.renameSync(req.query.source,'fixed');}",
            ),
            (
                "app.tsx",
                "import * as fs from 'fs'; function move(req){fs.renameSync(req.query.source,'fixed');}",
            ),
            (
                "App.cs",
                "using System.IO; class App { void move(string input){Directory.Move(input,\"fixed\");} }",
            ),
            (
                "App.java",
                "import java.nio.file.Files; import java.nio.file.Path; class App { void move(Path input)throws Exception{Files.move(input,Path.of(\"fixed\"));} }",
            ),
            (
                "app.kt",
                "import java.nio.file.Files\nimport java.nio.file.Path\nfun move(input:Path){Files.move(input,Path.of(\"fixed\"))}",
            ),
            (
                "app.go",
                "package app\nimport \"os\"\nfunc move(input string){os.Rename(input,\"fixed\")}",
            ),
            (
                "app.rs",
                "fn move_file(input:&str){std::fs::rename(input,\"fixed\");}",
            ),
            (
                "app.php",
                "<?php function move_file(){rename($_GET['source'],'fixed');}",
            ),
            (
                "app.py",
                "import shutil\ndef move(input):\n shutil.move(input,'fixed')\n",
            ),
            (
                "app.c",
                "void move_file(char *input){rename(input,\"fixed\");}",
            ),
            (
                "app.cpp",
                "void move_file(char *input){rename(input,\"fixed\");}",
            ),
        ],
    );
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, false).unwrap();
    for path in [
        "app.js", "app.ts", "app.tsx", "App.cs", "App.java", "app.kt", "app.go", "app.rs",
        "app.php", "app.py", "app.c", "app.cpp",
    ] {
        assert!(
            inventory
                .scan
                .evidence
                .iter()
                .any(|e| e.location.path == path && e.captures.contains_key("filesystem_source")),
            "lost source operand: {path}"
        );
        // Unconnected native API inventories remain excluded by existing policy.
        if !matches!(path, "app.c" | "app.cpp") {
            assert!(
                inventory.entries.iter().any(|e| e.path == path),
                "lost affected source review {path}"
            );
        }
    }
    for path in ["app.js", "app.ts", "app.tsx", "app.php"] {
        assert!(
            inventory
                .scan
                .security_paths
                .iter()
                .any(|p| p.capability == Capability::FilesystemWrite
                    && p.steps.last().is_some_and(|s| s.location.path == path)
                    && p.state != SecurityPathState::Protected),
            "lost connected move source: {path}"
        );
    }
}
