use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ignore::WalkBuilder;
use mehscan_core::{Diagnostic, DiagnosticLevel};

use super::classify::{FileClass, classify_path_with_options};
use crate::EngineError;

#[derive(Debug)]
pub(crate) struct DiscoveredFile {
    pub absolute: PathBuf,
    pub relative: String,
    pub class: FileClass,
    pub reason: Option<String>,
}

#[derive(Debug)]
pub(crate) struct Discovery {
    pub root: PathBuf,
    pub files: Vec<DiscoveredFile>,
    pub ignored_subtrees: Vec<String>,
    pub diagnostics: Vec<Diagnostic>,
}

pub(crate) fn discover(requested_root: &Path) -> Result<Discovery, EngineError> {
    discover_with_options(requested_root, false)
}

pub(crate) fn discover_with_options(
    requested_root: &Path,
    include_nonproduction: bool,
) -> Result<Discovery, EngineError> {
    let root = fs::canonicalize(requested_root).map_err(|error| {
        EngineError(format!(
            "cannot access scan root {}: {error}",
            requested_root.display()
        ))
    })?;
    let metadata = fs::metadata(&root)?;
    if !metadata.is_dir() && !metadata.is_file() {
        return Err(EngineError(format!(
            "scan root is neither a file nor a directory: {}",
            requested_root.display()
        )));
    }

    let mut discovery = Discovery {
        root: root.clone(),
        files: Vec::new(),
        ignored_subtrees: Vec::new(),
        diagnostics: Vec::new(),
    };
    if metadata.is_file() {
        push_file(&root, &root, include_nonproduction, &mut discovery);
    } else {
        walk_directory(&root, &root, include_nonproduction, &mut discovery);
    }
    discovery
        .files
        .sort_by(|left, right| left.relative.cmp(&right.relative));
    discovery.ignored_subtrees.sort();
    Ok(discovery)
}

fn walk_directory(
    root: &Path,
    directory: &Path,
    include_nonproduction: bool,
    discovery: &mut Discovery,
) {
    let ignored_subtrees = Arc::new(Mutex::new(Vec::new()));
    let filter_ignored_subtrees = Arc::clone(&ignored_subtrees);
    let filter_root = root.to_path_buf();
    let mut builder = WalkBuilder::new(directory);
    builder
        .hidden(false)
        .parents(false)
        .ignore(true)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
        .require_git(false)
        .follow_links(false)
        .sort_by_file_name(|left, right| left.cmp(right))
        .filter_entry(move |entry| {
            let ignored = entry.depth() > 0
                && entry.file_type().is_some_and(|kind| kind.is_dir())
                && ignored_directory(entry.path(), &filter_root);
            if ignored {
                if let Ok(mut paths) = filter_ignored_subtrees.lock() {
                    paths.push(format!("{}/", relative_path(&filter_root, entry.path())));
                }
            }
            !ignored
        });

    for entry in builder.build() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                discovery.diagnostics.push(Diagnostic {
                    level: DiagnosticLevel::Warning,
                    message: format!("repository entry could not be enumerated: {error}"),
                    path: None,
                });
                continue;
            }
        };
        if let Some(error) = entry.error() {
            discovery.diagnostics.push(Diagnostic {
                level: DiagnosticLevel::Warning,
                message: format!("ignore file could not be fully applied: {error}"),
                path: Some(relative_path(root, entry.path())),
            });
        }
        if entry.depth() == 0 {
            continue;
        }
        let path = entry.path();
        if entry.path_is_symlink() {
            discovery.files.push(DiscoveredFile {
                absolute: path.to_path_buf(),
                relative: relative_path(root, path),
                class: FileClass::Ignored,
                reason: Some("symbolic link is not followed".to_string()),
            });
        } else if entry.file_type().is_some_and(|kind| kind.is_file()) {
            push_file(root, path, include_nonproduction, discovery);
        }
    }
    if let Ok(mut paths) = ignored_subtrees.lock() {
        discovery.ignored_subtrees.append(&mut paths);
    }
}

fn push_file(root: &Path, path: &Path, include_nonproduction: bool, discovery: &mut Discovery) {
    let relative = relative_path(root, path);
    let relative_path = Path::new(&relative);
    let class = classify_path_with_options(relative_path, include_nonproduction);
    let reason = match class {
        FileClass::Supported(_)
        | FileClass::EmbeddedJavascriptTemplate
        | FileClass::Razor
        | FileClass::WebForms => None,
        FileClass::SecretOnly if super::classify::is_sast_excluded_source(relative_path) => {
            Some("test or generated source excluded from SAST; secret scan retained".to_string())
        }
        FileClass::SecretOnly => None,
        FileClass::UnsupportedSource => {
            Some("source language is not enabled in this slice".to_string())
        }
        FileClass::Ignored => Some("non-source file".to_string()),
    };
    discovery.files.push(DiscoveredFile {
        absolute: path.to_path_buf(),
        relative,
        class,
        reason,
    });
}

fn ignored_directory(path: &Path, root: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(
        name.as_str(),
        ".git"
            | ".hg"
            | ".svn"
            | "target"
            | "node_modules"
            | "bower_components"
            | "jspm_packages"
            | "vendor"
            | "pods"
            | ".pnpm-store"
            | ".cache"
            | ".next"
            | ".nuxt"
            | ".svelte-kit"
            | ".angular"
            | ".parcel-cache"
            | ".turbo"
            | ".venv"
            | "venv"
            | ".tox"
            | ".nox"
            | "site-packages"
            | "__pycache__"
            | ".gradle"
            | ".nuget"
            | "coverage"
            | "dist"
            | "build"
            | "out"
            | "obj"
    ) {
        return true;
    }
    let relative = relative_path(root, path);
    relative == "ast-grep-main" || relative == "crates/ast-grep"
}

pub(crate) fn relative_path(root: &Path, path: &Path) -> String {
    let relative = if root.is_file() {
        path.file_name().map(PathBuf::from).unwrap_or_default()
    } else {
        path.strip_prefix(root).unwrap_or(path).to_path_buf()
    };
    relative.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn normalizes_relative_paths() {
        let root = Path::new("root");
        assert_eq!(relative_path(root, Path::new("root/a/b.py")), "a/b.py");
    }

    #[test]
    fn prunes_dependency_and_cache_trees_but_not_authored_source() {
        let root = Path::new("repo");
        for directory in [
            "repo/.venv",
            "repo/venv",
            "repo/.tox",
            "repo/.nox",
            "repo/lib/site-packages",
            "repo/src/__pycache__",
            "repo/.gradle",
            "repo/.nuget",
        ] {
            assert!(ignored_directory(Path::new(directory), root), "{directory}");
        }
        assert!(!ignored_directory(Path::new("repo/src"), root));
        assert!(!ignored_directory(Path::new("repo/packages"), root));
    }

    #[test]
    fn honors_repository_ignore_files_without_global_hidden_file_filtering() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "mehscan-ignore-discovery-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("ignored")).expect("ignored fixture directory");
        fs::create_dir_all(root.join("target")).expect("mandatory fixture directory");
        fs::write(
            root.join(".gitignore"),
            "ignored/\n*.generated.js\n!important.generated.js\n!target/keep.rs\n",
        )
        .expect("gitignore fixture");
        fs::write(root.join(".ignore"), "scratch.py\n").expect("ignore fixture");
        fs::write(root.join("keep.js"), "eval(input);\n").expect("kept source");
        fs::write(root.join(".hidden.js"), "eval(input);\n").expect("hidden source");
        fs::write(root.join("ignored/bad.js"), "eval(input);\n").expect("ignored source");
        fs::write(root.join("ordinary.generated.js"), "eval(input);\n")
            .expect("glob ignored source");
        fs::write(root.join("important.generated.js"), "eval(input);\n")
            .expect("re-included source");
        fs::write(root.join("scratch.py"), "eval(input)\n").expect("ignore-file source");
        fs::write(root.join("target/keep.rs"), "unsafe {}\n").expect("mandatory ignored source");

        let discovery = discover_with_options(&root, false).expect("discover fixture");
        let paths = discovery
            .files
            .iter()
            .map(|file| file.relative.as_str())
            .collect::<Vec<_>>();
        assert!(paths.contains(&"keep.js"));
        assert!(paths.contains(&".hidden.js"));
        assert!(paths.contains(&"important.generated.js"));
        assert!(!paths.contains(&"ignored/bad.js"));
        assert!(!paths.contains(&"ordinary.generated.js"));
        assert!(!paths.contains(&"scratch.py"));
        assert!(!paths.contains(&"target/keep.rs"));
        assert!(discovery.ignored_subtrees.contains(&"target/".to_string()));

        fs::remove_dir_all(&root).expect("remove fixture repository");
    }
}
