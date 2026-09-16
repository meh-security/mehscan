use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ignore::WalkBuilder;
use mehscan_core::{Diagnostic, DiagnosticLevel, Language};
use serde::Deserialize;

use super::build_profile::StaticBuildProfiles;
use super::classify::{FileClass, classify_path_with_options};
use crate::EngineError;

#[derive(Debug)]
pub(crate) struct DiscoveredFile {
    pub absolute: PathBuf,
    pub relative: String,
    pub class: FileClass,
    pub reason: Option<String>,
    pub build_symbols: BTreeMap<String, bool>,
}

#[derive(Debug)]
pub(crate) struct Discovery {
    pub root: PathBuf,
    pub files: Vec<DiscoveredFile>,
    pub ignored_subtrees: Vec<String>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Default)]
struct CFamilyCompilationContext {
    directory_languages: BTreeMap<PathBuf, BTreeSet<Language>>,
    file_build_symbols: BTreeMap<PathBuf, Vec<BTreeMap<String, bool>>>,
    directory_build_symbols: BTreeMap<PathBuf, Vec<BTreeMap<String, bool>>>,
    static_profiles: Option<StaticBuildProfiles>,
}

#[derive(Debug, Deserialize)]
struct CompilationCommand {
    directory: PathBuf,
    file: PathBuf,
    #[serde(default)]
    arguments: Vec<String>,
    #[serde(default)]
    command: String,
}

impl CFamilyCompilationContext {
    fn load(root: &Path) -> Result<Option<Self>, String> {
        let path = root.join("compile_commands.json");
        if !path.is_file() {
            return StaticBuildProfiles::load(root).map(|profiles| {
                profiles.map(|static_profiles| Self {
                    static_profiles: Some(static_profiles),
                    ..Self::default()
                })
            });
        }
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("compile_commands.json could not be read: {error}"))?;
        let commands = serde_json::from_str::<Vec<CompilationCommand>>(&source)
            .map_err(|error| format!("compile_commands.json could not be parsed: {error}"))?;
        let mut context = Self::default();
        for command in commands {
            let directory = if command.directory.is_absolute() {
                command.directory
            } else {
                root.join(command.directory)
            };
            let file = if command.file.is_absolute() {
                command.file
            } else {
                directory.join(command.file)
            };
            let Some(language) = compilation_language(&file, &command.arguments, &command.command)
            else {
                continue;
            };
            let file = fs::canonicalize(&file).unwrap_or(file);
            let source_directory = file.parent().unwrap_or(&directory).to_path_buf();
            context
                .directory_languages
                .entry(source_directory.clone())
                .or_default()
                .insert(language);
            let symbols = compilation_build_symbols(&command.arguments, &command.command);
            context
                .file_build_symbols
                .entry(file)
                .or_default()
                .push(symbols.clone());
            context
                .directory_build_symbols
                .entry(source_directory)
                .or_default()
                .push(symbols);
        }
        Ok(Some(context))
    }

    fn header_language(&self, header: &Path) -> Option<Language> {
        let nearest = self
            .directory_languages
            .iter()
            .filter(|(directory, _)| header.starts_with(directory))
            .max_by_key(|(directory, _)| directory.components().count())
            .and_then(|(_, languages)| {
                (languages.len() == 1)
                    .then(|| languages.iter().next().copied())
                    .flatten()
            });
        nearest.or_else(|| {
            let languages = self
                .directory_languages
                .values()
                .flatten()
                .copied()
                .collect::<BTreeSet<_>>();
            (languages.len() == 1)
                .then(|| languages.iter().next().copied())
                .flatten()
        })
    }

    fn build_symbols(&self, path: &Path) -> BTreeMap<String, bool> {
        if let Some(profiles) = &self.static_profiles {
            return profiles.symbols_for(path);
        }
        let path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if let Some(command_symbols) = self.file_build_symbols.get(&path) {
            return consensus_build_symbols(command_symbols);
        }
        self.directory_build_symbols
            .iter()
            .filter(|(directory, _)| path.starts_with(directory))
            .max_by_key(|(directory, _)| directory.components().count())
            .map_or_else(BTreeMap::new, |(_, command_symbols)| {
                consensus_build_symbols(command_symbols)
            })
    }
}

fn consensus_build_symbols(command_symbols: &[BTreeMap<String, bool>]) -> BTreeMap<String, bool> {
    let Some(first) = command_symbols.first() else {
        return BTreeMap::new();
    };
    first
        .iter()
        .filter(|(name, value)| {
            command_symbols
                .iter()
                .all(|symbols| symbols.get(*name) == Some(*value))
        })
        .map(|(name, value)| (name.clone(), *value))
        .collect()
}

fn compilation_language(file: &Path, arguments: &[String], command: &str) -> Option<Language> {
    let tokens = compilation_tokens(arguments, command);
    for pair in tokens.windows(2) {
        if pair[0] != "-x" {
            continue;
        }
        return match pair[1] {
            "c" | "c-header" => Some(Language::C),
            "c++" | "c++-header" => Some(Language::Cpp),
            _ => None,
        };
    }
    match file
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "c" => Some(Language::C),
        "cc" | "cpp" | "cxx" | "c++" => Some(Language::Cpp),
        _ => None,
    }
}

fn compilation_tokens<'a>(arguments: &'a [String], command: &'a str) -> Vec<&'a str> {
    if arguments.is_empty() {
        command.split_whitespace().collect()
    } else {
        arguments.iter().map(String::as_str).collect()
    }
}

fn compilation_build_symbols(arguments: &[String], command: &str) -> BTreeMap<String, bool> {
    let tokens = compilation_tokens(arguments, command);
    let accepts_slash_switches = tokens.first().is_some_and(|compiler| {
        matches!(
            compiler
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(compiler)
                .to_ascii_lowercase()
                .as_str(),
            "cl" | "cl.exe" | "clang-cl" | "clang-cl.exe"
        )
    });
    let mut symbols = BTreeMap::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index];
        let slash_switch = accepts_slash_switches && matches!(token, "/D" | "/U");
        let (value, consumed_next) = if matches!(token, "-D" | "-U") || slash_switch {
            (tokens.get(index + 1).copied(), true)
        } else if let Some(value) = token
            .strip_prefix("-D")
            .or_else(|| token.strip_prefix("-U"))
            .or_else(|| {
                accepts_slash_switches
                    .then(|| token.strip_prefix("/D"))
                    .flatten()
            })
            .or_else(|| {
                accepts_slash_switches
                    .then(|| token.strip_prefix("/U"))
                    .flatten()
            })
        {
            ((!value.is_empty()).then_some(value), false)
        } else {
            (None, false)
        };
        if let Some(value) = value {
            let is_undefine = token == "-U"
                || token == "/U"
                || token.starts_with("-U")
                || token.starts_with("/U");
            let (name, assigned) = value.split_once('=').unwrap_or((value, "1"));
            if is_c_identifier(name) {
                if is_undefine || assigned == "1" {
                    symbols.insert(name.to_string(), !is_undefine);
                } else {
                    symbols.remove(name);
                }
            }
        }
        index += usize::from(consumed_next) + 1;
    }
    symbols
}

fn is_c_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
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

    let (c_family_context, compilation_diagnostic) = if metadata.is_dir() {
        match CFamilyCompilationContext::load(&root) {
            Ok(context) => (context, None),
            Err(message) => (None, Some(message)),
        }
    } else {
        (None, None)
    };
    let mut discovery = Discovery {
        root: root.clone(),
        files: Vec::new(),
        ignored_subtrees: Vec::new(),
        diagnostics: compilation_diagnostic
            .into_iter()
            .map(|message| {
                let path = message
                    .starts_with("compile_commands.json")
                    .then(|| "compile_commands.json".to_string());
                Diagnostic {
                    level: DiagnosticLevel::Warning,
                    message,
                    path,
                }
            })
            .collect(),
    };
    if metadata.is_file() {
        push_file(
            &root,
            &root,
            include_nonproduction,
            c_family_context.as_ref(),
            &mut discovery,
        );
    } else {
        walk_directory(
            &root,
            &root,
            include_nonproduction,
            c_family_context.as_ref(),
            &mut discovery,
        );
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
    c_family_context: Option<&CFamilyCompilationContext>,
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
            if ignored && let Ok(mut paths) = filter_ignored_subtrees.lock() {
                paths.push(format!("{}/", relative_path(&filter_root, entry.path())));
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
                build_symbols: BTreeMap::new(),
            });
        } else if entry.file_type().is_some_and(|kind| kind.is_file()) {
            push_file(
                root,
                path,
                include_nonproduction,
                c_family_context,
                discovery,
            );
        }
    }
    if let Ok(mut paths) = ignored_subtrees.lock() {
        discovery.ignored_subtrees.append(&mut paths);
    }
}

fn push_file(
    root: &Path,
    path: &Path,
    include_nonproduction: bool,
    c_family_context: Option<&CFamilyCompilationContext>,
    discovery: &mut Discovery,
) {
    let relative = relative_path(root, path);
    let relative_path = Path::new(&relative);
    let mut class = classify_path_with_options(relative_path, include_nonproduction);
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("h"))
        && matches!(class, FileClass::Supported(Language::Cpp))
        && let Some(language) = c_family_context.and_then(|context| context.header_language(path))
    {
        class = FileClass::Supported(language);
    }
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
        build_symbols: c_family_context
            .map(|context| context.build_symbols(path))
            .unwrap_or_default(),
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
            | "deps"
            | "third_party"
            | "third-party"
            | "thirdparty"
            | "3rdparty"
            | "3rd-party"
            | "singleheader"
            | "single-header"
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
            "repo/deps",
            "repo/third_party",
            "repo/third-party",
            "repo/thirdparty",
            "repo/3rdparty",
            "repo/3rd-party",
            "repo/singleheader",
            "repo/single-header",
        ] {
            assert!(ignored_directory(Path::new(directory), root), "{directory}");
        }
        assert!(!ignored_directory(Path::new("repo/src"), root));
        assert!(!ignored_directory(Path::new("repo/packages"), root));
    }

    #[test]
    fn compile_commands_disambiguates_c_headers_without_executing_commands() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "mehscan-compile-context-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("src")).expect("create source directory");
        fs::create_dir_all(root.join("include")).expect("create include directory");
        fs::write(root.join("src/native.c"), "int native(void) { return 0; }")
            .expect("write C source");
        fs::write(root.join("include/native.h"), "int native(void);").expect("write C header");
        let compilation_database = serde_json::json!([{
            "directory": root,
            "file": "src/native.c",
            "arguments": ["cc", "-c", "src/native.c"]
        }]);
        fs::write(
            root.join("compile_commands.json"),
            serde_json::to_vec(&compilation_database).expect("serialize compilation database"),
        )
        .expect("write compilation database");

        let discovery = discover(&root).expect("discover C fixture");
        let header = discovery
            .files
            .iter()
            .find(|file| file.relative == "include/native.h")
            .expect("discover header");
        assert_eq!(header.class, FileClass::Supported(Language::C));

        fs::remove_dir_all(root).expect("remove temporary fixture");
    }

    #[test]
    fn ambiguous_mixed_compile_commands_keeps_cpp_header_fallback() {
        let mut context = CFamilyCompilationContext::default();
        context
            .directory_languages
            .entry(PathBuf::from("repo/src"))
            .or_default()
            .extend([Language::C, Language::Cpp]);
        assert_eq!(
            context.header_language(Path::new("repo/src/native.h")),
            None
        );
    }

    #[test]
    fn compile_commands_exposes_only_consistent_boolean_build_symbols() {
        let arguments = vec![
            "cc".to_string(),
            "-DENABLED".to_string(),
            "-DZERO=0".to_string(),
            "-U".to_string(),
            "DISABLED".to_string(),
            "/Users/source.c".to_string(),
        ];
        assert_eq!(
            compilation_build_symbols(&arguments, ""),
            BTreeMap::from([
                ("DISABLED".to_string(), false),
                ("ENABLED".to_string(), true),
            ])
        );

        let msvc_arguments = vec![
            "clang-cl.exe".to_string(),
            "/DWIN_ENABLED=1".to_string(),
            "/UWIN_DISABLED".to_string(),
        ];
        assert_eq!(
            compilation_build_symbols(&msvc_arguments, ""),
            BTreeMap::from([
                ("WIN_DISABLED".to_string(), false),
                ("WIN_ENABLED".to_string(), true),
            ])
        );

        let commands = vec![
            BTreeMap::from([("PROFILE".to_string(), true)]),
            BTreeMap::new(),
        ];
        assert!(consensus_build_symbols(&commands).is_empty());
    }

    #[test]
    fn selected_compilation_database_takes_precedence_over_static_build_files() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "mehscan-build-precedence-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create precedence fixture");
        fs::write(root.join("profile.c"), "int profile(void) { return 0; }")
            .expect("write precedence source");
        fs::write(
            root.join("CMakeLists.txt"),
            "add_compile_definitions(STATIC_ONLY SELECTED_PROFILE)\n",
        )
        .expect("write static build profile");
        fs::write(
            root.join("compile_commands.json"),
            r#"[{"directory":".","file":"profile.c","arguments":["cc","-USELECTED_PROFILE","profile.c"]}]"#,
        )
        .expect("write selected compilation database");

        let discovery = discover(&root).expect("discover precedence fixture");
        let source = discovery
            .files
            .iter()
            .find(|file| file.relative == "profile.c")
            .expect("discover profile source");
        assert_eq!(
            source.build_symbols,
            BTreeMap::from([("SELECTED_PROFILE".to_string(), false)])
        );
        assert!(!source.build_symbols.contains_key("STATIC_ONLY"));
        fs::remove_dir_all(root).expect("remove precedence fixture");
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
