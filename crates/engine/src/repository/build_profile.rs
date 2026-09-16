use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use ignore::WalkBuilder;
use mehscan_core::Language;

#[derive(Debug, Default)]
pub(crate) struct StaticBuildProfiles {
    scopes: Vec<ScopedSymbols>,
    file_variants: BTreeMap<(PathBuf, BuildSystem), Vec<BTreeMap<String, bool>>>,
    detected: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum BuildSystem {
    Cmake,
    Meson,
    Bazel,
}

#[derive(Debug)]
struct ScopedSymbols {
    system: BuildSystem,
    directory: PathBuf,
    languages: BTreeSet<Language>,
    symbols: BTreeMap<String, bool>,
}

#[derive(Debug)]
struct Invocation {
    name: String,
    arguments: String,
    start: usize,
    column: usize,
}

impl StaticBuildProfiles {
    pub(crate) fn load(root: &Path) -> Result<Option<Self>, String> {
        let mut profiles = Self::default();
        let mut builder = WalkBuilder::new(root);
        builder
            .hidden(false)
            .parents(false)
            .ignore(true)
            .git_ignore(true)
            .git_global(false)
            .git_exclude(true)
            .require_git(false)
            .follow_links(false)
            .sort_by_file_name(|left, right| left.cmp(right));
        for entry in builder.build().filter_map(Result::ok) {
            if !entry.file_type().is_some_and(|kind| kind.is_file()) {
                continue;
            }
            let path = entry.path();
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            if !matches!(
                name,
                "CMakeLists.txt" | "meson.build" | "BUILD" | "BUILD.bazel"
            ) {
                continue;
            }
            let source = fs::read_to_string(path)
                .map_err(|error| format!("{} could not be read: {error}", path.display()))?;
            profiles.detected = true;
            match name {
                "CMakeLists.txt" => profiles.parse_cmake(path, &source),
                "meson.build" => profiles.parse_meson(path, &source),
                "BUILD" | "BUILD.bazel" => profiles.parse_bazel(path, &source),
                _ => unreachable!(),
            }
        }
        Ok(profiles.detected.then_some(profiles))
    }

    pub(crate) fn symbols_for(&self, path: &Path) -> BTreeMap<String, bool> {
        let path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let profiles = path_languages(&path)
            .into_iter()
            .map(|language| self.symbols_for_language(&path, language))
            .collect::<Vec<_>>();
        consensus(&profiles)
    }

    fn symbols_for_language(&self, path: &Path, language: Language) -> BTreeMap<String, bool> {
        let systems = self
            .scopes
            .iter()
            .filter(|scope| path.starts_with(&scope.directory))
            .filter(|scope| scope.languages.contains(&language))
            .map(|scope| scope.system)
            .chain(
                self.file_variants
                    .keys()
                    .filter(|(source, _)| source == path)
                    .map(|(_, system)| *system),
            )
            .collect::<BTreeSet<_>>();
        let profiles = systems
            .into_iter()
            .map(|system| {
                let base = consistent_union(
                    self.scopes
                        .iter()
                        .filter(|scope| scope.system == system)
                        .filter(|scope| path.starts_with(&scope.directory))
                        .filter(|scope| scope.languages.contains(&language))
                        .map(|scope| &scope.symbols),
                );
                let Some(variants) = self.file_variants.get(&(path.to_path_buf(), system)) else {
                    return base;
                };
                let combined = variants
                    .iter()
                    .map(|variant| consistent_union([&base, variant]))
                    .collect::<Vec<_>>();
                consensus(&combined)
            })
            .collect::<Vec<_>>();
        consensus(&profiles)
    }

    fn parse_cmake(&mut self, path: &Path, source: &str) {
        let directory = path.parent().unwrap_or(path);
        let directory = fs::canonicalize(directory).unwrap_or_else(|_| directory.to_path_buf());
        let invocations = invocations(source);
        let mut depth = 0_usize;
        let mut global = Vec::new();
        let mut targets = BTreeMap::<String, Vec<PathBuf>>::new();
        let mut definitions = BTreeMap::<String, Vec<BTreeMap<String, bool>>>::new();
        for invocation in invocations {
            let name = invocation.name.to_ascii_lowercase();
            if matches!(
                name.as_str(),
                "endif" | "endforeach" | "endwhile" | "endfunction" | "endmacro" | "endblock"
            ) {
                depth = depth.saturating_sub(1);
                continue;
            }
            if matches!(
                name.as_str(),
                "if" | "foreach" | "while" | "function" | "macro" | "block"
            ) {
                depth += 1;
                continue;
            }
            if depth != 0 {
                continue;
            }
            let tokens = cmake_tokens(&invocation.arguments);
            match name.as_str() {
                "add_compile_definitions" | "add_definitions" => {
                    global.extend(tokens.iter().filter_map(|token| define_fact(token, true)));
                }
                "add_executable" | "add_library" => {
                    let Some(target) = tokens.first().filter(|token| exact_word(token)) else {
                        continue;
                    };
                    let sources = tokens
                        .iter()
                        .skip(1)
                        .filter(|token| source_language(Path::new(token)).is_some())
                        .filter(|token| exact_path(token))
                        .map(|token| canonical_or_join(&directory, token))
                        .collect::<Vec<_>>();
                    targets.entry(target.clone()).or_default().extend(sources);
                }
                "target_compile_definitions" => {
                    let Some(target) = tokens.first().filter(|token| exact_word(token)) else {
                        continue;
                    };
                    let mut active = false;
                    let mut facts = Vec::new();
                    for token in tokens.iter().skip(1) {
                        match token.as_str() {
                            "PRIVATE" | "PUBLIC" => active = true,
                            "INTERFACE" => active = false,
                            _ if active => {
                                if let Some(fact) = define_fact(token, true) {
                                    facts.push(fact);
                                }
                            }
                            _ => {}
                        }
                    }
                    definitions
                        .entry(target.clone())
                        .or_default()
                        .push(facts_map(facts));
                }
                _ => {}
            }
        }
        let global = facts_map(global);
        if !global.is_empty() {
            self.scopes.push(ScopedSymbols {
                system: BuildSystem::Cmake,
                directory: directory.clone(),
                languages: BTreeSet::from([Language::C, Language::Cpp]),
                symbols: global,
            });
        }
        for (target, sources) in targets {
            let target_definitions = definitions
                .get(&target)
                .map(|sets| consistent_union(sets.iter()))
                .unwrap_or_default();
            for source in sources {
                self.file_variants
                    .entry((source, BuildSystem::Cmake))
                    .or_default()
                    .push(target_definitions.clone());
            }
        }
    }

    fn parse_meson(&mut self, path: &Path, source: &str) {
        let directory = path.parent().unwrap_or(path);
        let directory = fs::canonicalize(directory).unwrap_or_else(|_| directory.to_path_buf());
        let unconditional = unconditional_meson_ranges(source);
        for invocation in invocations(source).into_iter().filter(|invocation| {
            unconditional
                .iter()
                .any(|range| range.contains(&invocation.start))
        }) {
            let name = invocation.name.as_str();
            let segments = comma_segments(&invocation.arguments);
            if matches!(name, "add_project_arguments" | "add_global_arguments") {
                if segments
                    .iter()
                    .any(|segment| segment.trim_start().starts_with("native"))
                {
                    continue;
                }
                let languages = meson_languages(&segments);
                let facts = segments
                    .iter()
                    .take_while(|segment| !segment.contains(':'))
                    .flat_map(|segment| quoted_literals(segment))
                    .filter_map(|argument| define_fact(&argument, false))
                    .collect::<Vec<_>>();
                let symbols = facts_map(facts);
                if !languages.is_empty() && !symbols.is_empty() {
                    self.scopes.push(ScopedSymbols {
                        system: BuildSystem::Meson,
                        directory: directory.clone(),
                        languages,
                        symbols,
                    });
                }
                continue;
            }
            if !matches!(
                name,
                "executable" | "library" | "shared_library" | "static_library" | "both_libraries"
            ) {
                continue;
            }
            let sources = segments
                .iter()
                .skip(1)
                .take_while(|segment| !segment.contains(':'))
                .flat_map(|segment| quoted_literals(segment))
                .filter(|source| source_language(Path::new(source)).is_some() && exact_path(source))
                .map(|source| canonical_or_join(&directory, &source))
                .collect::<Vec<_>>();
            for source in sources {
                let language = source_language(&source).expect("filtered source language");
                let key = match language {
                    Language::C => "c_args",
                    Language::Cpp => "cpp_args",
                    _ => unreachable!(),
                };
                let facts = segments
                    .iter()
                    .filter_map(|segment| segment.split_once(':'))
                    .filter(|(name, _)| name.trim() == key)
                    .flat_map(|(_, value)| quoted_literals(value))
                    .filter_map(|argument| define_fact(&argument, false))
                    .collect::<Vec<_>>();
                self.file_variants
                    .entry((source, BuildSystem::Meson))
                    .or_default()
                    .push(facts_map(facts));
            }
        }
    }

    fn parse_bazel(&mut self, path: &Path, source: &str) {
        let directory = path.parent().unwrap_or(path);
        let directory = fs::canonicalize(directory).unwrap_or_else(|_| directory.to_path_buf());
        for invocation in invocations(source).into_iter().filter(|call| {
            call.column == 0 && matches!(call.name.as_str(), "cc_binary" | "cc_library" | "cc_test")
        }) {
            let attributes = comma_segments(&invocation.arguments)
                .into_iter()
                .filter_map(|segment| {
                    let (name, value) = segment.split_once('=')?;
                    Some((name.trim().to_string(), value.trim().to_string()))
                })
                .collect::<BTreeMap<_, _>>();
            let Some(srcs) = attributes.get("srcs") else {
                continue;
            };
            if srcs.contains("select(") || srcs.contains('+') {
                continue;
            }
            for source in quoted_literals(srcs)
                .into_iter()
                .filter(|source| source_language(Path::new(source)).is_some() && exact_path(source))
            {
                let source = canonical_or_join(&directory, &source);
                let language = source_language(&source).expect("filtered source language");
                let mut facts = Vec::new();
                for attribute in ["defines", "local_defines"] {
                    if let Some(value) = attributes
                        .get(attribute)
                        .filter(|value| !value.contains("select(") && !value.contains('+'))
                    {
                        facts.extend(
                            quoted_literals(value)
                                .into_iter()
                                .filter_map(|value| define_fact(&value, true)),
                        );
                    }
                }
                for attribute in [
                    "copts",
                    match language {
                        Language::C => "conlyopts",
                        Language::Cpp => "cxxopts",
                        _ => unreachable!(),
                    },
                ] {
                    if let Some(value) = attributes
                        .get(attribute)
                        .filter(|value| !value.contains("select(") && !value.contains('+'))
                    {
                        facts.extend(
                            quoted_literals(value)
                                .into_iter()
                                .filter_map(|value| define_fact(&value, false)),
                        );
                    }
                }
                self.file_variants
                    .entry((source, BuildSystem::Bazel))
                    .or_default()
                    .push(facts_map(facts));
            }
        }
    }
}

fn facts_map(facts: Vec<(String, bool)>) -> BTreeMap<String, bool> {
    let mut values = BTreeMap::new();
    let mut conflicts = BTreeSet::new();
    for (name, value) in facts {
        if values.get(&name).is_some_and(|existing| *existing != value) {
            values.remove(&name);
            conflicts.insert(name);
        } else if !conflicts.contains(&name) {
            values.insert(name, value);
        }
    }
    values
}

fn consistent_union<'a>(
    maps: impl IntoIterator<Item = &'a BTreeMap<String, bool>>,
) -> BTreeMap<String, bool> {
    facts_map(
        maps.into_iter()
            .flat_map(|map| map.iter().map(|(name, value)| (name.clone(), *value)))
            .collect(),
    )
}

fn consensus(maps: &[BTreeMap<String, bool>]) -> BTreeMap<String, bool> {
    let Some(first) = maps.first() else {
        return BTreeMap::new();
    };
    first
        .iter()
        .filter(|(name, value)| maps.iter().all(|map| map.get(*name) == Some(*value)))
        .map(|(name, value)| (name.clone(), *value))
        .collect()
}

fn define_fact(value: &str, allow_bare: bool) -> Option<(String, bool)> {
    let value = value.trim();
    if value.is_empty() || value.contains(['$', '<', '>', ';', ' ']) || value.starts_with(':') {
        return None;
    }
    let (value, defined) = if let Some(value) = value
        .strip_prefix("-D")
        .or_else(|| value.strip_prefix("/D"))
    {
        (value, true)
    } else if let Some(value) = value
        .strip_prefix("-U")
        .or_else(|| value.strip_prefix("/U"))
    {
        (value, false)
    } else if allow_bare {
        (value, true)
    } else {
        return None;
    };
    let (name, assigned) = value.split_once('=').unwrap_or((value, "1"));
    (is_identifier(name) && assigned == "1").then(|| (name.to_string(), defined))
}

fn is_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn exact_word(value: &str) -> bool {
    is_identifier(value) && !value.contains('$')
}

fn exact_path(value: &str) -> bool {
    !value.is_empty() && !value.contains(['$', '*', '?', ':']) && !Path::new(value).is_absolute()
}

fn canonical_or_join(directory: &Path, value: &str) -> PathBuf {
    let joined = directory.join(value);
    fs::canonicalize(&joined).unwrap_or(joined)
}

fn source_language(path: &Path) -> Option<Language> {
    match path
        .extension()
        .and_then(|extension| extension.to_str())?
        .to_ascii_lowercase()
        .as_str()
    {
        "c" => Some(Language::C),
        "cc" | "cpp" | "cxx" | "c++" => Some(Language::Cpp),
        _ => None,
    }
}

fn path_languages(path: &Path) -> Vec<Language> {
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("h"))
    {
        vec![Language::C, Language::Cpp]
    } else {
        source_language(path).into_iter().collect()
    }
}

fn meson_languages(segments: &[String]) -> BTreeSet<Language> {
    let Some(value) = segments.iter().find_map(|segment| {
        let (name, value) = segment.split_once(':')?;
        (name.trim() == "language").then_some(value)
    }) else {
        return BTreeSet::new();
    };
    quoted_literals(value)
        .into_iter()
        .filter_map(|language| match language.as_str() {
            "c" => Some(Language::C),
            "cpp" => Some(Language::Cpp),
            _ => None,
        })
        .collect()
}

fn unconditional_meson_ranges(source: &str) -> Vec<std::ops::Range<usize>> {
    let mut ranges = Vec::new();
    let mut depth = 0_usize;
    let mut offset = 0_usize;
    for line in source.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with("endif") || trimmed.starts_with("endforeach") {
            depth = depth.saturating_sub(1);
        }
        if depth == 0 {
            ranges.push(offset..offset + line.len());
        }
        if trimmed.starts_with("if ") || trimmed.starts_with("foreach ") {
            depth += 1;
        }
        offset += line.len();
    }
    ranges
}

fn cmake_tokens(arguments: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in arguments.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote.is_some() {
            escaped = true;
            continue;
        }
        if quote == Some(character) {
            quote = None;
            continue;
        }
        if quote.is_none() && matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if quote.is_none() && character.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn comma_segments(arguments: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut depth = 0_usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in arguments.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quote.is_some() {
            escaped = true;
            continue;
        }
        if quote == Some(character) {
            quote = None;
            continue;
        }
        if quote.is_none() && matches!(character, '\'' | '"') {
            quote = Some(character);
            continue;
        }
        if quote.is_none() {
            match character {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    segments.push(arguments[start..index].trim().to_string());
                    start = index + character.len_utf8();
                }
                _ => {}
            }
        }
    }
    segments.push(arguments[start..].trim().to_string());
    segments
}

fn quoted_literals(value: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut quote = None;
    let mut start = 0;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if let Some(expected) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == expected {
                values.push(value[start..index].to_string());
                quote = None;
            }
        } else if matches!(character, '\'' | '"') {
            quote = Some(character);
            start = index + character.len_utf8();
        }
    }
    values
}

fn invocations(source: &str) -> Vec<Invocation> {
    let bytes = source.as_bytes();
    let mut calls = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'#' {
            index = source[index..]
                .find('\n')
                .map_or(bytes.len(), |offset| index + offset + 1);
            continue;
        }
        if !(bytes[index] == b'_' || bytes[index].is_ascii_alphabetic()) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && (bytes[index] == b'_' || bytes[index].is_ascii_alphanumeric())
        {
            index += 1;
        }
        let name = &source[start..index];
        let mut open = index;
        while open < bytes.len() && bytes[open].is_ascii_whitespace() {
            open += 1;
        }
        if open >= bytes.len() || bytes[open] != b'(' {
            continue;
        }
        let mut cursor = open + 1;
        let mut depth = 1_usize;
        let mut quote = None;
        let mut escaped = false;
        while cursor < bytes.len() && depth > 0 {
            let character = bytes[cursor] as char;
            if escaped {
                escaped = false;
            } else if character == '\\' && quote.is_some() {
                escaped = true;
            } else if quote == Some(character) {
                quote = None;
            } else if quote.is_none() && matches!(character, '\'' | '"') {
                quote = Some(character);
            } else if quote.is_none() {
                if character == '#' {
                    cursor = source[cursor..]
                        .find('\n')
                        .map_or(bytes.len(), |offset| cursor + offset + 1);
                    continue;
                }
                match character {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
            }
            cursor += 1;
        }
        if depth == 0 {
            let line_start = source[..start].rfind('\n').map_or(0, |value| value + 1);
            let column = source[line_start..start].chars().count();
            calls.push(Invocation {
                name: name.to_string(),
                arguments: source[open + 1..cursor - 1].to_string(),
                start,
                column,
            });
            index = cursor;
        }
    }
    calls
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn literal_define_parser_rejects_dynamic_and_nonboolean_values() {
        assert_eq!(define_fact("FEATURE", true), Some(("FEATURE".into(), true)));
        assert_eq!(define_fact("-UOLD", false), Some(("OLD".into(), false)));
        assert_eq!(define_fact("FEATURE=0", true), None);
        assert_eq!(define_fact("$<CONFIG:Debug>", true), None);
        assert_eq!(define_fact("-DNAME=value", false), None);
    }

    #[test]
    fn balanced_invocations_ignore_comments_and_nested_parentheses() {
        let source = "# add_compile_definitions(BAD)\nadd_compile_definitions(GOOD fn(x))\n";
        let calls = invocations(source);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "add_compile_definitions");
        assert_eq!(calls[0].arguments, "GOOD fn(x)");
    }

    #[test]
    fn cmake_meson_and_bazel_expose_only_exact_consistent_file_facts() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "mehscan-static-build-profile-{}-{nonce}",
            std::process::id()
        ));
        for directory in ["cmake", "meson", "bazel"] {
            fs::create_dir_all(root.join(directory)).expect("create build fixture directory");
        }
        for file in [
            "cmake/fixed.c",
            "cmake/shared.c",
            "cmake/config.h",
            "meson/fixed.c",
            "meson/fixed.cpp",
            "meson/conditional.c",
            "bazel/fixed.c",
            "bazel/disabled.cpp",
            "bazel/dynamic.c",
            "bazel/shared.c",
            "multi.c",
        ] {
            fs::write(root.join(file), "int value;\n").expect("write source fixture");
        }
        fs::write(
            root.join("cmake/CMakeLists.txt"),
            r#"
add_compile_definitions(CMAKE_GLOBAL DYNAMIC=0 $<CONFIG:Debug>)
add_executable(one fixed.c shared.c)
add_executable(two shared.c)
target_compile_definitions(one PRIVATE CMAKE_TARGET)
if(ENABLE_EXTRA)
  add_compile_definitions(CONDITIONAL_BAD)
endif()
"#,
        )
        .expect("write CMake fixture");
        fs::write(
            root.join("meson/meson.build"),
            r#"
add_project_arguments('-DMESON_C', language : 'c')
add_project_arguments('-DMESON_CPP', language : 'cpp')
executable('mixed', 'fixed.c', 'fixed.cpp', c_args : ['-DMESON_TARGET_C'], cpp_args : '-DMESON_TARGET_CPP')
if get_option('extra')
  add_project_arguments('-DCONDITIONAL_BAD', language : ['c', 'cpp'])
endif
"#,
        )
        .expect("write Meson fixture");
        fs::write(
            root.join("bazel/BUILD.bazel"),
            r#"
cc_library(name = "fixed", srcs = ["fixed.c"], local_defines = ["BAZEL_FIX"])
cc_binary(name = "disabled", srcs = ["disabled.cpp"], copts = ["-UBAZEL_OLD"])
cc_library(name = "dynamic", srcs = select({"//conditions:default": ["dynamic.c"]}), local_defines = ["BAD"])
cc_library(name = "one", srcs = ["shared.c"], defines = ["SHARED_FIX"])
cc_library(name = "two", srcs = ["shared.c"])
"#,
        )
        .expect("write Bazel fixture");
        fs::write(
            root.join("CMakeLists.txt"),
            "add_executable(cmake_multi multi.c)\ntarget_compile_definitions(cmake_multi PRIVATE MULTI_FIX)\n",
        )
        .expect("write alternative CMake profile");
        fs::write(
            root.join("meson.build"),
            "executable('meson_multi', 'multi.c')\n",
        )
        .expect("write alternative Meson profile");

        let profiles = StaticBuildProfiles::load(&root)
            .expect("load build profiles")
            .expect("detect build profiles");
        assert_eq!(
            profiles.symbols_for(&root.join("cmake/fixed.c")),
            BTreeMap::from([
                ("CMAKE_GLOBAL".to_string(), true),
                ("CMAKE_TARGET".to_string(), true),
            ])
        );
        assert_eq!(
            profiles.symbols_for(&root.join("cmake/shared.c")),
            BTreeMap::from([("CMAKE_GLOBAL".to_string(), true)]),
            "a definition absent from another target variant stays unknown"
        );
        assert_eq!(
            profiles.symbols_for(&root.join("cmake/config.h")),
            BTreeMap::from([("CMAKE_GLOBAL".to_string(), true)])
        );
        assert_eq!(
            profiles.symbols_for(&root.join("meson/fixed.c")),
            BTreeMap::from([
                ("MESON_C".to_string(), true),
                ("MESON_TARGET_C".to_string(), true),
            ])
        );
        assert_eq!(
            profiles.symbols_for(&root.join("meson/fixed.cpp")),
            BTreeMap::from([
                ("MESON_CPP".to_string(), true),
                ("MESON_TARGET_CPP".to_string(), true),
            ])
        );
        assert!(
            !profiles
                .symbols_for(&root.join("meson/conditional.c"))
                .contains_key("CONDITIONAL_BAD")
        );
        assert_eq!(
            profiles.symbols_for(&root.join("bazel/fixed.c")),
            BTreeMap::from([("BAZEL_FIX".to_string(), true)])
        );
        assert_eq!(
            profiles.symbols_for(&root.join("bazel/disabled.cpp")),
            BTreeMap::from([("BAZEL_OLD".to_string(), false)])
        );
        assert!(
            profiles
                .symbols_for(&root.join("bazel/dynamic.c"))
                .is_empty()
        );
        assert!(
            profiles
                .symbols_for(&root.join("bazel/shared.c"))
                .is_empty()
        );
        assert!(
            profiles.symbols_for(&root.join("multi.c")).is_empty(),
            "facts absent from an alternative build system stay unknown"
        );
        fs::remove_dir_all(root).expect("remove build fixture");
    }
}
