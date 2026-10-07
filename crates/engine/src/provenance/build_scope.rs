//! Conditional Value scope, not a runtime reachability or safety proof.
use ast_grep_language::{LanguageExt, SupportLang};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn build_only(files: &BTreeMap<&str, &str>) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    let all_paths: BTreeSet<_> = files.keys().map(|p| (*p).to_owned()).collect();
    let manifests: Vec<_> = files
        .keys()
        .copied()
        .filter(|p| p.rsplit('/').next() == Some("package.json"))
        .collect();
    for &manifest in &manifests {
        let text = files[manifest];
        if text.len() > 2 * 1024 * 1024 {
            continue;
        }
        let Ok(package) = serde_json::from_str::<Value>(text) else {
            continue;
        };
        let Some(scripts) = package.get("scripts").and_then(Value::as_object) else {
            continue;
        };
        let base = super::parent(manifest);
        let prefix = if base.is_empty() {
            String::new()
        } else {
            format!("{base}/")
        };
        let members: BTreeMap<_, _> = files
            .iter()
            .filter(|(p, _)| {
                p.starts_with(&prefix)
                    && js(p)
                    && !manifests
                        .iter()
                        .any(|m| *m != manifest && p.starts_with(&format!("{}/", super::parent(m))))
            })
            .map(|(&p, &s)| (p.to_owned(), s))
            .collect();
        if members.len() > 256
            || members.values().any(|s| s.len() > 512 * 1024)
            || members.values().map(|s| s.len()).sum::<usize>() > 8 * 1024 * 1024
        {
            continue;
        }
        let paths: BTreeSet<_> = members.keys().cloned().collect();
        let mut build = BTreeSet::new();
        let mut application = BTreeSet::new();
        for (name, script) in scripts {
            let Some(script) = script.as_str() else {
                continue;
            };
            let is_build = matches!(
                name.as_str(),
                "build" | "prebuild" | "postbuild" | "prepare" | "generate" | "clean"
            ) || name.starts_with("build:")
                || name.starts_with("generate:");
            for token in script.split_whitespace() {
                if token.contains(['$', '*', '`', ';', '|', '&']) {
                    continue;
                }
                if let Some(path) = resolve(base, token.trim_matches(['\'', '"']), &paths) {
                    if is_build {
                        build.insert(path);
                    } else {
                        application.insert(path);
                    }
                }
            }
        }
        if build.is_empty() {
            continue;
        }
        fn entries(
            value: &Value,
            base: &str,
            paths: &BTreeSet<String>,
            application: &mut BTreeSet<String>,
        ) -> bool {
            match value {
                Value::String(entry) => {
                    if let Some(path) = resolve(base, entry, paths) {
                        application.insert(path);
                        true
                    } else {
                        false
                    }
                }
                Value::Object(values) => values
                    .values()
                    .all(|value| entries(value, base, paths, application)),
                Value::Array(values) => values
                    .iter()
                    .all(|value| entries(value, base, paths, application)),
                _ => true,
            }
        }
        let mut complete = true;
        for key in ["main", "module", "browser", "bin", "exports"] {
            if let Some(value) = package.get(key) {
                complete &= entries(value, base, &paths, &mut application);
            }
        }
        if !complete {
            continue;
        }
        let mut edges = BTreeMap::<String, BTreeSet<String>>::new();
        for (path, source) in &members {
            let language = if path.ends_with(".tsx") {
                SupportLang::Tsx
            } else if path.ends_with(".ts") {
                SupportLang::TypeScript
            } else {
                SupportLang::JavaScript
            };
            let ast = language.ast_grep(*source);
            let root = ast.root();
            let mut imports = BTreeSet::new();
            for node in root.dfs() {
                let kind = node.kind();
                if kind == "ERROR" {
                    complete = false;
                    break;
                }
                if kind == "variable_declarator"
                    && node.field("name").is_some_and(|n| n.text() == "require")
                {
                    complete = false;
                    break;
                }
                let specifier = if matches!(kind.as_ref(), "import_statement" | "export_statement")
                {
                    node.field("source")
                } else if kind == "call_expression"
                    && node
                        .field("function")
                        .is_some_and(|f| matches!(f.text().as_ref(), "require" | "import"))
                {
                    let args = node.field("arguments");
                    let args: Vec<_> = args
                        .into_iter()
                        .flat_map(|a| a.children().collect::<Vec<_>>())
                        .filter(|n| !matches!(n.kind().as_ref(), "(" | ")" | "," | "comment"))
                        .collect();
                    if args.len() != 1 || args[0].kind() != "string" {
                        complete = false;
                        break;
                    }
                    args.into_iter().next()
                } else {
                    None
                };
                if let Some(specifier) = specifier {
                    let literal = specifier.text();
                    let reference = literal
                        .get(1..literal.len().saturating_sub(1))
                        .unwrap_or("");
                    if reference.contains('\\') {
                        complete = false;
                        break;
                    }
                    if reference.starts_with('.') {
                        // Literal JSON metadata imports do not introduce code.
                        if reference.ends_with(".json")
                            && super::resolve(super::parent(path), reference, &all_paths).is_some()
                        {
                            continue;
                        }
                        if let Some(target) = resolve(super::parent(path), reference, &paths) {
                            imports.insert(target);
                        } else {
                            complete = false;
                            break;
                        }
                    }
                }
            }
            if !complete {
                break;
            }
            edges.insert(path.clone(), imports);
        }
        if !complete {
            continue;
        }
        fn expand(seeds: &mut BTreeSet<String>, edges: &BTreeMap<String, BTreeSet<String>>) {
            let mut pending: Vec<_> = seeds.iter().cloned().collect();
            while let Some(path) = pending.pop() {
                for target in edges.get(&path).into_iter().flatten() {
                    if seeds.insert(target.clone()) {
                        pending.push(target.clone());
                    }
                }
            }
        }
        expand(&mut build, &edges);
        // Unclassified files are possible application entrypoints. Shared imports
        // and explicitly exported/runtime entries must not become build-only.
        application.extend(paths.difference(&build).cloned());
        expand(&mut application, &edges);
        for path in build.difference(&application) {
            result.insert(path.clone(), manifest.to_owned());
        }
    }
    result
}

fn js(path: &str) -> bool {
    matches!(
        path.rsplit('.').next(),
        Some("js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx")
    )
}
fn resolve(base: &str, reference: &str, files: &BTreeSet<String>) -> Option<String> {
    let possibilities: BTreeSet<_> = [
        "",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".mjs",
        ".cjs",
        "/index.js",
        "/index.ts",
    ]
    .into_iter()
    .filter_map(|suffix| super::resolve(base, &format!("{reference}{suffix}"), files))
    .collect();
    (possibilities.len() == 1).then(|| possibilities.into_iter().next().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn build_dependencies_preserve_shared_runtime_unknown_and_nested_packages() {
        let mut files = BTreeMap::from([
            (
                "package.json",
                r#"{"main":"app.js","scripts":{"build":"node tools/build.js","start":"node app.js"}}"#,
            ),
            (
                "tools/build.js",
                "require('./render'); require('../shared');",
            ),
            (
                "tools/render.js",
                "require('fs').writeFileSync(target, content);",
            ),
            ("shared.js", "require('fs').readFileSync(path);"),
            ("app.js", "require('./shared');"),
            ("nested/package.json", r#"{"main":"app.js"}"#),
            ("nested/app.js", "require('fs').readFileSync(path);"),
        ]);
        assert_eq!(
            build_only(&files).keys().cloned().collect::<Vec<_>>(),
            ["tools/build.js", "tools/render.js"]
        );
        files.insert("app.js", "require('./tools/render');");
        assert!(!build_only(&files).contains_key("tools/render.js"));
        files.insert("tools/build.js", "require(selected);");
        assert!(build_only(&files).is_empty());
        files.insert("tools/build.js", "require('./missing');");
        assert!(build_only(&files).is_empty());
        files.insert("tools/build.js", "require('./render');");
        files.insert(
            "package.json",
            r#"{"exports":{"./*":"./tools/*"},"scripts":{"build":"node tools/build.js"}}"#,
        );
        assert!(
            build_only(&files).is_empty(),
            "unresolved exports stay open"
        );
        files.insert(
            "package.json",
            r#"{"main":"app.js","scripts":{"build":"node tools/build.js"}}"#,
        );
        files.insert("tools/render.ts", "export const value=1;");
        assert!(
            build_only(&files).is_empty(),
            "ambiguous resolution stays open"
        );
    }
}
