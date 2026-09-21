use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    FixedOutputFormat, Language, SymbolConfidence, SymbolResolution, SymbolResolutionMethod,
};

#[derive(Clone, Debug)]
struct Binding {
    target: String,
    method: SymbolResolutionMethod,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ProjectSymbolEnvironment {
    csharp_aliases: BTreeMap<String, Binding>,
    csharp_namespaces: BTreeSet<String>,
    csharp_statics: BTreeSet<String>,
    fixed_format_exports: BTreeMap<String, FixedFormatSummary>,
    password_kdf_exports: BTreeMap<String, PasswordKdfSummary>,
}

impl ProjectSymbolEnvironment {
    pub(crate) fn from_sources<'a>(
        sources: impl Iterator<Item = (&'a str, Language, &'a str)>,
    ) -> Self {
        let mut environment = Self::default();
        for (path, language, source) in sources {
            if language == Language::Csharp {
                for line in source.lines() {
                    let line = line.trim();
                    let Some(using) = line.strip_prefix("global using ") else {
                        continue;
                    };
                    parse_csharp_using(
                        using.trim_end_matches(';').trim(),
                        &mut environment.csharp_aliases,
                        &mut environment.csharp_namespaces,
                        &mut environment.csharp_statics,
                    );
                }
            }
            if matches!(
                language,
                Language::Javascript | Language::Typescript | Language::Tsx
            ) {
                collect_fixed_format_exports(path, source, &mut environment.fixed_format_exports);
                collect_password_kdf_exports(path, source, &mut environment.password_kdf_exports);
            }
        }
        environment
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct FileSymbolEnvironment {
    aliases: BTreeMap<String, Binding>,
    namespaces: BTreeSet<String>,
    statics: BTreeSet<String>,
    declarations: BTreeSet<String>,
    javascript_imports: BTreeSet<String>,
    path: String,
    fixed_format_exports: BTreeMap<String, FixedFormatSummary>,
    password_kdf_exports: BTreeMap<String, PasswordKdfSummary>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FixedFormatSummary {
    pub(crate) canonical: String,
    pub(crate) output_format: FixedOutputFormat,
    pub(crate) exact_length: usize,
    pub(crate) algorithm: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PasswordKdfSummary {
    pub(crate) canonical: String,
    pub(crate) algorithm: String,
    pub(crate) work_factor: Option<u64>,
    pub(crate) salt_is_constant: bool,
}

impl FileSymbolEnvironment {
    pub(crate) fn build(
        path: &str,
        root: &Node<'_, StrDoc<SupportLang>>,
        language: Language,
        source: &str,
        project: &ProjectSymbolEnvironment,
    ) -> Self {
        let mut environment = Self {
            path: path.to_string(),
            fixed_format_exports: project.fixed_format_exports.clone(),
            password_kdf_exports: project.password_kdf_exports.clone(),
            ..Self::default()
        };
        if language == Language::Csharp {
            environment.aliases.extend(project.csharp_aliases.clone());
            environment
                .namespaces
                .extend(project.csharp_namespaces.iter().cloned());
            environment
                .statics
                .extend(project.csharp_statics.iter().cloned());
        }

        for node in root.dfs() {
            let kind = node.kind();
            let text = node.text();
            match language {
                Language::Csharp if kind == "using_directive" => {
                    let using = text
                        .trim()
                        .strip_prefix("global using ")
                        .or_else(|| text.trim().strip_prefix("using "));
                    if let Some(using) = using {
                        parse_csharp_using(
                            using.trim_end_matches(';').trim(),
                            &mut environment.aliases,
                            &mut environment.namespaces,
                            &mut environment.statics,
                        );
                    }
                }
                Language::Python
                    if matches!(kind.as_ref(), "import_statement" | "import_from_statement") =>
                {
                    parse_python_import(text.as_ref(), &mut environment.aliases);
                }
                Language::Javascript | Language::Typescript | Language::Tsx
                    if kind == "import_statement" =>
                {
                    let mut imports = BTreeMap::new();
                    parse_javascript_import(text.as_ref(), &mut imports);
                    environment
                        .javascript_imports
                        .extend(imports.keys().cloned());
                    environment.aliases.extend(imports);
                }
                Language::Go if kind == "import_spec" => {
                    parse_go_import(text.as_ref(), &mut environment.aliases);
                }
                Language::Java if kind == "import_declaration" => {
                    parse_java_import(
                        text.as_ref(),
                        &mut environment.aliases,
                        &mut environment.namespaces,
                    );
                }
                _ => {}
            }

            if is_declaration_kind(kind.as_ref())
                && let Some(name) = node.field("name")
            {
                environment.declarations.insert(name.text().into_owned());
            }
            if matches!(
                language,
                Language::Javascript | Language::Typescript | Language::Tsx
            ) && kind == "variable_declarator"
                && let Some(name) = node.field("name")
                && name.kind().as_ref() == "identifier"
            {
                environment.declarations.insert(name.text().into_owned());
            }
        }

        if matches!(
            language,
            Language::Javascript | Language::Typescript | Language::Tsx
        ) {
            parse_javascript_requires(source, &mut environment.aliases);
            parse_javascript_promisify_aliases(source, &mut environment.aliases);
        }
        environment
    }

    pub(crate) fn has_declared_receiver(&self, observed: &str) -> bool {
        observed
            .split_once('.')
            .is_some_and(|(head, _)| self.declarations.contains(head))
    }

    pub(crate) fn has_import_alias_receiver(&self, observed: &str) -> bool {
        observed
            .split_once('.')
            .is_some_and(|(head, _)| self.aliases.contains_key(head))
    }

    pub(crate) fn has_shadowing_parameter(
        &self,
        call: &Node<'_, StrDoc<SupportLang>>,
        observed: &str,
        language: Language,
    ) -> bool {
        let observed = normalize_symbol(observed);
        let head = observed
            .split_once('.')
            .map_or(observed.as_str(), |(head, _)| head);
        if !self.aliases.contains_key(head) {
            return false;
        }

        parameter_shadows_name(call, head, language)
    }

    pub(crate) fn resolve(&self, observed: &str, canonical: &str) -> Option<SymbolResolution> {
        let observed = normalize_symbol(observed);
        let canonical = normalize_symbol(canonical);
        if observed == canonical {
            return Some(resolution(
                canonical,
                observed,
                SymbolResolutionMethod::FullyQualified,
                SymbolConfidence::Exact,
            ));
        }

        let (head, tail) = observed
            .split_once('.')
            .map_or((observed.as_str(), ""), |(head, tail)| (head, tail));
        if let Some(binding) = self.aliases.get(head) {
            let expanded = if tail.is_empty() {
                binding.target.clone()
            } else {
                format!("{}.{}", binding.target, tail)
            };
            if normalize_symbol(&expanded) == canonical {
                return Some(resolution(
                    canonical,
                    observed,
                    binding.method,
                    SymbolConfidence::High,
                ));
            }
        }

        for namespace in &self.namespaces {
            if normalize_symbol(&format!("{namespace}.{observed}")) == canonical {
                let confidence = if self.declarations.contains(head) {
                    SymbolConfidence::Ambiguous
                } else {
                    SymbolConfidence::High
                };
                return Some(resolution(
                    canonical,
                    observed,
                    SymbolResolutionMethod::ImportedNamespace,
                    confidence,
                ));
            }
        }

        for static_import in &self.statics {
            if normalize_symbol(&format!("{static_import}.{observed}")) == canonical {
                return Some(resolution(
                    canonical,
                    observed,
                    SymbolResolutionMethod::StaticImport,
                    SymbolConfidence::High,
                ));
            }
        }

        if canonical.ends_with(&format!(".{observed}")) {
            return Some(resolution(
                canonical,
                observed,
                SymbolResolutionMethod::Unqualified,
                SymbolConfidence::Ambiguous,
            ));
        }
        None
    }

    pub(crate) fn resolve_fixed_format(
        &self,
        observed: &str,
    ) -> Option<(SymbolResolution, FixedFormatSummary)> {
        let observed = normalize_symbol(observed);
        let (head, tail) = observed
            .split_once('.')
            .map_or((observed.as_str(), ""), |(head, tail)| (head, tail));
        let binding = self.aliases.get(head)?;
        if !self.javascript_imports.contains(head) {
            return None;
        }
        let expanded = if tail.is_empty() {
            binding.target.clone()
        } else {
            format!("{}.{}", binding.target, tail)
        };
        let (module, export) = expanded.rsplit_once('.')?;
        let module = resolve_module(&self.path, module)?;
        let key = format!("{module}.{export}");
        let summary = self.fixed_format_exports.get(&key)?.clone();
        let resolution = resolution(
            summary.canonical.clone(),
            observed,
            binding.method,
            SymbolConfidence::High,
        );
        Some((resolution, summary))
    }

    pub(crate) fn resolve_password_kdf(
        &self,
        observed: &str,
    ) -> Option<(SymbolResolution, PasswordKdfSummary)> {
        let observed = normalize_symbol(observed);
        let (head, tail) = observed
            .split_once('.')
            .map_or((observed.as_str(), ""), |(head, tail)| (head, tail));
        let binding = self.aliases.get(head)?;
        if !self.javascript_imports.contains(head) {
            return None;
        }
        let expanded = if tail.is_empty() {
            binding.target.clone()
        } else {
            format!("{}.{}", binding.target, tail)
        };
        let (module, export) = expanded.rsplit_once('.')?;
        let module = resolve_module(&self.path, module)?;
        let key = format!("{module}.{export}");
        let summary = self.password_kdf_exports.get(&key)?.clone();
        let resolution = resolution(
            summary.canonical.clone(),
            observed,
            binding.method,
            SymbolConfidence::High,
        );
        Some((resolution, summary))
    }
}

fn collect_password_kdf_exports(
    path: &str,
    source: &str,
    exports: &mut BTreeMap<String, PasswordKdfSummary>,
) {
    let mut aliases = BTreeMap::new();
    for line in source.lines() {
        if line.trim().starts_with("import ") {
            parse_javascript_import(line, &mut aliases);
        }
    }
    parse_javascript_requires(source, &mut aliases);
    let Some(module) = module_path(path) else {
        return;
    };
    for line in source.lines() {
        let Some((name, algorithm, work_factor, salt_is_constant)) =
            parse_password_kdf_export(line, &aliases)
        else {
            continue;
        };
        let canonical = format!("{module}.{name}");
        exports.insert(
            canonical.clone(),
            PasswordKdfSummary {
                canonical,
                algorithm,
                work_factor,
                salt_is_constant,
            },
        );
    }
}

fn parse_password_kdf_export(
    line: &str,
    aliases: &BTreeMap<String, Binding>,
) -> Option<(String, String, Option<u64>, bool)> {
    let declaration = line.trim().strip_prefix("export const ")?;
    let (name, expression) = declaration.split_once('=')?;
    let name = name.trim();
    if !is_simple_identifier(name) {
        return None;
    }
    let (parameters, expression) = expression.split_once("=>")?;
    let parameters = parameters
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')');
    let parameter = parameters
        .split(',')
        .next()?
        .split_once(':')
        .map_or(parameters, |(name, _)| name)
        .trim();
    if !is_simple_identifier(parameter) {
        return None;
    }
    let expression = expression
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let expression = expression.trim_end_matches(';');
    let (callee, arguments) = expression.split_once('(')?;
    let arguments = arguments.strip_suffix(')')?;
    let (head, tail) = callee
        .split_once('.')
        .map_or((callee, ""), |(head, tail)| (head, tail));
    let binding = aliases.get(head)?;
    let canonical = if tail.is_empty() {
        binding.target.clone()
    } else {
        format!("{}.{}", binding.target, tail)
    };
    let arguments = arguments.split(',').map(str::trim).collect::<Vec<_>>();
    if arguments.first().copied() != Some(parameter) {
        return None;
    }
    let (algorithm, work_factor, salt_is_constant) = match canonical.as_str() {
        "bcrypt.hash" | "bcrypt.hashSync" | "bcryptjs.hash" | "bcryptjs.hashSync" => (
            "bcrypt".to_string(),
            arguments.get(1).and_then(|value| value.parse().ok()),
            false,
        ),
        "argon2.hash" => ("argon2".to_string(), None, false),
        "crypto.scrypt" | "crypto.scryptSync" => (
            "scrypt".to_string(),
            None,
            arguments
                .get(1)
                .is_some_and(|value| exact_quoted(value).is_some()),
        ),
        "crypto.pbkdf2" | "crypto.pbkdf2Sync" => (
            "pbkdf2".to_string(),
            arguments.get(2).and_then(|value| value.parse().ok()),
            arguments
                .get(1)
                .is_some_and(|value| exact_quoted(value).is_some()),
        ),
        _ => return None,
    };
    Some((name.to_string(), algorithm, work_factor, salt_is_constant))
}

fn collect_fixed_format_exports(
    path: &str,
    source: &str,
    exports: &mut BTreeMap<String, FixedFormatSummary>,
) {
    let mut aliases = BTreeMap::new();
    for line in source.lines() {
        if line.trim().starts_with("import ") {
            parse_javascript_import(line, &mut aliases);
        }
    }
    let crypto_names = aliases
        .iter()
        .filter_map(|(name, binding)| (binding.target == "crypto").then_some(name.as_str()))
        .collect::<BTreeSet<_>>();
    if crypto_names.is_empty() {
        return;
    }
    let Some(module) = module_path(path) else {
        return;
    };
    for line in source.lines() {
        let Some((name, algorithm, exact_length)) = parse_fixed_hex_export(line, &crypto_names)
        else {
            continue;
        };
        let canonical = format!("{module}.{name}");
        exports.insert(
            canonical.clone(),
            FixedFormatSummary {
                canonical,
                output_format: FixedOutputFormat::LowercaseHexadecimal,
                exact_length,
                algorithm,
            },
        );
    }
}

fn parse_fixed_hex_export(
    line: &str,
    crypto_names: &BTreeSet<&str>,
) -> Option<(String, String, usize)> {
    let declaration = line.trim().strip_prefix("export const ")?;
    let (name, expression) = declaration.split_once('=')?;
    let name = name.trim();
    if !is_simple_identifier(name) {
        return None;
    }
    let (parameter, expression) = expression.split_once("=>")?;
    let parameter = parameter
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')');
    let parameter = parameter
        .split_once(':')
        .map_or(parameter, |(name, _)| name)
        .trim();
    if !is_simple_identifier(parameter) {
        return None;
    }
    let expression = expression
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let expression = expression.trim_end_matches(';');
    for crypto in crypto_names {
        let Some(rest) = expression.strip_prefix(&format!("{crypto}.createHash(")) else {
            continue;
        };
        let Some((algorithm, rest)) = rest.split_once(").update(") else {
            continue;
        };
        let algorithm = exact_quoted(algorithm)?;
        let exact_length = match algorithm.to_ascii_lowercase().as_str() {
            "md5" => 32,
            "sha1" => 40,
            "sha224" => 56,
            "sha256" => 64,
            "sha384" => 96,
            "sha512" => 128,
            _ => continue,
        };
        let Some((input, digest)) = rest.split_once(").digest(") else {
            continue;
        };
        if input != parameter || digest.strip_suffix(')').and_then(exact_quoted) != Some("hex") {
            continue;
        }
        return Some((
            name.to_string(),
            algorithm.to_ascii_lowercase(),
            exact_length,
        ));
    }
    None
}

fn exact_quoted(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    let quote = *bytes.first()?;
    if !matches!(quote, b'\'' | b'"') || bytes.last().copied() != Some(quote) || value.len() < 2 {
        return None;
    }
    let inner = &value[1..value.len() - 1];
    (!inner.contains(['\\', '\'', '"'])).then_some(inner)
}

fn resolve_module(importer: &str, imported: &str) -> Option<String> {
    if !imported.starts_with('.') {
        return module_path(imported);
    }
    let mut segments = importer
        .replace('\\', "/")
        .split('/')
        .map(str::to_string)
        .collect::<Vec<_>>();
    segments.pop()?;
    for segment in imported.replace('\\', "/").split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            value => segments.push(value.to_string()),
        }
    }
    module_path(&segments.join("/"))
}

fn module_path(path: &str) -> Option<String> {
    let path = path.replace('\\', "/");
    let path = path.trim_start_matches("./");
    let path = [".tsx", ".jsx", ".ts", ".js"]
        .iter()
        .find_map(|extension| path.strip_suffix(extension))
        .unwrap_or(path);
    (!path.is_empty()).then_some(path.to_string())
}

fn is_simple_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters.next().is_some_and(|first| {
        (first == '_' || first.is_ascii_alphabetic())
            && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
    })
}

fn resolution(
    canonical: String,
    observed: String,
    method: SymbolResolutionMethod,
    confidence: SymbolConfidence,
) -> SymbolResolution {
    SymbolResolution {
        canonical,
        observed,
        method,
        confidence,
    }
}

fn normalize_symbol(symbol: &str) -> String {
    symbol
        .trim()
        .trim_start_matches("node:")
        .trim_start_matches("global::")
        .replace("::", ".")
}

fn parse_csharp_using(
    using: &str,
    aliases: &mut BTreeMap<String, Binding>,
    namespaces: &mut BTreeSet<String>,
    statics: &mut BTreeSet<String>,
) {
    if let Some(target) = using.strip_prefix("static ") {
        statics.insert(target.trim().to_string());
    } else if let Some((alias, target)) = using.split_once('=') {
        aliases.insert(
            alias.trim().to_string(),
            Binding {
                target: target.trim().to_string(),
                method: SymbolResolutionMethod::Alias,
            },
        );
    } else if !using.is_empty() {
        namespaces.insert(using.to_string());
    }
}

fn parse_python_import(text: &str, aliases: &mut BTreeMap<String, Binding>) {
    let text = text.trim();
    if let Some(imports) = text.strip_prefix("import ") {
        for import in imports.split(',') {
            let mut words = import.split_whitespace();
            let Some(module) = words.next() else { continue };
            let explicit_alias = matches!(words.next(), Some("as"));
            let visible = if explicit_alias {
                words.next().unwrap_or(module)
            } else {
                module.split('.').next().unwrap_or(module)
            };
            aliases.insert(
                visible.to_string(),
                Binding {
                    target: module.to_string(),
                    method: if explicit_alias {
                        SymbolResolutionMethod::Alias
                    } else {
                        SymbolResolutionMethod::ImportedNamespace
                    },
                },
            );
        }
    } else if let Some(rest) = text.strip_prefix("from ")
        && let Some((module, imports)) = rest.split_once(" import ")
    {
        for import in imports.split(',') {
            let mut words = import.split_whitespace();
            let Some(name) = words.next() else { continue };
            let explicit_alias = matches!(words.next(), Some("as"));
            let visible = if explicit_alias {
                words.next().unwrap_or(name)
            } else {
                name
            };
            aliases.insert(
                visible.to_string(),
                Binding {
                    target: format!("{module}.{name}"),
                    method: if explicit_alias {
                        SymbolResolutionMethod::Alias
                    } else {
                        SymbolResolutionMethod::ImportedNamespace
                    },
                },
            );
        }
    }
}

fn parse_javascript_import(text: &str, aliases: &mut BTreeMap<String, Binding>) {
    let Some((clause, module)) = text
        .trim()
        .strip_prefix("import ")
        .and_then(|rest| rest.rsplit_once(" from "))
    else {
        return;
    };
    let module = unquote(module.trim().trim_end_matches(';'));
    if let Some(alias) = clause.trim().strip_prefix("* as ") {
        insert_alias(
            aliases,
            alias.trim(),
            &module,
            SymbolResolutionMethod::Alias,
        );
    } else if clause.trim().starts_with('{') {
        let names = clause.trim().trim_start_matches('{').trim_end_matches('}');
        for name in names.split(',') {
            let mut words = name.split_whitespace();
            let Some(imported) = words.next() else {
                continue;
            };
            let explicit_alias = matches!(words.next(), Some("as"));
            let visible = if explicit_alias {
                words.next().unwrap_or(imported)
            } else {
                imported
            };
            insert_alias(
                aliases,
                visible,
                &format!("{module}.{imported}"),
                if explicit_alias {
                    SymbolResolutionMethod::Alias
                } else {
                    SymbolResolutionMethod::ImportedNamespace
                },
            );
        }
    } else {
        let visible = clause.split(',').next().unwrap_or(clause).trim();
        insert_alias(
            aliases,
            visible,
            &module,
            SymbolResolutionMethod::ImportedNamespace,
        );
    }
}

fn parse_javascript_requires(source: &str, aliases: &mut BTreeMap<String, Binding>) {
    for line in source.lines() {
        let line = line.trim().trim_end_matches(';');
        let Some((declaration, require)) = line.split_once('=') else {
            continue;
        };
        let require = require.trim();
        let Some(require_body) = require.strip_prefix("require(") else {
            continue;
        };
        let Some(close) = require_body.find(')') else {
            continue;
        };
        let argument = require_body[..close].trim();
        let suffix = require_body[close + 1..].trim();
        if !suffix.is_empty()
            && (!suffix.starts_with('.')
                || suffix[1..]
                    .chars()
                    .any(|character| !(character == '_' || character.is_ascii_alphanumeric())))
        {
            continue;
        }
        let mut module = unquote(argument);
        if let Some(export) = suffix.strip_prefix('.') {
            module.push('.');
            module.push_str(export);
        }
        let declaration = declaration
            .trim()
            .strip_prefix("const ")
            .or_else(|| declaration.trim().strip_prefix("let "))
            .or_else(|| declaration.trim().strip_prefix("var "));
        let Some(declaration) = declaration else {
            continue;
        };
        if declaration.starts_with('{') {
            let names = declaration.trim_start_matches('{').trim_end_matches('}');
            for name in names.split(',') {
                let (imported, visible) = name
                    .split_once(':')
                    .map_or((name.trim(), name.trim()), |(left, right)| {
                        (left.trim(), right.trim())
                    });
                insert_alias(
                    aliases,
                    visible,
                    &format!("{module}.{imported}"),
                    SymbolResolutionMethod::Alias,
                );
            }
        } else {
            insert_alias(
                aliases,
                declaration.trim(),
                &module,
                SymbolResolutionMethod::Alias,
            );
        }
    }
}

fn parse_javascript_promisify_aliases(source: &str, aliases: &mut BTreeMap<String, Binding>) {
    for line in source.lines() {
        let line = line.trim().trim_end_matches(';');
        let Some(declaration) = line.strip_prefix("const ") else {
            continue;
        };
        let Some((visible, expression)) = declaration.split_once('=') else {
            continue;
        };
        let visible = visible.trim();
        if !is_simple_identifier(visible) {
            continue;
        }
        let expression = expression
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        let Some((callee, argument)) = expression.split_once('(') else {
            continue;
        };
        let Some(argument) = argument.strip_suffix(')') else {
            continue;
        };
        if argument.contains(',')
            || resolve_javascript_binding(callee, aliases).as_deref() != Some("util.promisify")
        {
            continue;
        }
        let Some(target) = resolve_javascript_binding(argument, aliases) else {
            continue;
        };
        if !matches!(
            target.as_str(),
            "child_process.exec"
                | "child_process.execFile"
                | "child_process.execFileSync"
                | "child_process.execSync"
        ) {
            continue;
        }
        aliases.insert(
            visible.to_string(),
            Binding {
                target,
                method: SymbolResolutionMethod::Alias,
            },
        );
    }
}

fn resolve_javascript_binding(value: &str, aliases: &BTreeMap<String, Binding>) -> Option<String> {
    let value = normalize_symbol(value);
    let (head, tail) = value
        .split_once('.')
        .map_or((value.as_str(), None), |(head, tail)| (head, Some(tail)));
    let target = normalize_symbol(&aliases.get(head)?.target);
    Some(tail.map_or(target.clone(), |tail| format!("{target}.{tail}")))
}

fn parse_go_import(text: &str, aliases: &mut BTreeMap<String, Binding>) {
    let mut words = text.split_whitespace();
    let first = words.next().unwrap_or_default();
    let (visible, path, method) = if let Some(path) = words.next() {
        (
            first.to_string(),
            unquote(path),
            SymbolResolutionMethod::Alias,
        )
    } else {
        let path = unquote(first);
        let visible = path.rsplit('/').next().unwrap_or(&path).to_string();
        (visible, path, SymbolResolutionMethod::ImportedNamespace)
    };
    if visible != "_" && visible != "." && !path.is_empty() {
        insert_alias(aliases, &visible, &path, method);
    }
}

fn parse_java_import(
    text: &str,
    aliases: &mut BTreeMap<String, Binding>,
    namespaces: &mut BTreeSet<String>,
) {
    let import = text
        .trim()
        .trim_end_matches(';')
        .strip_prefix("import ")
        .unwrap_or_default();
    if let Some(target) = import.strip_prefix("static ") {
        if let Some(visible) = target.rsplit('.').next() {
            insert_alias(
                aliases,
                visible,
                target,
                SymbolResolutionMethod::StaticImport,
            );
        }
    } else if let Some(namespace) = import.strip_suffix(".*") {
        namespaces.insert(namespace.to_string());
    } else if let Some(visible) = import.rsplit('.').next() {
        insert_alias(
            aliases,
            visible,
            import,
            SymbolResolutionMethod::ImportedNamespace,
        );
    }
}

fn insert_alias(
    aliases: &mut BTreeMap<String, Binding>,
    visible: &str,
    target: &str,
    method: SymbolResolutionMethod,
) {
    aliases.insert(
        visible.to_string(),
        Binding {
            target: normalize_symbol(target),
            method,
        },
    );
}

fn unquote(value: &str) -> String {
    value
        .trim()
        .trim_matches(|character| matches!(character, '\'' | '"' | '`'))
        .trim_start_matches("node:")
        .to_string()
}

fn is_declaration_kind(kind: &str) -> bool {
    matches!(
        kind,
        "class_declaration"
            | "struct_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "function_declaration"
            | "function_definition"
    )
}

fn is_callable_scope(kind: &str, language: Language) -> bool {
    match language {
        Language::C | Language::Cpp => matches!(kind, "function_definition" | "lambda_expression"),
        Language::Csharp => matches!(
            kind,
            "method_declaration"
                | "constructor_declaration"
                | "local_function_statement"
                | "lambda_expression"
                | "anonymous_method_expression"
        ),
        Language::Java => matches!(
            kind,
            "method_declaration" | "constructor_declaration" | "lambda_expression"
        ),
        Language::Javascript | Language::Typescript | Language::Tsx => matches!(
            kind,
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "generator_function"
                | "generator_function_declaration"
        ),
        Language::Python => matches!(kind, "function_definition" | "lambda"),
        Language::Go => matches!(
            kind,
            "function_declaration" | "method_declaration" | "func_literal"
        ),
        Language::Rust => false,
        Language::Kotlin => matches!(
            kind,
            "function_declaration" | "secondary_constructor" | "lambda_literal"
        ),
        Language::Php => matches!(
            kind,
            "function_definition" | "method_declaration" | "anonymous_function" | "arrow_function"
        ),
    }
}

fn parameter_list_binds(parameters: &Node<'_, StrDoc<SupportLang>>, name: &str) -> bool {
    parameters.dfs().any(|candidate| {
        candidate
            .field("name")
            .is_some_and(|bound| bound.text().as_ref() == name)
            || candidate
                .field("pattern")
                .is_some_and(|pattern| pattern.text().as_ref() == name)
            || (candidate.kind().as_ref() == "identifier"
                && candidate.text().as_ref() == name
                && candidate.parent().is_some_and(|parent| {
                    matches!(parent.kind().as_ref(), "parameters" | "formal_parameters")
                }))
    })
}

pub(crate) fn parameter_shadows_name(
    node: &Node<'_, StrDoc<SupportLang>>,
    name: &str,
    language: Language,
) -> bool {
    node.ancestors()
        .find(|ancestor| is_callable_scope(ancestor.kind().as_ref(), language))
        .and_then(|scope| scope.field("parameters"))
        .is_some_and(|parameters| parameter_list_binds(&parameters, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_only_exact_supported_hex_digest_expressions() {
        let crypto = BTreeSet::from(["crypto"]);
        assert_eq!(
            parse_fixed_hex_export(
                "export const hash = (data: string) => crypto.createHash('sha256').update(data).digest('hex')",
                &crypto,
            ),
            Some(("hash".to_string(), "sha256".to_string(), 64))
        );
        for lookalike in [
            "export const hash = (data: string) => crypto.createHash('sha256').update(data).digest('base64')",
            "export const hash = (data: string) => crypto.createHash('sha256').update('constant').digest('hex')",
            "export const hash = (data: string) => crypto.createHash('sha3-256').update(data).digest('hex')",
            "export const hash = (data: string) => normalize(crypto.createHash('sha256').update(data).digest('hex'))",
        ] {
            assert_eq!(parse_fixed_hex_export(lookalike, &crypto), None);
        }
    }

    #[test]
    fn resolves_direct_commonjs_property_bindings() {
        let mut aliases = BTreeMap::new();
        parse_javascript_requires(
            "const exec = require('child_process').exec;\nconst child = require('child_process');",
            &mut aliases,
        );
        assert_eq!(aliases["exec"].target, "child_process.exec");
        assert_eq!(aliases["child"].target, "child_process");
    }

    #[test]
    fn resolves_only_exact_promisified_child_process_bindings() {
        let mut aliases = BTreeMap::new();
        parse_javascript_import("import { exec } from 'node:child_process';", &mut aliases);
        parse_javascript_import("import { promisify } from 'node:util';", &mut aliases);
        parse_javascript_promisify_aliases(
            "const execAsync = promisify(exec);\nconst unrelated = wrap(exec);",
            &mut aliases,
        );
        assert_eq!(aliases["execAsync"].target, "child_process.exec");
        assert!(!aliases.contains_key("unrelated"));
    }
}
