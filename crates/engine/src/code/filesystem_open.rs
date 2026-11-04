//! Filesystem API identity and effective open modes. These facts describe an
//! operation, not path authority, containment, successful I/O or a verdict.
use std::collections::BTreeMap;

use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language,
    LiteralValue, OperandFact, OperandFactKind, Provenance, Resolution, SymbolConfidence,
};

use super::{
    comments::CommentRanges, conditional::ConditionalRegions, literals::LiteralEnvironment,
    native_api::NativeApiContext, symbols::FileSymbolEnvironment,
};
type N<'a> = Node<'a, StrDoc<SupportLang>>;

type ScopeKey = (usize, usize, String);
fn scope_key(n: &N<'_>) -> ScopeKey {
    (n.range().start, n.range().end, n.kind().into_owned())
}
fn python_scope(n: &N<'_>) -> bool {
    matches!(
        n.kind().as_ref(),
        "function_definition" | "lambda" | "class_definition" | "module"
    )
}

/// Name + lexical scope lookup avoids searching every same-named declaration
/// in sibling functions for each open. Scope kind distinguishes a file and its
/// sole function when tree-sitter gives them identical byte ranges.
pub(super) struct Bindings<'a> {
    names: BTreeMap<String, BTreeMap<ScopeKey, Vec<N<'a>>>>,
    python: bool,
}
struct PythonImports<'a> {
    names: BTreeMap<String, BTreeMap<ScopeKey, Vec<(N<'a>, String)>>>,
}
impl<'a> PythonImports<'a> {
    fn new(root: &N<'a>) -> Self {
        let mut names = BTreeMap::<String, BTreeMap<ScopeKey, Vec<(N<'a>, String)>>>::new();
        for n in root.dfs().filter(|n| {
            matches!(
                n.kind().as_ref(),
                "import_statement" | "import_from_statement"
            )
        }) {
            let Some(scope) = n.ancestors().find(python_scope) else {
                continue;
            };
            for (alias, target) in super::symbols::python_import_targets(n.text().as_ref()) {
                names
                    .entry(alias)
                    .or_default()
                    .entry(scope_key(&scope))
                    .or_default()
                    .push((n.clone(), target));
            }
        }
        Self { names }
    }
    fn entries(&self, call: &N<'a>, name: &str) -> Option<&[(N<'a>, String)]> {
        let scopes = self.names.get(name)?;
        call.ancestors()
            .filter(python_scope)
            .filter(|s| {
                s.kind().as_ref() != "class_definition"
                    || !call
                        .ancestors()
                        .take_while(|p| p.range() != s.range())
                        .any(|p| p.kind().as_ref() == "function_definition")
            })
            .find_map(|s| scopes.get(&scope_key(&s)).map(Vec::as_slice))
    }
    fn target(&self, call: &N<'a>, observed: &str) -> Option<String> {
        let (head, tail) = observed.split_once('.').unwrap_or((observed, ""));
        let [(n, target)] = self.entries(call, head)? else {
            return None;
        };
        if n.range().end > call.range().start {
            return None;
        }
        if n.ancestors().take_while(|p| !python_scope(p)).any(|p| {
            matches!(
                p.kind().as_ref(),
                "if_statement" | "try_statement" | "for_statement" | "while_statement"
            )
        }) {
            return None;
        }
        Some(if tail.is_empty() {
            target.clone()
        } else {
            format!("{target}.{tail}")
        })
    }
    fn binds(&self, call: &N<'a>, name: &str) -> bool {
        self.entries(call, name).is_some()
    }
}
impl<'a> Bindings<'a> {
    pub(super) fn new(root: &N<'a>) -> Self {
        let python = root.kind().as_ref() == "module";
        let mut names = BTreeMap::<String, BTreeMap<ScopeKey, Vec<N<'a>>>>::new();
        for n in root.dfs() {
            let kind = n.kind();
            let name = match kind.as_ref() {
                "function_definition"
                | "function_declaration"
                | "class_definition"
                | "class_declaration"
                | "enum_declaration"
                | "struct_declaration"
                | "parameter"
                | "parameter_declaration"
                | "required_parameter"
                | "optional_parameter"
                | "typed_parameter"
                | "default_parameter"
                | "var_spec"
                | "const_spec" => n
                    .field("name")
                    .or_else(|| n.children().find(|c| c.kind().as_ref() == "identifier")),
                "assignment"
                | "assignment_expression"
                | "augmented_assignment"
                | "short_var_declaration"
                | "for_statement"
                | "for_in_clause"
                | "range_clause"
                | "named_expression" => n.field("left"),
                "as_pattern" => n
                    .field("alias")
                    .or_else(|| n.children().filter(|n| n.is_named()).last()),
                "variable_declarator" => n.field("name"),
                "identifier"
                    if n.parent().is_some_and(|p| {
                        matches!(p.kind().as_ref(), "parameters" | "lambda_parameters")
                    }) =>
                {
                    Some(n.clone())
                }
                _ => None,
            };
            let Some(scope) = n.ancestors().find(|p| {
                if python {
                    python_scope(p)
                } else {
                    matches!(
                        p.kind().as_ref(),
                        "function_declaration"
                            | "method_declaration"
                            | "func_literal"
                            | "lambda_expression"
                            | "block"
                            | "statement_block"
                            | "compound_statement"
                            | "class_declaration"
                            | "source_file"
                            | "program"
                            | "compilation_unit"
                    )
                }
            }) else {
                continue;
            };
            if let Some(name) = name {
                let names_for_node = n.field_children("name").chain(std::iter::once(name));
                for part in names_for_node.flat_map(|n| {
                    n.dfs()
                        .filter(|p| matches!(p.kind().as_ref(), "identifier" | "type_identifier"))
                        .collect::<Vec<_>>()
                }) {
                    names
                        .entry(part.text().into_owned())
                        .or_default()
                        .entry(scope_key(&scope))
                        .or_default()
                        .push(n.clone());
                }
            }
        }
        Self { names, python }
    }
    pub(super) fn shadowed(&self, call: &N<'a>, name: &str) -> bool {
        let Some(scopes) = self.names.get(name) else {
            return false;
        };
        call.ancestors()
            .filter(|s| !self.python || python_scope(s))
            .filter(|s| {
                !self.python
                    || s.kind().as_ref() != "class_definition"
                    || !call
                        .ancestors()
                        .take_while(|p| p.range() != s.range())
                        .any(|p| p.kind().as_ref() == "function_definition")
            })
            .filter_map(|s| scopes.get(&scope_key(&s)))
            .flatten()
            .any(|n| {
                self.python
                    || n.range().start < call.range().start
                    || matches!(
                        n.kind().as_ref(),
                        "class_declaration" | "enum_declaration" | "struct_declaration"
                    )
            })
    }
}

pub(super) fn string_mode(value: &str) -> Option<bool> {
    let first = value.chars().next()?;
    if !matches!(first, 'r' | 'w' | 'a' | 'x' | 'c')
        || !value
            .chars()
            .all(|c| matches!(c, 'r' | 'w' | 'a' | 'x' | 'c' | '+' | 'b' | 't' | 'e'))
    {
        return None;
    }
    Some(first != 'r' || value.contains('+'))
}

fn raw_filesystem_rule(rule: &str) -> bool {
    rule.strip_suffix("-filesystem-read")
        .or_else(|| rule.strip_suffix("-filesystem-write"))
        .is_some_and(|language| {
            matches!(
                language,
                "c" | "cpp"
                    | "csharp"
                    | "java"
                    | "kotlin"
                    | "go"
                    | "python"
                    | "php"
                    | "javascript"
                    | "typescript"
                    | "tsx"
                    | "rust"
            )
        })
}
fn mode_value<'a>(
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    node: Option<&N<'a>>,
    default: Option<bool>,
) -> Option<bool> {
    match node {
        None => default,
        Some(n) => match literals.evaluate(n).value {
            Some(LiteralValue::String(s)) => string_mode(&s),
            _ => None,
        },
    }
}
fn arguments<'a>(call: &N<'a>) -> Vec<N<'a>> {
    call.field("arguments")
        .map(|a| {
            a.children()
                .filter(|n| n.is_named() && !n.kind().as_ref().contains("comment"))
                .map(|n| {
                    if matches!(n.kind().as_ref(), "argument" | "value_argument") {
                        n.children().filter(|c| c.is_named()).last().unwrap_or(n)
                    } else {
                        n
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}
fn keyword<'a>(args: &[N<'a>], name: &str, offset: usize) -> Option<N<'a>> {
    args.iter()
        .find_map(|a| {
            (a.kind().as_ref() == "keyword_argument"
                && a.field("name").is_some_and(|n| n.text() == name))
            .then(|| a.field("value"))
            .flatten()
        })
        .or_else(|| {
            args.iter()
                .filter(|a| a.kind().as_ref() != "keyword_argument")
                .nth(offset)
                .cloned()
        })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit<'a>(
    path: &str,
    call: &N<'a>,
    operand: &N<'a>,
    language: Language,
    write: Option<bool>,
    mode: Option<&N<'a>>,
    rule: &str,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let capability = if write == Some(true) {
        Capability::FilesystemWrite
    } else {
        Capability::FilesystemRead
    };
    let rule_id = if rule.is_empty() {
        format!(
            "{}-filesystem-{}",
            match language {
                Language::Javascript => "javascript",
                Language::Typescript => "typescript",
                Language::Tsx => "tsx",
                Language::Python => "python",
                Language::C => "c",
                Language::Cpp => "cpp",
                Language::Csharp => "csharp",
                Language::Java => "java",
                Language::Kotlin => "kotlin",
                Language::Php => "php",
                Language::Go => "go",
                Language::Rust => "rust",
            },
            if write == Some(true) { "write" } else { "read" }
        )
    } else {
        rule.to_owned()
    };
    let location = super::matcher::location(path, call);
    let mut captures = BTreeMap::from([(
        "path".into(),
        Capture {
            text: operand.text().into_owned(),
            location: super::matcher::location(path, operand),
        },
    )]);
    let mut literal_facts = BTreeMap::from([("path".into(), literals.evaluate(operand))]);
    if let Some(mode) = mode {
        captures.insert(
            "mode".into(),
            Capture {
                text: mode.text().into_owned(),
                location: super::matcher::location(path, mode),
            },
        );
        literal_facts.insert("mode".into(), literals.evaluate(mode));
    }
    let mode_label = match write {
        Some(true) => "write",
        Some(false) => "read",
        None => "unresolved",
    };
    let item = Evidence {
        id: super::matcher::evidence_id(path, &rule_id, call.range().start, call.range().end),
        kind: EvidenceKind::Sink,
        capability,
        rule_id,
        location: location.clone(),
        enclosing_symbol: super::context::enclosing_symbol(call),
        captures,
        cwe_candidates: vec!["CWE-22".into()],
        tags: vec![
            "filesystem".into(),
            "path".into(),
            "sdk-owned-open".into(),
            format!("filesystem-mode:{mode_label}"),
        ],
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: "mehscan filesystem-api-modes 1".into(),
            rule_version: 3,
        },
        context: EvidenceContext {
            availability: Some(conditional.availability_for(call.range())),
            reachability: Some(super::reachability::classify(call, literals)),
            literals: literal_facts,
            operand_facts: vec![OperandFact {
                role: "filesystem_mode".into(),
                kind: OperandFactKind::LocalOperandOrigin,
                location,
                value: mode.map_or_else(
                    || format!("default:{mode_label}"),
                    |n| format!("{mode_label}:{}", n.text()),
                ),
                remaining_checks: if write.is_none() {
                    vec!["effective_mode_and_successful_open".into()]
                } else {
                    vec![]
                },
            }],
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        related_evidence: vec![],
    };
    evidence.push(item);
}

#[allow(clippy::too_many_arguments)]
pub(super) fn add<'a>(
    path: &str,
    root: &N<'a>,
    language: Language,
    symbols: &FileSymbolEnvironment,
    native: &NativeApiContext,
    php: Option<&super::php::PhpContext<'a>>,
    kotlin: Option<&super::kotlin::Imports>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language == Language::Rust || language == Language::Java {
        return;
    }
    let node_language = matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    );
    let node_calls = if node_language {
        super::node_context::filesystem_calls(path, root)
    } else {
        BTreeMap::new()
    };
    let bindings = Bindings::new(root);
    let python_imports = PythonImports::new(root);
    let go_imports = if language == Language::Go {
        root.dfs()
            .filter(|n| n.kind().as_ref() == "import_spec")
            .filter_map(|n| {
                let path = n.field("path")?.text().trim_matches('"').to_owned();
                let name = n
                    .field("name")
                    .map(|n| n.text().into_owned())
                    .unwrap_or_else(|| path.rsplit('/').next().unwrap_or("").to_owned());
                Some((name, path))
            })
            .collect()
    } else {
        BTreeMap::new()
    };
    let calls = root
        .dfs()
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "call"
                    | "call_expression"
                    | "function_call_expression"
                    | "invocation_expression"
                    | "object_creation_expression"
            )
        })
        .collect::<Vec<_>>();
    let calls_by_range = calls
        .iter()
        .map(|n| ((n.range().start, n.range().end), n))
        .collect::<BTreeMap<_, _>>();
    // Apply identity before paths are built. A later correct summary must not
    // leave a second raw, spelling-only claim behind.
    evidence.retain(|e| {
        if !raw_filesystem_rule(&e.rule_id) {
            return true;
        }
        let Some(call) =
            calls_by_range.get(&(e.location.start.byte_offset, e.location.end.byte_offset))
        else {
            return true;
        };
        if node_language {
            return node_calls.contains_key(&(call.range().start, call.range().end));
        }
        let callee = call
            .field("function")
            .map(|n| n.text().into_owned())
            .unwrap_or_default();
        if language == Language::Python {
            return python_api(call, &callee, &python_imports, &bindings).is_some();
        }
        if language == Language::Go {
            return go_api(&go_imports, call, &callee, &bindings).is_some();
        }
        if matches!(language, Language::C | Language::Cpp) {
            return native.call_name(call).is_some();
        }
        if language == Language::Csharp {
            return callee.rsplit_once('.').is_some_and(|(_, method)| {
                ["File", "Directory"].iter().any(|ty| {
                    dotnet_owned(
                        call,
                        &callee,
                        &format!("System.IO.{ty}.{method}"),
                        symbols,
                        &bindings,
                    )
                })
            });
        }
        true
    });
    let mut generated = Vec::new();
    for call in &calls {
        if comments.is_in_comment(call.range()) {
            continue;
        }
        let args = arguments(call);
        let fallback = if language == Language::Kotlin {
            super::kotlin::filesystem_call(call)
                .and_then(|c| c.arguments.first().map(|a| a.value.clone()))
        } else if language == Language::Python {
            call.field("function")
                .and_then(|f| f.field("object"))
                .and_then(|r| arguments(&r).first().cloned())
        } else {
            None
        };
        let Some(first) = args.first().or(fallback.as_ref()) else {
            continue;
        };
        let callee = call
            .field("function")
            .or_else(|| call.field("type"))
            .map(|n| n.text().into_owned())
            .unwrap_or_default();
        let mut operand = first.clone();
        let (write, mode): (Option<bool>, Option<N<'a>>) = if node_language {
            let Some(api) = node_calls.get(&(call.range().start, call.range().end)) else {
                continue;
            };
            let method = api.rsplit('.').next().unwrap_or("");
            if matches!(method, "open" | "openSync") {
                let mode = args.get(1).cloned();
                (node_mode(literals, mode.as_ref(), None), mode)
            } else if matches!(
                method,
                "readFile"
                    | "readFileSync"
                    | "createReadStream"
                    | "writeFile"
                    | "writeFileSync"
                    | "appendFile"
                    | "appendFileSync"
                    | "createWriteStream"
            ) {
                let reading = matches!(method, "readFile" | "readFileSync" | "createReadStream");
                let options = args.get(if reading || method == "createWriteStream" {
                    1
                } else {
                    2
                });
                let (write, mode) = node_options(
                    literals,
                    options,
                    if matches!(method, "createReadStream" | "createWriteStream") {
                        "flags"
                    } else {
                        "flag"
                    },
                    !reading,
                );
                // These observations replace legacy read/write spelling only
                // for this actual operation; content sources remain intact.
                (if reading { write } else { Some(true) }, mode)
            } else {
                continue;
            }
        } else if language == Language::Python {
            let Some(api) = python_api(call, &callee, &python_imports, &bindings) else {
                continue;
            };
            if api == "pathlib.Path.open" {
                let Some(receiver) = call.field("function").and_then(|f| f.field("object")) else {
                    continue;
                };
                let Some(path) = arguments(&receiver).first().cloned() else {
                    continue;
                };
                operand = path;
                let mode = keyword(&args, "mode", 0);
                (mode_value(literals, mode.as_ref(), Some(false)), mode)
            } else if matches!(api.as_str(), "builtins.open" | "io.open" | "codecs.open") {
                operand = keyword(&args, "file", 0).unwrap_or_else(|| first.clone());
                let mode = keyword(&args, "mode", 1);
                (mode_value(literals, mode.as_ref(), Some(false)), mode)
            } else {
                continue;
            }
        } else if matches!(language, Language::C | Language::Cpp) {
            match native.call_name(call) {
                Some("fopen" | "freopen") => {
                    let mode = args.get(1).cloned();
                    (mode_value(literals, mode.as_ref(), None), mode)
                }
                Some("open" | "openat") => {
                    let start = usize::from(native.call_name(call) == Some("openat"));
                    let Some(path_arg) = args.get(start) else {
                        continue;
                    };
                    operand = path_arg.clone();
                    let mode = args.get(start + 1).cloned();
                    (posix_flags(mode.as_ref(), native), mode)
                }
                Some("creat") => (Some(true), None),
                _ => continue,
            }
        } else if language == Language::Php {
            if !php.is_some_and(|p| p.exact_function(call, "fopen")) {
                continue;
            }
            let mode = args.get(1).cloned();
            (mode_value(literals, mode.as_ref(), None), mode)
        } else if language == Language::Csharp {
            let Some((kind, mode, access)) = dotnet_open(call, &callee, symbols, &bindings) else {
                continue;
            };
            operand = super::csharp_mainstream::formal_argument(call, "path", 0).unwrap_or(operand);
            let write = dotnet_mode(
                call,
                &kind,
                mode.as_ref(),
                access.as_ref(),
                symbols,
                &bindings,
            );
            (write, mode)
        } else if language == Language::Kotlin {
            let Some(imports) = kotlin else { continue };
            let Some(kcall) = super::kotlin::filesystem_call(call) else {
                continue;
            };
            let name = kcall.callee.text();
            let owned = |ty: &str| imports.exact(root, call, name.as_ref(), ty);
            operand = kcall.arguments[0].value.clone();
            if owned("java.io.FileInputStream") || owned("java.io.FileReader") {
                (Some(false), None)
            } else if owned("java.io.FileOutputStream") || owned("java.io.FileWriter") {
                (Some(true), None)
            } else if owned("java.io.RandomAccessFile") {
                let mode = kcall.arguments.get(1).map(|a| a.value.clone());
                let write = mode
                    .as_ref()
                    .and_then(|n| match literals.evaluate(n).value {
                        Some(LiteralValue::String(ref s)) if s == "r" => Some(false),
                        Some(LiteralValue::String(ref s))
                            if matches!(s.as_str(), "rw" | "rws" | "rwd") =>
                        {
                            Some(true)
                        }
                        _ => None,
                    });
                (write, mode)
            } else if owned("java.nio.channels.FileChannel.open")
                || owned("java.nio.file.Files.newByteChannel")
            {
                let modes = &kcall.arguments[1..];
                let known = modes.iter().all(|a| {
                    [
                        "READ",
                        "WRITE",
                        "APPEND",
                        "CREATE",
                        "CREATE_NEW",
                        "TRUNCATE_EXISTING",
                        "DELETE_ON_CLOSE",
                        "SPARSE",
                        "SYNC",
                        "DSYNC",
                    ]
                    .iter()
                    .any(|v| {
                        imports.exact(
                            root,
                            call,
                            a.value.text().as_ref(),
                            &format!("java.nio.file.StandardOpenOption.{v}"),
                        )
                    })
                });
                let write = modes.iter().any(|a| {
                    ["WRITE", "APPEND", "DELETE_ON_CLOSE"]
                        .iter()
                        .any(|v| a.value.text().rsplit('.').next() == Some(v))
                });
                (
                    if known { Some(write) } else { None },
                    modes.first().map(|a| a.value.clone()),
                )
            } else {
                continue;
            }
        } else {
            continue;
        };
        let rule = if language == Language::Csharp && callee.ends_with("FileStream") {
            if write == Some(true) {
                "csharp-filestream-write"
            } else {
                "csharp-filestream-read"
            }
        } else {
            ""
        };
        emit(
            path,
            call,
            &operand,
            language,
            write,
            mode.as_ref(),
            rule,
            conditional,
            literals,
            &mut generated,
        );
    }
    let replacements = generated
        .iter()
        .map(|e| (e.location.start.byte_offset, e.location.end.byte_offset))
        .collect::<std::collections::BTreeSet<_>>();
    evidence.retain(|e| {
        !(replacements.contains(&(e.location.start.byte_offset, e.location.end.byte_offset))
            && (raw_filesystem_rule(&e.rule_id) || e.rule_id.starts_with("csharp-filestream-")))
    });
    evidence.extend(generated);
    if language == Language::Cpp {
        cpp_streams(path, root, native, conditional, literals, evidence);
    }
    if language == Language::Csharp {
        evidence.retain(|e| {
            !e.rule_id.starts_with("csharp-filestream-")
                || calls_by_range
                    .get(&(e.location.start.byte_offset, e.location.end.byte_offset))
                    .is_some_and(|call| {
                        let callee = call
                            .field("type")
                            .map(|n| n.text().into_owned())
                            .unwrap_or_default();
                        dotnet_owned(call, &callee, "System.IO.FileStream", symbols, &bindings)
                    })
        });
    }
}

fn python_api<'a>(
    call: &N<'a>,
    callee: &str,
    imports: &PythonImports<'a>,
    bindings: &Bindings<'a>,
) -> Option<String> {
    let head = callee.split('.').next()?;
    if bindings.shadowed(call, head) {
        return None;
    }
    if callee == "open" && !imports.binds(call, "open") {
        // A from-import named open must resolve exactly, rather than borrowing
        // the builtin contract. Scoped imports include these aliases.
        return Some("builtins.open".into());
    }
    if let Some(target) = imports.target(call, callee)
        && matches!(
            target.as_str(),
            "builtins.open"
                | "io.open"
                | "codecs.open"
                | "os.remove"
                | "os.unlink"
                | "os.rename"
                | "shutil.copy"
                | "shutil.copy2"
                | "shutil.copyfile"
                | "shutil.move"
                | "pathlib.Path"
        )
    {
        return Some(target);
    }
    if let Some(function) = call.field("function")
        && function
            .field("attribute")
            .is_some_and(|n| n.text() == "open")
        && let Some(receiver) = function.field("object")
        && let Some(constructor) = receiver.field("function")
        && !bindings.shadowed(call, constructor.text().split('.').next().unwrap_or(""))
        && imports.target(call, constructor.text().as_ref()).as_deref() == Some("pathlib.Path")
    {
        return Some("pathlib.Path.open".into());
    }
    // Existing read_text/write_text observations have the same exact Path owner.
    if callee.contains('(')
        && let Some(function) = call.field("function")
        && let Some(receiver) = function.field("object")
        && let Some(constructor) = receiver.field("function")
        && imports.target(call, constructor.text().as_ref()).as_deref() == Some("pathlib.Path")
    {
        return Some("pathlib.Path.method".into());
    }
    None
}
fn go_api<'a>(
    imports: &BTreeMap<String, String>,
    call: &N<'a>,
    callee: &str,
    bindings: &Bindings<'a>,
) -> Option<String> {
    let (head, method) = callee.split_once('.')?;
    if bindings.shadowed(call, head) || imports.get(head).map(String::as_str) != Some("os") {
        return None;
    }
    Some(format!("os.{method}"))
}
fn node_mode<'a>(
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    mode: Option<&N<'a>>,
    default: Option<bool>,
) -> Option<bool> {
    // Numeric flags are platform-dependent. Without proven constants, preserve
    // their expression and uncertainty instead of borrowing a suffix's value.
    mode_value(literals, mode, default)
}
fn node_options<'a>(
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    options: Option<&N<'a>>,
    key: &str,
    default_write: bool,
) -> (Option<bool>, Option<N<'a>>) {
    let Some(options) = options else {
        return (Some(default_write), None);
    };
    if options.kind().as_ref() == "object" {
        let mut flag = None;
        for pair in options.children().filter(|n| n.is_named()) {
            if pair.kind().as_ref() != "pair" {
                return (None, Some(options.clone()));
            }
            if pair
                .field("key")
                .is_some_and(|n| n.text().trim_matches(['\'', '"']) == key)
            {
                flag = pair.field("value");
            }
        }
        (
            node_mode(literals, flag.as_ref(), Some(default_write)),
            flag,
        )
    } else if matches!(
        literals.evaluate(options).value,
        Some(LiteralValue::String(_))
    ) || matches!(
        options.kind().as_ref(),
        "arrow_function" | "function_expression"
    ) {
        // Encoding strings / callbacks are not flag overrides.
        (Some(default_write), None)
    } else {
        (None, Some(options.clone()))
    }
}
fn posix_flags(mode: Option<&N<'_>>, native: &NativeApiContext) -> Option<bool> {
    let mode = mode?;
    let text = mode.text();
    let mut write = false;
    for part in text.split('|') {
        if native.macro_precedes(
            part.trim().trim_matches(['(', ')']).trim(),
            mode.range().start,
        ) {
            return None;
        }
        match part.trim().trim_matches(['(', ')']).trim() {
            "O_WRONLY" | "O_RDWR" | "O_CREAT" | "O_TRUNC" | "O_APPEND" => write = true,
            "O_RDONLY" | "O_NONBLOCK" | "O_CLOEXEC" | "O_EXCL" | "O_NOFOLLOW" | "O_SYNC"
            | "O_DSYNC" | "O_DIRECTORY" | "O_NOCTTY" | "O_LARGEFILE" => (),
            _ => return None,
        }
    }
    Some(write)
}
fn dotnet_owned<'a>(
    call: &N<'a>,
    observed: &str,
    canonical: &str,
    symbols: &FileSymbolEnvironment,
    bindings: &Bindings<'a>,
) -> bool {
    let observed = observed.strip_prefix("global::").unwrap_or(observed);
    !bindings.shadowed(call, observed.split('.').next().unwrap_or(""))
        && symbols
            .resolve(observed, canonical)
            .is_some_and(|r| r.confidence != SymbolConfidence::Ambiguous)
}
fn dotnet_open<'a>(
    call: &N<'a>,
    callee: &str,
    symbols: &FileSymbolEnvironment,
    bindings: &Bindings<'a>,
) -> Option<(String, Option<N<'a>>, Option<N<'a>>)> {
    let is_stream = call.kind().as_ref() == "object_creation_expression"
        && dotnet_owned(call, callee, "System.IO.FileStream", symbols, bindings);
    let is_open = dotnet_owned(call, callee, "System.IO.File.Open", symbols, bindings);
    if !is_stream && !is_open {
        return None;
    }
    let args = arguments(call);
    if args.len() < 2 {
        return None;
    }
    Some((
        if is_stream { "stream" } else { "file" }.into(),
        super::csharp_mainstream::formal_argument(call, "mode", 1),
        super::csharp_mainstream::formal_argument(call, "access", 2),
    ))
}
fn dotnet_mode<'a>(
    call: &N<'a>,
    _kind: &str,
    mode: Option<&N<'a>>,
    access: Option<&N<'a>>,
    symbols: &FileSymbolEnvironment,
    bindings: &Bindings<'a>,
) -> Option<bool> {
    let mode = mode?.text();
    let exact_mode = |value: &str| {
        dotnet_owned(
            call,
            mode.as_ref(),
            &format!("System.IO.FileMode.{value}"),
            symbols,
            bindings,
        )
    };
    if ["Create", "CreateNew", "OpenOrCreate", "Append", "Truncate"]
        .iter()
        .any(|n| exact_mode(n))
    {
        return Some(true);
    }
    if !exact_mode("Open") {
        return None;
    }
    match access {
        None => Some(true),
        Some(a)
            if dotnet_owned(
                call,
                a.text().as_ref(),
                "System.IO.FileAccess.Read",
                symbols,
                bindings,
            ) =>
        {
            Some(false)
        }
        Some(a)
            if dotnet_owned(
                call,
                a.text().as_ref(),
                "System.IO.FileAccess.ReadWrite",
                symbols,
                bindings,
            ) || dotnet_owned(
                call,
                a.text().as_ref(),
                "System.IO.FileAccess.Write",
                symbols,
                bindings,
            ) =>
        {
            Some(true)
        }
        _ => None,
    }
}
fn cpp_streams<'a>(
    path: &str,
    root: &N<'a>,
    native: &NativeApiContext,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for declaration in root.dfs().filter(|n| n.kind().as_ref() == "declaration") {
        let Some(ty) = declaration.field("type") else {
            continue;
        };
        let Some(kind) = native.filesystem_stream_type(&ty) else {
            continue;
        };
        for d in declaration.field_children("declarator") {
            let args = d
                .field("value")
                .or_else(|| d.field("arguments"))
                .or_else(|| d.children().find(|n| n.kind().as_ref() == "argument_list"))
                .or_else(|| {
                    d.field("parameters").filter(|p| {
                        p.children().filter(|n| n.is_named()).all(|parameter| {
                            parameter.field("declarator").is_none()
                                && parameter
                                    .field("type")
                                    .is_some_and(|n| native.local_shadow(&d, n.text().as_ref()))
                        })
                    })
                });
            let Some(args) = args else { continue };
            let args = args
                .children()
                .filter(|n| n.is_named())
                .map(|n| {
                    if n.kind().as_ref() == "parameter_declaration" {
                        n.field("type").unwrap_or(n)
                    } else {
                        n
                    }
                })
                .collect::<Vec<_>>();
            let Some(operand) = args.first() else {
                continue;
            };
            let mode = args.get(1);
            let write = if kind == "ofstream" {
                Some(true)
            } else if let Some(mode) = mode {
                let text = mode.text();
                let parts = text.split('|').map(str::trim).collect::<Vec<_>>();
                if parts.iter().all(|p| {
                    ["in", "out", "app", "trunc", "ate", "binary"]
                        .iter()
                        .any(|f| {
                            *p == format!("std::ios::{f}") || *p == format!("std::ios_base::{f}")
                        })
                }) {
                    Some(parts.iter().any(|p| {
                        p.ends_with("::out") || p.ends_with("::app") || p.ends_with("::trunc")
                    }))
                } else {
                    None
                }
            } else {
                Some(kind == "fstream")
            };
            emit(
                path,
                &d,
                operand,
                Language::Cpp,
                write,
                mode,
                "",
                conditional,
                literals,
                evidence,
            );
        }
    }
}
