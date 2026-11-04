//! Bounded filesystem purpose/provenance facts. These are not containment proofs.
use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{Capability, Evidence, Language, OperandFact, OperandFactKind};

type RustNode<'a> = Node<'a, StrDoc<SupportLang>>;

pub(super) fn annotate<'a>(language: Language, root: &RustNode<'a>, evidence: &mut [Evidence]) {
    if language != Language::Rust
        || !evidence.iter().any(|e| {
            matches!(
                e.rule_id.as_str(),
                "rust-filesystem-read" | "rust-filesystem-write"
            )
        })
    {
        return;
    }
    // Build once per file, never walk the repository or reparse per operation.
    // This proof resolves the file's outer module only. Child modules have
    // separate imports and namespaces (including test-only shadows).
    let mut child_module_end = 0;
    let nodes = root
        .dfs()
        .filter(|n| {
            if n.range().start < child_module_end {
                return false;
            }
            if n.kind().as_ref() == "mod_item" {
                child_module_end = n.range().end;
            }
            true
        })
        .collect::<Vec<_>>();
    if nodes
        .iter()
        .any(|n| n.kind().as_ref() == "ERROR" || n.is_missing())
    {
        return;
    }
    let mut imports = BTreeMap::new();
    let mut ambiguous = BTreeSet::new();
    for node in &nodes {
        if node.kind().as_ref() == "use_declaration" {
            // A glob can introduce a local module/type with an SDK spelling.
            // Its exported names are outside this file-local proof.
            if node.text().contains('*') {
                return;
            }
            for (name, canonical) in super::rust_context::rust_imports(node) {
                if node
                    .parent()
                    .is_none_or(|p| p.kind().as_ref() != "source_file")
                    || imports.insert(name.clone(), canonical).is_some()
                {
                    ambiguous.insert(name);
                }
            }
        } else if matches!(
            node.kind().as_ref(),
            "mod_item"
                | "struct_item"
                | "enum_item"
                | "union_item"
                | "trait_item"
                | "type_item"
                | "type_parameter"
                | "extern_crate_declaration"
        ) && let Some(name) = node.field("name")
        {
            ambiguous.insert(name.text().into_owned());
            if node.kind().as_ref() == "extern_crate_declaration"
                && let Some(alias) = node.field("alias")
            {
                ambiguous.insert(alias.text().into_owned());
            }
        }
    }
    let calls = nodes
        .iter()
        .filter(|n| n.kind().as_ref() == "call_expression")
        .map(|n| ((n.range().start, n.range().end), n))
        .collect::<BTreeMap<_, _>>();
    let mut bindings = BTreeMap::<(usize, String), Vec<&RustNode<'a>>>::new();
    let mut unstable = BTreeSet::new();
    for node in &nodes {
        if !matches!(
            node.kind().as_ref(),
            "let_declaration" | "parameter" | "assignment_expression" | "reference_expression"
        ) {
            continue;
        }
        let Some(scope) = callable(node) else {
            continue;
        };
        if matches!(node.kind().as_ref(), "let_declaration" | "parameter") {
            let Some(pattern) = node.field("pattern") else {
                continue;
            };
            for name in pattern.dfs().filter(|n| n.kind().as_ref() == "identifier") {
                let key = (scope.range().start, name.text().into_owned());
                if node.kind().as_ref() != "let_declaration"
                    || pattern.kind().as_ref() != "identifier"
                    || node
                        .children()
                        .any(|n| n.kind().as_ref() == "mutable_specifier")
                {
                    unstable.insert(key.clone());
                }
                bindings.entry(key).or_default().push(node);
            }
        }
        if node.kind().as_ref() == "assignment_expression"
            && let Some(left) = node.field("left")
        {
            unstable.insert((scope.range().start, left.text().into_owned()));
        }
        if node.kind().as_ref() == "reference_expression"
            && node
                .children()
                .any(|n| n.kind().as_ref() == "mutable_specifier")
            && let Some(value) = node.field("value")
        {
            unstable.insert((scope.range().start, value.text().into_owned()));
        }
    }
    let index = Index {
        imports,
        ambiguous,
        bindings,
        unstable,
    };
    for item in evidence.iter_mut().filter(|e| {
        matches!(
            e.rule_id.as_str(),
            "rust-filesystem-read" | "rust-filesystem-write"
        )
    }) {
        let Some(call) = calls.get(&(
            item.location.start.byte_offset,
            item.location.end.byte_offset,
        )) else {
            continue;
        };
        let Some(function) = call.field("function") else {
            continue;
        };
        let Some(path) = item.captures.get("path") else {
            continue;
        };
        if ![
            "std::fs::read",
            "std::fs::read_to_string",
            "std::fs::write",
            "std::fs::File::open",
            "std::fs::File::create",
            "std::fs::remove_file",
            "std::fs::remove_dir",
            "std::fs::remove_dir_all",
        ]
        .iter()
        .any(|name| index.exact(&function, name))
        {
            continue;
        }
        let (tag, value, checks) = if item.capability == Capability::FilesystemRead
            && index.exact(&function, "std::fs::File::open")
            && sync_only(call)
        {
            (
                "filesystem-effect:sync-only",
                "std::fs::File::open -> sync-only handle",
                vec![],
            )
        } else if !item.captures.contains_key("filesystem_source")
            && let Some(argument) = call
                .field("arguments")
                .and_then(|a| a.children().find(|n| n.is_named()))
            && argument.range().start == path.location.start.byte_offset
            && argument.range().end == path.location.end.byte_offset
            && index.temporary(&argument, call, 0) == Some(Temporary::Path)
        {
            (
                "filesystem-path:generated-temporary",
                "tempfile::NamedTempFile::new -> immutable temporary selection",
                vec!["temporary_file_identity_and_content_consumers".into()],
            )
        } else {
            continue;
        };
        item.tags.push(tag.into());
        let syncing = tag == "filesystem-effect:sync-only";
        item.context.operand_facts.push(OperandFact {
            role: if syncing {
                "resource_operation"
            } else {
                "path"
            }
            .into(),
            kind: if syncing {
                OperandFactKind::LocalOperandOrigin
            } else {
                OperandFactKind::TemporaryFilesystemPath
            },
            location: if syncing {
                item.location.clone()
            } else {
                path.location.clone()
            },
            value: if syncing {
                value.into()
            } else {
                path.text.clone()
            },
            remaining_checks: checks,
        });
    }
}

struct Index<'a, 'n> {
    imports: BTreeMap<String, String>,
    ambiguous: BTreeSet<String>,
    bindings: BTreeMap<(usize, String), Vec<&'n RustNode<'a>>>,
    unstable: BTreeSet<(usize, String)>,
}

#[derive(Clone, Copy, PartialEq)]
enum Temporary {
    Result,
    File,
    Path,
}

impl Index<'_, '_> {
    fn exact(&self, node: &RustNode<'_>, expected: &str) -> bool {
        let text = node.text();
        let text = text.trim();
        let head = text.split("::").next().unwrap_or(text);
        let library = expected.split("::").next().unwrap();
        !self.ambiguous.contains(head)
            && !self.ambiguous.contains(library)
            && self.imports.get(head).map_or_else(
                || text == expected,
                |base| format!("{base}{}", &text[head.len()..]) == expected,
            )
    }

    fn temporary(&self, node: &RustNode<'_>, at: &RustNode<'_>, depth: usize) -> Option<Temporary> {
        if depth >= 12 {
            return None;
        }
        if node.kind().as_ref() == "reference_expression" {
            return node
                .field("value")
                .and_then(|n| self.temporary(&n, at, depth + 1));
        }
        if node.kind().as_ref() == "try_expression" {
            let value = node.children().find(|n| n.is_named())?;
            return (self.temporary(&value, at, depth + 1) == Some(Temporary::Result))
                .then_some(Temporary::File);
        }
        if node.kind().as_ref() == "identifier" {
            let scope = callable(at)?;
            let key = (scope.range().start, node.text().into_owned());
            let declarations = self.bindings.get(&key)?;
            if self.unstable.contains(&key) || declarations.len() != 1 {
                return None;
            }
            let declaration = declarations[0];
            if declaration.range().end > at.range().start
                || declaration
                    .parent()
                    .is_none_or(|block| !block.range().contains(&at.range().start))
            {
                return None;
            }
            return declaration
                .field("value")
                .and_then(|v| self.temporary(&v, declaration, depth + 1));
        }
        if node.kind().as_ref() != "call_expression" {
            return None;
        }
        let function = node.field("function")?;
        let args = node.field("arguments")?;
        if self.exact(&function, "tempfile::NamedTempFile::new") {
            return (!args.children().any(|n| n.is_named())).then_some(Temporary::Result);
        }
        if function.kind().as_ref() != "field_expression" {
            return None;
        }
        let method = function.field("field")?;
        let method = method.text();
        let arguments = args.children().filter(|n| n.is_named()).count();
        let receiver = function.field("value")?;
        match (
            self.temporary(&receiver, at, depth + 1)?,
            method.as_ref(),
            arguments,
        ) {
            (Temporary::Result, "unwrap", 0) | (Temporary::Result, "expect", 1) => {
                Some(Temporary::File)
            }
            (Temporary::File, "path" | "into_temp_path", 0) => Some(Temporary::Path),
            _ => None,
        }
    }
}

fn callable<'a>(node: &RustNode<'a>) -> Option<RustNode<'a>> {
    node.ancestors()
        .find(|n| matches!(n.kind().as_ref(), "function_item" | "closure_expression"))
}

fn sync_only(call: &RustNode<'_>) -> bool {
    // Without unwrapping the std Result this could be an extension method on
    // Result<File>, whose implementation is not the std file syncing contract.
    let Some(receiver) = call
        .parent()
        .filter(|n| n.kind().as_ref() == "try_expression")
    else {
        return false;
    };
    let Some(field) = receiver
        .parent()
        .filter(|n| n.kind().as_ref() == "field_expression")
    else {
        return false;
    };
    if !field
        .field("field")
        .is_some_and(|n| matches!(n.text().as_ref(), "sync_all" | "sync_data"))
    {
        return false;
    }
    let Some(sync) = field
        .parent()
        .filter(|n| n.kind().as_ref() == "call_expression")
    else {
        return false;
    };
    if sync
        .field("arguments")
        .is_none_or(|args| args.children().any(|n| n.is_named()))
    {
        return false;
    }
    // No handle binding, return or additional consumer can inherit this proof.
    let Some(parent) = sync.parent() else {
        return false;
    };
    let effect = if parent.kind().as_ref() == "try_expression" {
        parent
    } else {
        sync
    };
    effect
        .parent()
        .is_some_and(|n| n.kind().as_ref() == "expression_statement")
}
