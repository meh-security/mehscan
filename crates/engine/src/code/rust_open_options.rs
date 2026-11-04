//! SDK-owned OpenOptions effects. A file-local abstract builder tracks aliases
//! and ordered setters; uncertain control flow/escapes never establish a mode.
use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language,
    OperandFact, OperandFactKind, Provenance, Resolution,
};

use super::{
    comments::CommentRanges, conditional::ConditionalRegions, literals::LiteralEnvironment,
};
type RustNode<'a> = Node<'a, StrDoc<SupportLang>>;
const FLAGS: [&str; 6] = [
    "read",
    "write",
    "append",
    "truncate",
    "create",
    "create_new",
];

#[allow(clippy::too_many_arguments)]
pub(super) fn add<'a>(
    path: &str,
    root: &RustNode<'a>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Rust {
        return;
    }
    let text = root.text();
    if !text.contains("OpenOptions") && !text.contains("options") {
        return;
    }
    let mut walker = Walker {
        names: Names::new(root),
        bindings: BTreeMap::new(),
        objects: Vec::new(),
        generation: 0,
        uncertain: Vec::new(),
        path,
        comments,
        conditional,
        literals,
        evidence,
    };
    walker.visit(root, 0);
}

fn scope(node: &RustNode<'_>) -> bool {
    matches!(
        node.kind().as_ref(),
        "source_file"
            | "declaration_list"
            | "block"
            | "function_item"
            | "closure_expression"
            | "for_expression"
            | "match_arm"
            | "if_expression"
            | "while_expression"
    )
}

type ScopeId = (usize, u8);

fn scope_id(node: &RustNode<'_>) -> ScopeId {
    // A function can begin at byte zero, just like its source file.
    (
        node.range().start,
        match node.kind().as_ref() {
            "source_file" => 0,
            "declaration_list" => 1,
            "block" => 2,
            "function_item" => 3,
            "closure_expression" => 4,
            "for_expression" => 5,
            "match_arm" => 6,
            "if_expression" => 7,
            _ => 8,
        },
    )
}

fn enclosing_scope(node: &RustNode<'_>) -> ScopeId {
    node.ancestors()
        .find(scope)
        .map_or((0, 0), |n| scope_id(&n))
}

#[derive(Default)]
struct Names {
    names: BTreeMap<(ScopeId, String), Option<String>>,
    globs: BTreeSet<ScopeId>,
    factories: BTreeSet<(ScopeId, String)>,
}

impl Names {
    fn new(root: &RustNode<'_>) -> Self {
        let mut result = Self::default();
        let mut functions = BTreeMap::<_, Vec<_>>::new();
        // Index namespace declarations once, including nested module and local
        // imports. A child module cannot borrow its parent's unqualified names.
        for node in root.dfs() {
            if !matches!(
                node.kind().as_ref(),
                "function_item"
                    | "use_declaration"
                    | "mod_item"
                    | "struct_item"
                    | "enum_item"
                    | "union_item"
                    | "trait_item"
                    | "type_item"
                    | "type_parameter"
                    | "extern_crate_declaration"
                    | "let_declaration"
                    | "parameter"
            ) {
                continue;
            }
            let owner = enclosing_scope(&node);
            if node.kind().as_ref() == "function_item" {
                if let Some(name) = node.field("name") {
                    functions
                        .entry((owner, name.text().into_owned()))
                        .or_default()
                        .push(node.clone());
                }
            } else if node.kind().as_ref() == "use_declaration" {
                if node.text().contains('*') {
                    result.globs.insert(owner);
                }
                for (name, canonical) in super::rust_context::rust_imports(&node) {
                    let key = (owner, name);
                    result
                        .names
                        .entry(key)
                        .and_modify(|value| *value = None)
                        .or_insert(Some(canonical));
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
            ) {
                if let Some(name) = node.field("alias").or_else(|| node.field("name")) {
                    result.names.insert((owner, name.text().into_owned()), None);
                }
            } else if matches!(node.kind().as_ref(), "let_declaration" | "parameter")
                && let Some(pattern) = node.field("pattern")
            {
                for name in pattern.dfs().filter(|n| n.kind().as_ref() == "identifier") {
                    result.names.insert((owner, name.text().into_owned()), None);
                }
            }
        }
        for (key, definitions) in functions {
            if definitions.len() == 1
                && !result.names.contains_key(&key)
                && definitions[0]
                    .field("return_type")
                    .is_some_and(|ty| result.options_type(&ty, &definitions[0]))
            {
                result.factories.insert(key);
            }
        }
        result
    }

    fn options_type(&self, ty: &RustNode<'_>, at: &RustNode<'_>) -> bool {
        if ty.kind().as_ref() == "reference_type" {
            return ty
                .field("type")
                .is_some_and(|inner| self.options_type(&inner, at));
        }
        matches!(
            ty.kind().as_ref(),
            "type_identifier" | "scoped_type_identifier"
        ) && self.canonical(at, ty.text().as_ref()).is_some_and(|name| {
            matches!(
                name.as_str(),
                "std::fs::OpenOptions" | "tokio::fs::OpenOptions"
            )
        })
    }

    fn factory(&self, at: &RustNode<'_>, name: &str) -> bool {
        for owner in at.ancestors().filter(scope) {
            let key = (scope_id(&owner), name.into());
            if self.names.contains_key(&key) {
                return false;
            }
            if self.factories.contains(&key) {
                return true;
            }
            if owner.kind().as_ref() == "declaration_list" {
                break;
            }
        }
        false
    }

    fn canonical(&self, at: &RustNode<'_>, text: &str) -> Option<String> {
        let text = text.trim();
        let head = text.trim_start_matches("::").split("::").next()?;
        // Absolute paths still require an external standard library spelling.
        if text.starts_with("::") {
            return matches!(head, "std" | "tokio").then(|| text[2..].into());
        }
        for ancestor in at.ancestors().filter(scope) {
            if let Some(value) = self.names.get(&(scope_id(&ancestor), head.into())) {
                let resolved = value
                    .as_ref()
                    .map(|base| format!("{base}{}", &text[head.len()..]))?;
                let library = resolved.split("::").next()?;
                // An import written through a locally shadowed `std`/`tokio`
                // path does not prove an external SDK identity.
                for owner in at.ancestors().filter(scope) {
                    if let Some(binding) = self.names.get(&(scope_id(&owner), library.into()))
                        && binding.as_deref() != Some(library)
                    {
                        return None;
                    }
                    if owner.kind().as_ref() == "declaration_list" {
                        break;
                    }
                }
                return Some(resolved);
            }
            if self.globs.contains(&scope_id(&ancestor)) {
                return None;
            }
            if ancestor.kind().as_ref() == "declaration_list" {
                break;
            }
        }
        matches!(head, "std" | "tokio").then(|| text.into())
    }
}

#[derive(Clone)]
struct Options {
    flags: [Option<bool>; 6],
    origin: usize,
    generation: usize,
}

struct Walker<'a, 'b> {
    names: Names,
    bindings: BTreeMap<(ScopeId, String), Option<usize>>,
    objects: Vec<Options>,
    generation: usize,
    uncertain: Vec<usize>,
    path: &'b str,
    comments: &'b CommentRanges,
    conditional: &'b ConditionalRegions,
    literals: &'b LiteralEnvironment<'a, StrDoc<SupportLang>>,
    evidence: &'b mut Vec<Evidence>,
}

impl<'a> Walker<'a, '_> {
    fn allocate(&mut self, origin: usize, flags: [Option<bool>; 6]) -> usize {
        let id = self.objects.len();
        self.objects.push(Options {
            flags,
            origin,
            generation: self.generation,
        });
        id
    }

    fn binding(&self, at: &RustNode<'_>, name: &str) -> Option<(ScopeId, String)> {
        for ancestor in at.ancestors().filter(scope) {
            if ancestor.kind().as_ref() == "if_expression"
                && ancestor
                    .field("alternative")
                    .is_some_and(|n| n.range().contains(&at.range().start))
            {
                // `if let` bindings do not extend into its else branch.
                continue;
            }
            let key = (scope_id(&ancestor), name.into());
            if self.bindings.contains_key(&key) {
                return Some(key);
            }
            if matches!(
                ancestor.kind().as_ref(),
                "function_item" | "source_file" | "declaration_list"
            ) {
                break;
            }
        }
        None
    }

    fn invalidate(&mut self, id: usize) {
        self.objects[id].flags = [None; 6];
        self.objects[id].generation = self.generation;
    }

    fn visit(&mut self, node: &RustNode<'a>, depth: usize) -> Option<usize> {
        if depth > 128 || node.kind().as_ref() == "ERROR" || node.is_missing() {
            // Preserve uncertainty on known builders if malformed/deep syntax
            // prevents us from following a mutation.
            self.generation += 1;
            return None;
        }
        match node.kind().as_ref() {
            "identifier" => {
                let key = self.binding(node, node.text().as_ref())?;
                return self.bindings[&key];
            }
            "reference_expression" | "parenthesized_expression" => {
                return node
                    .children()
                    .find(|n| {
                        n.is_named()
                            && !n.kind().as_ref().contains("comment")
                            && n.kind().as_ref() != "mutable_specifier"
                    })
                    .and_then(|n| self.visit(&n, depth + 1));
            }
            "let_declaration" => {
                let mut value = node.field("value").and_then(|n| self.visit(&n, depth + 1));
                if value.is_none()
                    && node
                        .field("type")
                        .is_some_and(|ty| self.names.options_type(&ty, node))
                {
                    value = Some(self.allocate(node.range().start, [None; 6]));
                }
                if let Some(pattern) = node.field("pattern") {
                    for name in pattern.dfs().filter(|n| n.kind().as_ref() == "identifier") {
                        self.bindings.insert(
                            (enclosing_scope(node), name.text().into_owned()),
                            if pattern.kind().as_ref() == "identifier" {
                                value
                            } else {
                                None
                            },
                        );
                    }
                }
                return None;
            }
            "parameter" => {
                let owned = node
                    .field("type")
                    .is_some_and(|ty| self.names.options_type(&ty, node));
                if let Some(pattern) = node.field("pattern") {
                    let id = owned.then(|| self.allocate(node.range().start, [None; 6]));
                    for name in pattern.dfs().filter(|n| n.kind().as_ref() == "identifier") {
                        self.bindings
                            .insert((enclosing_scope(node), name.text().into_owned()), id);
                    }
                }
                return None;
            }
            "assignment_expression" => {
                let value = node.field("right").and_then(|n| self.visit(&n, depth + 1));
                if let Some(left) = node.field("left")
                    && let Some(key) = self.binding(node, left.text().as_ref())
                {
                    let old = self.bindings[&key];
                    // A conditional rebind can select a different object. A
                    // later setter must not establish a mode on an old alias
                    // to only one of the possible objects.
                    let value = if (!self.uncertain.is_empty() || value.is_none())
                        && old.or(value).is_some()
                    {
                        for id in old.into_iter().chain(value) {
                            self.invalidate(id);
                        }
                        Some(self.allocate(node.range().start, [None; 6]))
                    } else {
                        value
                    };
                    self.bindings.insert(key, value);
                }
                return None;
            }
            "call_expression" => return self.call(node, depth + 1),
            _ => (),
        }
        // Pattern-bound values have their own lexical identity. An untyped
        // closure/loop/match binding must never borrow an outer SDK builder.
        if matches!(
            node.kind().as_ref(),
            "for_expression" | "match_arm" | "let_condition"
        ) && let Some(pattern) = node.field("pattern")
        {
            let owner = if node.kind().as_ref() == "let_condition" {
                enclosing_scope(node)
            } else {
                scope_id(node)
            };
            for name in pattern.dfs().filter(|n| n.kind().as_ref() == "identifier") {
                self.bindings
                    .insert((owner, name.text().into_owned()), None);
            }
        }
        if node.kind().as_ref() == "closure_expression"
            && let Some(parameters) = node.field("parameters")
        {
            for pattern in parameters
                .children()
                .filter(|n| n.is_named() && n.kind().as_ref() != "parameter")
            {
                for name in pattern.dfs().filter(|n| n.kind().as_ref() == "identifier") {
                    self.bindings
                        .insert((scope_id(node), name.text().into_owned()), None);
                }
            }
        }
        let uncertain = matches!(
            node.kind().as_ref(),
            "if_expression"
                | "match_expression"
                | "while_expression"
                | "for_expression"
                | "loop_expression"
                | "closure_expression"
                | "async_block"
        ) || (node.kind().as_ref() == "binary_expression"
            && node
                .children()
                .any(|n| matches!(n.text().as_ref(), "&&" | "||")));
        if uncertain {
            self.uncertain.push(node.range().start);
            if matches!(
                node.kind().as_ref(),
                "while_expression"
                    | "for_expression"
                    | "loop_expression"
                    | "closure_expression"
                    | "async_block"
            ) {
                // A later loop iteration/closure invocation can observe setters
                // that occur after an open in source order.
                // Lazy invalidation keeps this O(1) even in files with many
                // independent builders and closures.
                self.generation += 1;
            }
        }
        if node.kind().as_ref() == "macro_invocation" {
            self.generation += 1;
        }
        for child in node.children().filter(|n| n.is_named()) {
            if let Some(id) = self.visit(&child, depth + 1)
                && node.kind().as_ref() != "expression_statement"
            {
                // Unsupported containers and branch-valued expressions may
                // carry aliases to a consumer we cannot follow.
                self.invalidate(id);
            }
        }
        if uncertain {
            self.uncertain.pop();
        }
        None
    }

    fn call(&mut self, call: &RustNode<'a>, depth: usize) -> Option<usize> {
        let function = call.field("function")?;
        let args = call
            .field("arguments")?
            .children()
            .filter(|n| n.is_named() && !n.kind().as_ref().contains("comment"))
            .collect::<Vec<_>>();
        if args.is_empty()
            && self
                .names
                .canonical(call, function.text().as_ref())
                .is_some_and(|name| {
                    matches!(
                        name.as_str(),
                        "std::fs::OpenOptions::new"
                            | "std::fs::File::options"
                            | "tokio::fs::OpenOptions::new"
                            | "tokio::fs::File::options"
                    )
                })
        {
            return Some(self.allocate(call.range().start, [Some(false); 6]));
        }
        let receiver = if function.kind().as_ref() == "field_expression" {
            function
                .field("value")
                .and_then(|n| self.visit(&n, depth + 1))
        } else {
            None
        };
        let arg_objects = args
            .iter()
            .filter_map(|arg| self.visit(arg, depth + 1))
            .collect::<Vec<_>>();
        if args.len() == 2
            && arg_objects.len() == 1
            && self
                .names
                .canonical(call, function.text().as_ref())
                .as_deref()
                == Some("std::os::unix::fs::OpenOptionsExt::mode")
        {
            // This exact SDK setter changes creation permissions, not access
            // flags. Other extension/helper calls keep the escape treatment.
            return Some(arg_objects[0]);
        }
        let method = function.field("field").map(|n| n.text().into_owned());
        if let (Some(id), Some(method)) = (receiver, method) {
            if self.objects[id].generation != self.generation {
                self.invalidate(id);
            }
            if method == "open" && args.len() == 1 {
                self.push(call, &args[0], id);
                return None;
            }
            if let Some(flag) = FLAGS.iter().position(|name| *name == method)
                && args.len() == 1
            {
                let conditional = self
                    .uncertain
                    .iter()
                    .any(|start| self.objects[id].origin < *start);
                self.objects[id].flags[flag] = if conditional {
                    None
                } else {
                    match args[0].text().as_ref() {
                        "true" => Some(true),
                        "false" => Some(false),
                        _ => None,
                    }
                };
                return Some(id);
            }
            if method == "clone" && args.is_empty() {
                return Some(self.allocate(call.range().start, self.objects[id].flags));
            }
            self.invalidate(id);
        }
        // Passing a builder to an unknown helper can alter it through an alias.
        // Never carry an assumed read-only mode past that escape.
        for id in arg_objects {
            self.invalidate(id);
        }
        if function.kind().as_ref() == "identifier"
            && self.binding(call, function.text().as_ref()).is_none()
            && self.names.factory(call, function.text().as_ref())
        {
            // Declared SDK return ownership is sufficient for an observation,
            // never for importing the helper's effective settings or callers.
            return Some(self.allocate(call.range().start, [None; 6]));
        }
        None
    }

    fn push(&mut self, call: &RustNode<'a>, path: &RustNode<'a>, id: usize) {
        if self.comments.is_in_comment(call.range()) {
            return;
        }
        let flags = self.objects[id].flags;
        let write = flags[1] == Some(true)
            || flags[2] == Some(true)
            || ((flags[1].is_none() || flags[2].is_none()) && flags[3..].contains(&Some(true)));
        let invalid = (flags[..3].iter().all(|v| *v == Some(false)))
            || (flags[1] == Some(false)
                && flags[2] == Some(false)
                && (flags[4] == Some(true) || flags[5] == Some(true)))
            || (flags[3] == Some(true) && flags[1] == Some(false) && flags[5] == Some(false));
        let unresolved = invalid || flags.iter().any(Option::is_none);
        let mode = if unresolved {
            "unresolved"
        } else if write && flags[0] == Some(true) {
            "read-write"
        } else if write {
            "write"
        } else {
            "read"
        };
        let rule_id = if write {
            "rust-filesystem-write"
        } else {
            "rust-filesystem-read"
        };
        let location = super::matcher::location(self.path, call);
        let capture = Capture {
            text: path.text().into_owned(),
            location: super::matcher::location(self.path, path),
        };
        let mut tags = vec![
            "filesystem".into(),
            "path".into(),
            "rust".into(),
            "open-options".into(),
            format!("filesystem-mode:{mode}"),
        ];
        if invalid {
            tags.push("filesystem-options:invalid-combination".into());
        }
        self.evidence.push(Evidence {
            id: super::matcher::evidence_id(
                self.path,
                rule_id,
                call.range().start,
                call.range().end,
            ),
            kind: EvidenceKind::Sink,
            capability: if write {
                Capability::FilesystemWrite
            } else {
                Capability::FilesystemRead
            },
            location: location.clone(),
            enclosing_symbol: super::context::enclosing_symbol(call),
            captures: BTreeMap::from([("path".into(), capture)]),
            cwe_candidates: vec!["CWE-22".into()],
            tags,
            confidence: Confidence::High,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "mehscan bounded-rust-open-options 1".into(),
                rule_version: 2,
            },
            context: EvidenceContext {
                reachability: Some(super::reachability::classify(call, self.literals)),
                availability: Some(self.conditional.availability_for(call.range())),
                literals: BTreeMap::from([("path".into(), self.literals.evaluate(path))]),
                operand_facts: vec![OperandFact {
                    role: "filesystem_mode".into(),
                    kind: OperandFactKind::LocalOperandOrigin,
                    location,
                    value: FLAGS
                        .iter()
                        .zip(flags)
                        .map(|(flag, value)| {
                            format!(
                                "{flag}={}",
                                value.map_or("unknown", |v| if v { "true" } else { "false" })
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", "),
                    remaining_checks: if unresolved {
                        vec!["effective_open_options_and_successful_open".into()]
                    } else {
                        vec![]
                    },
                }],
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: rule_id.into(),
            related_evidence: vec![],
        });
    }
}
