//! Bounded local call targets for review packets. No receiver dispatch or flow inference.
use super::*;

type N<'a> = ast_grep_core::Node<'a, StrDoc<SupportLang>>;

struct Target {
    name: String,
    call: std::ops::Range<usize>,
    definition: std::ops::Range<usize>,
}

pub(super) struct LocalHelpers {
    targets: Vec<Target>,
    owners: Vec<std::ops::Range<usize>>,
}

fn callable(node: &N<'_>) -> bool {
    matches!(
        node.kind().as_ref(),
        "function_declaration"
            | "generator_function_declaration"
            | "function_expression"
            | "generator_function"
            | "arrow_function"
    )
}

fn names(node: N<'_>, blocked: &mut BTreeSet<String>) {
    for id in node.dfs().filter(|n| {
        matches!(
            n.kind().as_ref(),
            "identifier" | "shorthand_property_identifier_pattern"
        )
    }) {
        blocked.insert(id.text().into_owned());
    }
}

impl LocalHelpers {
    pub(super) fn build(file: &SourceFile) -> Option<Self> {
        let language = file.language?;
        if !matches!(
            language,
            Language::Javascript | Language::Typescript | Language::Tsx
        ) || file.source.len() > MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES
        {
            return None;
        }
        let ast = AstGrep::doc(StrDoc::try_new(&file.source, parser_language(language)).ok()?);
        let root = ast.root();
        let mut definitions =
            BTreeMap::<String, Vec<(std::ops::Range<usize>, std::ops::Range<usize>)>>::new();
        let mut blocked = BTreeSet::new();
        let mut calls = Vec::new();
        let mut owners = Vec::new();
        // One traversal per selected file, shared across all its resource questions.
        for node in root.dfs() {
            let kind = node.kind();
            if callable(&node) || kind.as_ref() == "method_definition" {
                owners.push(node.range());
            }
            if kind.as_ref() == "ERROR" || node.is_missing() || kind.as_ref() == "with_statement" {
                return None;
            }
            if (callable(&node) || kind.as_ref() == "method_definition")
                && let Some(parameters) =
                    node.field("parameters").or_else(|| node.field("parameter"))
            {
                names(parameters, &mut blocked);
            }
            match kind.as_ref() {
                "variable_declarator"
                | "function_declaration"
                | "generator_function_declaration" => {
                    let Some(name) = node.field("name") else {
                        continue;
                    };
                    let stable = if kind.as_ref() == "variable_declarator" {
                        node.parent().is_some_and(|p| {
                            p.kind().as_ref() == "lexical_declaration"
                                && p.text().trim_start().starts_with("const ")
                        }) && node.field("value").is_some_and(|value| callable(&value))
                    } else {
                        true
                    };
                    if !stable || name.kind().as_ref() != "identifier" {
                        names(name, &mut blocked);
                        continue;
                    }
                    let scope = node.ancestors().find(|p| {
                        matches!(
                            p.kind().as_ref(),
                            "statement_block" | "program" | "switch_body"
                        )
                    });
                    if let Some(scope) = scope {
                        definitions
                            .entry(name.text().into_owned())
                            .or_default()
                            .push((node.range(), scope.range()));
                    }
                }
                "assignment_expression" | "augmented_assignment_expression" => {
                    if let Some(left) = node.field("left")
                        && !matches!(
                            left.kind().as_ref(),
                            "member_expression" | "subscript_expression"
                        )
                    {
                        names(left, &mut blocked);
                    }
                }
                "update_expression" => {
                    if let Some(argument) = node.field("argument") {
                        names(argument, &mut blocked);
                    }
                }
                "import_statement" => names(node.clone(), &mut blocked),
                "class_declaration" | "class" | "function_expression" | "generator_function" => {
                    if let Some(name) = node.field("name") {
                        names(name, &mut blocked);
                    }
                }
                "catch_clause" => {
                    if let Some(parameter) = node.field("parameter") {
                        names(parameter, &mut blocked);
                    }
                }
                "for_in_statement" => {
                    if let Some(left) = node.field("left") {
                        names(left, &mut blocked);
                    }
                }
                "enum_declaration" => {
                    if let Some(name) = node.field("name") {
                        names(name, &mut blocked);
                    }
                }
                "call_expression" => {
                    if let Some(callee) = node
                        .field("function")
                        .filter(|n| n.kind().as_ref() == "identifier")
                    {
                        if callee.text().as_ref() == "eval" {
                            return None;
                        }
                        calls.push((callee.text().into_owned(), node.range()));
                    }
                }
                _ => {}
            }
        }
        let mut targets = calls
            .into_iter()
            .filter_map(|(name, call)| {
                if blocked.contains(&name) {
                    return None;
                }
                let [(definition, scope)] = definitions.get(&name)?.as_slice() else {
                    return None;
                };
                if call.start < scope.start || call.end > scope.end {
                    return None;
                }
                // Lexical identity only; no callback scheduling or execution-order claim.
                Some(Target {
                    name,
                    call,
                    definition: definition.clone(),
                })
            })
            .collect::<Vec<_>>();
        targets.sort_by_key(|target| target.call.start);
        Some(Self { targets, owners })
    }

    pub(super) fn owner_location(&self, file: &SourceFile, anchor: &Location) -> Option<Location> {
        let range = self
            .owners
            .iter()
            .filter(|r| r.start <= anchor.start.byte_offset && r.end >= anchor.end.byte_offset)
            .min_by_key(|r| r.end - r.start)?;
        Some(location_from_offsets(
            &file.path,
            &file.source,
            range.start,
            range.end,
        ))
    }

    pub(super) fn calls(
        &self,
    ) -> impl Iterator<Item = (&std::ops::Range<usize>, &std::ops::Range<usize>)> {
        self.targets.iter().map(|t| (&t.call, &t.definition))
    }

    pub(super) fn facts(
        &self,
        file: &SourceFile,
        operation: &Location,
        existing: &[ReviewNeighborhoodFact],
        limit: usize,
    ) -> (Vec<ReviewNeighborhoodFact>, bool) {
        let mut facts = Vec::new();
        let mut seen = BTreeSet::new();
        let first = self
            .targets
            .partition_point(|target| target.call.start < operation.start.byte_offset);
        for target in self.targets[first..]
            .iter()
            .take_while(|target| target.call.start < operation.end.byte_offset)
        {
            if target.call.end > operation.end.byte_offset || !seen.insert(target.definition.start)
            {
                continue;
            }
            let location = location_from_offsets(
                &file.path,
                &file.source,
                target.definition.start,
                target.definition.end,
            );
            if facts_cover_location(existing, &location) {
                continue;
            }
            if facts.len() == limit {
                return (facts, true);
            }
            let Some(definition) = file.source.get(target.definition.clone()) else {
                continue;
            };
            let mut excerpt = definition
                .split_inclusive('\n')
                .take(40)
                .collect::<String>();
            if excerpt.len() > MAX_SOURCE_BYTES {
                excerpt.truncate(floor_char_boundary(&excerpt, MAX_SOURCE_BYTES));
            }
            let cut = excerpt.len() < definition.len();
            let location = location_from_offsets(
                &file.path,
                &file.source,
                target.definition.start,
                target.definition.start + excerpt.len(),
            );
            facts.push(ReviewNeighborhoodFact {
                role: "helper_definition_context".into(), symbol: target.name.clone(), location,
                excerpt: redact_helper_definition(&target.name, &excerpt), evidence_id: None,
                provenance: QueryProvenance { resolution: Resolution::Ast, engine: "direct identifier call with unique stable same-file lexical binding; target context, not execution or authorization proof 1".into() },
            });
            if cut {
                return (facts, true);
            }
        }
        (facts, false)
    }
}
