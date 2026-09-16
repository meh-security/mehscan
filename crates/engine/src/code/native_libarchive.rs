use std::collections::BTreeMap;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    AvailabilityState, Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind,
    Language, Location, Position, Provenance, Resolution, SecurityPath, SecurityPathProvenance,
    SecurityPathState, SecurityPathStep, SecurityPathStepKind,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const ENTRY_RULE: &str = "native-libarchive-entry-path";
const WRITE_RULE: &str = "native-libarchive-disk-extraction";
const DOTDOT_RULE: &str = "native-libarchive-dotdot-control";
const ABSOLUTE_RULE: &str = "native-libarchive-absolute-path-control";
const SYMLINK_RULE: &str = "native-libarchive-symlink-control";
const PRIVILEGE_RULE: &str = "native-libarchive-metadata-restore-context";
const ENGINE: &str = "tree-sitter c-family libarchive extraction-options relationship";

struct Extraction<'tree> {
    operation: Node<'tree, StrDoc<SupportLang>>,
    configuration: Node<'tree, StrDoc<SupportLang>>,
    entry: Node<'tree, StrDoc<SupportLang>>,
    options: Node<'tree, StrDoc<SupportLang>>,
}

pub(crate) fn add_native_libarchive_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) -> Vec<SecurityPath> {
    if !matches!(language, Language::C | Language::Cpp) {
        return Vec::new();
    }
    let mut additions = Vec::new();
    let mut paths = Vec::new();
    for extraction in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
        .filter(|node| !comments.is_in_comment(node.range()))
        .filter_map(extraction)
    {
        let (options, option_text) =
            resolve_options(&extraction.operation, &extraction.options, conditional)
                .unwrap_or_else(|| {
                    let text = extraction.options.text().into_owned();
                    (extraction.options, text)
                });
        if !availability_compatible(
            &extraction.configuration,
            &extraction.operation,
            conditional,
        ) || !availability_compatible(&options, &extraction.operation, conditional)
        {
            continue;
        }
        if !known_options(&option_text) {
            continue;
        }
        let entry = item(
            path,
            &extraction.entry,
            ENTRY_RULE,
            EvidenceKind::Source,
            Capability::ArchiveEntryPath,
            BTreeMap::from([("entry".to_string(), capture(path, &extraction.entry))]),
            vec!["native", "libarchive", "archive-entry-path"],
            comments,
            conditional,
            literals,
            Vec::new(),
            &["CWE-22", "CWE-59", "CWE-732"],
        );
        let sink = item(
            path,
            &extraction.operation,
            WRITE_RULE,
            EvidenceKind::Sink,
            Capability::FilesystemWrite,
            BTreeMap::from([
                (
                    "operation".to_string(),
                    capture(path, &extraction.operation),
                ),
                (
                    "options".to_string(),
                    text_capture(path, &options, &option_text),
                ),
            ]),
            vec!["native", "libarchive", "disk-extraction"],
            comments,
            conditional,
            literals,
            vec![entry.id.clone()],
            &["CWE-22", "CWE-59", "CWE-732"],
        );
        let dotdot = has_flag(&option_text, "ARCHIVE_EXTRACT_SECURE_NODOTDOT").then(|| {
            item(
                path,
                &options,
                DOTDOT_RULE,
                EvidenceKind::Guard,
                Capability::PathContainmentCheck,
                BTreeMap::from([("control".to_string(), capture(path, &options))]),
                vec!["native", "libarchive", "dotdot-component-rejection"],
                comments,
                conditional,
                literals,
                vec![sink.id.clone()],
                &["CWE-22"],
            )
        });
        let absolute =
            has_flag(&option_text, "ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS").then(|| {
                item(
                    path,
                    &options,
                    ABSOLUTE_RULE,
                    EvidenceKind::Guard,
                    Capability::PathContainmentCheck,
                    BTreeMap::from([("control".to_string(), capture(path, &options))]),
                    vec!["native", "libarchive", "absolute-path-rejection"],
                    comments,
                    conditional,
                    literals,
                    vec![sink.id.clone()],
                    &["CWE-22"],
                )
            });
        let symlink = has_flag(&option_text, "ARCHIVE_EXTRACT_SECURE_SYMLINKS").then(|| {
            item(
                path,
                &options,
                SYMLINK_RULE,
                EvidenceKind::Guard,
                Capability::PathContainmentCheck,
                BTreeMap::from([("control".to_string(), capture(path, &options))]),
                vec!["native", "libarchive", "symlink-redirection-rejection"],
                comments,
                conditional,
                literals,
                vec![sink.id.clone()],
                &["CWE-59"],
            )
        });
        let privilege = (has_flag(&option_text, "ARCHIVE_EXTRACT_OWNER")
            || has_flag(&option_text, "ARCHIVE_EXTRACT_PERM"))
        .then(|| {
            item(
                path,
                &options,
                PRIVILEGE_RULE,
                EvidenceKind::SecurityConfiguration,
                Capability::Authorization,
                BTreeMap::from([(
                    "metadata_restore_flags".to_string(),
                    capture(path, &options),
                )]),
                vec![
                    "native",
                    "libarchive",
                    "privilege-sensitive-metadata-restore",
                ],
                comments,
                conditional,
                literals,
                vec![sink.id.clone()],
                &["CWE-732"],
            )
        });

        paths.push(extraction_path(
            &entry,
            &sink,
            dotdot.as_ref(),
            "CWE-22",
            "dotdot",
            "archive_entry_dotdot_component_rejection_unproven",
        ));
        paths.push(extraction_path(
            &entry,
            &sink,
            absolute.as_ref(),
            "CWE-22",
            "absolute",
            "archive_entry_absolute_path_rejection_unproven",
        ));
        paths.push(extraction_path(
            &entry,
            &sink,
            symlink.as_ref(),
            "CWE-59",
            "symlink",
            "archive_entry_symlink_redirection_rejection_unproven",
        ));
        if let Some(context) = privilege.as_ref() {
            paths.push(privilege_path(&entry, &sink, context));
        }
        additions.extend([entry, sink]);
        if let Some(value) = dotdot {
            additions.push(value);
        }
        if let Some(value) = absolute {
            additions.push(value);
        }
        if let Some(value) = symlink {
            additions.push(value);
        }
        if let Some(value) = privilege {
            additions.push(value);
        }
    }
    let mut unique = BTreeMap::<String, Evidence>::new();
    for addition in additions {
        if let Some(existing) = unique.get_mut(&addition.id) {
            existing.related_evidence.extend(addition.related_evidence);
            existing.related_evidence.sort();
            existing.related_evidence.dedup();
        } else {
            unique.insert(addition.id.clone(), addition);
        }
    }
    evidence.extend(unique.into_values());
    paths
}

fn extraction<'tree>(call: Node<'tree, StrDoc<SupportLang>>) -> Option<Extraction<'tree>> {
    let function = global_function(&call)?;
    let args = arguments(&call);
    match function.as_str() {
        "archive_read_extract" => Some(Extraction {
            operation: call.clone(),
            configuration: call,
            entry: args.get(1)?.clone(),
            options: args.get(2)?.clone(),
        }),
        "archive_write_header" => {
            let handle = args.first()?.text().trim().to_string();
            let setup = preceding_setup(&call, &handle)?;
            let setup_args = arguments(&setup);
            Some(Extraction {
                operation: call,
                configuration: setup,
                entry: args.get(1)?.clone(),
                options: setup_args.get(1)?.clone(),
            })
        }
        "archive_read_extract2" => {
            let handle = args.get(2)?.text().trim().to_string();
            let setup = preceding_setup(&call, &handle)?;
            let setup_args = arguments(&setup);
            Some(Extraction {
                operation: call,
                configuration: setup,
                entry: args.get(1)?.clone(),
                options: setup_args.get(1)?.clone(),
            })
        }
        _ => None,
    }
}

fn preceding_setup<'tree>(
    operation: &Node<'tree, StrDoc<SupportLang>>,
    handle: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let scope = operation
        .ancestors()
        .find(|node| node.kind().as_ref() == "function_definition")?;
    scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
        .filter(|node| node.range().end < operation.range().start)
        .filter(|node| global_function(node).as_deref() == Some("archive_write_disk_set_options"))
        .filter(|node| {
            arguments(node)
                .first()
                .is_some_and(|argument| argument.text().trim() == handle)
        })
        .last()
}

fn known_options(text: &str) -> bool {
    text.trim_matches(['(', ')', ' ']) == "0" || text.contains("ARCHIVE_EXTRACT_")
}

fn has_flag(text: &str, expected: &str) -> bool {
    text.split(|character: char| character != '_' && !character.is_ascii_alphanumeric())
        .any(|token| token == expected)
}

fn global_function(call: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let function = call.field("function")?;
    let text = function.text();
    let value = text.trim();
    let value = value.strip_prefix("::").unwrap_or(value);
    is_identifier(value).then(|| value.to_string())
}

fn arguments<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    call.field("arguments")
        .map(|args| args.children().filter(|child| child.is_named()).collect())
        .unwrap_or_default()
}

fn resolve_options<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
    options: &Node<'tree, StrDoc<SupportLang>>,
    conditional: &ConditionalRegions,
) -> Option<(Node<'tree, StrDoc<SupportLang>>, String)> {
    let text = options.text();
    let local = is_identifier(text.trim()).then_some(text.trim())?;
    let scope = call
        .ancestors()
        .find(|node| node.kind().as_ref() == "function_definition")?;
    let declaration = scope
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "declaration" && node.range().end < options.range().start
        })
        .filter(|node| {
            node.dfs()
                .filter(|child| child.kind().as_ref() == "identifier")
                .any(|identifier| identifier.text().trim() == local)
        })
        .filter(|node| {
            node.ancestors()
                .find(|ancestor| ancestor.kind().as_ref() == "compound_statement")
                .is_some_and(|block| {
                    block.range().start <= call.range().start
                        && call.range().end <= block.range().end
                })
        })
        .last()?;
    let initializer = declaration
        .dfs()
        .filter(|node| node.kind().as_ref() == "init_declarator")
        .find(|node| {
            node.field("declarator")
                .is_some_and(|declarator| declarator.text().trim() == local)
        })
        .and_then(|node| node.field("value"));
    let mut anchor = initializer.clone().unwrap_or_else(|| declaration.clone());
    let mut combined = initializer.map(|value| value.text().into_owned());
    for assignment in scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .filter(|node| {
            declaration.range().end < node.range().start && node.range().end < options.range().start
        })
        .filter(|node| {
            node.field("left")
                .is_some_and(|left| left.text().trim() == local)
        })
    {
        if !availability_compatible(&assignment, call, conditional) {
            return None;
        }
        let right = assignment.field("right")?.text().into_owned();
        let compact = compact(assignment.text().as_ref());
        if compact.starts_with(&format!("{local}|=")) {
            let current = combined.as_mut()?;
            current.push('|');
            current.push_str(&right);
        } else if compact.starts_with(&format!("{local}=")) {
            combined = Some(right);
            anchor = assignment;
        } else {
            return None;
        }
    }
    Some((anchor, combined?))
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn compact(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn availability_compatible(
    configuration: &Node<'_, StrDoc<SupportLang>>,
    operation: &Node<'_, StrDoc<SupportLang>>,
    conditional: &ConditionalRegions,
) -> bool {
    if !runtime_requirements_satisfied(configuration, operation) {
        return false;
    }
    let configuration = conditional.availability_for(configuration.range());
    let operation = conditional.availability_for(operation.range());
    match configuration.state {
        AvailabilityState::Always => operation.state != AvailabilityState::Excluded,
        AvailabilityState::Conditional | AvailabilityState::Unknown => configuration == operation,
        AvailabilityState::Excluded => false,
    }
}

fn runtime_requirements_satisfied(
    configuration: &Node<'_, StrDoc<SupportLang>>,
    operation: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    configuration.ancestors().all(|ancestor| {
        let fields: &[&str] = match ancestor.kind().as_ref() {
            "if_statement" | "conditional_expression" => &["consequence", "alternative"],
            "for_statement" | "while_statement" | "do_statement" => &["body"],
            _ => return true,
        };
        fields
            .iter()
            .filter_map(|field| ancestor.field(field))
            .find(|region| contains(region, configuration))
            .is_none_or(|region| contains(&region, operation))
    })
}

fn contains(outer: &Node<'_, StrDoc<SupportLang>>, inner: &Node<'_, StrDoc<SupportLang>>) -> bool {
    outer.range().start <= inner.range().start && inner.range().end <= outer.range().end
}

#[allow(clippy::too_many_arguments)]
fn item<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule: &str,
    kind: EvidenceKind,
    capability: Capability,
    captures: BTreeMap<String, Capture>,
    tags: Vec<&str>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    related_evidence: Vec<String>,
    cwes: &[&str],
) -> Evidence {
    Evidence {
        id: evidence_id(path, rule, node),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes.iter().map(|value| (*value).to_string()).collect(),
        tags: tags
            .into_iter()
            .map(str::to_string)
            .chain(std::iter::once(
                "parse-recovery:locally-complete".to_string(),
            ))
            .collect(),
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(node.range()),
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule.to_string(),
        related_evidence,
    }
}

fn extraction_path(
    source: &Evidence,
    sink: &Evidence,
    protection: Option<&Evidence>,
    cwe: &str,
    invariant: &str,
    uncertainty: &str,
) -> SecurityPath {
    let state = if protection.is_some() {
        SecurityPathState::Protected
    } else {
        SecurityPathState::Unknown
    };
    let mut steps = vec![step(SecurityPathStepKind::Source, source)];
    if let Some(value) = protection {
        steps.push(step(SecurityPathStepKind::Protection, value));
    }
    steps.push(step(SecurityPathStepKind::Sink, sink));
    SecurityPath {
        id: path_id(source, sink, state, cwe, invariant),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: Capability::FilesystemWrite,
        cwe_candidates: vec![cwe.to_string()],
        state,
        steps,
        protection_evidence_ids: protection
            .map(|value| vec![value.id.clone()])
            .unwrap_or_default(),
        uncertainty_reasons: protection
            .is_none()
            .then_some(uncertainty.to_string())
            .into_iter()
            .collect(),
        provenance: SecurityPathProvenance {
            engine: "mehscan c-family libarchive extraction-options relationship 1".to_string(),
            maximum_propagation_depth: 0,
        },
    }
}

fn privilege_path(source: &Evidence, sink: &Evidence, context: &Evidence) -> SecurityPath {
    SecurityPath {
        id: path_id(
            source,
            sink,
            SecurityPathState::Unknown,
            "CWE-732",
            "metadata-restore",
        ),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: Capability::FilesystemWrite,
        cwe_candidates: vec!["CWE-732".to_string()],
        state: SecurityPathState::Unknown,
        steps: vec![
            step(SecurityPathStepKind::Source, source),
            step(SecurityPathStepKind::Assignment, context),
            step(SecurityPathStepKind::Sink, sink),
        ],
        protection_evidence_ids: Vec::new(),
        uncertainty_reasons: vec![
            "archive_controlled_owner_or_permission_restore_requires_effective_privilege_review"
                .to_string(),
        ],
        provenance: SecurityPathProvenance {
            engine: "mehscan c-family libarchive extraction-options relationship 1".to_string(),
            maximum_propagation_depth: 0,
        },
    }
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}
fn text_capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>, text: &str) -> Capture {
    Capture {
        text: text.to_string(),
        location: location(path, node),
    }
}
fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.to_string(),
        start: Position {
            line: start.line() + 1,
            column: start.column(node) + 1,
            byte_offset: node.range().start,
        },
        end: Position {
            line: end.line() + 1,
            column: end.column(node) + 1,
            byte_offset: node.range().end,
        },
    }
}
fn evidence_id(path: &str, rule: &str, node: &Node<'_, StrDoc<SupportLang>>) -> String {
    stable_id(
        "ev",
        &format!(
            "{path}\0{rule}\0{}\0{}",
            node.range().start,
            node.range().end
        ),
    )
}
fn path_id(
    source: &Evidence,
    sink: &Evidence,
    state: SecurityPathState,
    cwe: &str,
    invariant: &str,
) -> String {
    stable_id(
        "path",
        &format!("{}\0{}\0{state:?}\0{cwe}\0{invariant}", source.id, sink.id),
    )
}
fn stable_id(prefix: &str, input: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{prefix}-{hash:016x}")
}
fn step(kind: SecurityPathStepKind, item: &Evidence) -> SecurityPathStep {
    SecurityPathStep {
        kind,
        location: item.location.clone(),
        evidence_id: Some(item.id.clone()),
        symbol: None,
    }
}
