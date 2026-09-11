use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::java_context::JavaProjectContext;
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan java-upload-storage-summary 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_java_upload_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    project: &JavaProjectContext,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Java {
        return;
    }
    let imports = imports(root);
    let declarations = declared_types(root);
    let receivers = receiver_types(root);
    let multipart = imported_exact(
        &imports,
        &declarations,
        "org.springframework.web.multipart.MultipartFile",
        "MultipartFile",
    );

    let persisted = add_persistence_observations(
        path,
        root,
        multipart,
        &receivers,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_filename_validation(
        path,
        root,
        &imports,
        &declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_stored_process_observations(
        path,
        root,
        &receivers,
        &persisted,
        project,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_persistence_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    multipart_imported: bool,
    receivers: &BTreeMap<String, String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) -> BTreeMap<String, String> {
    let mut persisted = BTreeMap::new();
    for method in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_declaration")
    {
        let source_parameters = source_parameters(path, &method, evidence);
        if source_parameters.is_empty() || !has_repository_save(&method, receivers) {
            continue;
        }
        let text = method.text();
        let multipart_parameters = method_parameters(&method)
            .into_iter()
            .filter(|parameter| {
                multipart_imported
                    && parameter
                        .field("type")
                        .is_some_and(|kind| kind.text().as_ref() == "MultipartFile")
            })
            .filter_map(|parameter| parameter.field("name"))
            .map(|name| name.text().into_owned())
            .collect::<BTreeSet<_>>();

        if !multipart_parameters.is_empty() && text.contains(".getBytes()") {
            let mut tags = vec!["upload", "database-blob", "review-context"];
            if !text.contains(".getContentType()") {
                tags.push("content-type-check-not-observed");
            }
            if !text.contains(".getSize()") {
                tags.push("size-check-not-observed");
            }
            if !text.contains("ImageIO.read(") && !text.contains(".detect(") {
                tags.push("content-signature-check-not-observed");
            }
            push_without_capture(
                path,
                &method,
                "java-multipart-blob-validation-context",
                EvidenceKind::SecurityConfiguration,
                Capability::FileUpload,
                &["CWE-434"],
                &tags,
                comments,
                conditional,
                literals,
                evidence,
                Vec::new(),
            );
            for (observed, rule_id, tags) in [
                (
                    text.contains(".getContentType()"),
                    "java-multipart-content-type-validation-control",
                    &["upload", "content-type", "validation"][..],
                ),
                (
                    text.contains(".getSize()"),
                    "java-multipart-size-validation-control",
                    &["upload", "size", "validation"][..],
                ),
                (
                    text.contains("ImageIO.read(") || text.contains(".detect("),
                    "java-multipart-content-signature-validation-control",
                    &["upload", "content-signature", "validation"][..],
                ),
            ] {
                if observed {
                    push_without_capture(
                        path,
                        &method,
                        rule_id,
                        EvidenceKind::Validation,
                        Capability::FileUpload,
                        &["CWE-434"],
                        tags,
                        comments,
                        conditional,
                        literals,
                        evidence,
                        Vec::new(),
                    );
                }
            }
        }

        for invocation in method
            .dfs()
            .filter(|node| node.kind().as_ref() == "method_invocation")
        {
            let (Some(name), Some(argument)) =
                (invocation.field("name"), first_argument(&invocation))
            else {
                continue;
            };
            let setter = name.text();
            let Some(property) = setter.strip_prefix("set") else {
                continue;
            };
            let value = argument.text();
            let Some(source) = source_parameters
                .iter()
                .find(|source| contains_identifier(value.as_ref(), &source.name))
            else {
                continue;
            };
            let normalized = normalize_property(property);
            let (rule_id, capability, cwes, tags) = if value.contains("getOriginalFilename(") {
                (
                    "java-uploaded-original-filename-persistence",
                    Capability::UploadedFilePath,
                    &["CWE-434", "CWE-22"][..],
                    &["upload", "original-filename", "database-persistence"][..],
                )
            } else if value.contains("getBytes(") {
                (
                    "java-multipart-blob-persistence",
                    Capability::FileUpload,
                    &["CWE-434"][..],
                    &["upload", "content", "database-blob"][..],
                )
            } else if normalized == "conversionparams" {
                (
                    "java-stored-command-property-persistence",
                    Capability::StoredUserContent,
                    &["CWE-78"][..],
                    &["stored-data", "command-property", "database-persistence"][..],
                )
            } else {
                continue;
            };
            let id = evidence_id(path, &invocation, rule_id);
            push(
                path,
                &invocation,
                &argument,
                rule_id,
                EvidenceKind::SensitiveOperation,
                capability,
                "value",
                cwes,
                tags,
                comments,
                conditional,
                literals,
                evidence,
                vec![source.evidence_id.clone()],
            );
            persisted.insert(normalized, id);
        }
    }
    persisted
}

#[allow(clippy::too_many_arguments)]
fn add_filename_validation<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let exact_string_utils = imported_exact(
        imports,
        declarations,
        "org.springframework.util.StringUtils",
        "StringUtils",
    );
    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_invocation")
    {
        if exact_string_utils
            && invocation
                .field("name")
                .is_some_and(|name| name.text().as_ref() == "cleanPath")
            && invocation
                .field("object")
                .is_some_and(|object| object.text().as_ref() == "StringUtils")
            && let Some(value) = first_argument(&invocation)
        {
            push(
                path,
                &invocation,
                &value,
                "java-spring-uploaded-filename-normalization-control",
                EvidenceKind::Validation,
                Capability::UploadedFilenameValidation,
                "value",
                &["CWE-434", "CWE-22"],
                &["upload", "filename", "spring-clean-path"],
                comments,
                conditional,
                literals,
                evidence,
                Vec::new(),
            );
        }
    }

    for branch in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "if_statement")
    {
        let Some(condition) = branch.field("condition") else {
            continue;
        };
        if !condition.text().contains(".contains(\"..\")") {
            continue;
        }
        let consequence = branch
            .field("consequence")
            .map(|node| node.text().into_owned())
            .unwrap_or_default();
        let enforcing = consequence.contains("throw ") || consequence.contains("return ");
        push_without_capture(
            path,
            &branch,
            if enforcing {
                "java-uploaded-filename-traversal-rejection-control"
            } else {
                "java-uploaded-filename-check-without-rejection"
            },
            if enforcing {
                EvidenceKind::Validation
            } else {
                EvidenceKind::SecurityConfiguration
            },
            Capability::UploadedFilenameValidation,
            &["CWE-434", "CWE-22"],
            if enforcing {
                &["upload", "filename", "traversal", "rejects"]
            } else {
                &["upload", "filename", "traversal", "log-only-check"]
            },
            comments,
            conditional,
            literals,
            evidence,
            Vec::new(),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_stored_process_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    receivers: &BTreeMap<String, String>,
    persisted: &BTreeMap<String, String>,
    project: &JavaProjectContext,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if persisted.is_empty() {
        return;
    }
    for method in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_declaration")
    {
        let shell_calls = method
            .dfs()
            .filter(|node| node.kind().as_ref() == "method_invocation")
            .filter(|invocation| {
                let (Some(object), Some(name)) =
                    (invocation.field("object"), invocation.field("name"))
                else {
                    return false;
                };
                receivers
                    .get(object.text().trim())
                    .is_some_and(|owner| project.is_shell_helper(owner, name.text().as_ref()))
            })
            .collect::<Vec<_>>();
        if shell_calls.is_empty() {
            continue;
        }
        for shell_call in shell_calls {
            let Some(command) = first_argument(&shell_call) else {
                continue;
            };
            let command_value = command_value(&method, &command).unwrap_or_else(|| command.clone());
            let related = command_value
                .dfs()
                .filter(|node| node.kind().as_ref() == "method_invocation")
                .filter_map(|invocation| {
                    let name = invocation.field("name")?;
                    let name_text = name.text();
                    let property = name_text.strip_prefix("get")?;
                    persisted.get(&normalize_property(property)).cloned()
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            if !related.is_empty() {
                push_without_capture(
                    path,
                    &command_value,
                    "java-persisted-user-command-construction-source",
                    EvidenceKind::Source,
                    Capability::StoredUserContent,
                    &["CWE-78"],
                    &[
                        "stored-data",
                        "user-controlled",
                        "command-construction",
                        "second-order",
                    ],
                    comments,
                    conditional,
                    literals,
                    evidence,
                    related,
                );
            }
            push(
                path,
                &shell_call,
                &command,
                "java-proved-shell-helper-invocation",
                EvidenceKind::Sink,
                Capability::ProcessExecution,
                "command",
                &["CWE-78"],
                &["process", "project-proved-helper", "bash-c"],
                comments,
                conditional,
                literals,
                evidence,
                Vec::new(),
            );
        }
    }
}

fn command_value<'tree>(
    method: &Node<'tree, StrDoc<SupportLang>>,
    command: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let name = command.text();
    if !name.chars().enumerate().all(|(index, character)| {
        character == '_' || character.is_alphabetic() || (index > 0 && character.is_ascii_digit())
    }) {
        return None;
    }
    method
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .filter(|node| node.range().end < command.range().start)
        .find_map(|variable| {
            (variable
                .field("name")
                .is_some_and(|candidate| candidate.text() == name))
            .then(|| variable.field("value"))
            .flatten()
        })
}

#[derive(Clone)]
struct SourceParameter {
    name: String,
    evidence_id: String,
}

fn source_parameters(
    path: &str,
    method: &Node<'_, StrDoc<SupportLang>>,
    evidence: &[Evidence],
) -> Vec<SourceParameter> {
    method_parameters(method)
        .into_iter()
        .filter_map(|parameter| {
            let name = parameter.field("name")?;
            let item = evidence.iter().find(|item| {
                item.kind == EvidenceKind::Source
                    && item.location.path == path
                    && item.location.start.byte_offset == name.range().start
                    && matches!(
                        item.capability,
                        Capability::HttpRequestData | Capability::UploadedFileContent
                    )
            })?;
            Some(SourceParameter {
                name: name.text().into_owned(),
                evidence_id: item.id.clone(),
            })
        })
        .collect()
}

fn has_repository_save(
    method: &Node<'_, StrDoc<SupportLang>>,
    receivers: &BTreeMap<String, String>,
) -> bool {
    method.dfs().any(|invocation| {
        invocation.kind().as_ref() == "method_invocation"
            && invocation
                .field("name")
                .is_some_and(|name| matches!(name.text().as_ref(), "save" | "saveAndFlush"))
            && invocation.field("object").is_some_and(|object| {
                receivers
                    .get(object.text().trim())
                    .is_some_and(|kind| kind.ends_with("Repository"))
            })
    })
}

fn method_parameters<'tree>(
    method: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    method
        .field("parameters")
        .map(|parameters| {
            parameters
                .children()
                .filter(|node| node.kind().as_ref() == "formal_parameter")
                .collect()
        })
        .unwrap_or_default()
}

fn receiver_types(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    for declaration in root.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "field_declaration" | "local_variable_declaration"
        )
    }) {
        let Some(kind) = declaration.field("type") else {
            continue;
        };
        let kind = kind.text().trim().to_string();
        for variable in declaration
            .children()
            .filter(|node| node.kind().as_ref() == "variable_declarator")
        {
            if let Some(name) = variable.field("name") {
                result.insert(name.text().into_owned(), kind.clone());
            }
        }
    }
    result
}

fn imports(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "import_declaration")
        .map(|import| {
            import
                .text()
                .trim()
                .trim_start_matches("import ")
                .trim_start_matches("static ")
                .trim_end_matches(';')
                .to_string()
        })
        .collect()
}

fn declared_types(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| {
            matches!(
                node.kind().as_ref(),
                "class_declaration"
                    | "interface_declaration"
                    | "record_declaration"
                    | "enum_declaration"
            )
        })
        .filter_map(|node| node.field("name"))
        .map(|name| name.text().into_owned())
        .collect()
}

fn imported_exact(
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    canonical: &str,
    short: &str,
) -> bool {
    !declarations.contains(short)
        && (imports.contains(canonical)
            || canonical
                .rsplit_once('.')
                .is_some_and(|(namespace, _)| imports.contains(&format!("{namespace}.*"))))
}

fn first_argument<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    invocation
        .field("arguments")?
        .children()
        .find(|child| child.is_named())
}

fn contains_identifier(text: &str, name: &str) -> bool {
    text.match_indices(name).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let after = text[start + name.len()..].chars().next();
        !before.is_some_and(|character| character == '_' || character.is_alphanumeric())
            && !after.is_some_and(|character| character == '_' || character.is_alphanumeric())
    })
}

fn normalize_property(property: &str) -> String {
    property
        .chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn push<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    captured: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    role: &str,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
    related_evidence: Vec<String>,
) {
    push_evidence(
        path,
        node,
        rule_id,
        kind,
        capability,
        BTreeMap::from([(
            role.to_string(),
            Capture {
                text: captured.text().into_owned(),
                location: location(path, captured),
            },
        )]),
        cwes,
        tags,
        comments,
        conditional,
        literals,
        evidence,
        related_evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_without_capture<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
    related_evidence: Vec<String>,
) {
    push_evidence(
        path,
        node,
        rule_id,
        kind,
        capability,
        BTreeMap::new(),
        cwes,
        tags,
        comments,
        conditional,
        literals,
        evidence,
        related_evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_evidence<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    captures: BTreeMap<String, Capture>,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
    related_evidence: Vec<String>,
) {
    let id = evidence_id(path, node, rule_id);
    if comments.is_in_comment(node.range()) || evidence.iter().any(|item| item.id == id) {
        return;
    }
    evidence.push(Evidence {
        id,
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes.iter().map(|cwe| (*cwe).to_string()).collect(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence,
    });
}

fn evidence_id(path: &str, node: &Node<'_, StrDoc<SupportLang>>, rule_id: &str) -> String {
    format!(
        "{path}:{}:{}:{rule_id}",
        node.range().start,
        node.range().end
    )
}

fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let range = node.range();
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.to_string(),
        start: Position {
            byte_offset: range.start,
            line: start.line() + 1,
            column: start.column(node) + 1,
        },
        end: Position {
            byte_offset: range.end,
            line: end.line() + 1,
            column: end.column(node) + 1,
        },
    }
}
