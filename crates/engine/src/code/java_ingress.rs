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
use super::literals::LiteralEnvironment;
use super::reachability;

pub(crate) const SPRING_PARAMETER_RULE_ID: &str = "java-spring-mvc-parameter-source";
pub(crate) const SPRING_MULTIPART_RULE_ID: &str = "java-spring-multipart-content-source";
const ENGINE: &str = "mehscan java-spring-mvc-parameter-summary 1";

const MAPPING_ANNOTATIONS: &[&str] = &[
    "RequestMapping",
    "GetMapping",
    "PostMapping",
    "PutMapping",
    "DeleteMapping",
    "PatchMapping",
];
const BINDING_ANNOTATIONS: &[(&str, &str)] = &[
    ("RequestBody", "request_body"),
    ("RequestParam", "request_parameter"),
    ("PathVariable", "path_variable"),
    ("RequestHeader", "request_header"),
    ("CookieValue", "request_cookie"),
    ("RequestPart", "multipart_part"),
    ("ModelAttribute", "model_attribute"),
];

#[derive(Default)]
struct SpringImports {
    wildcard: bool,
    names: BTreeSet<String>,
    multipart_file: bool,
}

pub(crate) fn add_spring_parameter_sources<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Java {
        return;
    }
    let imports = spring_imports(root);
    let locally_declared_types = root
        .dfs()
        .filter(|node| {
            matches!(
                node.kind().as_ref(),
                "annotation_type_declaration"
                    | "class_declaration"
                    | "interface_declaration"
                    | "record_declaration"
                    | "enum_declaration"
            )
        })
        .filter_map(|node| node.field("name"))
        .map(|name| name.text().into_owned())
        .collect::<BTreeSet<_>>();

    for method in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_declaration")
    {
        if !MAPPING_ANNOTATIONS
            .iter()
            .any(|name| has_spring_annotation(&method, name, &imports, &locally_declared_types))
        {
            continue;
        }
        let Some(parameters) = method.field("parameters") else {
            continue;
        };
        for parameter in parameters
            .children()
            .filter(|node| node.kind().as_ref() == "formal_parameter")
        {
            if comments.is_in_comment(parameter.range()) {
                continue;
            }
            let Some((_, binding)) = BINDING_ANNOTATIONS.iter().find(|(name, _)| {
                has_spring_annotation(&parameter, name, &imports, &locally_declared_types)
            }) else {
                continue;
            };
            let is_multipart = *binding == "multipart_part"
                && is_exact_multipart_file(&parameter, &imports, &locally_declared_types);
            push_source(
                path,
                &parameter,
                binding,
                is_multipart,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

pub(crate) fn is_bound_spring_parameter(
    root: &Node<'_, StrDoc<SupportLang>>,
    method: &Node<'_, StrDoc<SupportLang>>,
    parameter: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let imports = spring_imports(root);
    let locally_declared_types = declared_types(root);
    MAPPING_ANNOTATIONS
        .iter()
        .any(|name| has_spring_annotation(method, name, &imports, &locally_declared_types))
        && BINDING_ANNOTATIONS.iter().any(|(name, _)| {
            has_spring_annotation(parameter, name, &imports, &locally_declared_types)
        })
}

pub(crate) fn is_spring_multipart_parameter(
    root: &Node<'_, StrDoc<SupportLang>>,
    method: &Node<'_, StrDoc<SupportLang>>,
    parameter: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let imports = spring_imports(root);
    let locally_declared_types = declared_types(root);
    is_bound_spring_parameter(root, method, parameter)
        && has_spring_annotation(parameter, "RequestPart", &imports, &locally_declared_types)
        && is_exact_multipart_file(parameter, &imports, &locally_declared_types)
}

pub(crate) fn spring_parameter_evidence_id(path: &str, start: usize, end: usize) -> String {
    evidence_id(path, SPRING_PARAMETER_RULE_ID, start, end)
}

pub(crate) fn spring_multipart_evidence_id(path: &str, start: usize, end: usize) -> String {
    evidence_id(path, SPRING_MULTIPART_RULE_ID, start, end)
}

fn declared_types(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| {
            matches!(
                node.kind().as_ref(),
                "annotation_type_declaration"
                    | "class_declaration"
                    | "interface_declaration"
                    | "record_declaration"
                    | "enum_declaration"
            )
        })
        .filter_map(|node| node.field("name"))
        .map(|name| name.text().into_owned())
        .collect()
}

fn spring_imports(root: &Node<'_, StrDoc<SupportLang>>) -> SpringImports {
    let mut result = SpringImports::default();
    for import in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "import_declaration")
    {
        let text = import.text();
        let imported = text
            .trim()
            .trim_start_matches("import ")
            .trim_start_matches("static ")
            .trim_end_matches(';');
        if imported == "org.springframework.web.bind.annotation.*" {
            result.wildcard = true;
        } else if let Some(name) = imported.strip_prefix("org.springframework.web.bind.annotation.")
        {
            result.names.insert(name.to_string());
        }
        if imported == "org.springframework.web.multipart.MultipartFile" {
            result.multipart_file = true;
        }
    }
    result
}

fn has_spring_annotation(
    node: &Node<'_, StrDoc<SupportLang>>,
    name: &str,
    imports: &SpringImports,
    locally_declared: &BTreeSet<String>,
) -> bool {
    let Some(modifiers) = node
        .children()
        .find(|child| child.kind().as_ref() == "modifiers")
    else {
        return false;
    };
    modifiers
        .children()
        .filter(|annotation| {
            matches!(
                annotation.kind().as_ref(),
                "annotation" | "marker_annotation"
            )
        })
        .any(|annotation| {
            let text = annotation.text();
            let head = text
                .trim()
                .trim_start_matches('@')
                .split(['(', ' ', '\n', '\r', '\t'])
                .next()
                .unwrap_or_default();
            head == format!("org.springframework.web.bind.annotation.{name}")
                || (head == name
                    && !locally_declared.contains(name)
                    && (imports.wildcard || imports.names.contains(name)))
        })
}

fn is_exact_multipart_file(
    parameter: &Node<'_, StrDoc<SupportLang>>,
    imports: &SpringImports,
    locally_declared: &BTreeSet<String>,
) -> bool {
    let Some(kind) = parameter.field("type") else {
        return false;
    };
    let text = kind.text();
    text.as_ref() == "org.springframework.web.multipart.MultipartFile"
        || (text.as_ref() == "MultipartFile"
            && imports.multipart_file
            && !locally_declared.contains("MultipartFile"))
}

#[allow(clippy::too_many_arguments)]
fn push_source<'tree>(
    path: &str,
    parameter: &Node<'tree, StrDoc<SupportLang>>,
    binding: &str,
    multipart: bool,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let (Some(name), Some(kind)) = (parameter.field("name"), parameter.field("type")) else {
        return;
    };
    let parameter_location = location(path, &name);
    let rule_id = if multipart {
        SPRING_MULTIPART_RULE_ID
    } else {
        SPRING_PARAMETER_RULE_ID
    };
    if evidence.iter().any(|item| {
        item.rule_id == rule_id
            && item.location.start.byte_offset == parameter_location.start.byte_offset
            && item.location.path == parameter_location.path
    }) {
        return;
    }
    evidence.push(Evidence {
        id: evidence_id(path, rule_id, name.range().start, name.range().end),
        kind: EvidenceKind::Source,
        capability: if multipart {
            Capability::UploadedFileContent
        } else {
            Capability::HttpRequestData
        },
        location: parameter_location.clone(),
        enclosing_symbol: enclosing_symbol(parameter),
        captures: BTreeMap::from([
            (
                "parameter".to_string(),
                Capture {
                    text: name.text().into_owned(),
                    location: parameter_location,
                },
            ),
            (
                "type".to_string(),
                Capture {
                    text: kind.text().into_owned(),
                    location: location(path, &kind),
                },
            ),
        ]),
        cwe_candidates: vec![if multipart { "CWE-434" } else { "CWE-20" }.to_string()],
        tags: vec![
            "http".to_string(),
            "request".to_string(),
            "attacker-controlled".to_string(),
            "spring-mvc".to_string(),
            "model-binding".to_string(),
            binding.to_string(),
        ],
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(parameter.range()),
            reachability: Some(reachability::classify(parameter, literals)),
            availability: Some(conditional.availability_for(parameter.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
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

fn evidence_id(path: &str, rule_id: &str, start: usize, end: usize) -> String {
    format!("{path}:{start}:{end}:{rule_id}")
}
