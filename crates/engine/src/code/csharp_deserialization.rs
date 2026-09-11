use std::collections::BTreeMap;
use std::ops::Range;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::{enclosing_symbol, lexical_declaration_visible_at};
use super::dotnet_project::{DotnetProjectContext, LegacySerializerFamily, RuntimeApplicability};
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan csharp-legacy-deserialization 1";

#[derive(Clone, Copy)]
struct DangerousSerializer {
    canonical: &'static str,
    rule_id: &'static str,
    tag: &'static str,
    family: LegacySerializerFamily,
    methods: &'static [&'static str],
}

type InvocationParts<'tree> = (
    Node<'tree, StrDoc<SupportLang>>,
    String,
    Node<'tree, StrDoc<SupportLang>>,
);

const SERIALIZERS: &[DangerousSerializer] = &[
    DangerousSerializer {
        canonical: "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter",
        rule_id: "csharp-binaryformatter-deserialization",
        tag: "binaryformatter",
        family: LegacySerializerFamily::BinaryFormatter,
        methods: &[
            "Deserialize",
            "UnsafeDeserialize",
            "UnsafeDeserializeMethodResponse",
        ],
    },
    DangerousSerializer {
        canonical: "System.Runtime.Serialization.Formatters.Soap.SoapFormatter",
        rule_id: "csharp-soapformatter-deserialization",
        tag: "soapformatter",
        family: LegacySerializerFamily::FrameworkOnly,
        methods: &["Deserialize"],
    },
    DangerousSerializer {
        canonical: "System.Runtime.Serialization.NetDataContractSerializer",
        rule_id: "csharp-netdatacontractserializer-deserialization",
        tag: "netdatacontractserializer",
        family: LegacySerializerFamily::FrameworkOnly,
        methods: &["Deserialize", "ReadObject"],
    },
    DangerousSerializer {
        canonical: "System.Web.UI.LosFormatter",
        rule_id: "csharp-losformatter-deserialization",
        tag: "losformatter",
        family: LegacySerializerFamily::FrameworkOnly,
        methods: &["Deserialize"],
    },
    DangerousSerializer {
        canonical: "System.Web.UI.ObjectStateFormatter",
        rule_id: "csharp-objectstateformatter-deserialization",
        tag: "objectstateformatter",
        family: LegacySerializerFamily::FrameworkOnly,
        methods: &["Deserialize"],
    },
];

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_deserialization_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    project_context: &DotnetProjectContext,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Csharp {
        return;
    }

    // These declarative rules predate exact type and runtime applicability.
    // Replace their C# observations with the bounded implementation below.
    evidence.retain(|item| {
        !matches!(
            item.rule_id.as_str(),
            "csharp-binary-deserialization" | "csharp-deserialization-restriction"
        )
    });

    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "invocation_expression")
    {
        if comments.is_in_comment(invocation.range()) {
            continue;
        }
        if let Some(payload) = typed_system_text_json_payload(root, &invocation) {
            push(
                path,
                &invocation,
                &payload,
                EvidenceKind::Validation,
                Capability::Deserialization,
                "csharp-system-text-json-typed-deserialization-context",
                &[],
                &[
                    "deserialization",
                    "system-text-json",
                    "typed-contract",
                    "not-inherently-cwe-502",
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
            continue;
        }
        let Some((receiver, method, payload)) = invocation_receiver_method_payload(&invocation)
        else {
            continue;
        };
        for serializer in SERIALIZERS {
            if !serializer.methods.contains(&method.as_str())
                || !receiver_has_type(root, &invocation, &receiver, serializer.canonical)
            {
                continue;
            }
            let applicability = project_context.applicability(path, serializer.family);
            let (kind, cwes, applicability_tag) = match applicability {
                RuntimeApplicability::Active => {
                    (EvidenceKind::Sink, &[][..], "runtime-applicability:active")
                }
                RuntimeApplicability::NonExecuting => (
                    EvidenceKind::SecurityConfiguration,
                    &[][..],
                    "runtime-applicability:non-executing",
                ),
                RuntimeApplicability::Unknown => {
                    (EvidenceKind::Sink, &[][..], "runtime-applicability:unknown")
                }
            };
            let cwes = if kind == EvidenceKind::Sink {
                &["CWE-502"][..]
            } else {
                cwes
            };
            push(
                path,
                &invocation,
                &payload,
                kind,
                Capability::Deserialization,
                if kind == EvidenceKind::Sink {
                    serializer.rule_id
                } else {
                    "csharp-legacy-deserializer-nonexecuting-runtime-context"
                },
                cwes,
                &[
                    "deserialization",
                    "dangerous-object-graph",
                    serializer.tag,
                    applicability_tag,
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
            break;
        }
    }
    add_dynamic_xml_type_selection(path, root, comments, conditional, literals, evidence);
}

#[allow(clippy::too_many_arguments)]
fn add_dynamic_xml_type_selection<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for declaration in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
    {
        let Some(name) = declaration.field("name") else {
            continue;
        };
        let Some(value) = declaration.field("value").or_else(|| {
            declaration
                .children()
                .filter(|child| child.is_named())
                .last()
        }) else {
            continue;
        };
        let value_text = compact(value.text().as_ref());
        if !value_text.ends_with(".GetAttribute(\"Type\")") {
            continue;
        }
        let Some(method) = declaration
            .ancestors()
            .find(|node| node.kind().as_ref() == "method_declaration")
        else {
            continue;
        };
        let method_text = compact(method.text().as_ref());
        if !(method_text.contains(".Load(Request.Body)")
            || method_text.contains(".Load(HttpContext.Request.Body)"))
            || !method_text.contains(".SelectNodes(")
        {
            continue;
        }
        let selector = name.text().trim().to_string();
        for serializer in method.dfs().filter(|node| {
            node.kind().as_ref() == "object_creation_expression"
                && node.field("type").is_some_and(|kind| {
                    matches!(
                        compact(kind.text().as_ref()).as_str(),
                        "XmlSerializer" | "System.Xml.Serialization.XmlSerializer"
                    )
                })
                && node.range().start > declaration.range().end
        }) {
            let Some(argument) = invocation_arguments(&serializer)
                .and_then(|arguments| arguments.into_iter().next())
            else {
                continue;
            };
            if compact(argument.text().as_ref()) != format!("Type.GetType({selector})")
                && compact(argument.text().as_ref()) != format!("System.Type.GetType({selector})")
            {
                continue;
            }
            let serializer_name = serializer
                .ancestors()
                .find(|ancestor| ancestor.kind().as_ref() == "variable_declarator")
                .and_then(|declarator| declarator.field("name"))
                .map(|name| name.text().trim().to_string());
            if serializer_name
                .as_ref()
                .is_none_or(|receiver| !method_text.contains(&format!("{receiver}.Deserialize(")))
                || dynamic_type_is_allowlisted(
                    &method,
                    &selector,
                    serializer.range().start,
                    literals,
                )
            {
                continue;
            }
            push(
                path,
                &name,
                &name,
                EvidenceKind::Source,
                Capability::HttpRequestData,
                "csharp-request-xml-type-selector",
                &["CWE-20", "CWE-470"],
                &["http", "xml", "dynamic-type", "attacker-controlled"],
                comments,
                conditional,
                literals,
                evidence,
            );
            push(
                path,
                &serializer,
                &name,
                EvidenceKind::Sink,
                Capability::Deserialization,
                "csharp-xmlserializer-dynamic-type-deserialization",
                &["CWE-470", "CWE-502"],
                &["xml", "deserialization", "dynamic-type", "type-get-type"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn dynamic_type_is_allowlisted<'tree>(
    method: &Node<'tree, StrDoc<SupportLang>>,
    selector: &str,
    before: usize,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> bool {
    method
        .dfs()
        .filter(|node| node.kind().as_ref() == "if_statement" && node.range().start < before)
        .any(|guard| {
            let Some(condition) = guard.field("condition") else {
                return false;
            };
            let condition = compact(condition.text().as_ref());
            let rejects_selector = condition.contains(&format!("{selector}!="))
                || condition.contains(&format!("!AllowedTypes.Contains({selector})"))
                || condition.contains(&format!("!allowedTypes.Contains({selector})"));
            rejects_selector
                && guard
                    .field("consequence")
                    .is_some_and(|body| reachability::always_terminates(&body, literals))
        })
}

fn typed_system_text_json_payload<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let function = invocation.field("function")?;
    let function_text = compact(function.text().as_ref());
    let receiver = function_text.split(".Deserialize<").next()?;
    if !function_text.contains(".Deserialize<")
        || !type_is(root, receiver, "System.Text.Json.JsonSerializer")
    {
        return None;
    }
    invocation_arguments(invocation)?.into_iter().next()
}

fn invocation_receiver_method_payload<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<InvocationParts<'tree>> {
    let function = invocation.field("function")?;
    if function.kind().as_ref() != "member_access_expression" {
        return None;
    }
    let receiver = function.field("expression")?;
    let method = function.field("name")?.text().trim().to_string();
    let payload = invocation_arguments(invocation)?.into_iter().next()?;
    Some((receiver, method, payload))
}

fn receiver_has_type(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &Node<'_, StrDoc<SupportLang>>,
    canonical: &str,
) -> bool {
    if receiver.kind().as_ref() == "object_creation_expression" {
        return receiver
            .field("type")
            .is_some_and(|kind| type_is(root, kind.text().as_ref(), canonical));
    }
    let receiver_text = receiver.text();
    let Some(receiver_name) = simple_identifier(receiver_text.trim()) else {
        return false;
    };
    let scope = scope_range(use_site, root);
    root.dfs().any(|node| {
        node.range().start < use_site.range().start
            && scope.start <= node.range().start
            && node.range().end <= scope.end
            && ((node.kind().as_ref() == "parameter"
                && node
                    .field("name")
                    .is_some_and(|name| name.text().trim() == receiver_name)
                && node
                    .field("type")
                    .is_some_and(|kind| type_is(root, kind.text().as_ref(), canonical)))
                || (node.kind().as_ref() == "variable_declarator"
                    && lexical_declaration_visible_at(&node, use_site)
                    && node
                        .field("name")
                        .is_some_and(|name| name.text().trim() == receiver_name)
                    && (node
                        .parent()
                        .and_then(|parent| parent.field("type"))
                        .is_some_and(|kind| type_is(root, kind.text().as_ref(), canonical))
                        || node.dfs().any(|child| {
                            child.kind().as_ref() == "object_creation_expression"
                                && child.field("type").is_some_and(|kind| {
                                    type_is(root, kind.text().as_ref(), canonical)
                                })
                        }))))
    })
}

fn type_is(root: &Node<'_, StrDoc<SupportLang>>, actual: &str, canonical: &str) -> bool {
    let actual = compact(actual);
    if actual == canonical {
        return true;
    }
    let (namespace, short) = canonical.rsplit_once('.').unwrap_or(("", canonical));
    let declarations_shadow = root.dfs().any(|node| {
        matches!(
            node.kind().as_ref(),
            "class_declaration" | "struct_declaration" | "record_declaration"
        ) && node
            .field("name")
            .is_some_and(|name| name.text().trim() == short)
    });
    for using in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "using_directive")
        .map(|node| compact(node.text().as_ref()))
    {
        let using = using
            .strip_prefix("globalusing")
            .or_else(|| using.strip_prefix("using"))
            .unwrap_or(&using)
            .trim_end_matches(';');
        if let Some((alias, target)) = using.split_once('=') {
            if (target == canonical && actual == alias)
                || (target == namespace && actual == format!("{alias}.{short}"))
            {
                return true;
            }
        } else if using == namespace && actual == short && !declarations_shadow {
            return true;
        }
    }
    false
}

fn invocation_arguments<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Vec<Node<'tree, StrDoc<SupportLang>>>> {
    Some(
        invocation
            .field("arguments")?
            .children()
            .filter(|child| child.is_named())
            .map(|argument| {
                if argument.kind().as_ref() == "argument" {
                    argument
                        .children()
                        .filter(|child| child.is_named())
                        .last()
                        .unwrap_or(argument)
                } else {
                    argument
                }
            })
            .collect(),
    )
}

fn scope_range(
    node: &Node<'_, StrDoc<SupportLang>>,
    root: &Node<'_, StrDoc<SupportLang>>,
) -> Range<usize> {
    node.ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "method_declaration"
                    | "constructor_declaration"
                    | "local_function_statement"
                    | "lambda_expression"
                    | "anonymous_method_expression"
            )
        })
        .map(|ancestor| ancestor.range())
        .unwrap_or_else(|| root.range())
}

fn simple_identifier(text: &str) -> Option<&str> {
    let mut characters = text.chars();
    let first = characters.next()?;
    if !(first == '_' || first.is_alphabetic())
        || !characters.all(|character| character == '_' || character.is_alphanumeric())
    {
        return None;
    }
    Some(text)
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn push<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    payload: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    evidence.push(Evidence {
        id: evidence_id(path, rule_id, node.range().start, node.range().end),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures: BTreeMap::from([(
            "payload".to_string(),
            Capture {
                text: payload.text().into_owned(),
                location: location(path, payload),
            },
        )]),
        cwe_candidates: cwes.iter().map(|cwe| (*cwe).to_string()).collect(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
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
            literals: BTreeMap::from([("payload".to_string(), literals.evaluate(payload))]),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
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

fn evidence_id(path: &str, rule_id: &str, start: usize, end: usize) -> String {
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let hash = input.bytes().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
    });
    format!("ev-{hash:016x}")
}
