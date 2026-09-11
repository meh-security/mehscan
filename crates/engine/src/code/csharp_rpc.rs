use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_core::{AstGrep, Node};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::csharp_ingress::is_service_parameter;
use super::literals::LiteralEnvironment;
use super::reachability;

pub(crate) const GRPC_RULE_ID: &str = "csharp-grpc-request-parameter-source";
pub(crate) const SIGNALR_RULE_ID: &str = "csharp-signalr-hub-parameter-source";
pub(crate) const WCF_RULE_ID: &str = "csharp-wcf-operation-parameter-source";
const ENGINE: &str = "mehscan csharp-rpc-parameter-summary 1";

#[derive(Clone, Debug, Default)]
pub(crate) struct CsharpRpcProjectContext {
    wcf_implementations: BTreeMap<String, BTreeSet<usize>>,
}

impl CsharpRpcProjectContext {
    pub(crate) fn from_sources<'a>(
        sources: impl Iterator<Item = (&'a str, Language, &'a str)>,
    ) -> Self {
        let sources = sources
            .filter(|(_, language, _)| *language == Language::Csharp)
            .collect::<Vec<_>>();
        let mut contracts = BTreeMap::<String, Vec<BTreeSet<String>>>::new();
        for (_, _, source) in &sources {
            let Ok(document) = StrDoc::try_new(source, SupportLang::CSharp) else {
                continue;
            };
            let ast = AstGrep::doc(document);
            let root = ast.root();
            for interface in root
                .dfs()
                .filter(|node| node.kind().as_ref() == "interface_declaration")
                .filter(|node| has_attribute(node, "ServiceContract"))
            {
                let Some(name) = interface.field("name") else {
                    continue;
                };
                let methods = interface
                    .dfs()
                    .filter(|node| node.kind().as_ref() == "method_declaration")
                    .filter(|node| has_attribute(node, "OperationContract"))
                    .filter_map(|method| method_signature(&method))
                    .collect::<BTreeSet<_>>();
                if !methods.is_empty() {
                    contracts
                        .entry(name.text().trim().to_string())
                        .or_default()
                        .push(methods);
                }
            }
        }
        let contracts = contracts
            .into_iter()
            .filter_map(|(name, declarations)| {
                (declarations.len() == 1).then(|| (name, declarations.into_iter().next().unwrap()))
            })
            .collect::<BTreeMap<_, _>>();
        let mut context = Self::default();
        for (path, _, source) in sources {
            let Ok(document) = StrDoc::try_new(source, SupportLang::CSharp) else {
                continue;
            };
            let ast = AstGrep::doc(document);
            let root = ast.root();
            for class in root
                .dfs()
                .filter(|node| node.kind().as_ref() == "class_declaration")
            {
                let implemented = base_types(&class)
                    .into_iter()
                    .filter_map(|base| contracts.get(terminal_type(&compact_type(&base))))
                    .collect::<Vec<_>>();
                if implemented.len() != 1 {
                    continue;
                }
                for method in class
                    .dfs()
                    .filter(|node| node.kind().as_ref() == "method_declaration")
                    .filter(|node| {
                        enclosing_class(node).is_some_and(|owner| owner.range() == class.range())
                    })
                    .filter(|node| has_modifier(node, "public"))
                {
                    let Some(signature) = method_signature(&method) else {
                        continue;
                    };
                    if implemented[0].contains(&signature) {
                        context
                            .wcf_implementations
                            .entry(path.to_string())
                            .or_default()
                            .insert(method.range().start);
                    }
                }
            }
        }
        context
    }

    fn is_wcf_operation(&self, path: &str, method: &Node<'_, StrDoc<SupportLang>>) -> bool {
        self.wcf_implementations
            .get(path)
            .is_some_and(|methods| methods.contains(&method.range().start))
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_rpc_parameter_sources<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    project_context: &CsharpRpcProjectContext,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Csharp {
        return;
    }
    let signalr_imported = has_exact_using(root, "Microsoft.AspNetCore.SignalR");
    let grpc_imported = has_exact_using(root, "Grpc.Core");

    for method in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_declaration")
    {
        let Some(class) = enclosing_class(&method) else {
            continue;
        };
        if project_context.is_wcf_operation(path, &method) {
            add_method_parameters(
                path,
                &method,
                WCF_RULE_ID,
                "wcf",
                comments,
                conditional,
                literals,
                evidence,
                |_| false,
            );
        } else if is_grpc_method(&method, &class, grpc_imported) {
            add_method_parameters(
                path,
                &method,
                GRPC_RULE_ID,
                "grpc",
                comments,
                conditional,
                literals,
                evidence,
                is_grpc_framework_parameter,
            );
        } else if signalr_imported && is_signalr_hub_method(&method, &class) {
            add_method_parameters(
                path,
                &method,
                SIGNALR_RULE_ID,
                "signalr",
                comments,
                conditional,
                literals,
                evidence,
                is_signalr_framework_parameter,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_method_parameters<'tree>(
    path: &str,
    method: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    framework: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
    is_framework_parameter: fn(&Node<'_, StrDoc<SupportLang>>) -> bool,
) {
    let Some(parameters) = method.field("parameters") else {
        return;
    };
    for parameter in parameters
        .children()
        .filter(|node| node.kind().as_ref() == "parameter")
    {
        if comments.is_in_comment(parameter.range())
            || is_framework_parameter(&parameter)
            || is_service_parameter(&parameter)
        {
            continue;
        }
        let Some(name) = parameter.field("name") else {
            continue;
        };
        let mut captures = BTreeMap::from([(
            "parameter".to_string(),
            Capture {
                text: name.text().into_owned(),
                location: location(path, &name),
            },
        )]);
        if let Some(kind) = parameter.field("type") {
            captures.insert(
                "type".to_string(),
                Capture {
                    text: kind.text().into_owned(),
                    location: location(path, &kind),
                },
            );
        }
        evidence.push(Evidence {
            id: evidence_id(path, rule_id, name.range().start, name.range().end),
            kind: EvidenceKind::Source,
            capability: Capability::RpcRequestData,
            location: location(path, &name),
            enclosing_symbol: enclosing_symbol(&parameter),
            captures,
            cwe_candidates: vec!["CWE-20".to_string()],
            tags: vec![
                "rpc".to_string(),
                "remote".to_string(),
                "attacker-controlled".to_string(),
                framework.to_string(),
                "parameter-binding".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: ENGINE.to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: comments.is_in_comment(parameter.range()),
                reachability: Some(reachability::classify(&parameter, literals)),
                availability: Some(conditional.availability_for(parameter.range())),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: rule_id.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

fn is_grpc_method(
    method: &Node<'_, StrDoc<SupportLang>>,
    class: &Node<'_, StrDoc<SupportLang>>,
    grpc_imported: bool,
) -> bool {
    if !has_modifier(method, "public") || !has_modifier(method, "override") {
        return false;
    }
    let generated_base = base_types(class).into_iter().any(|base| {
        let compact = compact_type(&base);
        compact.contains('.') && terminal_type(&compact).ends_with("Base")
    });
    if !generated_base {
        return false;
    }
    method.field("parameters").is_some_and(|parameters| {
        parameters
            .children()
            .filter(|parameter| parameter.kind().as_ref() == "parameter")
            .filter_map(|parameter| parameter.field("type"))
            .any(|kind| {
                let observed = compact_type(kind.text().as_ref());
                terminal_type(&observed) == "ServerCallContext"
                    && (grpc_imported || observed.contains("Grpc.Core."))
            })
    })
}

fn is_signalr_hub_method(
    method: &Node<'_, StrDoc<SupportLang>>,
    class: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    if !has_modifier(method, "public")
        || has_modifier(method, "static")
        || has_modifier(method, "override")
        || has_attribute(method, "NonHubMethod")
    {
        return false;
    }
    base_types(class).into_iter().any(|base| {
        let compact = compact_type(&base);
        let terminal = terminal_type(&compact);
        terminal == "Hub" || terminal.starts_with("Hub<")
    })
}

fn is_grpc_framework_parameter(parameter: &Node<'_, StrDoc<SupportLang>>) -> bool {
    parameter.field("type").is_some_and(|kind| {
        let observed = terminal_type(&compact_type(kind.text().as_ref())).to_string();
        observed == "ServerCallContext"
            || observed == "CancellationToken"
            || observed.starts_with("IServerStreamWriter<")
            || observed.starts_with("IAsyncStreamReader<")
    })
}

fn is_signalr_framework_parameter(parameter: &Node<'_, StrDoc<SupportLang>>) -> bool {
    parameter.field("type").is_some_and(|kind| {
        let observed = terminal_type(&compact_type(kind.text().as_ref())).to_string();
        observed == "CancellationToken"
            || observed.starts_with("IProgress<")
            || observed.starts_with("ChannelWriter<")
    })
}

fn enclosing_class<'tree>(
    method: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    method
        .ancestors()
        .filter(|ancestor| ancestor.kind().as_ref() == "class_declaration")
        .last()
}

fn base_types(class: &Node<'_, StrDoc<SupportLang>>) -> Vec<String> {
    class
        .children()
        .find(|child| child.kind().as_ref() == "base_list")
        .map(|base_list| {
            base_list
                .children()
                .filter(|child| child.is_named())
                .map(|child| child.text().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn has_modifier(node: &Node<'_, StrDoc<SupportLang>>, expected: &str) -> bool {
    node.children()
        .any(|child| child.kind().as_ref() == "modifier" && child.text().trim() == expected)
}

fn has_attribute(node: &Node<'_, StrDoc<SupportLang>>, expected: &str) -> bool {
    node.children()
        .filter(|child| child.kind().as_ref() == "attribute_list")
        .flat_map(|list| list.children().collect::<Vec<_>>())
        .filter(|attribute| attribute.kind().as_ref() == "attribute")
        .filter_map(|attribute| attribute.field("name"))
        .any(|name| normalize_attribute(name.text().as_ref()) == expected)
}

fn normalize_attribute(name: &str) -> String {
    let terminal = name.rsplit(['.', ':']).next().unwrap_or(name);
    terminal
        .strip_suffix("Attribute")
        .unwrap_or(terminal)
        .to_string()
}

fn has_exact_using(root: &Node<'_, StrDoc<SupportLang>>, namespace: &str) -> bool {
    let expected = format!("using{namespace};");
    let global_expected = format!("globalusing{namespace};");
    root.dfs()
        .filter(|node| node.kind().as_ref() == "using_directive")
        .map(|node| {
            node.text()
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
        })
        .any(|observed| observed == expected || observed == global_expected)
}

fn compact_type(observed: &str) -> String {
    observed
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>()
        .trim_start_matches("global::")
        .trim_end_matches('?')
        .to_string()
}

fn terminal_type(observed: &str) -> &str {
    observed.rsplit('.').next().unwrap_or(observed)
}

fn method_signature(method: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let name = method.field("name")?.text().trim().to_string();
    let parameters = method.field("parameters")?;
    let types = parameters
        .children()
        .filter(|node| node.kind().as_ref() == "parameter")
        .map(|parameter| {
            parameter
                .field("type")
                .map(|kind| compact_type(kind.text().as_ref()))
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(",");
    Some(format!("{name}({types})"))
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
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}
