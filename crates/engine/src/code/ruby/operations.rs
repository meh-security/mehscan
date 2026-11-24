use std::collections::{BTreeMap, BTreeSet};

use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceKind, OperandFact, OperandFactKind,
    Provenance, Resolution, SecurityPath, SecurityPathProvenance, SecurityPathState,
    SecurityPathStep, SecurityPathStepKind,
};

use super::super::context::{enclosing_symbol, unknown_textual_context};
use super::super::matcher::{evidence_id, location};
use super::project::{FrameworkClass, RubyProject, constant, enclosing_namespace};
use super::{RubyNode, capture, loads_library, replaces_require};

const REQUEST_RULE: &str = "ruby-rails-request-parameter";

struct Operation<'tree> {
    rule: &'static str,
    capability: Capability,
    cwe: &'static str,
    role: &'static str,
    operand: RubyNode<'tree>,
    binding: Option<Capture>,
}

pub(super) fn observations(
    path: &str,
    root: &RubyNode<'_>,
    project: &RubyProject,
    evidence: &mut Vec<Evidence>,
) -> Vec<SecurityPath> {
    let mut paths = Vec::new();
    let mut sources = BTreeMap::new();
    let mut known_paths = BTreeSet::new();
    let require_replaced = root.dfs().any(|node| replaces_require(&node));
    let loads = root
        .children()
        .filter(|_| !require_replaced)
        .filter_map(|node| {
            ["net/http", "yaml", "psych"]
                .into_iter()
                .find(|library| loads_library(&node, library))
                .map(|library| (library, node))
        })
        .collect::<Vec<_>>();
    for call in root.dfs().filter(|node| node.kind() == "call") {
        let Some(method) = call.field("method") else {
            continue;
        };
        let method_name = method.text();
        if !matches!(
            method_name.as_ref(),
            "where"
                | "sql"
                | "find_by"
                | "find_by!"
                | "find_by_sql"
                | "order"
                | "reorder"
                | "having"
                | "joins"
                | "from"
                | "select"
                | "group"
                | "render"
                | "redirect_to"
                | "send_file"
                | "load"
                | "restore"
                | "unsafe_load"
                | "get"
                | "get_response"
                | "post"
                | "read"
                | "binread"
                | "write"
                | "binwrite"
                | "system"
                | "exec"
                | "spawn"
        ) {
            continue;
        }
        let arguments = arguments(&call);
        if arguments.is_empty() || call.field("block").is_some() {
            continue;
        }
        let owner = enclosing_namespace(&call);
        let controller = controller_method(&call);
        let operation =
            record_operation(&call, &method_name, &arguments, owner.as_deref(), project)
                .or_else(|| {
                    controller.as_ref()?;
                    controller_operation(
                        &call,
                        &method_name,
                        &arguments,
                        owner.as_deref()?,
                        project,
                    )
                })
                .or_else(|| {
                    library_operation(
                        path,
                        &call,
                        &method_name,
                        &arguments,
                        &loads,
                        owner.as_deref(),
                        project,
                    )
                });
        let Some(operation) = operation else {
            continue;
        };
        if fixed(&operation.operand) {
            continue;
        }
        let operands = request_operands(&operation.operand, project);
        let params = (!operands.is_empty())
            .then(|| {
                let method = controller.as_ref()?;
                if shadows_params(method) {
                    return None;
                }
                project.witness(owner.as_deref()?, FrameworkClass::Controller, "params")
            })
            .flatten();
        let allow_other_host = (operation.capability == Capability::Redirect)
            .then(|| {
                let mut options = arguments
                    .iter()
                    .filter(|argument| keyword(argument, "allow_other_host").is_some());
                let option = options.next()?;
                if options.next().is_some() || arguments.iter().any(opaque_argument) {
                    return None;
                }
                keyword(option, "allow_other_host").filter(|value| value.kind() == "true")?;
                Some(option)
            })
            .flatten();
        if params.is_none()
            && matches!(
                operation.capability,
                Capability::FilesystemRead | Capability::FilesystemWrite | Capability::Redirect
            )
            && !interpolated(&operation.operand)
            && allow_other_host.is_none()
        {
            continue;
        }
        let decision_critical = params.is_some()
            || allow_other_host.is_some()
            || operation.capability == Capability::ProcessExecution;
        let mut captures =
            BTreeMap::from([(operation.role.into(), capture(path, &operation.operand))]);
        if let Some(binding) = operation.binding {
            captures.insert("api_binding".into(), binding);
        }
        if let Some(option) = allow_other_host {
            captures.insert("redirect_policy".into(), capture(path, option));
        }
        let mut sink = observation(
            path,
            &call,
            operation.rule,
            operation.capability,
            EvidenceKind::Sink,
            Some(operation.cwe),
            captures,
            decision_critical,
        );
        if operation.capability == Capability::ProcessExecution {
            sink.context.operand_facts.push(OperandFact {
                role: "command".into(),
                kind: OperandFactKind::ProcessShellMode,
                location: location(path, &operation.operand),
                value: "unresolved".into(),
                remaining_checks: vec![
                    "caller_authority".into(),
                    "shell_selection_and_child_argument_semantics".into(),
                ],
            });
        }
        if let Some(witness) = params {
            for parameter in operands {
                let range = parameter.range();
                let source = sources.entry((range.start, range.end)).or_insert_with(|| {
                    observation(
                        path,
                        &parameter,
                        REQUEST_RULE,
                        Capability::HttpRequestData,
                        EvidenceKind::Source,
                        None,
                        BTreeMap::from([
                            ("field".into(), capture(path, &parameter)),
                            ("api_binding".into(), witness.clone()),
                        ]),
                        false,
                    )
                });
                let proof = direct_path(source, &sink);
                if known_paths.insert(proof.id.clone()) {
                    paths.push(proof);
                }
            }
        }
        evidence.push(sink);
    }
    evidence.extend(sources.into_values());
    paths
}

fn arguments<'tree>(call: &RubyNode<'tree>) -> Vec<RubyNode<'tree>> {
    let Some(arguments) = call.field("arguments") else {
        return Vec::new();
    };
    arguments
        .children()
        .filter(|child| child.is_named() && child.kind() != "comment")
        .collect()
}

fn controller_method<'tree>(node: &RubyNode<'tree>) -> Option<RubyNode<'tree>> {
    node.ancestors()
        .find(|parent| {
            matches!(
                parent.kind().as_ref(),
                "method" | "singleton_method" | "class" | "module"
            )
        })
        .filter(|parent| parent.kind() == "method")
}

fn shadows_params(method: &RubyNode<'_>) -> bool {
    method.dfs().any(|node| {
        let binding = match node.kind().as_ref() {
            "method_parameters" | "block_parameters" => Some(node.clone()),
            "assignment" | "operator_assignment" => node.field("left"),
            _ => None,
        };
        binding.is_some_and(|node| {
            node.dfs()
                .any(|part| part.kind() == "identifier" && part.text() == "params")
        })
    })
}

fn record_operation<'tree>(
    call: &RubyNode<'tree>,
    method: &str,
    arguments: &[RubyNode<'tree>],
    owner: Option<&str>,
    project: &RubyProject,
) -> Option<Operation<'tree>> {
    let operand = arguments.first()?.clone();
    if !interpolated(&operand) {
        return None;
    }
    let receiver = call.field("receiver")?;
    if method == "sql" {
        let name = constant(&receiver)?;
        if project.resolve(&name, owner) != "Arel" || project.defines("Arel") {
            return None;
        }
        return Some(Operation {
            rule: "ruby-arel-query-text",
            capability: Capability::DatabaseQuery,
            cwe: "CWE-89",
            role: "query",
            operand,
            binding: Some(project.active_record_base()?.clone()),
        });
    }
    if !matches!(
        method,
        "where"
            | "find_by"
            | "find_by!"
            | "find_by_sql"
            | "order"
            | "reorder"
            | "having"
            | "joins"
            | "from"
            | "select"
            | "group"
    ) {
        return None;
    }
    let class = record_receiver(&receiver, owner, project, 0)?;
    let binding = project
        .witness(&class, FrameworkClass::Record, method)?
        .clone();
    Some(Operation {
        rule: "ruby-active-record-query-text",
        capability: Capability::DatabaseQuery,
        cwe: "CWE-89",
        role: "query",
        operand,
        binding: Some(binding),
    })
}

fn record_receiver(
    receiver: &RubyNode<'_>,
    owner: Option<&str>,
    project: &RubyProject,
    depth: usize,
) -> Option<String> {
    if let Some(class) = constant(receiver) {
        return Some(project.resolve(&class, owner));
    }
    if depth == 4 || receiver.kind() != "call" || receiver.field("block").is_some() {
        return None;
    }
    let method = receiver.field("method")?.text().into_owned();
    if !matches!(
        method.as_str(),
        "all" | "where" | "order" | "joins" | "includes" | "limit" | "offset" | "distinct"
    ) {
        return None;
    }
    let class = record_receiver(&receiver.field("receiver")?, owner, project, depth + 1)?;
    project.witness(&class, FrameworkClass::Record, &method)?;
    Some(class)
}

fn controller_operation<'tree>(
    call: &RubyNode<'tree>,
    method: &str,
    arguments: &[RubyNode<'tree>],
    owner: &str,
    project: &RubyProject,
) -> Option<Operation<'tree>> {
    if call
        .field("receiver")
        .is_some_and(|receiver| receiver.kind() != "self")
    {
        return None;
    }
    if !matches!(method, "render" | "redirect_to" | "send_file") {
        return None;
    }
    let binding = project
        .witness(owner, FrameworkClass::Controller, method)?
        .clone();
    let (rule, capability, cwe, role, operand) = match method {
        "render" => {
            if arguments.iter().any(opaque_argument) {
                return None;
            }
            let mut modes = arguments.iter().filter(|argument| {
                argument.kind() == "pair"
                    && argument.field("key").is_some_and(|key| {
                        key.kind() == "hash_key_symbol"
                            && matches!(
                                key.text().as_ref(),
                                "html"
                                    | "inline"
                                    | "file"
                                    | "plain"
                                    | "body"
                                    | "json"
                                    | "xml"
                                    | "js"
                                    | "partial"
                                    | "template"
                                    | "action"
                                    | "renderable"
                            )
                    })
            });
            let pair = modes.next()?;
            if modes.next().is_some() {
                return None;
            }
            let key = pair.field("key")?;
            let value = pair.field("value")?;
            match key.text().as_ref() {
                "html" => {
                    if value.kind() != "call"
                        || value.field("block").is_some()
                        || !value
                            .field("method")
                            .is_some_and(|method| method.text() == "html_safe")
                        || !arguments_of_call_are_empty(&value)
                    {
                        return None;
                    }
                    (
                        "ruby-rails-raw-html",
                        Capability::HtmlOutput,
                        "CWE-79",
                        "content",
                        value.field("receiver")?,
                    )
                }
                "inline" => (
                    "ruby-rails-inline-template",
                    Capability::TemplateEvaluation,
                    "CWE-1336",
                    "template",
                    value,
                ),
                "file" => (
                    "ruby-rails-render-file",
                    Capability::FilesystemRead,
                    "CWE-22",
                    "path",
                    value,
                ),
                _ => return None,
            }
        }
        "redirect_to" => (
            "ruby-rails-redirect",
            Capability::Redirect,
            "CWE-601",
            "destination",
            arguments.first()?.clone(),
        ),
        "send_file" => (
            "ruby-rails-send-file",
            Capability::FilesystemRead,
            "CWE-22",
            "path",
            arguments.first()?.clone(),
        ),
        _ => return None,
    };
    if matches!(
        operand.kind().as_ref(),
        "hash" | "pair" | "array" | "block_argument" | "splat_argument"
    ) {
        return None;
    }
    Some(Operation {
        rule,
        capability,
        cwe,
        role,
        operand,
        binding: Some(binding),
    })
}

fn keyword<'tree>(argument: &RubyNode<'tree>, name: &str) -> Option<RubyNode<'tree>> {
    (argument.kind() == "pair"
        && argument
            .field("key")
            .is_some_and(|key| key.kind() == "hash_key_symbol" && key.text() == name))
    .then(|| argument.field("value"))
    .flatten()
}

fn opaque_argument(node: &RubyNode<'_>) -> bool {
    matches!(
        node.kind().as_ref(),
        "hash_splat_argument" | "splat_argument" | "forward_argument"
    )
}

fn arguments_of_call_are_empty(call: &RubyNode<'_>) -> bool {
    arguments(call).is_empty()
}

fn library_operation<'tree>(
    path: &str,
    call: &RubyNode<'tree>,
    method: &str,
    arguments: &[RubyNode<'tree>],
    loads: &[(&str, RubyNode<'tree>)],
    owner: Option<&str>,
    project: &RubyProject,
) -> Option<Operation<'tree>> {
    if !matches!(
        method,
        "load"
            | "restore"
            | "unsafe_load"
            | "get"
            | "get_response"
            | "post"
            | "read"
            | "binread"
            | "write"
            | "binwrite"
            | "system"
            | "exec"
            | "spawn"
    ) {
        return None;
    }
    let receiver = constant(&call.field("receiver")?)?;
    let canonical = project.resolve(&receiver, owner);
    if project.defines(canonical.split("::").next()?) || project.defines(&canonical) {
        return None;
    }
    let (rule, capability, cwe, role, library) = match (canonical.as_str(), method) {
        ("Kernel", "system" | "exec" | "spawn")
            if receiver == "::Kernel"
                && matches!(arguments, [command] if interpolated(command)) =>
        {
            (
                "ruby-kernel-command-string",
                Capability::ProcessExecution,
                "CWE-78",
                "command",
                None,
            )
        }
        ("File", "read" | "binread") => (
            "ruby-file-read",
            Capability::FilesystemRead,
            "CWE-22",
            "path",
            None,
        ),
        ("File", "write" | "binwrite") => (
            "ruby-file-write",
            Capability::FilesystemWrite,
            "CWE-22",
            "path",
            None,
        ),
        ("Marshal", "load" | "restore") => (
            "ruby-marshal-load",
            Capability::Deserialization,
            "CWE-502",
            "input",
            None,
        ),
        ("YAML", "unsafe_load") => (
            "ruby-yaml-unsafe-load",
            Capability::Deserialization,
            "CWE-502",
            "input",
            Some("yaml"),
        ),
        ("Psych", "unsafe_load") => (
            "ruby-yaml-unsafe-load",
            Capability::Deserialization,
            "CWE-502",
            "input",
            Some("psych"),
        ),
        ("Net::HTTP", "get" | "get_response" | "post") => (
            "ruby-net-http-request",
            Capability::OutboundNetworkRequest,
            "CWE-918",
            "url",
            Some("net/http"),
        ),
        _ => return None,
    };
    let binding = if let Some(library) = library {
        let (_, load) = loads
            .iter()
            .find(|(loaded, node)| *loaded == library && node.range().end <= call.range().start)?;
        Some(capture(path, load))
    } else {
        None
    };
    let operand = arguments.first()?.clone();
    if matches!(
        operand.kind().as_ref(),
        "hash" | "pair" | "array" | "block_argument" | "splat_argument"
    ) {
        return None;
    }
    Some(Operation {
        rule,
        capability,
        cwe,
        role,
        operand,
        binding,
    })
}

fn fixed(node: &RubyNode<'_>) -> bool {
    matches!(
        node.kind().as_ref(),
        "integer" | "float" | "nil" | "true" | "false" | "simple_symbol"
    ) || (node.kind() == "string" && !interpolated(node))
}

fn interpolated(node: &RubyNode<'_>) -> bool {
    node.kind() == "string" && node.children().any(|part| part.kind() == "interpolation")
}

fn request_operands<'tree>(value: &RubyNode<'tree>, project: &RubyProject) -> Vec<RubyNode<'tree>> {
    if is_request_parameter(value) {
        return vec![value.clone()];
    }
    if value.kind() == "string" {
        return value
            .children()
            .filter(|part| part.kind() == "interpolation")
            .flat_map(|part| {
                part.children()
                    .filter(is_request_parameter)
                    .collect::<Vec<_>>()
            })
            .collect();
    }
    // Only unwrap the explicit standard URI constructor. User-defined
    // helpers inside a request expression may validate or replace the value.
    if value.kind() == "call" && !project.defines("URI") {
        let receiver = value.field("receiver").and_then(|node| constant(&node));
        if receiver.as_deref() == Some("::URI")
            && value
                .field("method")
                .is_some_and(|method| method.text() == "parse")
        {
            let args = arguments(value);
            if let [argument] = args.as_slice()
                && is_request_parameter(argument)
            {
                return vec![argument.clone()];
            }
        }
    }
    Vec::new()
}

fn is_request_parameter(value: &RubyNode<'_>) -> bool {
    let is_params = |node: &RubyNode<'_>| {
        (node.kind() == "identifier" && node.text() == "params")
            || (node.kind() == "call"
                && node
                    .field("receiver")
                    .is_none_or(|receiver| receiver.kind() == "self")
                && node
                    .field("method")
                    .is_some_and(|method| method.text() == "params")
                && arguments(node).is_empty())
    };
    let fixed_key = |node: &RubyNode<'_>| {
        matches!(node.kind().as_ref(), "simple_symbol" | "string") && !interpolated(node)
    };
    match value.kind().as_ref() {
        "element_reference" => {
            let Some(receiver) = value.field("object").filter(is_params) else {
                return false;
            };
            let keys = value
                .children()
                .filter(|node| {
                    node.is_named() && node.kind() != "comment" && node.range() != receiver.range()
                })
                .collect::<Vec<_>>();
            matches!(keys.as_slice(), [key] if fixed_key(key))
        }
        "call" => {
            value
                .field("receiver")
                .is_some_and(|receiver| is_params(&receiver))
                && value
                    .field("method")
                    .is_some_and(|method| matches!(method.text().as_ref(), "require" | "fetch"))
                && matches!(arguments(value).as_slice(), [key] if fixed_key(key))
        }
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn observation(
    path: &str,
    node: &RubyNode<'_>,
    rule: &str,
    capability: Capability,
    kind: EvidenceKind,
    cwe: Option<&str>,
    captures: BTreeMap<String, Capture>,
    direct: bool,
) -> Evidence {
    let anchor = location(path, node);
    let mut tags = vec!["review-language:ruby".into()];
    if direct {
        tags.push("review-origin:decision-critical".into());
    }
    Evidence {
        id: evidence_id(path, rule, anchor.start.byte_offset, anchor.end.byte_offset),
        rule_id: rule.into(),
        capability,
        kind,
        location: anchor,
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwe.into_iter().map(str::to_string).collect(),
        tags,
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: "tree-sitter Ruby operation binding".into(),
            rule_version: 1,
        },
        context: unknown_textual_context(),
        symbol_resolution: None,
        related_evidence: Vec::new(),
    }
}

fn direct_path(source: &Evidence, sink: &Evidence) -> SecurityPath {
    let state = SecurityPathState::Direct;
    let steps = [
        (SecurityPathStepKind::Source, source),
        (SecurityPathStepKind::Sink, sink),
    ]
    .into_iter()
    .map(|(kind, evidence)| SecurityPathStep {
        kind,
        location: evidence.location.clone(),
        evidence_id: Some(evidence.id.clone()),
        symbol: None,
    })
    .collect::<Vec<_>>();
    SecurityPath {
        id: super::super::security_paths::path_id(source, sink, state, &steps),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: sink.capability,
        cwe_candidates: sink.cwe_candidates.clone(),
        state,
        steps,
        protection_evidence_ids: Vec::new(),
        uncertainty_reasons: vec![
            "rails_parameter_binding_is_syntactic".into(),
            "runtime_dispatch_unverified".into(),
        ],
        provenance: SecurityPathProvenance {
            engine: "tree-sitter Ruby direct operand 1".into(),
            maximum_propagation_depth: 0,
        },
    }
}
