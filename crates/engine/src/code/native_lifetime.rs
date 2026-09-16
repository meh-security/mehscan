use std::collections::{BTreeMap, BTreeSet};

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

const ESCAPE_RULE_ID: &str = "c-family-stack-address-state-escape";
const RESTORE_RULE_ID: &str = "c-family-stack-state-restoration";
const HANDOFF_RULE_ID: &str = "c-family-callback-lifetime-handoff";
const DEREFERENCE_RULE_ID: &str = "c-family-post-callback-state-dereference";
const ENGINE: &str = "tree-sitter c-family callback-lifetime relationship";

pub(crate) fn add_native_lifetime_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !matches!(language, Language::C | Language::Cpp) {
        return;
    }
    for assignment in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .filter(|node| !comments.is_in_comment(node.range()))
    {
        let Some(escape) = stack_escape(&assignment) else {
            continue;
        };
        let source = escape_evidence(path, &escape, comments, conditional, literals);
        if is_excluded(&source) {
            continue;
        }
        evidence.push(source.clone());
        if let Some(restoration) = escape.restoration.as_ref() {
            evidence.push(restoration_evidence(
                path,
                restoration,
                &escape,
                &source,
                comments,
                conditional,
                literals,
            ));
        }
    }
    for call in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
        .filter(|node| !comments.is_in_comment(node.range()))
    {
        if let Some(wrapper) = callback_wrapper(&call) {
            let item = dereference_evidence(path, &wrapper, comments, conditional, literals);
            if !is_excluded(&item) {
                evidence.push(item);
            }
        }
        if let Some(handoff) = callback_handoff(&call) {
            let item = handoff_evidence(path, &handoff, comments, conditional, literals);
            if !is_excluded(&item) {
                evidence.push(item);
            }
        }
    }
}

struct StackEscape<'tree> {
    assignment: Node<'tree, StrDoc<SupportLang>>,
    release: Node<'tree, StrDoc<SupportLang>>,
    restoration: Option<Node<'tree, StrDoc<SupportLang>>>,
    callback: String,
    owner: String,
    member: String,
    local: String,
}

fn stack_escape<'tree>(
    assignment: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<StackEscape<'tree>> {
    let left = assignment.field("left")?;
    let right = assignment.field("right")?;
    let (owner, member) = direct_member(left.text().as_ref())?;
    let local = addressed_identifier(right.text().as_ref())?;
    let function = assignment
        .ancestors()
        .find(|node| node.kind().as_ref() == "function_definition")?;
    let callback = function_name(&function)?;
    let declared = function
        .dfs()
        .filter(|node| node.kind().as_ref() == "declaration")
        .filter(|node| node.range().start < assignment.range().start)
        .any(|node| declaration_declares(&node, &local));
    if !declared
        || !function.dfs().any(|node| {
            node.kind().as_ref() == "return_statement"
                && node.range().start > assignment.range().end
        })
    {
        return None;
    }
    let release = function
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
        .filter(|node| node.range().start > assignment.range().end)
        .find(|node| {
            node.field("function").is_some_and(|callee| {
                let name = callee.text().to_ascii_lowercase();
                name.contains("free") || name.contains("destroy") || name.contains("release")
            })
        })?;
    let left_text = left.text();
    let restoration = function
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .filter(|node| node.range().start > assignment.range().end)
        .find(|node| {
            node.field("left")
                .is_some_and(|candidate| candidate.text().trim() == left_text.trim())
                && node
                    .field("right")
                    .is_some_and(|value| !contains_address_of(value.text().as_ref(), &local))
        });
    Some(StackEscape {
        assignment: assignment.clone(),
        release,
        restoration,
        callback,
        owner,
        member,
        local,
    })
}

struct WrapperDereference<'tree> {
    callback_call: Node<'tree, StrDoc<SupportLang>>,
    pre_use: Node<'tree, StrDoc<SupportLang>>,
    post_use: Node<'tree, StrDoc<SupportLang>>,
    wrapper: String,
    callback_parameter: String,
    callback_argument: String,
    owner_alias: String,
    owner_parameter: String,
    member: String,
}

fn callback_wrapper<'tree>(
    callback_call: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<WrapperDereference<'tree>> {
    let callback_parameter = callback_call.field("function")?.text().trim().to_string();
    simple_identifier(&callback_parameter)?;
    let callback_arguments = named_arguments(callback_call);
    if callback_arguments.len() != 1 {
        return None;
    }
    let callback_argument = callback_arguments[0].text().trim().to_string();
    simple_identifier(&callback_argument)?;
    let function = callback_call
        .ancestors()
        .find(|node| node.kind().as_ref() == "function_definition")?;
    let wrapper = function_name(&function)?;
    let parameters = function
        .dfs()
        .find(|node| node.kind().as_ref() == "parameter_list")?
        .text();
    if !contains_identifier(parameters.as_ref(), &callback_parameter)
        || !contains_identifier(parameters.as_ref(), &callback_argument)
    {
        return None;
    }
    let pre_use = function
        .dfs()
        .filter(|node| node.kind().as_ref() == "field_expression")
        .filter(|node| node.range().end < callback_call.range().start)
        .find(|node| member_chain(node.text().as_ref()).is_some())?;
    let (owner_alias, member, leaf) = member_chain(pre_use.text().as_ref())?;
    let post_use = function
        .dfs()
        .filter(|node| node.kind().as_ref() == "field_expression")
        .filter(|node| node.range().start > callback_call.range().end)
        .find(|node| {
            member_chain(node.text().as_ref()).is_some_and(|candidate| {
                candidate == (owner_alias.clone(), member.clone(), leaf.clone())
            })
        })?;
    let owner_parameter = alias_initializer(&function, &owner_alias)?;
    Some(WrapperDereference {
        callback_call: callback_call.clone(),
        pre_use,
        post_use,
        wrapper,
        callback_parameter,
        callback_argument,
        owner_alias,
        owner_parameter,
        member,
    })
}

struct CallbackHandoff<'tree> {
    call: Node<'tree, StrDoc<SupportLang>>,
    wrapper: String,
    callback: String,
    owner: String,
}

fn callback_handoff<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<CallbackHandoff<'tree>> {
    let wrapper = call.field("function")?.text().trim().to_string();
    simple_identifier(&wrapper)?;
    let arguments = named_arguments(call);
    if arguments.len() < 3 {
        return None;
    }
    let owner = arguments[0].text().trim().to_string();
    let callback = arguments[1].text().trim().to_string();
    let callback_owner = arguments[2].text().trim().to_string();
    simple_identifier(&owner)?;
    simple_identifier(&callback)?;
    simple_identifier(&callback_owner)?;
    if owner != callback_owner || wrapper == callback {
        return None;
    }
    Some(CallbackHandoff {
        call: call.clone(),
        wrapper,
        callback,
        owner,
    })
}

fn escape_evidence<'tree>(
    path: &str,
    escape: &StackEscape<'tree>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    make_evidence(
        path,
        &escape.assignment,
        ESCAPE_RULE_ID,
        EvidenceKind::Source,
        Capability::StackAddressEscape,
        BTreeMap::from([
            (
                "callback".to_string(),
                text_capture(path, &escape.assignment, &escape.callback),
            ),
            (
                "owner".to_string(),
                text_capture(path, &escape.assignment, &escape.owner),
            ),
            (
                "member".to_string(),
                text_capture(path, &escape.assignment, &escape.member),
            ),
            (
                "stack_local".to_string(),
                text_capture(path, &escape.assignment, &escape.local),
            ),
            ("escape".to_string(), capture(path, &escape.assignment)),
            ("release".to_string(), capture(path, &escape.release)),
        ]),
        vec![
            "native",
            "stack-address-stored-in-owner-state",
            "parse-recovery:locally-complete",
        ],
        comments,
        conditional,
        literals,
        Vec::new(),
    )
}

#[allow(clippy::too_many_arguments)]
fn restoration_evidence<'tree>(
    path: &str,
    restoration: &Node<'tree, StrDoc<SupportLang>>,
    escape: &StackEscape<'tree>,
    source: &Evidence,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    make_evidence(
        path,
        restoration,
        RESTORE_RULE_ID,
        EvidenceKind::Validation,
        Capability::StackLifetimeRestoration,
        BTreeMap::from([
            (
                "owner".to_string(),
                text_capture(path, restoration, &escape.owner),
            ),
            (
                "member".to_string(),
                text_capture(path, restoration, &escape.member),
            ),
            ("restoration".to_string(), capture(path, restoration)),
        ]),
        vec![
            "native",
            "escaped-state-restored-before-return",
            "parse-recovery:locally-complete",
        ],
        comments,
        conditional,
        literals,
        vec![source.id.clone()],
    )
}

fn handoff_evidence<'tree>(
    path: &str,
    handoff: &CallbackHandoff<'tree>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    make_evidence(
        path,
        &handoff.call,
        HANDOFF_RULE_ID,
        EvidenceKind::Guard,
        Capability::LifetimeCallbackHandoff,
        BTreeMap::from([
            (
                "wrapper".to_string(),
                text_capture(path, &handoff.call, &handoff.wrapper),
            ),
            (
                "callback".to_string(),
                text_capture(path, &handoff.call, &handoff.callback),
            ),
            (
                "owner".to_string(),
                text_capture(path, &handoff.call, &handoff.owner),
            ),
            ("handoff".to_string(), capture(path, &handoff.call)),
        ]),
        vec![
            "native",
            "concrete-callback-owner-handoff",
            "parse-recovery:locally-complete",
        ],
        comments,
        conditional,
        literals,
        Vec::new(),
    )
}

fn dereference_evidence<'tree>(
    path: &str,
    wrapper: &WrapperDereference<'tree>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    make_evidence(
        path,
        &wrapper.post_use,
        DEREFERENCE_RULE_ID,
        EvidenceKind::Sink,
        Capability::PostReturnDereference,
        BTreeMap::from([
            (
                "wrapper".to_string(),
                text_capture(path, &wrapper.post_use, &wrapper.wrapper),
            ),
            (
                "callback_parameter".to_string(),
                text_capture(path, &wrapper.callback_call, &wrapper.callback_parameter),
            ),
            (
                "callback_argument".to_string(),
                text_capture(path, &wrapper.callback_call, &wrapper.callback_argument),
            ),
            (
                "owner_alias".to_string(),
                text_capture(path, &wrapper.post_use, &wrapper.owner_alias),
            ),
            (
                "owner_parameter".to_string(),
                text_capture(path, &wrapper.post_use, &wrapper.owner_parameter),
            ),
            (
                "member".to_string(),
                text_capture(path, &wrapper.post_use, &wrapper.member),
            ),
            (
                "pre_callback_access".to_string(),
                capture(path, &wrapper.pre_use),
            ),
            (
                "callback_call".to_string(),
                capture(path, &wrapper.callback_call),
            ),
            (
                "post_callback_dereference".to_string(),
                capture(path, &wrapper.post_use),
            ),
        ]),
        vec![
            "native",
            "same-member-access-after-callback-return",
            "parse-recovery:locally-complete",
        ],
        comments,
        conditional,
        literals,
        Vec::new(),
    )
}

#[allow(clippy::too_many_arguments)]
fn make_evidence<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    captures: BTreeMap<String, Capture>,
    tags: Vec<&str>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    related_evidence: Vec<String>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, rule_id, node),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes(),
        tags: tags.into_iter().map(str::to_string).collect(),
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: evidence_context(node, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence,
    }
}

pub(crate) fn link_native_lifetime_paths(evidence: &mut Vec<Evidence>) -> Vec<SecurityPath> {
    let escapes = by_capability(evidence, Capability::StackAddressEscape);
    let restorations = by_capability(evidence, Capability::StackLifetimeRestoration);
    let handoffs = by_capability(evidence, Capability::LifetimeCallbackHandoff);
    let dereferences = by_capability(evidence, Capability::PostReturnDereference);
    let mut paths = Vec::new();
    let mut retained = BTreeSet::new();
    for handoff in &handoffs {
        let Some(callback) = capture_text(handoff, "callback") else {
            continue;
        };
        let Some(wrapper_name) = capture_text(handoff, "wrapper") else {
            continue;
        };
        for source in escapes.iter().filter(|source| {
            capture_text(source, "callback") == Some(callback)
                && same_c_family_language(&source.location.path, &handoff.location.path)
        }) {
            let Some(member) = capture_text(source, "member") else {
                continue;
            };
            for sink in dereferences.iter().filter(|sink| {
                capture_text(sink, "wrapper") == Some(wrapper_name)
                    && capture_text(sink, "member") == Some(member)
                    && same_c_family_language(&source.location.path, &sink.location.path)
            }) {
                let protection = restorations.iter().find(|item| {
                    item.related_evidence.iter().any(|id| id == &source.id) && !is_excluded(item)
                });
                retained.extend([source.id.clone(), handoff.id.clone(), sink.id.clone()]);
                if let Some(item) = protection {
                    retained.insert(item.id.clone());
                }
                if let Some(item) = evidence.iter_mut().find(|item| item.id == sink.id) {
                    item.related_evidence
                        .extend([source.id.clone(), handoff.id.clone()]);
                    if let Some(protection) = protection {
                        item.related_evidence.push(protection.id.clone());
                    }
                    item.related_evidence.sort();
                    item.related_evidence.dedup();
                }
                paths.push(lifetime_path(source, handoff, sink, protection));
            }
        }
    }
    evidence.retain(|item| {
        !matches!(
            item.capability,
            Capability::StackAddressEscape
                | Capability::LifetimeCallbackHandoff
                | Capability::PostReturnDereference
                | Capability::StackLifetimeRestoration
        ) || retained.contains(&item.id)
    });
    paths.sort_by(|a, b| a.id.cmp(&b.id));
    paths.dedup_by(|a, b| a.id == b.id);
    paths
}

fn lifetime_path(
    source: &Evidence,
    handoff: &Evidence,
    sink: &Evidence,
    protection: Option<&Evidence>,
) -> SecurityPath {
    let state = if protection.is_some() {
        SecurityPathState::Protected
    } else {
        SecurityPathState::Unknown
    };
    let mut steps = vec![step(SecurityPathStepKind::Source, source)];
    if let Some(protection) = protection {
        steps.push(step(SecurityPathStepKind::Protection, protection));
    }
    steps.push(step(SecurityPathStepKind::Alias, handoff));
    steps.push(step(SecurityPathStepKind::Sink, sink));
    SecurityPath {
        id: path_id(source, sink, state, &steps),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: Capability::PostReturnDereference,
        cwe_candidates: cwes(),
        state,
        steps,
        protection_evidence_ids: protection
            .map(|item| vec![item.id.clone()])
            .unwrap_or_default(),
        uncertainty_reasons: if protection.is_some() {
            Vec::new()
        } else {
            vec![
                "callback_local_address_lifetime_after_return_requires_confirmation".to_string(),
                "concrete_callback_and_owner_handoff_requires_confirmation".to_string(),
            ]
        },
        provenance: SecurityPathProvenance {
            engine: "mehscan c-family callback-lifetime relationship 1".to_string(),
            maximum_propagation_depth: 2,
        },
    }
}

fn direct_member(text: &str) -> Option<(String, String)> {
    let compact = text
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    let (owner, member) = compact.split_once("->")?;
    (!owner.contains(['.', '-'])
        && !member.contains("->")
        && simple_identifier(owner).is_some()
        && simple_identifier(member).is_some())
    .then(|| (owner.to_string(), member.to_string()))
}
fn member_chain(text: &str) -> Option<(String, String, String)> {
    let compact = text
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    let mut parts = compact.split("->");
    let value = (
        parts.next()?.to_string(),
        parts.next()?.to_string(),
        parts.next()?.to_string(),
    );
    parts.next().is_none().then_some(value)
}
fn addressed_identifier(text: &str) -> Option<String> {
    let compact = text
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '(' | ')'))
        .collect::<String>();
    simple_identifier(compact.strip_prefix('&')?).map(str::to_string)
}
fn contains_address_of(text: &str, name: &str) -> bool {
    text.chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '(' | ')'))
        .collect::<String>()
        == format!("&{name}")
}
fn declaration_declares(node: &Node<'_, StrDoc<SupportLang>>, name: &str) -> bool {
    node.dfs()
        .any(|child| child.kind().as_ref() == "identifier" && child.text().trim() == name)
}
fn function_name(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let declarator = node.field("declarator")?;
    declarator
        .dfs()
        .find(|child| child.kind().as_ref() == "identifier")
        .map(|child| child.text().into_owned())
}
fn alias_initializer(function: &Node<'_, StrDoc<SupportLang>>, alias: &str) -> Option<String> {
    function
        .dfs()
        .filter(|node| node.kind().as_ref() == "init_declarator")
        .find_map(|node| {
            let declarator = node.field("declarator")?;
            (declarator.text().trim() == alias
                || declarator.dfs().any(|child| {
                    child.kind().as_ref() == "identifier" && child.text().trim() == alias
                }))
            .then(|| simple_identifier(node.field("value")?.text().trim()).map(str::to_string))
            .flatten()
        })
}
fn named_arguments<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    call.field("arguments")
        .map(|args| args.children().filter(|child| child.is_named()).collect())
        .unwrap_or_default()
}
fn simple_identifier(value: &str) -> Option<&str> {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        .then_some(())?;
    chars
        .all(|c| c == '_' || c.is_ascii_alphanumeric())
        .then_some(value)
}
fn identifiers(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(|c: char| c != '_' && !c.is_ascii_alphanumeric())
        .filter(|token| simple_identifier(token).is_some())
}
fn contains_identifier(text: &str, name: &str) -> bool {
    identifiers(text).any(|candidate| candidate == name)
}
fn capture_text<'a>(evidence: &'a Evidence, name: &str) -> Option<&'a str> {
    evidence.captures.get(name).map(|item| item.text.as_str())
}
fn by_capability(evidence: &[Evidence], capability: Capability) -> Vec<Evidence> {
    evidence
        .iter()
        .filter(|item| item.capability == capability)
        .cloned()
        .collect()
}
fn cwes() -> Vec<String> {
    vec![
        "CWE-416".to_string(),
        "CWE-562".to_string(),
        "CWE-825".to_string(),
    ]
}
fn is_excluded(evidence: &Evidence) -> bool {
    evidence
        .context
        .availability
        .as_ref()
        .is_some_and(|a| a.state == AvailabilityState::Excluded)
}
fn same_c_family_language(left: &str, right: &str) -> bool {
    fn family(path: &str) -> Option<bool> {
        match path.rsplit_once('.')?.1.to_ascii_lowercase().as_str() {
            "c" => Some(false),
            "cc" | "cpp" | "cxx" | "c++" | "hpp" | "hh" | "hxx" => Some(true),
            _ => None,
        }
    }
    match (family(left), family(right)) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    }
}
fn evidence_context<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> EvidenceContext {
    EvidenceContext {
        comment: comments.is_in_comment(node.range()),
        reachability: Some(reachability::classify(node, literals)),
        availability: Some(conditional.availability_for(node.range())),
        literals: BTreeMap::new(),
        secret: None,
        value_transform: None,
        http_routes: Vec::new(),
        resource_policy: None,
        runtime_environment: None,
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
    let s = node.start_pos();
    let e = node.end_pos();
    Location {
        path: path.to_string(),
        start: Position {
            line: s.line() + 1,
            column: s.column(node) + 1,
            byte_offset: node.range().start,
        },
        end: Position {
            line: e.line() + 1,
            column: e.column(node) + 1,
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
    steps: &[SecurityPathStep],
) -> String {
    let mut input = format!("{}\0{}\0{state:?}", source.id, sink.id);
    for step in steps {
        input.push_str(&format!(
            "\0{:?}\0{}\0{}",
            step.kind, step.location.start.byte_offset, step.location.end.byte_offset
        ));
    }
    stable_id("path", &input)
}
fn stable_id(prefix: &str, input: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{prefix}-{hash:016x}")
}
fn step(kind: SecurityPathStepKind, evidence: &Evidence) -> SecurityPathStep {
    SecurityPathStep {
        kind,
        location: evidence.location.clone(),
        evidence_id: Some(evidence.id.clone()),
        symbol: evidence.enclosing_symbol.clone(),
    }
}
