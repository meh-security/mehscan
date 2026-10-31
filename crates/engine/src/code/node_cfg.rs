//! Opt-in local CFG experiment. Observations only: never closes a review.
//! No heap, interprocedural propagation, exception graph or path enumeration.
use super::{literals::LiteralEnvironment, matcher::location};
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{Capability, Capture, Evidence, EvidenceKind, Language, LiteralValue};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::Range;
use std::sync::OnceLock;

type N<'a> = Node<'a, StrDoc<SupportLang>>;
const MAX_NODES: usize = 384;
const MAX_LOCALS: usize = 64;
const MAX_STEPS: usize = 4096;
const MAX_DEFINITIONS: usize = 4;

fn function(n: &N<'_>) -> bool {
    matches!(
        n.kind().as_ref(),
        "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "method_definition"
            | "generator_function"
            | "generator_function_declaration"
    )
}
fn owner<'a>(n: &N<'a>) -> Option<N<'a>> {
    n.ancestors().find(function)
}
fn children<'a>(n: &N<'a>) -> Vec<N<'a>> {
    n.children()
        .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
        .collect()
}
fn peel<'a>(mut n: N<'a>) -> N<'a> {
    while matches!(
        n.kind().as_ref(),
        "parenthesized_expression" | "as_expression" | "type_assertion" | "non_null_expression"
    ) {
        let Some(inner) = children(&n).first().cloned() else {
            break;
        };
        n = inner;
    }
    n
}

struct Step<'a> {
    node: Option<N<'a>>,
    edges: Vec<usize>,
    condition: bool,
}
#[derive(Clone, Copy)]
struct Loop {
    exit: usize,
    again: usize,
}
struct Graph<'a> {
    steps: Vec<Step<'a>>,
    entry: usize,
}
impl<'a> Graph<'a> {
    fn push(
        &mut self,
        node: Option<N<'a>>,
        edges: Vec<usize>,
        condition: bool,
    ) -> Result<usize, &'static str> {
        if self.steps.len() == MAX_NODES {
            return Err("node_budget");
        }
        self.steps.push(Step {
            node,
            edges,
            condition,
        });
        Ok(self.steps.len() - 1)
    }
    fn statement(
        &mut self,
        n: N<'a>,
        next: usize,
        lp: Option<Loop>,
        depth: usize,
    ) -> Result<usize, &'static str> {
        if depth > 32 {
            return Err("nesting_budget");
        }
        match n.kind().as_ref() {
            "statement_block" => {
                let mut entry = next;
                for child in children(&n).into_iter().rev() {
                    entry = self.statement(child, entry, lp, depth + 1)?;
                }
                Ok(entry)
            }
            "if_statement" => {
                let condition = n.field("condition").ok_or("missing_condition")?;
                let yes = self.statement(
                    n.field("consequence").ok_or("missing_branch")?,
                    next,
                    lp,
                    depth + 1,
                )?;
                let no = if let Some(alt) = n.field("alternative") {
                    self.statement(alt, next, lp, depth + 1)?
                } else {
                    next
                };
                let literal = peel(condition.clone());
                let edges = match literal.kind().as_ref() {
                    "true" => vec![yes],
                    "false" => vec![no],
                    _ => vec![yes, no],
                };
                self.push(Some(condition), edges, true)
            }
            "else_clause" => self.statement(
                children(&n).into_iter().next().ok_or("missing_else")?,
                next,
                lp,
                depth + 1,
            ),
            "while_statement" | "do_statement" | "for_statement" => {
                let condition = n.field("condition");
                let header = self.push(condition.clone(), vec![], true)?;
                let again = if let Some(update) = n.field("increment") {
                    self.push(Some(update), vec![header], false)?
                } else {
                    header
                };
                let body = self.statement(
                    n.field("body").ok_or("missing_loop")?,
                    again,
                    Some(Loop { exit: next, again }),
                    depth + 1,
                )?;
                let known = condition
                    .as_ref()
                    .map(|c| peel(c.clone()).kind().into_owned());
                self.steps[header].edges = match known.as_deref() {
                    Some("true") | None => vec![body],
                    Some("false") => vec![next],
                    _ => vec![body, next],
                };
                let entry = if n.kind().as_ref() == "do_statement" {
                    body
                } else {
                    header
                };
                if let Some(init) = n.field("initializer") {
                    self.push(Some(init), vec![entry], false)
                } else {
                    Ok(entry)
                }
            }
            "return_statement" | "throw_statement" => self.push(Some(n), vec![], false),
            "break_statement" => self.push(Some(n), vec![lp.ok_or("nonloop_break")?.exit], false),
            "continue_statement" => {
                self.push(Some(n), vec![lp.ok_or("nonloop_continue")?.again], false)
            }
            "try_statement" | "switch_statement" | "labeled_statement" | "with_statement"
            | "for_in_statement" => Err("unsupported_control"),
            _ => self.push(Some(n), vec![next], false),
        }
    }
    fn reaches(&self, start: usize, target: usize, blocked: Option<usize>) -> bool {
        let mut seen = BTreeSet::new();
        let mut todo = vec![start];
        while let Some(i) = todo.pop() {
            if Some(i) == blocked || !seen.insert(i) {
                continue;
            }
            if i == target {
                return true;
            }
            todo.extend(&self.steps[i].edges);
        }
        false
    }
}

#[derive(Clone)]
struct Local {
    name: String,
    scope: Range<usize>,
    usable: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Value {
    literal: LiteralValue,
    definitions: BTreeMap<usize, Range<usize>>,
}
type State = Vec<Option<Value>>; // None = unknown; absent incoming state = unreachable.
fn join(a: &Option<Value>, b: &Option<Value>) -> Option<Value> {
    let (Some(a), Some(b)) = (a, b) else {
        return None;
    };
    if a.literal != b.literal {
        return None;
    }
    let mut value = a.clone();
    value.definitions.extend(b.definitions.clone());
    (value.definitions.len() <= MAX_DEFINITIONS).then_some(value)
}
struct Analysis<'a> {
    graph: Graph<'a>,
    locals: Vec<Local>,
    incoming: Vec<Option<State>>,
    predicates: BTreeMap<String, (Range<usize>, Range<usize>, BTreeSet<String>)>,
}
#[derive(Default)]
struct Outcome {
    literal: Option<Value>,
    guards: Vec<(Range<usize>, bool)>,
    unreachable: bool,
    guards_cut: bool,
    predicate_definitions: BTreeMap<usize, Range<usize>>,
    operand_related: BTreeSet<usize>,
}

// Source association for choosing context, not a value/taint/sanitizer proof.
fn identifiers(n: &N<'_>) -> BTreeSet<String> {
    n.dfs()
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "identifier" | "shorthand_property_identifier"
            )
        })
        .map(|n| n.text().into_owned())
        .collect()
}

fn written<'a>(n: &N<'a>) -> Option<N<'a>> {
    match n.kind().as_ref() {
        "assignment_expression" | "augmented_assignment_expression" => n.field("left"),
        "update_expression" => n.field("argument"),
        _ => None,
    }
}
fn local_index(locals: &[Local], n: &N<'_>) -> Option<usize> {
    if n.kind().as_ref() != "identifier" {
        return None;
    }
    locals
        .iter()
        .position(|l| l.usable && l.name == n.text().as_ref() && l.scope.contains(&n.range().start))
}
fn havoc(n: &N<'_>, state: &mut State, locals: &[Local]) {
    for target in n.dfs().filter_map(|n| written(&n)) {
        kill(&target, state, locals);
    }
}
fn kill(n: &N<'_>, state: &mut State, locals: &[Local]) {
    let mut names = Vec::new();
    super::node_identity::bound_names(n, &mut names);
    for name in names {
        for (i, l) in locals.iter().enumerate() {
            if l.name == name && l.scope.contains(&n.range().start) {
                state[i] = None;
            }
        }
    }
}
fn value<'a>(
    n: &N<'a>,
    state: &State,
    locals: &[Local],
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
) -> Option<Value> {
    let n = peel(n.clone());
    if let Some(i) = local_index(locals, &n) {
        return state[i].clone();
    }
    if !matches!(
        n.kind().as_ref(),
        "string" | "number" | "true" | "false" | "null"
    ) {
        return None;
    }
    let literal = literals.evaluate(&n).value?;
    Some(Value {
        literal,
        definitions: BTreeMap::from([(n.range().start, n.range())]),
    })
}
fn assign<'a>(
    target: &N<'a>,
    rhs: Option<N<'a>>,
    node: &N<'a>,
    state: &mut State,
    locals: &[Local],
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
) {
    let evaluated = rhs
        .as_ref()
        .and_then(|rhs| value(rhs, state, locals, literals));
    if let Some(rhs) = rhs {
        havoc(&rhs, state, locals);
    }
    if let Some(i) = local_index(locals, target) {
        state[i] = evaluated.and_then(|mut v| {
            v.definitions.insert(node.range().start, node.range());
            (v.definitions.len() <= MAX_DEFINITIONS).then_some(v)
        });
    } else {
        kill(target, state, locals);
    }
}
fn transfer<'a>(
    n: &N<'a>,
    state: &mut State,
    locals: &[Local],
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
) {
    match n.kind().as_ref() {
        "lexical_declaration" | "variable_declaration" => {
            for d in children(n)
                .into_iter()
                .filter(|d| d.kind().as_ref() == "variable_declarator")
            {
                if let Some(target) = d.field("name") {
                    assign(&target, d.field("value"), &d, state, locals, literals);
                }
            }
        }
        "expression_statement" => {
            if let Some(expr) = children(n).first() {
                transfer(expr, state, locals, literals);
            }
        }
        "assignment_expression" => {
            if let Some(target) = n.field("left") {
                assign(&target, n.field("right"), n, state, locals, literals);
            }
        }
        _ => havoc(n, state, locals),
    }
}

impl<'a> Analysis<'a> {
    fn build(
        function_node: &N<'a>,
        literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    ) -> Result<Self, &'static str> {
        Self::build_region(
            function_node,
            function_node.field("body").ok_or("missing_body")?,
            literals,
        )
    }
    fn build_region(
        function_node: &N<'a>,
        body: N<'a>,
        literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    ) -> Result<Self, &'static str> {
        if function_node.range().len() > 65_536 {
            return Err("function_bytes");
        }
        let own = function_node.range();
        // A nested direct eval can mutate enclosing locals without spelling
        // their names in its AST. Do not assume that a closure is read-only.
        if function_node.dfs().any(|n| {
            n.kind().as_ref() == "call_expression"
                && n.field("function")
                    .is_some_and(|f| f.text().trim() == "eval")
        }) {
            return Err("unsupported_control");
        }
        for n in body
            .dfs()
            .filter(|n| owner(n).is_some_and(|p| p.range() == own))
        {
            if n.is_missing()
                || n.kind().as_ref() == "ERROR"
                || matches!(
                    n.kind().as_ref(),
                    "yield_expression"
                        | "with_statement"
                        | "try_statement"
                        | "switch_statement"
                        | "labeled_statement"
                        | "for_in_statement"
                )
                || n.kind().as_ref() == "call_expression"
                    && n.field("function")
                        .is_some_and(|f| f.text().trim() == "eval")
                || matches!(n.kind().as_ref(), "break_statement" | "continue_statement")
                    && n.field("label").is_some()
            {
                return Err("unsupported_control");
            }
        }
        let mut locals = Vec::new();
        let mut blocked = Vec::new();
        let parameters = function_node
            .field("parameters")
            .map(|p| children(&p))
            .unwrap_or_else(|| function_node.field("parameter").into_iter().collect());
        for p in parameters {
            let name = p.field("pattern").or_else(|| p.field("name")).unwrap_or(p);
            if name.kind().as_ref() == "identifier" {
                locals.push(Local {
                    name: name.text().into_owned(),
                    scope: own.clone(),
                    usable: true,
                });
            } else {
                super::node_identity::bound_names(&name, &mut blocked);
            }
        }
        if function_node
            .dfs()
            .any(|n| n.kind().as_ref() == "identifier" && n.text().as_ref() == "arguments")
        {
            // Sloppy JS arguments can alias parameters. Do not assume strict mode.
            blocked.extend(locals.iter().map(|l| l.name.clone()));
        }
        for d in function_node.dfs().filter(|n| {
            n.kind().as_ref() == "variable_declarator" && owner(n).is_some_and(|p| p.range() == own)
        }) {
            if let Some(name) = d
                .field("name")
                .filter(|n| n.kind().as_ref() == "identifier")
            {
                let is_var = d
                    .parent()
                    .is_some_and(|p| p.kind().as_ref() == "variable_declaration");
                let scope = if is_var {
                    own.clone()
                } else {
                    d.ancestors()
                        .find(|p| {
                            matches!(
                                p.kind().as_ref(),
                                "statement_block" | "for_statement" | "for_in_statement"
                            )
                        })
                        .map(|p| p.range())
                        .unwrap_or(own.clone())
                };
                locals.push(Local {
                    name: name.text().into_owned(),
                    scope,
                    usable: true,
                });
            }
        }
        if locals.len() > MAX_LOCALS {
            return Err("local_budget");
        }
        for n in function_node
            .dfs()
            .filter(|n| owner(n).is_some_and(|p| p.range() == own))
        {
            if n.kind().as_ref() == "variable_declarator" {
                if let Some(name) = n
                    .field("name")
                    .filter(|n| n.kind().as_ref() != "identifier")
                {
                    super::node_identity::bound_names(&name, &mut blocked);
                }
            } else if matches!(
                n.kind().as_ref(),
                "function_declaration" | "class_declaration"
            ) {
                if let Some(name) = n.field("name") {
                    blocked.push(name.text().into_owned());
                }
            }
        }
        let mut counts = BTreeMap::new();
        for local in &locals {
            *counts.entry(local.name.clone()).or_insert(0usize) += 1;
        }
        for local in &mut locals {
            let captured = function_node.dfs().any(|n| {
                matches!(
                    n.kind().as_ref(),
                    "identifier" | "shorthand_property_identifier"
                ) && n.text().as_ref() == local.name
                    && owner(&n).is_some_and(|p| p.range() != own)
            });
            local.usable = counts[&local.name] == 1 && !captured && !blocked.contains(&local.name);
        }
        let mut predicates = BTreeMap::new();
        for d in function_node.dfs().filter(|n| {
            n.kind().as_ref() == "variable_declarator" && owner(n).is_some_and(|p| p.range() == own)
        }) {
            let Some(name) = d
                .field("name")
                .filter(|n| n.kind().as_ref() == "identifier")
            else {
                continue;
            };
            let Some(value) = d.field("value") else {
                continue;
            };
            // Only unique const bindings. Include a callback's source references
            // for inspection; this does not claim the callback executes or is pure.
            if !d
                .parent()
                .is_some_and(|p| p.text().trim_start().starts_with("const "))
                || d.range().len() > 2048
                || counts.get(name.text().as_ref()) != Some(&1)
            {
                continue;
            }
            let Some(local) = locals.iter().find(|l| l.name == name.text().as_ref()) else {
                continue;
            };
            predicates.insert(
                name.text().into_owned(),
                (local.scope.clone(), d.range(), identifiers(&value)),
            );
        }
        let mut graph = Graph {
            steps: vec![],
            entry: 0,
        };
        let exit = graph.push(None, vec![], false)?;
        let body = graph.statement(body, exit, None, 0)?;
        graph.entry = graph.push(None, vec![body], false)?;
        let mut incoming = vec![None; graph.steps.len()];
        incoming[graph.entry] = Some(vec![None; locals.len()]);
        let mut todo = VecDeque::from([graph.entry]);
        let mut count = 0;
        while let Some(i) = todo.pop_front() {
            count += 1;
            if count > MAX_STEPS {
                return Err("fixed_point_budget");
            }
            let mut out = incoming[i].clone().unwrap();
            if let Some(n) = &graph.steps[i].node {
                if graph.steps[i].condition {
                    havoc(n, &mut out, &locals);
                } else {
                    transfer(n, &mut out, &locals, literals);
                }
            }
            for &next in &graph.steps[i].edges {
                let merged = if let Some(old) = &incoming[next] {
                    old.iter().zip(&out).map(|(a, b)| join(a, b)).collect()
                } else {
                    out.clone()
                };
                if incoming[next].as_ref() != Some(&merged) {
                    incoming[next] = Some(merged);
                    todo.push_back(next);
                }
            }
        }
        Ok(Self {
            graph,
            locals,
            incoming,
            predicates,
        })
    }
    fn outcome(&self, at: usize, operand: Option<&str>) -> Outcome {
        let Some((sink, step)) = self
            .graph
            .steps
            .iter()
            .enumerate()
            .filter(|(_, s)| s.node.as_ref().is_some_and(|n| n.range().contains(&at)))
            .min_by_key(|(_, s)| s.node.as_ref().unwrap().range().len())
        else {
            return Outcome::default();
        };
        let Some(state) = &self.incoming[sink] else {
            return Outcome {
                unreachable: true,
                ..Outcome::default()
            };
        };
        let mut outcome = Outcome::default();
        if let Some(name) = operand {
            if let Some(i) = self
                .locals
                .iter()
                .position(|l| l.usable && l.name == name && l.scope.contains(&at))
            {
                let writes_here = step
                    .node
                    .as_ref()
                    .unwrap()
                    .dfs()
                    .filter_map(|n| written(&n))
                    .any(|n| {
                        n.dfs().any(|id| {
                            id.kind().as_ref() == "identifier" && id.text().as_ref() == name
                        })
                    });
                if !writes_here {
                    outcome.literal = state[i].clone();
                }
            }
        }
        let conditions = self
            .graph
            .steps
            .iter()
            .filter(|s| s.condition && s.edges.len() == 2)
            .count();
        if conditions > 32 {
            outcome.guards_cut = true;
            return outcome;
        }
        for (i, guard) in self
            .graph
            .steps
            .iter()
            .enumerate()
            .filter(|(i, s)| *i != sink && s.condition && s.edges.len() == 2)
        {
            if self.graph.reaches(self.graph.entry, sink, Some(i)) {
                continue;
            }
            let yes = self.graph.reaches(guard.edges[0], sink, None);
            let no = self.graph.reaches(guard.edges[1], sink, None);
            if yes != no {
                outcome
                    .guards
                    .push((guard.node.as_ref().unwrap().range(), yes));
            }
        }
        let mut operand_names = operand
            .and_then(|text| step.node.as_ref()?.dfs().find(|n| n.text().trim() == text))
            .map(|n| identifiers(&n))
            .unwrap_or_default();
        // Shared module constants/callees do not connect two operations. Only
        // same-function bindings participate in this context-ranking heuristic.
        operand_names.retain(|name| {
            self.locals
                .iter()
                .any(|l| l.name == *name && l.scope.contains(&at))
        });
        let mut scores = BTreeMap::new();
        for (range, _) in &outcome.guards {
            let Some(condition) = self
                .graph
                .steps
                .iter()
                .filter_map(|s| s.node.as_ref())
                .find(|n| n.range() == *range)
            else {
                continue;
            };
            let names = identifiers(condition);
            let mut score = usize::from(!names.is_disjoint(&operand_names)) * 2;
            for name in names {
                if let Some((scope, definition, refs)) = self.predicates.get(&name) {
                    if scope.contains(&range.start)
                        && definition.end <= range.start
                        && !refs.is_disjoint(&operand_names)
                    {
                        score = score.max(1);
                        outcome
                            .predicate_definitions
                            .insert(range.start, definition.clone());
                        break;
                    }
                }
            }
            if score > 0 {
                outcome.operand_related.insert(range.start);
            }
            scores.insert(range.start, score);
        }
        outcome.guards.sort_by_key(|(r, _)| {
            (
                std::cmp::Reverse(scores.get(&r.start).copied().unwrap_or(0)),
                std::cmp::Reverse(r.start),
            )
        });
        outcome.guards_cut = outcome.guards.len() > 3;
        outcome.guards.truncate(3);
        outcome
    }

    fn guard_only_outcome(&self, at: usize, operand: Option<&str>) -> Outcome {
        let mut result = self.outcome(at, operand);
        result.literal = None;
        result.unreachable = false;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast_grep_core::AstGrep;
    fn inspect(body: &str) -> Result<Outcome, &'static str> {
        inspect_operand(body, "url")
    }
    fn inspect_operand(body: &str, operand: &str) -> Result<Outcome, &'static str> {
        let source = format!("function f(input:any,flag:boolean){{{body}}}");
        let ast = AstGrep::doc(StrDoc::try_new(&source, SupportLang::TypeScript).unwrap());
        let root = ast.root();
        let literals = LiteralEnvironment::build(&root, Language::Typescript);
        let function = root.dfs().find(super::function).unwrap();
        let analysis = Analysis::build(&function, &literals)?;
        Ok(analysis.outcome(source.rfind("sink(").unwrap(), Some(operand)))
    }
    #[test]
    fn branch_joins_loops_and_mutations_require_a_complete_literal_proof() {
        for body in [
            "let url=input;if(flag)url='fixed';else url='fixed';sink(url);",
            "let a='fixed';let url=a;sink(url);",
            "let url=input;do{url='fixed';}while(flag);sink(url);",
            "let url=input;while(true){url='fixed';break;}sink(url);",
        ] {
            let result = inspect(body).unwrap();
            assert_eq!(
                result.literal.map(|v| v.literal),
                Some(LiteralValue::String("fixed".into())),
                "{body}"
            );
        }
        for body in [
            "let url=input;if(flag)url='fixed';sink(url);",
            "let url=input;if(flag)url='a';else url='b';sink(url);",
            "let url=input;while(flag){url='fixed';}sink(url);",
            "let url=input;for(let i=0;i<2;i++){url='fixed';continue;}sink(url);",
            "let url='fixed';function mutate(){url=input;}invoke(mutate);sink(url);",
            "let url='fixed';{let url=input;sink(url);}",
            "{let url='fixed';}sink(url);",
            "for(let url='fixed';flag;){noop();}sink(url);",
            "let url='fixed';({url}=input);sink(url);",
            "let url='fixed';{const {url}=input;sink(url);}",
            "let url='fixed';{function url(){}sink(url);}",
            "let url='fixed';sink(url=input);",
            "let url=1;url++;sink(url);",
            "input='fixed';arguments[0]=other();let url=input;sink(url);",
        ] {
            assert!(
                inspect(body).unwrap().literal.is_none(),
                "unsound closure: {body}"
            );
        }
    }
    #[test]
    fn required_branch_is_control_placement_not_a_sanitizer_or_same_value_proof() {
        let result = inspect("let url=input;if(!allowed(url))return;sink(url);").unwrap();
        assert_eq!(result.guards.len(), 1);
        assert!(!result.guards[0].1);
        assert!(result.literal.is_none());
        let result = inspect("let url=input;if(flag){sink(url);}").unwrap();
        assert_eq!(result.guards.len(), 1);
        assert!(result.guards[0].1);
        assert!(
            inspect("let url=input;if(flag)check(url);sink(url);")
                .unwrap()
                .guards
                .is_empty()
        );
        let result =
            inspect("let url=input;if(!allowed(input))return;url=other();sink(url);").unwrap();
        assert_eq!(result.guards.len(), 1);
        assert!(result.literal.is_none());
        assert!(inspect("return;sink(url);").unwrap().unreachable);
        assert!(
            inspect("if(true)throw Error();sink(url);")
                .unwrap()
                .unreachable
        );
    }
    #[test]
    fn unsupported_control_and_budgets_fail_without_proofs() {
        assert_eq!(
            inspect("try{throw Error();}catch{sink(url);}").err(),
            Some("unsupported_control")
        );
        assert_eq!(
            inspect("eval(input);sink(url);").err(),
            Some("unsupported_control")
        );
        assert_eq!(
            inspect("let url='fixed';function mutate(){eval(input);}invoke(mutate);sink(url);")
                .err(),
            Some("unsupported_control")
        );
        assert_eq!(
            inspect("switch(input){case 1:break;}sink(url);").err(),
            Some("unsupported_control")
        );
        assert_eq!(
            inspect(&format!("{}sink(url);", "noop();".repeat(MAX_NODES))).err(),
            Some("node_budget")
        );
    }

    #[test]
    fn guard_budget_prefers_operand_context_over_nearby_unrelated_checks() {
        let result = inspect("let url=input;const accepted=[flag].some(x=>validate(url,x));if(!accepted)throw Error();if(a)return;if(b)return;if(c)return;sink(url);").unwrap();
        assert_eq!(result.guards.len(), 3);
        assert!(result.guards_cut);
        assert!(result.operand_related.contains(&result.guards[0].0.start));
        assert!(
            result
                .predicate_definitions
                .contains_key(&result.guards[0].0.start)
        );
        // A source reference is not a pure predicate or same-value proof.
        assert!(result.literal.is_none());
        for body in [
            "let url=input;let accepted=validate(url);accepted=true;if(!accepted)return;if(a)return;if(b)return;if(c)return;sink(url);",
            "let url=input;{const accepted=validate(url);}if(!accepted)return;if(a)return;if(b)return;if(c)return;sink(url);",
        ] {
            assert!(inspect(body).unwrap().predicate_definitions.is_empty());
        }
        let unrelated = inspect_operand("let id=input;const response=dispatch(`${HOST}/delete`);if(!response.ok)return;sink(`${HOST}/${id}`);", "`${HOST}/${id}`").unwrap();
        assert!(unrelated.predicate_definitions.is_empty());
        assert!(unrelated.operand_related.is_empty());
    }

    #[test]
    fn exception_region_provides_local_guards_without_scalar_or_unreachable_proofs() {
        let source = "function f(input,flag){try{let url='fixed';if(!allowed(url))throw Error();sink(url);}catch(e){sink(input);}finally{cleanup();}}";
        let ast = AstGrep::doc(StrDoc::try_new(source, SupportLang::TypeScript).unwrap());
        let root = ast.root();
        let literals = LiteralEnvironment::build(&root, Language::Typescript);
        let function = root.dfs().find(super::function).unwrap();
        assert_eq!(
            Analysis::build(&function, &literals).err(),
            Some("unsupported_control")
        );
        let body = root
            .dfs()
            .find(|n| n.kind().as_ref() == "try_statement")
            .unwrap()
            .field("body")
            .unwrap();
        let analysis = Analysis::build_region(&function, body, &literals).unwrap();
        let result = analysis.guard_only_outcome(source.find("sink(url)").unwrap(), Some("url"));
        assert_eq!(result.guards.len(), 1);
        assert!(!result.guards[0].1);
        assert!(result.literal.is_none() && !result.unreachable);
        // Guard in the try body must not be attributed to catch/finally sinks.
        assert!(
            analysis
                .guard_only_outcome(source.find("sink(input)").unwrap(), Some("input"))
                .guards
                .is_empty()
        );
    }
}

fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("MEHSCAN_EXPERIMENTAL_NODE_CFG").is_ok_and(|s| s == "1"))
}
fn captured(path: &str, root: &N<'_>, range: &Range<usize>) -> Capture {
    let n = root
        .dfs()
        .find(|n| n.range() == *range)
        .expect("CFG locations originate in this AST");
    Capture {
        text: n.text().into_owned(),
        location: location(path, &n),
    }
}
fn role(e: &Evidence) -> Option<&'static str> {
    if e.kind != EvidenceKind::Sink {
        return None;
    }
    match e.capability {
        Capability::OutboundNetworkRequest => Some("endpoint"),
        Capability::DatabaseQuery => Some("query"),
        Capability::ResourceAccess => Some("filter"),
        Capability::FilesystemRead | Capability::FilesystemWrite => Some("path"),
        Capability::ProcessExecution => Some("command"),
        Capability::DynamicCodeExecution => Some("code"),
        Capability::Redirect => Some("location"),
        Capability::BrowserNavigation => Some("destination"),
        _ => None,
    }
}

pub(super) fn emit_if_enabled<'a>(
    path: &str,
    language: Language,
    root: &N<'a>,
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    evidence: &[Evidence],
) {
    if !matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    ) || !enabled()
    {
        return;
    }
    if !evidence.iter().any(|e| role(e).is_some()) {
        return;
    }
    // Keep shadow diagnostics out of native admission and path construction.
    // Context captures are not additional command/destination operands.
    let mut evidence = evidence.to_vec();
    let started = std::time::Instant::now();
    let functions = root.dfs().filter(function).collect::<Vec<_>>();
    let mut cache = BTreeMap::new();
    let mut region_cache = BTreeMap::new();
    let mut regions = BTreeMap::new();
    let mut skipped = BTreeMap::new();
    let (mut guarded, mut literal, mut unreachable) = (0, 0, 0);
    for e in evidence.iter_mut() {
        let Some(role) = role(e) else {
            continue;
        };
        let at = e.location.start.byte_offset;
        let Some(function) = functions
            .iter()
            .filter(|f| f.range().contains(&at))
            .min_by_key(|f| f.range().len())
        else {
            continue;
        };
        let key = (function.range().start, function.range().end);
        let analysis = cache
            .entry(key)
            .or_insert_with(|| Analysis::build(function, literals));
        // Recover only control placement inside an independently supported
        // exception body. Never infer function reachability or scalar closure
        // through catches/finally. Inspect at most three regions per sink.
        let mut region_keys = Vec::new();
        if matches!(analysis, Err("unsupported_control")) {
            let mut candidates = function
                .dfs()
                .filter(|n| {
                    n.kind().as_ref() == "statement_block"
                        && n.range().contains(&at)
                        && owner(n).is_some_and(|p| p.range() == function.range())
                        && n.parent().is_some_and(|p| {
                            matches!(
                                p.kind().as_ref(),
                                "try_statement" | "catch_clause" | "finally_clause"
                            )
                        })
                })
                .collect::<Vec<_>>();
            candidates.sort_by_key(|n| std::cmp::Reverse(n.range().len()));
            for block in candidates.into_iter().take(3) {
                let key = (block.range().start, block.range().end);
                region_cache
                    .entry(key)
                    .or_insert_with(|| Analysis::build_region(function, block, literals));
                region_keys.push(key);
            }
        }
        let region = region_keys
            .iter()
            .find_map(|k| region_cache.get(k)?.as_ref().ok().map(|a| (*k, a)));
        let region_only = region.is_some();
        let analysis = match (analysis, region) {
            (_, Some((bounds, a))) => {
                regions.insert(e.id.clone(), serde_json::json!({"scope":"exception-body-only","start_byte":bounds.0,"end_byte":bounds.1}));
                e.tags.push("local-cfg:guard-region-only".into());
                a
            }
            (Ok(a), _) => a,
            (Err(reason), _) => {
                *skipped.entry(*reason).or_insert(0usize) += 1;
                e.tags.push(format!("local-cfg:unavailable:{reason}"));
                continue;
            }
        };
        let operand = e.captures.get(role).map(|c| c.text.trim());
        let result = if region_only {
            analysis.guard_only_outcome(at, operand)
        } else {
            analysis.outcome(at, operand)
        };
        if result.unreachable {
            e.tags
                .push("local-cfg:unreachable-in-modeled-function".into());
            unreachable += 1;
        }
        if let Some(value) = result.literal {
            e.tags.push("local-cfg:literal-on-all-modeled-paths".into());
            literal += 1;
            for (i, r) in value.definitions.into_values().enumerate() {
                e.captures.insert(
                    format!("local_cfg_literal_{i}_definition"),
                    captured(path, root, &r),
                );
            }
        }
        if !result.guards.is_empty() {
            guarded += 1;
        }
        for (i, (r, yes)) in result.guards.into_iter().enumerate() {
            e.tags.push(format!(
                "local-cfg:guard-{i}:{}-edge-required",
                if yes { "true" } else { "false" }
            ));
            e.captures.insert(
                format!("local_cfg_guard_{i}_definition"),
                captured(path, root, &r),
            );
            if result.operand_related.contains(&r.start) {
                e.tags
                    .push(format!("local-cfg:guard-{i}:operand-reference-context"));
            }
            if let Some(definition) = result.predicate_definitions.get(&r.start) {
                e.captures.insert(
                    format!("local_cfg_guard_{i}_predicate_definition"),
                    captured(path, root, definition),
                );
            }
        }
        if result.guards_cut {
            e.tags.push("local-cfg:guard-budget-partial".into());
        }
        // These facts say nothing about guard policy, resource authority or
        // whether a literal operation is secure. No existing literals change.
    }
    let observations=evidence.iter().filter(|e|e.tags.iter().any(|t|t.starts_with("local-cfg:"))).map(|e|serde_json::json!({
        "id":e.id,
        "region":regions.get(&e.id),
        "tags":e.tags.iter().filter(|t|t.starts_with("local-cfg:")).collect::<Vec<_>>(),
        "captures":e.captures.iter().filter(|(k,_)|k.starts_with("local_cfg_")).collect::<BTreeMap<_,_>>()
    })).collect::<Vec<_>>();
    eprintln!(
        "mehscan_node_cfg {}",
        serde_json::json!({"path":path,"functions":cache.len(),"analyzed":cache.values().filter(|a|a.is_ok()).count(),"analyzed_regions":region_cache.values().filter(|a|a.is_ok()).count(),"nodes":cache.values().filter_map(|a|a.as_ref().ok()).map(|a|a.graph.steps.len()).sum::<usize>(),"region_nodes":region_cache.values().filter_map(|a|a.as_ref().ok()).map(|a|a.graph.steps.len()).sum::<usize>(),"guarded_sinks":guarded,"literal_sinks":literal,"unreachable_sinks":unreachable,"skipped_sinks":skipped,"microseconds":started.elapsed().as_micros(),"observations":observations})
    );
}
