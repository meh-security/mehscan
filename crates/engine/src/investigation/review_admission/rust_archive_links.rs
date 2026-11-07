//! Source witnesses for link-following directory checks and archive writes.
use super::*;
use ast_grep_core::matcher::MatcherExt;
use rust_allocation::method;
use rust_parser_provenance::{arguments, enclosing_function, named, peel, unique};
use rust_receiver_types::{lexical_binding, local_binding};
use rust_shared_state::AstNode as N;

fn same(a: &N<'_>, b: &N<'_>) -> bool {
    a.range() == b.range()
}

fn parameter_index<'a>(function: &N<'a>, value: &N<'a>) -> Option<usize> {
    let binding = local_binding(&peel(value.clone())?, function)?;
    named(&function.field("parameters")?)
        .filter(|n| n.kind().as_ref() == "parameter")
        .position(|n| same(&binding, &n))
}

fn expression<'a>(node: &N<'a>) -> Option<N<'a>> {
    if node.kind().as_ref() == "expression_statement" {
        named(node).next()
    } else {
        Some(node.clone())
    }
}

fn operation<'a>(node: &N<'a>) -> Option<N<'a>> {
    let node = peel(expression(node)?)?;
    (node.kind().as_ref() == "call_expression").then_some(node)
}

fn propagated(node: &N<'_>) -> bool {
    expression(node).is_some_and(|n| n.kind().as_ref() == "try_expression")
}

fn enabled_call<'a>(call: &N<'a>, function: &N<'a>, enabled: &impl Fn(&N<'a>) -> bool) -> bool {
    enabled(call)
        && enclosing_function(call).is_some_and(|owner| same(&owner, function))
        && rust_buffer_initialization::runtime_path(call, function)
}

// Resolve a self call in its own impl, or a lexically visible private free
// helper. Keep alternative cfg implementations separate.
fn definitions<'a>(
    call: &N<'a>,
    function: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> Vec<N<'a>> {
    let matches = |scope: &N<'a>, name: &str| {
        named(scope)
            .filter(|n| {
                n.kind().as_ref() == "function_item"
                    && rust_parser_provenance::private(n)
                    && enabled(n)
                    && n.field("name").is_some_and(|n| n.text() == name)
            })
            .collect::<Vec<_>>()
    };
    if let Some((receiver, name)) = method(call) {
        if receiver.text() != "self" {
            return vec![];
        }
        return function
            .parent()
            .filter(|n| n.parent().is_some_and(|p| p.kind().as_ref() == "impl_item"))
            .and_then(|body| unique(matches(&body, &name).into_iter()))
            .into_iter()
            .collect();
    }
    let Some(callee) = call.field("function") else {
        return vec![];
    };
    if callee.kind().as_ref() != "identifier" || lexical_binding(&callee, function).is_some() {
        return vec![];
    }
    let name = callee.text();
    for scope in call.ancestors().filter(|n| n.kind().as_ref() == "block") {
        if named(&scope).any(|n| n.kind().as_ref() == "use_declaration") {
            return vec![];
        }
        let found = matches(&scope, &name);
        if !found.is_empty() {
            return found;
        }
    }
    rust_parser_provenance::definition(call, function, enabled, 0)
        .filter(rust_parser_provenance::private)
        .into_iter()
        .collect()
}

const DIRECTORY_FALLBACK: &str = "$CREATE($P).or_else(|$ERR| { if $ERR.kind() == $EXISTS { let $PREV = $METADATA($P); if $PREV.map(|$M| $M.is_dir()).unwrap_or(false) { return Ok(()); } } $$$REST })";

fn canonical<'a>(root: &N<'a>, name: &N<'a>, expected: &str) -> bool {
    rust_raw_memory::canonical(root, name, &name.text()).as_deref() == Some(expected)
}

fn path_parameter<'a>(root: &N<'a>, function: &N<'a>, value: &N<'a>) -> Option<usize> {
    let index = parameter_index(function, value)?;
    let mut ty = named(&function.field("parameters")?)
        .filter(|n| n.kind().as_ref() == "parameter")
        .nth(index)?
        .field("type")?;
    if ty.kind().as_ref() == "reference_type" {
        ty = ty.field("type")?;
    }
    (canonical(root, &ty, "std::path::Path") || canonical(root, &ty, "std::path::PathBuf"))
        .then_some(index)
}

fn following_directory<'a>(
    root: &N<'a>,
    function: &N<'a>,
    path_index: usize,
    pattern: &Pattern,
) -> Option<N<'a>> {
    let tail = named(&function.field("body")?).last()?;
    let found = pattern.match_node(tail.clone())?;
    let env = found.get_env();
    (parameter_index(function, env.get_match("P")?)? == path_index
        && canonical(root, env.get_match("CREATE")?, "std::fs::create_dir")
        && canonical(root, env.get_match("METADATA")?, "std::fs::metadata")
        && canonical(
            root,
            env.get_match("EXISTS")?,
            "std::io::ErrorKind::AlreadyExists",
        ))
    .then_some(tail)
}

fn no_handle_arm<'a>(call: &N<'a>, function: &N<'a>, none: usize) -> bool {
    call.ancestors()
        .take_while(|n| !same(n, function))
        .filter(|n| n.kind().as_ref() == "match_arm")
        .any(|arm| {
            let Some(expr) = arm
                .ancestors()
                .find(|n| n.kind().as_ref() == "match_expression")
            else {
                return false;
            };
            arm.field("pattern").is_some_and(|p| p.text() == "None")
                && expr
                    .field("value")
                    .and_then(|n| parameter_index(function, &n))
                    == Some(none)
        })
}

fn permissions_sink<'a>(
    root: &N<'a>,
    function: &N<'a>,
    path: usize,
    none: Option<usize>,
    enabled: &impl Fn(&N<'a>) -> bool,
    depth: usize,
) -> Option<N<'a>> {
    if depth == 0 {
        return None;
    }
    function.field("body")?.dfs().find_map(|call| {
        if call.kind().as_ref() != "call_expression"
            || !enabled_call(&call, function, enabled)
            || call
                .ancestors()
                .take_while(|n| !same(n, function))
                .any(|n| n.kind().as_ref() == "closure_expression")
        {
            return None;
        }
        let args = arguments(&call)?;
        let arg = |wanted| {
            args.iter()
                .position(|n| parameter_index(function, n) == Some(wanted))
        };
        let next = arg(path)?;
        if next == 0
            && rust_raw_memory::api(root, &call).as_deref() == Some("std::fs::set_permissions")
            && none.map_or_else(
                || {
                    !call
                        .ancestors()
                        .take_while(|n| !same(n, function))
                        .any(|n| n.kind().as_ref() == "match_arm")
                },
                |index| no_handle_arm(&call, function, index),
            )
        {
            return Some(call);
        }
        let next_none = none.map(arg).unwrap_or(Some(0))?;
        definitions(&call, function, enabled)
            .into_iter()
            .find_map(|helper| {
                permissions_sink(
                    root,
                    &helper,
                    next,
                    none.map(|_| next_none),
                    enabled,
                    depth - 1,
                )
            })
    })
}

fn directory_permissions<'a>(
    root: &N<'a>,
    statement: &N<'a>,
    pattern: &Pattern,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> Option<[(&'static str, N<'a>); 4]> {
    if !propagated(statement) {
        return None;
    }
    let guard_call = operation(statement)?;
    let function = enclosing_function(&guard_call)?;
    let guard_helper = unique(definitions(&guard_call, &function, enabled).into_iter())?;
    let guard_args = arguments(&guard_call)?;
    let [destination] = guard_args.as_slice() else {
        return None;
    };
    let destination_binding = local_binding(&peel(destination.clone())?, &function)?;
    let guard = following_directory(root, &guard_helper, 0, pattern)?;
    let block = statement
        .parent()
        .filter(|p| p.kind().as_ref() == "block")?;
    if previous_statement(&block, statement).is_some_and(|prior| {
        enabled(&prior) && rejects_final_link(root, &function, &prior, destination).is_some()
    }) {
        return None;
    }
    let next = named(&block).skip_while(|n| !same(n, statement)).nth(1)?;
    let write_call = operation(&next)?;
    if !enabled_call(&guard_call, &function, enabled)
        || !enabled_call(&write_call, &function, enabled)
    {
        return None;
    }
    let args = arguments(&write_call)?;
    let path = args.iter().position(|value| {
        peel(value.clone())
            .and_then(|n| local_binding(&n, &function))
            .is_some_and(|n| same(&n, &destination_binding))
    })?;
    let sink = if path == 0
        && rust_raw_memory::api(root, &write_call).as_deref() == Some("std::fs::set_permissions")
    {
        write_call.clone()
    } else {
        let none = args.iter().position(|n| n.text() == "None");
        unique(definitions(&write_call, &function, enabled).into_iter())
            .and_then(|helper| permissions_sink(root, &helper, path, none, enabled, 4))?
    };
    Some([
        ("following_directory_check", guard),
        ("directory_call", guard_call),
        ("permission_call", write_call),
        ("permission_sink", sink),
    ])
}

fn bound<'a>(function: &N<'a>, a: &N<'a>, b: &N<'a>) -> bool {
    let binding = |n: &N<'a>| {
        peel(n.clone())
            .and_then(|v| local_binding(&v, function))
            .map(|v| v.range())
    };
    binding(a).is_some_and(|r| binding(b) == Some(r))
}

fn previous_statement<'a>(block: &N<'a>, statement: &N<'a>) -> Option<N<'a>> {
    named(block)
        .take_while(|node| node.range().start < statement.range().start)
        .last()
}

fn rejecting_condition<'a>(statement: &N<'a>, exit_kind: &str) -> Option<N<'a>> {
    let branch = expression(statement)?;
    if branch.kind().as_ref() != "if_expression" || branch.field("alternative").is_some() {
        return None;
    }
    let exit = expression(&unique(named(&branch.field("consequence")?))?)?;
    if exit.kind().as_ref() != exit_kind {
        return None;
    }
    // A labelled continue can target a different loop. A nested helper
    // returning is likewise outside this direct-statement check.
    if exit_kind == "continue_expression" && named(&exit).next().is_some() {
        return None;
    }
    branch.field("condition")
}

fn method_receiver<'a>(call: &N<'a>, name: &str) -> Option<N<'a>> {
    let (receiver, actual) = method(call)?;
    (actual == name && arguments(call)?.is_empty()).then_some(receiver)
}

fn fallible_operand<'a>(root: &N<'a>, expression: &N<'a>, api: &str) -> Option<N<'a>> {
    if expression.kind().as_ref() != "try_expression" {
        return None;
    }
    let call = operation(expression)?;
    if rust_raw_memory::api(root, &call).as_deref() != Some(api) {
        return None;
    }
    unique(arguments(&call)?.into_iter())
}

// These controls close the selected sequential link mechanism. Neither
// check establishes safety against concurrent filesystem replacement.
fn rejects_final_link<'a>(
    root: &N<'a>,
    function: &N<'a>,
    statement: &N<'a>,
    destination: &N<'a>,
) -> Option<()> {
    let condition = rejecting_condition(statement, "return_expression")?;
    let file_type = method_receiver(&condition, "is_symlink")?;
    let metadata = method_receiver(&file_type, "file_type")?;
    let selected = fallible_operand(root, &metadata, "std::fs::symlink_metadata")?;
    bound(function, &selected, destination).then_some(())
}

fn confines_parent<'a>(
    root: &N<'a>,
    function: &N<'a>,
    statement: &N<'a>,
    destination: &N<'a>,
    base: &N<'a>,
) -> Option<()> {
    let condition = rejecting_condition(statement, "continue_expression")?;
    if condition.kind().as_ref() != "unary_expression" || !condition.text().starts_with('!') {
        return None;
    }
    let check = peel(unique(named(&condition))?)?;
    let (parent, method_name) = method(&check)?;
    if method_name != "starts_with" {
        return None;
    }
    let root_arg = unique(arguments(&check)?.into_iter())?;
    let root_arg = fallible_operand(root, &root_arg, "std::fs::canonicalize")?;
    let parent = fallible_operand(root, &parent, "std::fs::canonicalize")?;
    let parent = method_receiver(&parent, "unwrap")?;
    let child = method_receiver(&parent, "parent")?;
    (bound(function, &root_arg, base) && bound(function, &child, destination)).then_some(())
}

fn compact_is(node: &N<'_>, expected: &str) -> bool {
    rust_shared_state::compact(&node.text()) == expected
}

fn arm_pattern<'a>(arm: &N<'a>) -> Option<N<'a>> {
    let pattern = arm.field("pattern")?;
    if pattern.kind().as_ref() == "match_pattern" {
        unique(named(&pattern))
    } else {
        Some(pattern)
    }
}

fn tuple_binding<'a>(pattern: &N<'a>, variant: &str) -> Option<N<'a>> {
    if pattern.kind().as_ref() != "tuple_struct_pattern" {
        return None;
    }
    let ty = pattern.field("type")?;
    if ty.text() != variant {
        return None;
    }
    unique(named(pattern).filter(|n| !same(n, &ty)))
}

fn following_parent<'a>(
    root: &N<'a>,
    helper: &N<'a>,
    path: usize,
    base: Option<usize>,
) -> Option<N<'a>> {
    let branch = expression(&named(&helper.field("body")?).next()?)?;
    let condition = branch.field("condition")?;
    let tests: Vec<_> = if condition.kind().as_ref() == "let_chain" {
        named(&condition).collect()
    } else {
        vec![condition]
    };
    let parent = tests.first()?.field("pattern")?;
    let parent = tuple_binding(&parent, "Some")?;
    let parent_name = parent.text();
    let (receiver, name) = method(&tests[0].field("value")?)?;
    if name != "parent" || path_parameter(root, helper, &receiver)? != path {
        return None;
    }
    match tests.as_slice() {
        [_] => (),
        [_, test]
            if test.kind().as_ref() == "binary_expression"
                && test.field("operator").is_some_and(|n| n.text() == "!=")
                && test.field("left").is_some_and(|n| n.text() == parent_name)
                && test
                    .field("right")
                    .and_then(|n| parameter_index(helper, &n))
                    == base
                && base.is_some() =>
        {
            ()
        }
        _ => return None,
    }
    let guard = expression(&named(&branch.field("consequence")?).next()?)?;
    if guard.kind().as_ref() != "match_expression" {
        return None;
    }
    let call = guard.field("value")?;
    let parent_arg = unique(arguments(&call)?.into_iter())?;
    let first_arm = named(&guard.field("body")?).next()?;
    (parent_arg.text() == parent_name
        && rust_raw_memory::api(root, &call).as_deref() == Some("std::fs::create_dir_all")
        && compact_is(&arm_pattern(&first_arm)?, "Ok(_)")
        && compact_is(&first_arm.field("value")?, "returnOk(())"))
    .then_some(guard)
}

fn entry_value<'a>(
    function: &N<'a>,
    value: N<'a>,
    entry: &N<'a>,
    field: &str,
    depth: usize,
) -> bool {
    if depth == 0 {
        return false;
    }
    let Some(value) = peel(value) else {
        return false;
    };
    let follows = |value| entry_value(function, value, entry, field, depth - 1);
    if value.kind().as_ref() == "identifier" {
        return local_binding(&value, function)
            .and_then(|n| n.field("value"))
            .is_some_and(follows);
    }
    if value.kind().as_ref() == "if_expression" {
        return value
            .field("alternative")
            .is_some_and(|n| rust_shared_state::compact(&n.text()) == "else{None}")
            && value
                .field("consequence")
                .and_then(|n| unique(named(&n)))
                .is_some_and(follows);
    }
    let Some((receiver, name)) = method(&value) else {
        return false;
    };
    if name == field && arguments(&value).is_some_and(|a| a.is_empty()) {
        return bound(function, &receiver, entry);
    }
    match name.as_str() {
        "map_err" | "ok_or_else" | "into_owned" => follows(receiver),
        "map" => {
            arguments(&value).is_some_and(|args| {
                let [closure] = args.as_slice() else {
                    return false;
                };
                let Some(parameter) = closure.field("parameters").and_then(|n| unique(named(&n)))
                else {
                    return false;
                };
                closure
                    .field("body")
                    .and_then(|n| method(&n))
                    .is_some_and(|(object, method)| {
                        object.text() == parameter.text() && method == "into_owned"
                    })
            }) && follows(receiver)
        }
        _ => false,
    }
}

fn lexical_entry_path<'a>(
    root: &N<'a>,
    function: &N<'a>,
    value: N<'a>,
    entry: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> bool {
    if entry_value(function, value.clone(), entry, "path", 8) {
        return true;
    }
    // The selected Option value must be returned unchanged from a helper
    // that builds it from the input's path components.
    let Some(value) = peel(value)
        .and_then(|v| local_binding(&v, function))
        .and_then(|b| b.field("value"))
    else {
        return false;
    };
    if value.kind().as_ref() != "match_expression" {
        return false;
    }
    let Some(arms) = value.field("body") else {
        return false;
    };
    let arms: Vec<_> = named(&arms).collect();
    let [success, rejection] = arms.as_slice() else {
        return false;
    };
    let Some(binding) = arm_pattern(success).and_then(|n| tuple_binding(&n, "Some")) else {
        return false;
    };
    if !success
        .field("value")
        .is_some_and(|n| n.text() == binding.text())
        || !arm_pattern(rejection).is_some_and(|n| n.text() == "None")
        || !rejection
            .field("value")
            .and_then(|n| named(&n).last())
            .and_then(|n| expression(&n))
            .is_some_and(|n| compact_is(&n, "continue"))
    {
        return false;
    }
    let Some(call) = value.field("value") else {
        return false;
    };
    let Some(arg) = arguments(&call).and_then(|v| unique(v.into_iter())) else {
        return false;
    };
    if !entry_value(function, arg, entry, "path", 8) {
        return false;
    }
    unique(definitions(&call, function, enabled).into_iter())
        .is_some_and(|helper| lexical_components(root, &helper).is_some())
}

fn lexical_components<'a>(root: &N<'a>, helper: &N<'a>) -> Option<()> {
    let body = helper.field("body")?;
    let items: Vec<_> = named(&body).collect();
    let [parts, iteration, result] = items.as_slice() else {
        return None;
    };
    let accumulator = parts.field("pattern")?;
    let iteration = expression(iteration)?;
    let (path, name) = method(&iteration.field("value")?)?;
    if name != "components" || path_parameter(root, helper, &path)? != 0 {
        return None;
    }
    let dispatch = expression(&unique(named(&iteration.field("body")?))?)?;
    if dispatch.field("value")?.text() != iteration.field("pattern")?.text() {
        return None;
    }
    let body = dispatch.field("body")?;
    let mut normal = false;
    for arm in named(&body) {
        let value = arm.field("value")?;
        let pattern = arm_pattern(&arm)?;
        let Some(variant) = pattern.field("type") else {
            if compact_is(&value, "continue")
                || compact_is(&value, "{}")
                || compact_is(&value, &format!("{{{}.pop()?;}}", accumulator.text()))
            {
                continue;
            }
            return None;
        };
        if normal || !canonical(root, &variant, "std::path::Component::Normal") {
            return None;
        }
        let binding = tuple_binding(&pattern, &variant.text())?;
        let (receiver, name) = method(&value)?;
        let argument = unique(arguments(&value)?.into_iter())?;
        let (component, convert) = method(&argument)?;
        if receiver.text() != accumulator.text()
            || name != "push"
            || convert != "to_os_string"
            || component.text() != binding.text()
        {
            return None;
        }
        normal = true;
    }
    (normal
        && compact_is(
            result,
            &format!("Some({}.into_iter().collect())", accumulator.text()),
        ))
    .then_some(())
}

fn symlink_sink<'a>(
    root: &N<'a>,
    call: &N<'a>,
    function: &N<'a>,
    target: usize,
    path: usize,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> Option<N<'a>> {
    if rust_raw_memory::api(root, call).as_deref() == Some("std::os::unix::fs::symlink") {
        return (target == 0 && path == 1).then(|| call.clone());
    }
    let helper = unique(definitions(call, function, enabled).into_iter())?;
    helper.field("body")?.dfs().find(|candidate| {
        rust_raw_memory::api(root, candidate).as_deref() == Some("std::os::unix::fs::symlink")
            && enabled_call(candidate, &helper, enabled)
            && arguments(candidate).is_some_and(|a| {
                a.len() == 2
                    && parameter_index(&helper, &a[0]) == Some(target)
                    && parameter_index(&helper, &a[1]) == Some(path)
            })
    })
}

fn written_entry<'a>(
    root: &N<'a>,
    writer: &N<'a>,
    entry: usize,
    destination: usize,
    file: &str,
    evidence: &[&Evidence],
    enabled: &impl Fn(&N<'a>) -> bool,
) -> Option<N<'a>> {
    let body = writer.field("body")?;
    for copy in body
        .dfs()
        .filter(|n| n.kind().as_ref() == "call_expression")
    {
        if rust_raw_memory::api(root, &copy).as_deref() != Some("std::io::copy")
            || !enabled_call(&copy, writer, enabled)
        {
            continue;
        }
        let Some(args) = arguments(&copy) else {
            continue;
        };
        let [input, output] = args.as_slice() else {
            continue;
        };
        if parameter_index(writer, input) != Some(entry) {
            continue;
        }
        let Some(output) = peel(output.clone())
            .and_then(|n| local_binding(&n, writer))
            .and_then(|n| n.field("value"))
        else {
            continue;
        };
        let Some(mut open) = peel(output) else {
            continue;
        };
        if let Some((receiver, name)) = method(&open)
            && name == "map_err"
        {
            open = receiver;
        }
        if enabled_call(&open, writer, enabled) {
            if evidence.iter().any(|e| {
                e.location.path == file
                    && e.location.start.byte_offset == open.range().start
                    && e.location.end.byte_offset == open.range().end
            }) && arguments(&open).is_some_and(|args| {
                args.len() == 1 && parameter_index(writer, &args[0]) == Some(destination)
            }) {
                return Some(open);
            }
        }
    }
    None
}

fn branch_calls<'a>(arm: &N<'a>) -> Vec<N<'a>> {
    let Some(body) = arm.field("value") else {
        return vec![];
    };
    if body.kind().as_ref() == "block" {
        named(&body).filter_map(|n| operation(&n)).collect()
    } else {
        operation(&body).into_iter().collect()
    }
}

fn archive_parent_write<'a>(
    root: &N<'a>,
    dispatch: &N<'a>,
    file: &str,
    evidence: &[&Evidence],
    enabled: &impl Fn(&N<'a>) -> bool,
) -> Option<[(&'static str, N<'a>); 7]> {
    let function = enclosing_function(dispatch)?;
    let loop_node = dispatch
        .ancestors()
        .find(|n| n.kind().as_ref() == "for_expression")?;
    if !rust_archive::tar_entries(root, &loop_node.field("value")?, &function, 0) {
        return None;
    }
    let discriminant = peel(dispatch.field("value")?)?;
    let kind = local_binding(&discriminant, &function)?.field("value")?;
    let (header, method_name) = method(&kind)?;
    let (entry, header_method) = method(&header)?;
    if method_name != "entry_type"
        || header_method != "header"
        || !rust_archive::tar_entry(root, &entry, &function, 0)
    {
        return None;
    }
    let arms = dispatch.field("body")?;
    let variant = |arm: &N<'a>, variant: &str| {
        arm.field("pattern").is_some_and(|p| {
            p.dfs()
                .any(|n| n.kind().as_ref() == "scoped_identifier" && canonical(root, &n, variant))
        })
    };
    let regular = unique(named(&arms).filter(|a| variant(a, "tar::EntryType::Regular")))?;
    let link = unique(named(&arms).filter(|a| variant(a, "tar::EntryType::Symlink")))?;
    for write_call in branch_calls(&regular) {
        let Some(args) =
            arguments(&write_call).filter(|_| enabled_call(&write_call, &function, enabled))
        else {
            continue;
        };
        let Some(entry_index) = args.iter().position(|n| bound(&function, n, &entry)) else {
            continue;
        };
        let Some(writer) = unique(definitions(&write_call, &function, enabled).into_iter()) else {
            continue;
        };
        for (path_index, destination) in args.iter().enumerate().filter(|(i, _)| *i != entry_index)
        {
            let Some(join) = peel(destination.clone())
                .and_then(|n| local_binding(&n, &function))
                .and_then(|b| b.field("value"))
            else {
                continue;
            };
            let Some((base, join_method)) = method(&join) else {
                continue;
            };
            if join_method != "join"
                || path_parameter(root, &function, &base).is_none()
                || !arguments(&join)
                    .and_then(|a| unique(a.into_iter()))
                    .is_some_and(|path| lexical_entry_path(root, &function, path, &entry, enabled))
            {
                continue;
            }
            let Some(open) = written_entry(
                root,
                &writer,
                entry_index,
                path_index,
                file,
                evidence,
                enabled,
            ) else {
                continue;
            };
            let Some((parent_call, parent_guard)) =
                parent_before_dispatch(root, dispatch, &function, destination, &base, enabled)
            else {
                continue;
            };
            for link_call in branch_calls(&link) {
                let Some(args) =
                    arguments(&link_call).filter(|_| enabled_call(&link_call, &function, enabled))
                else {
                    continue;
                };
                let Some(link_path) = args.iter().position(|n| bound(&function, n, destination))
                else {
                    continue;
                };
                let Some(target) = args
                    .iter()
                    .position(|n| entry_value(&function, n.clone(), &entry, "link_name", 12))
                else {
                    continue;
                };
                if let Some(symlink) =
                    symlink_sink(root, &link_call, &function, target, link_path, enabled)
                {
                    return Some([
                        ("archive_write_call", write_call),
                        ("entry_destination", join),
                        ("link_creation_call", link_call),
                        ("link_creation_sink", symlink),
                        ("parent_check_call", parent_call),
                        ("following_parent_check", parent_guard),
                        ("write_sink", open),
                    ]);
                }
            }
        }
    }
    None
}

fn parent_before_dispatch<'a>(
    root: &N<'a>,
    dispatch: &N<'a>,
    function: &N<'a>,
    destination: &N<'a>,
    base: &N<'a>,
    enabled: &impl Fn(&N<'a>) -> bool,
) -> Option<(N<'a>, N<'a>)> {
    let parent = dispatch.parent()?;
    let block = if parent.kind().as_ref() == "expression_statement" {
        parent.parent()?
    } else {
        parent
    };
    if block.kind().as_ref() != "block" {
        return None;
    }
    named(&block)
        .take_while(|n| n.range().start < dispatch.range().start)
        .filter(|n| propagated(n))
        .find_map(|n| {
            let call = operation(&n).filter(|call| enabled_call(call, function, enabled))?;
            let args = arguments(&call)?;
            let path = args.iter().position(|n| bound(function, n, destination))?;
            if previous_statement(&block, &n).is_some_and(|prior| {
                enabled(&prior)
                    && confines_parent(root, function, &prior, destination, base).is_some()
            }) {
                return None;
            }
            let base = args.iter().position(|n| bound(function, n, base));
            let helper = unique(definitions(&call, function, enabled).into_iter())?;
            let guard = following_parent(root, &helper, path, base)?;
            Some((call, guard))
        })
}

fn emit(
    groups: &mut Vec<ObservationGroup>,
    file: &SourceFile,
    rule: &str,
    facts: &[(&str, N<'_>)],
    scope: Option<&mehscan_core::ImpactScanScope>,
) {
    let anchor = &facts[0].1;
    let location = rust_dependencies::capture(file, anchor).location;
    if scope.is_some_and(|s| {
        s.result_policy == "changed_locations"
            && !facts.iter().any(|(_, node)| {
                crate::impact::location_is_changed(
                    &rust_dependencies::capture(file, node).location,
                    &s.changed_files,
                )
            })
    }) {
        return;
    }
    let id = review_admission_marker_id(&file.path, rule, anchor.range().start, anchor.range().end);
    if let Some(previous) = groups
        .iter_mut()
        .find(|g| g.anchor_evidence_ids.contains(&id))
    {
        let evidence = &mut previous.evidence[0];
        for (role, node) in &facts[1..] {
            let capture = rust_dependencies::capture(file, node);
            if !evidence
                .captures
                .values()
                .any(|existing| existing == &capture)
            {
                evidence
                    .captures
                    .insert(format!("{role}_{}", node.range().start), capture);
            }
        }
        return;
    }
    let symbol = enclosing_function(anchor)
        .and_then(|f| f.field("name"))
        .map(|n| n.text().into_owned())
        .unwrap_or_default();
    groups.push(ObservationGroup {
        path: file.path.clone(),
        symbol: symbol.clone(),
        anchor_evidence_ids: vec![id.clone()],
        priority: 1,
        review_material: is_review_material_path(&file.path),
        evidence: vec![Evidence {
            id,
            rule_id: rule.into(),
            kind: EvidenceKind::SensitiveOperation,
            capability: Capability::RustArchiveExtractionReview,
            location,
            enclosing_symbol: Some(symbol),
            captures: facts
                .iter()
                .map(|(role, node)| ((*role).into(), rust_dependencies::capture(file, node)))
                .collect(),
            cwe_candidates: vec!["CWE-59".into()],
            tags: vec![
                "review-admission-marker".into(),
                "rust-filesystem-link-boundary".into(),
            ],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "bounded Rust filesystem link relationship".into(),
                rule_version: 1,
            },
            context: EvidenceContext::default(),
            symbol_resolution: None,
            related_evidence: vec![],
        }],
    });
}

pub(super) fn groups(
    sources: &RepositorySources,
    evidence: &[Evidence],
    scope: Option<&mehscan_core::ImpactScanScope>,
    selection: &rust_configuration::Selection,
    parsed: &rust_dependencies::RustSources,
) -> Vec<ObservationGroup> {
    let directory = Pattern::new(DIRECTORY_FALLBACK, parser_language(Language::Rust));
    let mut groups = Vec::new();
    let mut writes = BTreeMap::<&str, Vec<&Evidence>>::new();
    for item in evidence
        .iter()
        .filter(|e| e.rule_id == "rust-filesystem-write")
    {
        writes.entry(&item.location.path).or_default().push(item);
    }
    for file in sources
        .files
        .values()
        .filter(|f| f.language == Some(Language::Rust))
    {
        let permissions =
            file.source.contains("set_permissions") && file.source.contains("create_dir");
        let archive = file.source.contains("link_name") && file.source.contains("symlink");
        if !permissions && !archive {
            continue;
        }
        let Some(root) = parsed.root(&file.path) else {
            continue;
        };
        let enabled = |n: &N<'_>| !selection.excluded(&file.path, n.range());
        for node in root.dfs().filter(|n| enabled(n)) {
            if permissions
                && node.kind().as_ref() == "expression_statement"
                && let Some(facts) = directory_permissions(&root, &node, &directory, &enabled)
            {
                emit(
                    &mut groups,
                    file,
                    "rust-directory-symlink-permissions-review",
                    &facts,
                    scope,
                );
            }
            if archive
                && node.kind().as_ref() == "match_expression"
                && let Some(writes) = writes.get(file.path.as_str())
                && let Some(facts) =
                    archive_parent_write(&root, &node, &file.path, writes, &enabled)
            {
                emit(
                    &mut groups,
                    file,
                    "rust-archive-parent-symlink-write-review",
                    &facts,
                    scope,
                );
            }
        }
    }
    groups
}
