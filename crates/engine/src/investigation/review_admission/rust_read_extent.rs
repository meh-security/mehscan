//! Source-bound allocation extents decoded from a successful local header read.
use super::*;
use rust_allocation::method;
use rust_module_bindings::Project;
use rust_receiver_types::lexical_binding;
use rust_shared_state::AstNode as N;

fn named<'a, 'node>(node: &'node N<'a>) -> impl Iterator<Item = N<'a>> + use<'a, 'node> {
    node.children()
        .filter(|n| n.is_named() && !n.kind().contains("comment"))
}

fn only<'a>(mut nodes: impl Iterator<Item = N<'a>>) -> Option<N<'a>> {
    let first = nodes.next()?;
    nodes.next().is_none().then_some(first)
}

fn argument<'a>(call: &N<'a>) -> Option<N<'a>> {
    only(named(&call.field("arguments")?))
}

fn unpack<'a>(node: N<'a>) -> Option<N<'a>> {
    match node.kind().as_ref() {
        "try_expression" | "parenthesized_expression" | "expression_statement" => {
            only(named(&node))
        }
        "call_expression" => {
            let (receiver, name) = method(&node)?;
            let count = named(&node.field("arguments")?).count();
            matches!(
                (name.as_str(), count),
                ("unwrap" | "ok", 0) | ("map_err" | "expect", 1)
            )
            .then_some(receiver)
        }
        _ => None,
    }
}

fn direct_statement<'a>(node: &N<'a>, block: &N<'a>) -> Option<N<'a>> {
    std::iter::once(node.clone())
        .chain(node.ancestors())
        .find(|n| n.parent().is_some_and(|p| p.range() == block.range()))
}

fn decoded_length<'a>(root: &N<'a>, mut node: N<'a>, function: &N<'a>) -> Option<N<'a>> {
    for _ in 0..12 {
        match node.kind().as_ref() {
            "identifier" => {
                let binding = rust_receiver_types::local_binding(&node, function)?;
                if binding
                    .children()
                    .any(|n| n.kind().as_ref() == "mutable_specifier")
                {
                    return None;
                }
                node = binding.field("value")?;
            }
            "type_cast_expression" if node.field("type")?.text() == "usize" => {
                node = node.field("value")?;
            }
            "call_expression" => {
                let callee = node.field("function")?;
                if let Some(ty) = callee.field("path")
                    && matches!(ty.text().as_ref(), "u32" | "u64" | "u128" | "usize")
                    && rust_raw_memory::canonical(root, &ty, &ty.text()).as_deref()
                        == Some(ty.text().as_ref())
                {
                    let name = callee.field("name")?;
                    if ty.text() == "usize" && name.text() == "try_from" {
                        node = argument(&node)?;
                        continue;
                    }
                    if matches!(
                        name.text().as_ref(),
                        "from_le_bytes" | "from_be_bytes" | "from_ne_bytes"
                    ) {
                        return Some(node);
                    }
                }
                node = unpack(node)?;
            }
            _ => node = unpack(node)?,
        }
    }
    None
}

fn slice_base<'a>(mut node: N<'a>) -> Option<N<'a>> {
    for _ in 0..8 {
        match node.kind().as_ref() {
            "identifier" => return Some(node),
            "reference_expression"
                if !node
                    .children()
                    .any(|n| n.kind().as_ref() == "mutable_specifier") =>
            {
                node = node.field("value")?;
            }
            "index_expression" => {
                let base = named(&node).next()?;
                node = base;
            }
            _ => node = unpack(node)?,
        }
    }
    None
}

fn byte_array_input<'a>(mut node: N<'a>) -> Option<N<'a>> {
    for _ in 0..8 {
        if let Some((receiver, name)) = method(&node)
            && name == "try_into"
            && named(&node.field("arguments")?).next().is_none()
        {
            return Some(receiver);
        }
        node = unpack(node)?;
    }
    None
}

// Match a source-owned slice-to-array adapter by its return and exact body.
// A same-named helper, a constant return or an opaque transform is insufficient.
fn slice_adapter<'a>(definition: &N<'a>) -> Option<()> {
    let ty = definition.field("return_type")?;
    if ty.kind().as_ref() != "array_type" || ty.field("element")?.text() != "u8" {
        return None;
    }
    let parameter = only(named(&definition.field("parameters")?))?;
    let ty = parameter.field("type")?;
    if ty.kind().as_ref() != "reference_type"
        || !ty.field("type").is_some_and(|t| {
            t.kind().as_ref() == "array_type"
                && t.field("length").is_none()
                && t.field("element").is_some_and(|e| e.text() == "u8")
        })
    {
        return None;
    }
    let pattern = parameter.field("pattern")?;
    if pattern.kind().as_ref() != "identifier" {
        return None;
    }
    let body = only(named(&definition.field("body")?))?;
    let slice = byte_array_input(body)?;
    if slice.kind().as_ref() != "index_expression"
        || !named(&slice)
            .nth(1)
            .is_some_and(|n| n.kind().as_ref() == "range_expression")
        || slice_base(slice)?.text() != pattern.text()
    {
        return None;
    }
    Some(())
}

fn buffer_source<'a>(
    input: N<'a>,
    function: &N<'a>,
    file: &'a SourceFile,
    project: &Project<'a>,
) -> Option<(N<'a>, Vec<Capture>)> {
    if let Some(buffer) = byte_array_input(input.clone()).and_then(slice_base) {
        return Some((buffer, Vec::new()));
    }
    if input.kind().as_ref() != "call_expression" {
        return Some((slice_base(input)?, Vec::new()));
    }
    let mut callee = input.field("function")?;
    if callee.kind().as_ref() == "generic_function" {
        callee = callee.field("function")?;
    }
    let (definition, mut support) =
        rust_receiver_types::function_definition(project, &callee, function, file)?;
    slice_adapter(&definition.node)?;
    support.push(definition.capture());
    Some((slice_base(argument(&input)?)?, support))
}

fn is_read_trait<'a>(root: &N<'a>, ty: &N<'a>) -> bool {
    rust_raw_memory::canonical(root, ty, &ty.text()).as_deref() == Some("std::io::Read")
}

fn read_bound<'a>(root: &N<'a>, receiver: &N<'a>, function: &N<'a>) -> Option<N<'a>> {
    let binding = rust_receiver_types::local_binding(receiver, function)?;
    let mut ty = binding.field("type")?;
    while ty.kind().as_ref() == "reference_type" {
        ty = ty.field("type")?;
    }
    if matches!(ty.kind().as_ref(), "abstract_type" | "dynamic_type") {
        let bound = ty.field("trait")?;
        return is_read_trait(root, &bound).then_some(bound);
    }
    let name = ty.text();
    let declarations = function.field("type_parameters").into_iter().chain(
        function
            .children()
            .filter(|n| n.kind().as_ref() == "where_clause"),
    );
    for declaration in declarations {
        for constraint in named(&declaration) {
            let parameter = constraint
                .field("name")
                .or_else(|| constraint.field("left"));
            if parameter.is_some_and(|p| p.text() == name)
                && constraint
                    .field("bounds")
                    .is_some_and(|bounds| named(&bounds).any(|bound| is_read_trait(root, &bound)))
            {
                return Some(constraint);
            }
        }
    }
    None
}

fn read_call<'a>(statement: &N<'a>) -> Option<N<'a>> {
    // Only a direct fallible read with a propagated failure establishes that
    // the subsequent decoder runs after the whole buffer was filled.
    let mut call = only(named(statement))?;
    if statement.kind().as_ref() != "expression_statement"
        || call.kind().as_ref() != "try_expression"
    {
        return None;
    }
    call = unpack(call)?;
    if let Some((receiver, name)) = method(&call)
        && name == "map_err"
        && argument(&call).is_some()
    {
        call = receiver;
    }
    (call.kind().as_ref() == "call_expression").then_some(call)
}

fn fills_buffer<'a>(
    root: &N<'a>,
    call: &N<'a>,
    binding: &N<'a>,
    function: &N<'a>,
    file: &'a SourceFile,
    project: &Project<'a>,
) -> Option<Vec<Capture>> {
    let (buffer, support) = if let Some((receiver, name)) = method(call) {
        if name != "read_exact" {
            return None;
        }
        let buffer = argument(call)?;
        let support = read_bound(root, &receiver, function)
            .filter(|bound| project.selected(&project.locate(file, bound.clone())))
            .map(|bound| vec![rust_dependencies::capture(file, &bound)])
            .or_else(|| {
                let (identity, import) = crate::code::rust_http::canonical(root, call, "Read")?;
                if identity != "std::io::Read" {
                    return None;
                }
                let mut support =
                    rust_receiver_types::std_reader_support(project, &receiver, function, file)?;
                let import = import?;
                if !project.selected(&project.locate(file, import.clone())) {
                    return None;
                }
                support.push(rust_dependencies::capture(file, &import));
                Some(support)
            })?;
        (buffer, support)
    } else {
        if rust_raw_memory::api(root, call).as_deref() != Some("std::io::Read::read_exact") {
            return None;
        }
        let arguments = call.field("arguments")?;
        let mut arguments = named(&arguments);
        arguments.next()?;
        (only(arguments)?, Vec::new())
    };
    if buffer.kind().as_ref() != "reference_expression"
        || !buffer
            .children()
            .any(|n| n.kind().as_ref() == "mutable_specifier")
        || lexical_binding(&buffer.field("value")?, function)?.range() != binding.range()
    {
        return None;
    }
    Some(support)
}

fn can_change_buffer(node: &N<'_>, name: &str) -> bool {
    let mentions = |n: &N<'_>| {
        n.dfs()
            .any(|x| x.kind().as_ref() == "identifier" && x.text() == name)
    };
    match node.kind().as_ref() {
        "assignment_expression" | "compound_assignment_expr" => {
            node.field("left").is_some_and(|n| mentions(&n))
        }
        "reference_expression" => {
            node.children()
                .any(|n| n.kind().as_ref() == "mutable_specifier")
                && node.field("value").is_some_and(|n| mentions(&n))
        }
        "call_expression" => method(node).is_some_and(|(receiver, _)| mentions(&receiver)),
        "macro_invocation" => mentions(node),
        "unsafe_block" => true,
        _ => false,
    }
}

fn guard<'a>(
    root: &N<'a>,
    block: &N<'a>,
    before: usize,
    decoder: &N<'a>,
    function: &N<'a>,
) -> Option<N<'a>> {
    for statement in named(block).filter(|n| n.range().end <= before) {
        let n = if statement.kind().as_ref() == "expression_statement" {
            only(named(&statement)).unwrap_or(statement)
        } else {
            statement
        };
        if n.kind().as_ref() != "if_expression" || n.field("alternative").is_some() {
            continue;
        }
        let Some(condition) = n.field("condition") else {
            continue;
        };
        let Some(op) = condition.field("operator") else {
            continue;
        };
        let Some(length) = (match op.text().as_ref() {
            ">" | ">=" => condition.field("left"),
            "<" | "<=" => condition.field("right"),
            _ => None,
        }) else {
            continue;
        };
        if !decoded_length(root, length, function)
            .is_some_and(|value| value.range() == decoder.range())
        {
            continue;
        }
        let Some(body) = n.field("consequence") else {
            continue;
        };
        if only(named(&body)).is_some_and(|stmt| {
            let stmt = if stmt.kind().as_ref() == "expression_statement" {
                only(named(&stmt)).unwrap_or(stmt)
            } else {
                stmt
            };
            stmt.kind().as_ref() == "return_expression"
        }) {
            return Some(n);
        }
    }
    None
}

pub(super) fn evidence<'a>(
    root: &N<'a>,
    extent: &N<'a>,
    allocation: &N<'a>,
    function: &N<'a>,
    file: &'a SourceFile,
    project: &Project<'a>,
) -> Option<BTreeMap<String, Capture>> {
    let decoder = decoded_length(root, extent.clone(), function)?;
    let (buffer, adapter) = buffer_source(argument(&decoder)?, function, file, project)?;
    let binding = lexical_binding(&buffer, function)?;
    if binding.kind().as_ref() != "let_declaration"
        || binding.field("pattern")?.kind().as_ref() != "identifier"
        || binding.field("value")?.kind().as_ref() != "array_expression"
    {
        return None;
    }
    let block = binding.parent()?;
    let decoding_statement = direct_statement(&decoder, &block)?;
    let allocation_statement = direct_statement(allocation, &block)?;
    let mut read = None;
    for statement in named(&block).filter(|n| {
        n.range().start >= binding.range().end && n.range().end <= decoding_statement.range().start
    }) {
        if let Some(call) = read_call(&statement)
            && project.selected(&project.locate(file, statement.clone()))
            && let Some(support) = fills_buffer(root, &call, &binding, function, file, project)
        {
            read = Some((statement, support));
        } else if statement
            .dfs()
            .any(|n| can_change_buffer(&n, &buffer.text()))
        {
            read = None;
        }
    }
    let (read, support) = read?;
    let mut captures = BTreeMap::from([
        ("input_read".into(), rust_dependencies::capture(file, &read)),
        (
            "input_buffer".into(),
            rust_dependencies::capture(file, &binding),
        ),
        (
            "length_decode".into(),
            rust_dependencies::capture(file, &decoder),
        ),
    ]);
    let mut locations = BTreeSet::new();
    for (i, item) in support
        .into_iter()
        .chain(adapter)
        .filter(|item| {
            locations.insert((
                item.location.path.clone(),
                item.location.start.byte_offset,
                item.location.end.byte_offset,
            ))
        })
        .enumerate()
    {
        captures.insert(format!("read_extent_support_{i:02}"), item);
    }
    if let Some(guard) = guard(
        root,
        &block,
        allocation_statement.range().start,
        &decoder,
        function,
    ) && project.selected(&project.locate(file, guard.clone()))
    {
        captures.insert(
            "allocation_guard".into(),
            rust_dependencies::capture(file, &guard),
        );
    }
    Some(captures)
}
