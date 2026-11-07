//! Source-bound allocation extents decoded from a successful local header read.
use super::*;
use rust_allocation::method;
use rust_module_bindings::Project;
use rust_receiver_types::{ReaderContract, lexical_binding};
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

fn decoded_length<'a>(
    root: &N<'a>,
    mut node: N<'a>,
    function: &N<'a>,
    accepts: impl Fn(&N<'a>) -> bool,
) -> Option<N<'a>> {
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
                if accepts(&node) {
                    return Some(node);
                }
                let callee = node.field("function")?;
                if callee.field("name").is_some_and(|n| n.text() == "try_from")
                    && callee.field("path").is_some_and(|ty| {
                        ty.text() == "usize"
                            && rust_raw_memory::canonical(root, &ty, &ty.text()).as_deref()
                                == Some("usize")
                    })
                {
                    node = argument(&node)?;
                    continue;
                }
                node = unpack(node)?;
            }
            _ => node = unpack(node)?,
        }
    }
    None
}

fn primitive_decode<'a>(root: &N<'a>, call: &N<'a>) -> bool {
    call.field("function").is_some_and(|callee| {
        callee.field("path").is_some_and(|ty| {
            matches!(ty.text().as_ref(), "u32" | "u64" | "u128" | "usize")
                && rust_raw_memory::canonical(root, &ty, &ty.text()).as_deref()
                    == Some(ty.text().as_ref())
        }) && callee.field("name").is_some_and(|name| {
            matches!(
                name.text().as_ref(),
                "from_le_bytes" | "from_be_bytes" | "from_ne_bytes"
            )
        })
    })
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

fn statement_expression(statement: N<'_>) -> N<'_> {
    if statement.kind() == "expression_statement" {
        only(named(&statement)).unwrap_or(statement)
    } else {
        statement
    }
}

fn plain_if(statement: N<'_>) -> Option<N<'_>> {
    let node = statement_expression(statement);
    (node.kind() == "if_expression" && node.field("alternative").is_none()).then_some(node)
}

fn rejects(branch: &N<'_>) -> bool {
    branch.field("consequence").is_some_and(|body| {
        only(named(&body))
            .is_some_and(|stmt| statement_expression(stmt).kind() == "return_expression")
    })
}

fn guard<'a>(
    block: &N<'a>,
    before: usize,
    decoder: &N<'a>,
    resolve: impl Fn(N<'a>) -> Option<N<'a>>,
) -> Option<N<'a>> {
    named(block)
        .filter(|n| n.range().end <= before)
        .filter_map(plain_if)
        .find(|n| {
            n.field("condition")
                .and_then(|condition| {
                    let length = match condition.field("operator")?.text().as_ref() {
                        ">" | ">=" => condition.field("left"),
                        "<" | "<=" => condition.field("right"),
                        _ => None,
                    }?;
                    resolve(length)
                })
                .is_some_and(|value| value.range() == decoder.range())
                && rejects(n)
        })
}

pub(super) fn evidence<'a>(
    root: &N<'a>,
    extent: &N<'a>,
    allocation: &N<'a>,
    function: &N<'a>,
    file: &'a SourceFile,
    project: &Project<'a>,
) -> Option<BTreeMap<String, Capture>> {
    let resolve = |node| decoded_length(root, node, function, |call| primitive_decode(root, call));
    let decoder = resolve(extent.clone())?;
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
    let comparison = guard(
        &block,
        allocation_statement.range().start,
        &decoder,
        resolve,
    )
    .filter(|guard| project.selected(&project.locate(file, guard.clone())));
    Some(read_captures(
        file,
        &read,
        &binding,
        &decoder,
        support.into_iter().chain(adapter),
        comparison,
    ))
}

fn read_captures<'a>(
    file: &SourceFile,
    read: &N<'a>,
    buffer: &N<'a>,
    decoder: &N<'a>,
    support: impl Iterator<Item = Capture>,
    comparison: Option<N<'a>>,
) -> BTreeMap<String, Capture> {
    let mut captures = BTreeMap::from([
        ("input_read".into(), rust_dependencies::capture(file, read)),
        (
            "input_buffer".into(),
            rust_dependencies::capture(file, buffer),
        ),
        (
            "length_decode".into(),
            rust_dependencies::capture(file, decoder),
        ),
    ]);
    add_read_support(&mut captures, support);
    if let Some(guard) = comparison {
        captures.insert(
            "allocation_guard".into(),
            rust_dependencies::capture(file, &guard),
        );
    }
    captures
}

fn add_read_support(
    captures: &mut BTreeMap<String, Capture>,
    support: impl Iterator<Item = Capture>,
) {
    let mut locations = BTreeSet::new();
    for (i, item) in support
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
}

fn byteorder_decode<'a>(root: &N<'a>, call: &N<'a>) -> Option<(&'static str, Vec<N<'a>>)> {
    let callee = call.field("function")?;
    let width = match callee.field("name")?.text().as_ref() {
        "read_u32" => "4",
        "read_u64" => "8",
        _ => return None,
    };
    let owner = callee.field("path")?;
    let (identity, endian_import) = crate::code::rust_http::canonical(root, &owner, &owner.text())?;
    if !matches!(
        identity.as_str(),
        "byteorder::BigEndian" | "byteorder::LittleEndian"
    ) {
        return None;
    }
    let (identity, trait_import) = crate::code::rust_http::canonical(root, call, "ByteOrder")?;
    if identity != "byteorder::ByteOrder" {
        return None;
    }
    Some((
        width,
        endian_import.into_iter().chain([trait_import?]).collect(),
    ))
}

fn self_field<'a>(value: &N<'a>) -> Option<N<'a>> {
    (value.kind() == "field_expression" && value.field("value")?.kind() == "self")
        .then(|| value.field("field"))?
}

fn scalar_read<'a>(call: &N<'a>) -> Option<(N<'a>, String, N<'a>)> {
    let generic = call.field("function")?;
    if generic.kind() != "generic_function" || named(&call.field("arguments")?).next().is_some() {
        return None;
    }
    let (receiver, method) = method(call)?;
    if !matches!(method.as_str(), "read_i32" | "read_i64")
        || call.parent()?.kind() != "try_expression"
    {
        return None;
    }
    self_field(&receiver)?;
    Some((
        receiver,
        method,
        only(named(&generic.field("type_arguments")?))?,
    ))
}

fn negative_guard<'a>(
    block: &N<'a>,
    before: usize,
    decoder: &N<'a>,
    function: &N<'a>,
) -> Option<N<'a>> {
    named(block)
        .filter(|n| n.range().end <= before)
        .filter_map(plain_if)
        .find(|branch| {
            let Some(binding) = branch.field("condition").and_then(|condition| {
                let (value, zero) = match condition.field("operator")?.text().as_ref() {
                    "<" => (condition.field("left")?, condition.field("right")?),
                    ">" => (condition.field("right")?, condition.field("left")?),
                    _ => return None,
                };
                (zero.text() == "0").then_some(())?;
                rust_receiver_types::local_binding(&value, function)
            }) else {
                return false;
            };
            // Comparing an already cast unsigned alias to zero is not a sign check.
            binding.field("value").is_some_and(|value| {
                value.kind() == "try_expression"
                    && only(named(&value)).is_some_and(|call| call.range() == decoder.range())
            }) && rejects(branch)
        })
}

pub(super) fn scalar_field_evidence<'a>(
    root: &N<'a>,
    extent: &N<'a>,
    allocation: &N<'a>,
    function: &N<'a>,
    file: &'a SourceFile,
    project: &Project<'a>,
) -> Option<BTreeMap<String, Capture>> {
    let resolve = |node| decoded_length(root, node, function, |call| scalar_read(call).is_some());
    let decoder = resolve(extent.clone())?;
    let (reader, method, endian) = scalar_read(&decoder)?;
    let (identity, endian_import) =
        crate::code::rust_http::canonical(root, &endian, &endian.text())?;
    if !matches!(
        identity.as_str(),
        "byteorder::BigEndian" | "byteorder::LittleEndian"
    ) {
        return None;
    }
    let (identity, extension) = crate::code::rust_http::canonical(root, &decoder, "ReadBytesExt")?;
    if identity != "byteorder::ReadBytesExt" {
        return None;
    }
    let imports = [endian_import, Some(extension?)];
    let declaration = decoder
        .ancestors()
        .find(|n| n.kind() == "let_declaration")?;
    let block = declaration.parent()?;
    if block.kind() != "block"
        || declaration.range().end > allocation.range().start
        || allocation
            .ancestors()
            .find(|n| n.kind() == "block")?
            .range()
            != block.range()
        || std::iter::once(&decoder)
            .chain(imports.iter().flatten())
            .any(|n| !project.selected(&project.locate(file, n.clone())))
    {
        return None;
    }
    let support = rust_receiver_types::reader_field_support(
        project,
        &reader,
        function,
        file,
        ReaderContract::Scalar(&method),
    )?;
    let mut captures = BTreeMap::from([(
        "scalar_length_read".into(),
        rust_dependencies::capture(file, &decoder),
    )]);
    add_read_support(
        &mut captures,
        support.into_iter().chain(
            imports
                .iter()
                .flatten()
                .map(|n| rust_dependencies::capture(file, n)),
        ),
    );
    let before = allocation.range().start;
    let optional = named(&block)
        .filter(|n| n.range().end <= before)
        .filter_map(plain_if)
        .find(|branch| {
            branch
                .field("condition")
                .is_some_and(|condition| condition.kind() == "let_condition")
                && branch.field("consequence").is_some_and(|body| {
                    guard(&body, before, &decoder, resolve)
                        .is_some_and(|inner| project.selected(&project.locate(file, inner)))
                })
        });
    for (key, comparison) in [
        ("allocation_guard", guard(&block, before, &decoder, resolve)),
        ("allocation_optional_guard", optional),
        (
            "allocation_sign_guard",
            negative_guard(&block, before, &decoder, function),
        ),
    ] {
        if let Some(comparison) =
            comparison.filter(|n| project.selected(&project.locate(file, n.clone())))
        {
            captures.insert(key.into(), rust_dependencies::capture(file, &comparison));
        }
    }
    Some(captures)
}

// Admit a same-block sequence only. The successful read and decoder must be
// adjacent so a write or alternate path cannot replace the header in between.
pub(super) fn async_field_evidence<'a>(
    root: &N<'a>,
    extent: &N<'a>,
    allocation: &N<'a>,
    function: &N<'a>,
    file: &'a SourceFile,
    project: &Project<'a>,
) -> Option<BTreeMap<String, Capture>> {
    let (destination, name) = method(allocation)?;
    if name != "resize" {
        return None;
    }
    let field = self_field(&destination)?.text().into_owned();
    let resolve = |node| {
        decoded_length(root, node, function, |call| {
            byteorder_decode(root, call).is_some()
        })
    };
    let decoder = resolve(extent.clone())?;
    let (width, mut imports) = byteorder_decode(root, &decoder)?;
    let buffer = argument(&decoder)?;
    if buffer.kind() != "reference_expression"
        || self_field(&buffer.field("value")?)?.text() != field
    {
        return None;
    }
    let declaration = decoder
        .ancestors()
        .find(|n| n.kind() == "let_declaration")?;
    let block = declaration.parent()?;
    if block.kind() != "block" || allocation.parent()?.parent()?.range() != block.range() {
        return None;
    }
    let previous: Vec<_> = named(&block)
        .take_while(|n| n.range().start < declaration.range().start)
        .collect();
    let [.., header, read] = previous.as_slice() else {
        return None;
    };
    let header_call = only(named(header))?;
    let (header_buffer, name) = method(&header_call)?;
    let header_args = header_call.field("arguments")?;
    let mut args = named(&header_args);
    if name != "resize"
        || self_field(&header_buffer)?.text() != field
        || args.next()?.text() != width
        || args.next()?.text() != "0"
        || args.next().is_some()
    {
        return None;
    }
    let fallible = only(named(read))?;
    let awaited = only(named(&fallible))?;
    if read.kind() != "expression_statement"
        || fallible.kind() != "try_expression"
        || awaited.kind() != "await_expression"
    {
        return None;
    }
    let call = only(named(&awaited))?;
    if call.field("function")?.kind() != "field_expression" {
        return None;
    }
    let (reader, name) = method(&call)?;
    let output = argument(&call)?;
    if name != "read_exact"
        || output.kind() != "reference_expression"
        || !output.children().any(|n| n.kind() == "mutable_specifier")
        || self_field(&output.field("value")?)?.text() != field
    {
        return None;
    }
    let (identity, import) = crate::code::rust_http::canonical(root, &call, "AsyncReadExt")?;
    if identity != "tokio::io::AsyncReadExt" {
        return None;
    }
    imports.push(import?);
    if [&decoder, header, read]
        .into_iter()
        .chain(&imports)
        .any(|n| !project.selected(&project.locate(file, n.clone())))
    {
        return None;
    }
    let support = rust_receiver_types::reader_field_support(
        project,
        &reader,
        function,
        file,
        ReaderContract::Async,
    )?;
    let comparison = guard(&block, allocation.range().start, &decoder, resolve)
        .filter(|guard| project.selected(&project.locate(file, guard.clone())));
    Some(read_captures(
        file,
        read,
        header,
        &decoder,
        support
            .into_iter()
            .chain(imports.iter().map(|n| rust_dependencies::capture(file, n))),
        comparison,
    ))
}
