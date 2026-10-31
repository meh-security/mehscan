//! Small string contracts over proven primitive path results, not method-name
//! passthrough or a regular-expression interpreter.
use super::{
    FileSymbolEnvironment, Language, MAX_PROPAGATION_DEPTH, Node, NodeOperandIndex, Range, StrDoc,
    SupportLang, simple_string_literal,
};

type Ast<'a> = Node<'a, StrDoc<SupportLang>>;

pub(super) fn replacement_receiver<'a>(call: &Ast<'a>) -> Option<Ast<'a>> {
    if call.kind().as_ref() != "call_expression" {
        return None;
    }
    let callee = call.field("function")?;
    if callee.kind().as_ref() != "member_expression"
        || callee.field("property")?.text() != "replace"
    {
        return None;
    }
    let arguments = call.field("arguments")?;
    let mut args = arguments
        .children()
        .filter(|n| n.is_named() && n.kind().as_ref() != "comment");
    let search = args.next()?;
    let replacement = args.next()?;
    if args.next().is_some()
        || replacement.kind().as_ref() != "string"
        || replacement.range().len() > 256
        || search.range().len() > 256
    {
        return None;
    }
    let replacement = replacement.text();
    let replacement = simple_string_literal(&replacement)?;
    if replacement.contains('$') {
        return None; // No replacement expansion/callback semantics.
    }
    let supported = if search.kind().as_ref() == "string" {
        simple_string_literal(&search.text()).is_some_and(|s| !s.is_empty() && s.len() <= 128)
    } else if search.kind().as_ref() == "regex" {
        let pattern = search.field("pattern")?;
        search
            .field("flags")
            .is_none_or(|n| matches!(n.text().as_ref(), "" | "g"))
            && edge_class(&pattern.text())
    } else {
        false
    };
    supported.then(|| callee.field("object")).flatten()
}

// One edge anchor, a positive finite character class, and an optional simple
// quantifier. No dot, complement classes, ranges, groups, alternation, lookaround,
// flags changing matching semantics or full-value patterns. Bound syntax work.
fn edge_class(pattern: &str) -> bool {
    if pattern.len() > 128 {
        return false;
    }
    let Some(class) = pattern
        .strip_prefix('^')
        .or_else(|| pattern.strip_suffix('$'))
    else {
        return false;
    };
    let class = class.strip_suffix(['+', '*', '?']).unwrap_or(class);
    let Some(class) = class.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
        return false;
    };
    if class.is_empty() {
        return false;
    }
    let mut chars = class.bytes();
    while let Some(c) = chars.next() {
        if c == b'\\' {
            if !chars.next().is_some_and(|e| {
                matches!(
                    e,
                    b'\\'
                        | b'/'
                        | b'-'
                        | b']'
                        | b'['
                        | b'^'
                        | b's'
                        | b't'
                        | b'n'
                        | b'r'
                        | b'f'
                        | b'v'
                )
            }) {
                return false;
            }
        } else if !c.is_ascii_graphic() && c != b' ' || matches!(c, b'[' | b']' | b'^' | b'-') {
            return false;
        }
    }
    true
}

pub(super) fn path_string(
    node: &Ast<'_>,
    symbols: &FileSymbolEnvironment,
    language: Language,
    index: &NodeOperandIndex<'_>,
    scope: &Range<usize>,
    depth: usize,
    work: &mut usize,
) -> bool {
    if *work == 0 || depth > MAX_PROPAGATION_DEPTH {
        return false;
    }
    *work -= 1;
    match node.kind().as_ref() {
        "call_expression" => node
            .field("function")
            .is_some_and(|callee| index.path_api(symbols, language, &callee).is_some()),
        "identifier" => {
            if index
                .nested_binding_writes
                .contains(&((scope.start, scope.end), node.text().into_owned()))
            {
                return false;
            }
            index.alias_assignment(scope, node).is_some_and(|a| {
                a.projection.is_empty()
                    && path_string(&a.right, symbols, language, index, scope, depth + 1, work)
            })
        }
        "parenthesized_expression" | "as_expression" | "non_null_expression" => node
            .children()
            .find(|n| n.is_named())
            .is_some_and(|n| path_string(&n, symbols, language, index, scope, depth + 1, work)),
        _ => false,
    }
}
