//! Local field copies only. No heap, schema, middleware or object-alias inference.
use super::{Node, NodeOperandIndex, Range, StrDoc, SupportLang};

type Ast<'a> = Node<'a, StrDoc<SupportLang>>;

pub(super) fn source_in_object(source: &Ast<'_>, scope: &Range<usize>) -> bool {
    source
        .ancestors()
        .take_while(|n| n.range() != *scope)
        .any(|n| {
            n.kind().as_ref() == "variable_declarator"
                && n.field("name")
                    .is_some_and(|n| n.kind().as_ref() == "identifier")
                && n.field("value")
                    .is_some_and(|v| v.kind().as_ref() == "object")
        })
}

pub(super) fn projected_value<'a>(
    target: &Ast<'a>,
    index: &NodeOperandIndex<'a>,
    scope: &Range<usize>,
    depth: usize,
    work: &mut usize,
) -> Option<Ast<'a>> {
    if depth > super::MAX_PROPAGATION_DEPTH || *work == 0 {
        return None;
    }
    *work -= 1;
    let access = super::node_static_access(target, 0)?;
    let key = access.last()?;
    let receiver = target.field("object")?;
    let object = match receiver.kind().as_ref() {
        "identifier" => {
            let binding = index.alias_assignment(scope, &receiver)?;
            if binding.right.kind().as_ref() != "object" {
                return None;
            }
            let name = receiver.text();
            let start = binding.node.range().end;
            let end = target.range().start;
            if index
                .writes
                .get(name.as_ref())
                .into_iter()
                .flatten()
                .any(|w| {
                    (w.range.start >= start && w.range.start < end)
                        || (w.scope != (scope.start, scope.end)
                            && scope.start <= w.scope.0
                            && w.scope.1 <= scope.end)
                })
                || index
                    .object_escapes()
                    .get(name.as_ref())
                    .into_iter()
                    .flatten()
                    .any(|r| {
                        // A closure can escape the object before its definition or
                        // execute a textually later use; do not assume call order.
                        scope.start <= r.start && r.end <= scope.end
                    })
            {
                return None;
            }
            binding.right.clone()
        }
        "member_expression" | "subscript_expression" => {
            projected_value(&receiver, index, scope, depth + 1, work)?
        }
        _ => return None,
    };
    if object.kind().as_ref() != "object" {
        return None;
    }
    let mut selected = None;
    let mut keys = std::collections::BTreeSet::new();
    for field in object.children().filter(|n| n.is_named()) {
        if *work == 0 {
            return None;
        }
        *work -= 1;
        // Spread, computed properties, getters and duplicate keys invalidate
        // this small contract instead of guessing override/execution semantics.
        if field.kind().as_ref() == "comment" {
            continue;
        }
        if field.kind().as_ref() != "pair" {
            return None;
        }
        let field_key = field.field("key")?;
        let name = match field_key.kind().as_ref() {
            "property_identifier" => field_key.text().into_owned(),
            "string" => {
                let text = field_key.text();
                if text.contains('\\') {
                    return None;
                }
                super::simple_string_literal(&text)?.to_string()
            }
            _ => return None,
        };
        if name == "__proto__" || !keys.insert(name.clone()) {
            return None;
        }
        if name == *key {
            selected = field.field("value");
        }
    }
    selected
}
