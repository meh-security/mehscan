//! Pure returned-object projections. This does not model parsers or validators.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::Location;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub(crate) struct ReturnedObject {
    pub imported: bool,
    pub canonical: String,
    pub location: Location,
    // None means unresolved, not constant or safe.
    pub fields: Option<BTreeMap<Vec<String>, (usize, Vec<String>)>>,
}

pub(super) fn unique_functions(
    functions: &[(String, Node<'_, StrDoc<SupportLang>>)],
) -> BTreeSet<String> {
    let mut declarations = BTreeMap::<String, BTreeSet<_>>::new();
    for (name, function) in functions {
        declarations
            .entry(name.clone())
            .or_default()
            .insert((function.range().start, function.range().end));
    }
    declarations
        .into_iter()
        .filter_map(|(name, ranges)| (ranges.len() == 1).then_some(name))
        .collect()
}

pub(super) fn collect_one(
    path: &str,
    canonical: &str,
    function: &Node<'_, StrDoc<SupportLang>>,
    expression: &Node<'_, StrDoc<SupportLang>>,
    parameters: &[String],
    summaries: &mut BTreeMap<(String, String), ReturnedObject>,
) {
    let expression = if expression.kind().as_ref() == "parenthesized_expression" {
        expression
            .children()
            .find(|n| n.is_named())
            .unwrap_or_else(|| expression.clone())
    } else {
        expression.clone()
    };
    if expression.kind().as_ref() != "object" {
        return;
    }
    let Some(body) = function.field("body") else {
        return;
    };
    let only_return = body.kind().as_ref() != "statement_block" || {
        let statements = body
            .children()
            .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
            .collect::<Vec<_>>();
        statements.len() == 1 && statements[0].kind().as_ref() == "return_statement"
    };
    let pure = only_return
        && !function.kind().contains("generator")
        && !function.children().any(|n| n.kind().as_ref() == "async")
        && super::calls_in_function(function).next().is_none()
        && !function.field("parameters").is_some_and(|p| {
            p.dfs().any(|n| {
                matches!(
                    n.kind().as_ref(),
                    "object_pattern" | "array_pattern" | "rest_pattern" | "assignment_pattern"
                ) || (matches!(
                    n.kind().as_ref(),
                    "required_parameter" | "optional_parameter"
                ) && n.field("value").is_some())
            })
        })
        && parameters.iter().collect::<BTreeSet<_>>().len() == parameters.len()
        && parameters
            .iter()
            .all(|p| super::summary_parameter_is_unmodified(function, p, expression.range().start));
    let mut fields = BTreeMap::new();
    let understood = pure && collect_fields(&expression, parameters, &[], &mut fields, &mut 64);
    summaries.insert(
        (path.to_string(), canonical.to_string()),
        ReturnedObject {
            imported: false,
            canonical: canonical.to_string(),
            location: super::location(path, &expression),
            fields: understood.then_some(fields),
        },
    );
}

fn collect_fields(
    object: &Node<'_, StrDoc<SupportLang>>,
    parameters: &[String],
    prefix: &[String],
    fields: &mut BTreeMap<Vec<String>, (usize, Vec<String>)>,
    work: &mut usize,
) -> bool {
    if prefix.len() >= 4 {
        return false;
    }
    let mut keys = BTreeSet::new();
    for field in object.children().filter(|n| n.is_named()) {
        if *work == 0 {
            return false;
        }
        *work -= 1;
        if field.kind().as_ref() == "comment" {
            continue;
        }
        let (key, value) = if field.kind().as_ref() == "pair" {
            let (Some(key), Some(value)) = (field.field("key"), field.field("value")) else {
                return false;
            };
            let key = match key.kind().as_ref() {
                "property_identifier" => key.text().into_owned(),
                "string" if !key.text().contains('\\') => {
                    let text = key.text();
                    let Some(value) = super::exact_quoted(&text) else {
                        return false;
                    };
                    value.to_string()
                }
                _ => return false,
            };
            (key, value)
        } else if field.kind().as_ref() == "shorthand_property_identifier" {
            (field.text().into_owned(), field.clone())
        } else {
            return false;
        };
        if key == "__proto__" || !keys.insert(key.clone()) {
            return false;
        }
        let mut output = prefix.to_vec();
        output.push(key);
        if value.kind().as_ref() == "object" {
            if !collect_fields(&value, parameters, &output, fields, work) {
                return false;
            }
        } else if let Some(access) = (value.kind().as_ref() == "shorthand_property_identifier")
            .then(|| vec![value.text().into_owned()])
            .or_else(|| super::super::security_paths::node_static_access(&value, 0))
        {
            let Some(index) = parameters.iter().position(|p| p == &access[0]) else {
                return false;
            };
            fields.insert(output, (index, access[1..].to_vec()));
        } else if !matches!(
            value.kind().as_ref(),
            "string" | "number" | "true" | "false" | "null"
        ) {
            return false;
        }
    }
    true
}
