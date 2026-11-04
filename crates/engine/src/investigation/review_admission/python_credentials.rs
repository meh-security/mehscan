//! Bounded password-state effects, including services outside HTTP decorators.
//! ORM/API shape establishes a review lead, not persistence, caller authority,
//! credential purpose, token invalidation or a vulnerability verdict.
use super::*;
use ast_grep_core::Node;
use ast_grep_language::SupportLang;

type PyNode<'a> = Node<'a, StrDoc<SupportLang>>;

#[derive(Default)]
struct Imports {
    sqlalchemy: BTreeSet<String>,
    select: BTreeSet<String>,
    model_modules: BTreeSet<String>,
    model_types: BTreeSet<String>,
    casts: BTreeSet<String>,
    django_auth: bool,
}

fn owner(node: &PyNode<'_>) -> Option<std::ops::Range<usize>> {
    node.ancestors()
        .find(|n| matches!(n.kind().as_ref(), "function_definition" | "lambda"))
        .map(|n| n.range())
}

fn compact(text: &str) -> String {
    text.split_whitespace().collect()
}

fn import_names(node: &PyNode<'_>) -> Vec<(String, String, String)> {
    let source = node.text().replace(['(', ')', '\n', '\r'], " ");
    let (module, names) = if let Some(rest) = source.trim().strip_prefix("from ") {
        let Some((module, names)) = rest.split_once(" import ") else {
            return Vec::new();
        };
        (module.trim(), names)
    } else if let Some(names) = source.trim().strip_prefix("import ") {
        ("", names)
    } else {
        return Vec::new();
    };
    names
        .split(',')
        .filter_map(|name| {
            let name = name.trim();
            let (original, alias) = name.split_once(" as ").unwrap_or((name, name));
            (!original.is_empty() && original != "*").then(|| {
                (
                    module.to_string(),
                    original.trim().to_string(),
                    alias.trim().to_string(),
                )
            })
        })
        .collect()
}

fn visible(node: &PyNode<'_>, function: &PyNode<'_>) -> bool {
    // Class namespaces are not enclosing lexical scopes for bare names in
    // methods or unrelated functions. Do not borrow a class-local import.
    if node
        .ancestors()
        .find(|n| {
            matches!(
                n.kind().as_ref(),
                "function_definition" | "lambda" | "class_definition"
            )
        })
        .is_some_and(|n| n.kind().as_ref() == "class_definition")
    {
        return false;
    }
    owner(node).is_none_or(|range| range == function.range())
}

fn unshadowed(root: &PyNode<'_>, function: &PyNode<'_>, name: &str) -> bool {
    let imports = root
        .dfs()
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "import_statement" | "import_from_statement"
            ) && visible(n, function)
                && import_names(n).iter().any(|(_, _, alias)| alias == name)
        })
        .count();
    imports == 1
        && !root.dfs().any(|n| {
            if !visible(&n, function) {
                return false;
            }
            let binding = match n.kind().as_ref() {
                "assignment" | "augmented_assignment" | "named_expression" => {
                    n.field("left").or_else(|| n.field("name"))
                }
                "function_definition" | "class_definition" => n.field("name"),
                "for_statement" => n.field("left"),
                _ => None,
            };
            binding.is_some_and(|left| {
                left.text().as_ref() == name
                    || left
                        .field("object")
                        .is_some_and(|object| object.text().as_ref() == name)
                    || (matches!(left.kind().as_ref(), "pattern_list" | "tuple_pattern")
                        && left.dfs().any(|n| n.text().as_ref() == name))
            })
        })
        && !function.field("parameters").is_some_and(|parameters| {
            parameters.children().any(|p| {
                p.kind().as_ref() == "identifier" && p.text().as_ref() == name
                    || p.is_named()
                        && p.children()
                            .find(|n| n.kind().as_ref() == "identifier")
                            .is_some_and(|n| n.text().as_ref() == name)
            })
        })
}

fn imports(root: &PyNode<'_>, function: &PyNode<'_>) -> Imports {
    let mut result = Imports::default();
    for node in root.dfs().filter(|n| {
        matches!(
            n.kind().as_ref(),
            "import_statement" | "import_from_statement"
        ) && visible(n, function)
            && n.range().start < function.range().end
    }) {
        for (module, name, alias) in import_names(&node) {
            if !unshadowed(root, function, &alias) {
                continue;
            }
            if module == "" && name == "sqlalchemy" {
                result.sqlalchemy.insert(alias.clone());
            }
            if module == "sqlalchemy" && name == "select" {
                result.select.insert(alias.clone());
            }
            if module == "typing" && name == "cast" {
                result.casts.insert(alias.clone());
            }
            if module.starts_with("django.contrib.auth") {
                result.django_auth = true;
            }
            if name == "models" {
                result.model_modules.insert(alias.clone());
            }
            if module == "models" || module.ends_with(".models") {
                result.model_types.insert(alias);
            }
        }
    }
    result
}

fn model_type(node: &PyNode<'_>, imports: &Imports) -> bool {
    let text = compact(node.text().as_ref());
    imports.model_types.contains(&text)
        || text.split_once('.').is_some_and(|(module, name)| {
            imports.model_modules.contains(module) && !name.contains('.') && !name.is_empty()
        })
}

fn arguments<'a>(call: &PyNode<'a>) -> Vec<PyNode<'a>> {
    call.field("arguments")
        .map(|args| {
            args.children()
                .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
                .collect()
        })
        .unwrap_or_default()
}

fn sqlalchemy_row(expression: &PyNode<'_>, imports: &Imports) -> bool {
    let Some(function) = expression.field("function") else {
        return false;
    };
    let Some(method) = function.field("attribute") else {
        return false;
    };
    if !matches!(method.text().as_ref(), "scalar_one_or_none" | "scalar_one") {
        return false;
    }
    let Some(execute) = function
        .field("object")
        .filter(|n| n.kind().as_ref() == "call")
    else {
        return false;
    };
    if !execute
        .field("function")
        .and_then(|n| n.field("attribute"))
        .is_some_and(|n| n.text().as_ref() == "execute")
    {
        return false;
    }
    arguments(&execute).first().is_some_and(|query| {
        query.dfs().any(|n| {
            n.kind().as_ref() == "call"
                && n.field("function").is_some_and(|f| {
                    let text = compact(f.text().as_ref());
                    imports.select.contains(&text)
                        || imports
                            .sqlalchemy
                            .iter()
                            .any(|m| text == format!("{m}.select"))
                })
        })
    })
}

fn django_row(expression: &PyNode<'_>, imports: &Imports) -> bool {
    if !imports.django_auth {
        return false;
    }
    let Some(function) = expression.field("function") else {
        return false;
    };
    if !function
        .field("attribute")
        .is_some_and(|n| n.text().as_ref() == "get")
    {
        return false;
    }
    function.field("object").is_some_and(|manager| {
        manager
            .field("attribute")
            .is_some_and(|n| n.text().as_ref() == "objects")
            && manager
                .field("object")
                .is_some_and(|model| model_type(&model, imports))
    })
}

fn entity(
    expression: &PyNode<'_>,
    function: &PyNode<'_>,
    imports: &Imports,
    before: usize,
    depth: usize,
) -> bool {
    if depth > 4 {
        return false;
    }
    if expression.kind().as_ref() == "call" {
        if sqlalchemy_row(expression, imports) || django_row(expression, imports) {
            return true;
        }
        let Some(callee) = expression.field("function") else {
            return false;
        };
        let args = arguments(expression);
        // A typed Django model cast provides a bounded type/API lead, not an
        // assertion that a GraphQL context is authenticated or caller-bound.
        if imports.django_auth
            && imports.casts.contains(callee.text().as_ref())
            && args.len() == 2
            && model_type(&args[0], imports)
        {
            return true;
        }
        // Preserve the model-shaped fallback in a guarded lookup failure branch.
        // It must be the same imported model queried in this function, not an
        // arbitrary constructor whose name resembles an account.
        return imports.django_auth
            && args.is_empty()
            && model_type(&callee, imports)
            && function.dfs().any(|n| {
                owner(&n) == Some(function.range())
                    && n.range().start < before
                    && django_row(&n, imports)
                    && n.field("function")
                        .and_then(|f| f.field("object"))
                        .and_then(|m| m.field("object"))
                        .is_some_and(|m| m.text() == callee.text())
            });
    }
    if expression.kind().as_ref() != "identifier" {
        return false;
    }
    let name = expression.text();
    if function.dfs().any(|n| {
        owner(&n) == Some(function.range()) && n.range().start < before && {
            match n.kind().as_ref() {
                "for_statement" | "augmented_assignment" | "named_expression" => {
                    n.field("left").or_else(|| n.field("name"))
                }
                "as_pattern" => n.field("alias"),
                _ => None,
            }
            .is_some_and(|binding| {
                binding
                    .dfs()
                    .any(|n| n.kind().as_ref() == "identifier" && n.text() == name)
            })
        }
    }) {
        return false;
    }
    if function.dfs().any(|n| {
        n.kind().as_ref() == "assignment"
            && owner(&n) == Some(function.range())
            && n.range().start < before
            && n.field("left").is_some_and(|left| {
                let text = compact(left.text().as_ref());
                text == format!("{name}.set_password")
                    || text == format!("{name}.set_unusable_password")
                    || matches!(left.kind().as_ref(), "pattern_list" | "tuple_pattern")
                        && left
                            .dfs()
                            .any(|n| n.kind().as_ref() == "identifier" && n.text() == name)
            })
    }) {
        return false;
    }
    let assignments = function
        .dfs()
        .filter(|n| {
            n.kind().as_ref() == "assignment"
                && owner(n) == Some(function.range())
                && n.range().end <= before
                && n.field("left").is_some_and(|left| left.text() == name)
        })
        .collect::<Vec<_>>();
    let start = assignments
        .iter()
        .rposition(|n| {
            !n.ancestors()
                .take_while(|n| n.range() != function.range())
                .any(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "if_statement"
                            | "try_statement"
                            | "for_statement"
                            | "while_statement"
                            | "with_statement"
                            | "match_statement"
                    )
                })
        })
        .unwrap_or(0);
    !assignments.is_empty()
        && assignments[start..].iter().all(|n| {
            n.field("right")
                .is_some_and(|right| entity(&right, function, imports, n.range().start, depth + 1))
        })
}

pub(super) fn inspect(
    file: &SourceFile,
    spans: &[(usize, usize)],
) -> BTreeMap<usize, ServerMutationMarker> {
    let mut markers = BTreeMap::new();
    if file.language != Some(Language::Python)
        || !["password", "passwd"]
            .iter()
            .any(|s| file.source.contains(s))
    {
        return markers;
    }
    let Ok(document) = StrDoc::try_new(&file.source, parser_language(Language::Python)) else {
        return markers;
    };
    let ast = AstGrep::doc(document);
    let root = ast.root();
    if root.dfs().any(|n| n.is_error() || n.is_missing()) {
        return markers;
    }
    for function in root
        .dfs()
        .filter(|n| n.kind().as_ref() == "function_definition")
    {
        let Some(name) = function.field("name") else {
            continue;
        };
        // Resolve imports only for a syntactic effect with a potentially bound
        // receiver. Most functions in account/model files merely read fields;
        // repeating whole-file binding scans for them is quadratic wasted work.
        let mut imported = None;
        let effect = function.dfs().find_map(|node| {
            if owner(&node) != Some(function.range()) {
                return None;
            }
            let (receiver, basis) = match node.kind().as_ref() {
                "assignment" => {
                    let left = node.field("left")?;
                    let attribute = left.field("attribute")?;
                    if !matches!(
                        attribute.text().as_ref(),
                        "password" | "password_hash" | "passwd"
                    ) || node.field("right").is_none()
                    {
                        return None;
                    }
                    (
                        left.field("object")?,
                        "ORM/type-bound entity password-field assignment",
                    )
                }
                "call" => {
                    let callee = node.field("function")?;
                    let method = callee.field("attribute")?;
                    if !(method.text().as_ref() == "set_password" && !arguments(&node).is_empty()
                        || method.text().as_ref() == "set_unusable_password"
                            && arguments(&node).is_empty())
                    {
                        return None;
                    }
                    (
                        callee.field("object")?,
                        "ORM/type-bound password setter invocation",
                    )
                }
                _ => return None,
            };
            if receiver.kind().as_ref() == "identifier"
                && !function.dfs().any(|n| {
                    n.kind().as_ref() == "assignment"
                        && owner(&n) == Some(function.range())
                        && n.range().end <= node.range().start
                        && n.field("left")
                            .is_some_and(|left| left.text() == receiver.text())
                })
            {
                return None;
            }
            let imports = imported.get_or_insert_with(|| imports(&root, &function));
            entity(&receiver, &function, imports, node.range().start, 0)
                .then(|| (node.range(), basis))
        });
        let Some((range, basis)) = effect else {
            continue;
        };
        let start_index = spans.partition_point(|(_, end)| *end <= function.range().start);
        let end_index = spans
            .partition_point(|(start, _)| *start < function.range().end)
            .saturating_sub(1)
            .min(start_index + 119);
        if spans[end_index].1 < range.end {
            continue;
        }
        markers.insert(
            start_index,
            ServerMutationMarker {
                start_index,
                end_index,
                symbol: name.text().into_owned(),
                effect: "credential-password-write".into(),
                related_handlers: Vec::new(),
                credential_effect: Some((range, basis)),
            },
        );
    }
    markers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symbols(source: &str) -> BTreeSet<String> {
        let file = SourceFile {
            path: "service.py".into(),
            language: Some(Language::Python),
            source: source.into(),
        };
        inspect(&file, &line_spans(source))
            .into_values()
            .map(|m| m.symbol)
            .collect()
    }

    #[test]
    fn services_bind_real_password_writes_to_orm_results_and_typed_setters() {
        let source = r#"
import sqlalchemy as sa
from django.contrib.auth import password_validation
from typing import cast
from accounts import models
def apply(db, subject, next_value):
    record = db.session.execute(sa.select(subject).filter_by(id=7)).scalar_one_or_none()
    if record is None:
        raise ValueError()
    record.password = next_value
def complete(email, value, token):
    try:
        record = models.Member.objects.get(email=email)
    except Missing:
        record = models.Member()
    if not verify(record, token):
        raise ValueError()
    record.set_password(value)
    record.save()
def change(context, value):
    record = context.subject
    record = cast(models.Member, record)
    record.set_password(value)
"#;
        assert_eq!(
            symbols(source),
            BTreeSet::from(["apply".into(), "complete".into(), "change".into()])
        );
    }

    #[test]
    fn one_use_and_password_state_controls_remain_reviewable_without_a_verdict() {
        let source = r#"
from django.contrib.auth import password_validation
from accounts import models
def one_use(id, value, token):
    record = models.Member.objects.get(id=id)
    consume_once(token, record.id)
    record.set_password(value)
    record.save()
def state_bound(id, value, token):
    record = models.Member.objects.get(id=id)
    if not generator.check_token(record, token):
        raise ValueError()
    record.set_password(value)
    record.save()
"#;
        assert_eq!(
            symbols(source),
            BTreeSet::from(["one_use".into(), "state_bound".into()])
        );
    }

    #[test]
    fn names_strings_reads_and_unrelated_setters_do_not_admit_effects() {
        let source = r#"
import sqlalchemy as sa
from django.contrib.auth import password_validation
from accounts import models
def reset_password(obj, value):
    obj.set_password(value)
    return "record.password = value"
def demonstrate(db, model, value):
    record = db.session.execute(sa.select(model)).scalar_one_or_none()
    return record.password == value
def token_only():
    return random_token()
def documented():
    '''record.password = value'''
    # record.set_password(value)
"#;
        assert!(symbols(source).is_empty());
    }

    #[test]
    fn receiver_module_shadowing_and_rebinding_abstain() {
        for tail in [
            "record = incoming",
            "if flag:\n        record = incoming",
            "record, other = incoming",
            "for record in incoming:\n        pass",
            "record.set_password = incoming",
        ] {
            let source = format!(
                "import sqlalchemy as sa\ndef apply(db, model, incoming, flag, value):\n    record = db.session.execute(sa.select(model)).scalar_one_or_none()\n    {tail}\n    record.set_password(value)\n"
            );
            assert!(symbols(&source).is_empty(), "{tail}");
        }
        for prefix in ["sa = replacement\n", "sa.select = replacement\n"] {
            let source = format!(
                "import sqlalchemy as sa\n{prefix}def apply(db, model, value):\n    record = db.session.execute(sa.select(model)).scalar_one_or_none()\n    record.password = value\n"
            );
            assert!(symbols(&source).is_empty(), "{prefix}");
        }
        let source = "import sqlalchemy as sa\ndef apply(sa, db, model, value):\n    record = db.session.execute(sa.select(model)).scalar_one_or_none()\n    record.password = value\n";
        assert!(symbols(source).is_empty());
    }

    #[test]
    fn nested_effect_belongs_only_to_its_implementation() {
        let source = r#"
from sqlalchemy import select as choose
def wrapper():
    def implementation(db, model, value):
        record = db.session.execute(choose(model)).scalar_one()
        record.password_hash = value
    return implementation
"#;
        assert_eq!(symbols(source), BTreeSet::from(["implementation".into()]));
    }

    #[test]
    fn class_local_import_does_not_bind_an_unrelated_bare_name() {
        let source = r#"
class Other:
    import sqlalchemy as sa
def apply(db, model, value):
    record = db.session.execute(sa.select(model)).scalar_one()
    record.password = value
"#;
        assert!(symbols(source).is_empty());
    }
}
