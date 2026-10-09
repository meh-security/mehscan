//! Local construction, scalar equality and repeated lookup accounting. No CFG,
//! cross-file taint, owner-hint closure or framework-wide method safe list.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{Capability, Evidence, EvidenceKind, Language, OperandFact, OperandFactKind};
use std::collections::{BTreeMap, BTreeSet};

type N<'a> = Node<'a, StrDoc<SupportLang>>;
const BUILDER: &str = "query-construction:sql-builder";

pub(super) fn annotate(language: Language, root: &N<'_>, evidence: &mut Vec<Evidence>) {
    let needs_sql = matches!(
        language,
        Language::Php
            | Language::Javascript
            | Language::Typescript
            | Language::Tsx
            | Language::Java
            | Language::Kotlin
    ) && evidence
        .iter()
        .any(|e| e.kind == EvidenceKind::Sink && e.cwe_candidates == ["CWE-89"]);
    if !needs_sql && !evidence.iter().any(orm) {
        return;
    }
    let ranges = evidence
        .iter()
        .flat_map(|e| {
            std::iter::once((e.location.start.byte_offset, e.location.end.byte_offset)).chain(
                e.captures
                    .values()
                    .map(|c| (c.location.start.byte_offset, c.location.end.byte_offset)),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut nodes = BTreeMap::new();
    let mut calls = BTreeMap::<usize, Vec<N<'_>>>::new();
    for n in root.dfs() {
        if ranges.contains(&(n.range().start, n.range().end)) {
            nodes.insert((n.range().start, n.range().end), n.clone());
        }
        if needs_sql && is_call(&n) {
            calls
                .entry(scope(&n).map_or(0, |s| s.range().start))
                .or_default()
                .push(n);
        }
    }
    for e in evidence
        .iter_mut()
        .filter(|e| e.kind == EvidenceKind::Sink && e.cwe_candidates == ["CWE-89"])
    {
        let Some(n) = nodes.get(&(e.location.start.byte_offset, e.location.end.byte_offset)) else {
            continue;
        };
        let Some((receiver, method, _)) = call(n) else {
            continue;
        };
        let builder = match language {
            Language::Php => e.rule_id == "php-extended-sql-facade" && method == "raw",
            Language::Javascript | Language::Typescript | Language::Tsx => {
                method == "raw"
                    && e.rule_id.ends_with("-extended-sql-query")
                    && receiver
                        .as_ref()
                        .is_some_and(|r| super::database_receiver::knex_receiver(root, r, language))
            }
            Language::Java | Language::Kotlin => {
                matches!(
                    method.as_str(),
                    "createQuery"
                        | "createNativeQuery"
                        | "createSQLQuery"
                        | "preparedQuery"
                        | "prepareStatement"
                        | "prepareCall"
                ) && (e.rule_id == "java-typed-persistence-query"
                    || e.rule_id == "java-database-query"
                    || e.rule_id.ends_with("-extended-sql-query")
                    || e.rule_id == "kotlin-persistence-query"
                    || e.rule_id.contains("jdbc"))
            }
            _ => false,
        };
        if !builder {
            continue;
        }
        e.tags.push(BUILDER.into());
        if let Some(awaited) = n
            .ancestors()
            .take_while(|p| {
                matches!(
                    p.kind().as_ref(),
                    "parenthesized_expression" | "await_expression" | "await"
                )
            })
            .find(|p| matches!(p.kind().as_ref(), "await_expression" | "await"))
        {
            e.captures.insert(
                "query_execution".into(),
                super::node_operands::capture_at("", e, &awaited),
            );
        }
        let candidates = calls
            .get(&scope(n).map_or(0, |s| s.range().start))
            .into_iter()
            .flatten();
        let bound = binding(n);
        for consumer in candidates {
            let Some((receiver, method, _)) = call(consumer) else {
                continue;
            };
            let terminal = match language {
                Language::Php => matches!(
                    method.as_str(),
                    "get"
                        | "first"
                        | "value"
                        | "pluck"
                        | "cursor"
                        | "update"
                        | "delete"
                        | "insert"
                        | "execute"
                        | "executeQuery"
                        | "executeStatement"
                ),
                Language::Java | Language::Kotlin => matches!(
                    method.as_str(),
                    "getResultList"
                        | "getSingleResult"
                        | "getResultStream"
                        | "list"
                        | "uniqueResult"
                        | "executeUpdate"
                        | "execute"
                        | "executeQuery"
                        | "executeBatch"
                ),
                _ => matches!(method.as_str(), "then" | "asCallback" | "stream" | "pipe"),
            };
            if !terminal {
                continue;
            }
            let inline =
                consumer.range().start <= n.range().start && n.range().end <= consumer.range().end;
            let local = bound.as_ref().is_some_and(|(b, name)| {
                receiver.as_ref().is_some_and(|r| r.text().trim() == name)
                    && consumer.range().start >= b.range().end
                    && locally_visible(b, consumer)
                    && receiver.as_ref().is_some_and(|r| primitive_unchanged(b, r))
            });
            if inline || local {
                e.captures.insert(
                    "query_execution".into(),
                    super::node_operands::capture_at("", e, consumer),
                );
                break;
            }
        }
    }
    attach_reloads(language, root, &nodes, evidence);
}

pub(super) fn close_equalities<'a>(language: Language, root: &N<'a>, evidence: &mut Vec<Evidence>) {
    if !matches!(
        language,
        Language::Csharp
            | Language::Java
            | Language::Kotlin
            | Language::Javascript
            | Language::Typescript
            | Language::Tsx
            | Language::Python
            | Language::Php
    ) {
        return;
    }
    let ranges = evidence
        .iter()
        .filter(|e| e.kind == EvidenceKind::Sink && e.cwe_candidates == ["CWE-943"])
        .filter_map(|e| {
            e.captures
                .get("nosql_query")
                .or_else(|| e.captures.get("filter"))
        })
        .map(|c| (c.location.start.byte_offset, c.location.end.byte_offset))
        .chain(
            evidence
                .iter()
                .filter(|e| e.cwe_candidates == ["CWE-943"])
                .map(|e| (e.location.start.byte_offset, e.location.end.byte_offset)),
        )
        .collect::<BTreeSet<_>>();
    if ranges.is_empty() {
        return;
    }
    let nodes = root
        .dfs()
        .filter(|n| ranges.contains(&(n.range().start, n.range().end)))
        .map(|n| ((n.range().start, n.range().end), n))
        .collect::<BTreeMap<_, _>>();
    // Equality closure removes only the interpretation question. Resource and
    // write-policy observations are separate and never touched here.
    evidence.retain(|e| {
        if e.kind != EvidenceKind::Sink
            || e.capability != Capability::DatabaseQuery
            || e.cwe_candidates != ["CWE-943"]
        {
            return true;
        }
        if !(e.rule_id.ends_with("-extended-nosql-query")
            || e.rule_id == "php-extended-nosql-execution")
        {
            return true;
        }
        let operation = nodes
            .get(&(e.location.start.byte_offset, e.location.end.byte_offset))
            .and_then(call)
            .map(|(_, method, _)| method);
        if !operation.is_some_and(|m| {
            matches!(
                m.as_str(),
                "find"
                    | "findOne"
                    | "find_one"
                    | "countDocuments"
                    | "count_documents"
                    | "deleteOne"
                    | "deleteMany"
                    | "delete_one"
                    | "delete_many"
                    | "updateOne"
                    | "updateMany"
                    | "update_one"
                    | "update_many"
                    | "replaceOne"
                    | "replace_one"
                    | "findOneAndUpdate"
                    | "findOneAndDelete"
                    | "find_one_and_update"
                    | "find_one_and_delete"
                    | "Find"
                    | "FindAsync"
                    | "CountDocuments"
                    | "DeleteOne"
                    | "DeleteMany"
                    | "UpdateOne"
                    | "UpdateMany"
                    | "ReplaceOne"
                    | "FindOneAndUpdate"
                    | "executeQuery"
            )
        }) {
            return true;
        }
        let Some(q) = e
            .captures
            .get("nosql_query")
            .or_else(|| e.captures.get("filter"))
        else {
            return true;
        };
        let Some(n) = nodes.get(&(q.location.start.byte_offset, q.location.end.byte_offset)) else {
            return true;
        };
        !equality(root, n, language, 3)
    });
    let referenced = evidence
        .iter()
        .flat_map(|e| e.related_evidence.iter().cloned())
        .collect::<BTreeSet<_>>();
    evidence.retain(|e| {
        !(e.kind == EvidenceKind::Resource
            && e.cwe_candidates == ["CWE-943"]
            && e.tags.iter().any(|t| t == "query-construction:consumed")
            && !referenced.contains(&e.id))
    });
}

fn orm(e: &Evidence) -> bool {
    e.kind == EvidenceKind::Sink
        && e.capability == Capability::ResourceAccess
        && e.cwe_candidates == ["CWE-639"]
        && (e.rule_id == "csharp-ef-unscoped-resource-query"
            || e.rule_id == "python-django-orm-resource-access"
            || e.rule_id.ends_with("-sequelize-resource-access"))
}

fn scope<'a>(n: &N<'a>) -> Option<N<'a>> {
    n.ancestors().find(|n| {
        matches!(
            n.kind().as_ref(),
            "method_declaration"
                | "constructor_declaration"
                | "function_definition"
                | "function_declaration"
                | "method_definition"
                | "arrow_function"
                | "function_expression"
                | "lambda_expression"
                | "lambda_literal"
        )
    })
}

fn unwrap<'a>(n: &N<'a>) -> N<'a> {
    let mut n = n.clone();
    for _ in 0..3 {
        if !matches!(
            n.kind().as_ref(),
            "await_expression" | "await" | "parenthesized_expression" | "literal_element"
        ) {
            break;
        }
        let Some(next) = n.children().find(|c| c.is_named()) else {
            break;
        };
        n = next;
    }
    n
}

fn call<'a>(n: &N<'a>) -> Option<(Option<N<'a>>, String, Vec<N<'a>>)> {
    if !is_call(n) {
        return None;
    }
    let function = n.field("function").or_else(|| {
        n.children()
            .find(|c| c.kind().as_ref() == "navigation_expression")
    });
    let receiver = n
        .field("object")
        .or_else(|| n.field("scope"))
        .or_else(|| {
            function.as_ref().and_then(|f| {
                f.field("object")
                    .or_else(|| f.field("expression"))
                    .or_else(|| f.field("value"))
            })
        })
        .or_else(|| {
            function
                .as_ref()
                .filter(|f| f.kind().as_ref() == "navigation_expression")
                .and_then(|f| f.children().find(|c| c.is_named()))
        });
    let method = n
        .field("name")
        .or_else(|| {
            function.as_ref().and_then(|f| {
                f.field("property")
                    .or_else(|| f.field("attribute"))
                    .or_else(|| f.field("name"))
                    .or_else(|| f.field("field"))
            })
        })
        .map(|n| n.text().into_owned())
        .or_else(|| {
            function
                .as_ref()
                .map(|f| f.text().rsplit('.').next().unwrap_or("").to_string())
        })?;
    let method = method.split('<').next().unwrap_or(&method).to_string();
    let args = n
        .field("arguments")
        .or_else(|| {
            n.children()
                .find(|c| c.kind().as_ref() == "call_suffix")
                .and_then(|c| {
                    c.children()
                        .find(|c| c.kind().as_ref() == "value_arguments")
                })
        })
        .map(|args| {
            args.children()
                .filter(|n| n.is_named())
                .filter(|n| n.kind().as_ref() != "comment")
                .map(|a| {
                    if matches!(a.kind().as_ref(), "argument" | "value_argument") {
                        a.children().filter(|n| n.is_named()).last().unwrap_or(a)
                    } else {
                        a
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    Some((receiver, method, args))
}

fn is_call(n: &N<'_>) -> bool {
    matches!(
        n.kind().as_ref(),
        "call"
            | "call_expression"
            | "invocation_expression"
            | "method_invocation"
            | "member_call_expression"
            | "scoped_call_expression"
    )
}

fn binding<'a>(origin: &N<'a>) -> Option<(N<'a>, String)> {
    let mut origin = origin.clone();
    while let Some(parent) = origin.parent() {
        if matches!(
            parent.kind().as_ref(),
            "await_expression" | "await" | "parenthesized_expression" | "equals_value_clause"
        ) {
            origin = parent;
        } else {
            break;
        }
    }
    let b = origin.parent()?;
    if !matches!(
        b.kind().as_ref(),
        "variable_declarator" | "assignment" | "assignment_expression" | "property_declaration"
    ) {
        return None;
    }
    let name = b.field("name").or_else(|| b.field("left")).or_else(|| {
        b.children()
            .find(|n| n.kind().as_ref() == "variable_declaration")
            .and_then(|d| {
                d.children()
                    .find(|n| n.kind().as_ref() == "simple_identifier")
            })
    })?;
    matches!(
        name.kind().as_ref(),
        "identifier" | "simple_identifier" | "variable_name"
    )
    .then(|| (b, name.text().into_owned()))
}

pub(super) fn unused_local_builder(n: &N<'_>) -> bool {
    if n.ancestors()
        .take_while(|p| {
            matches!(
                p.kind().as_ref(),
                "parenthesized_expression" | "await_expression" | "await"
            )
        })
        .any(|p| matches!(p.kind().as_ref(), "await_expression" | "await"))
    {
        return false;
    }
    let mut origin = n.clone();
    while let Some(parent) = origin.parent() {
        if parent.kind().as_ref() == "parenthesized_expression" {
            origin = parent;
        } else {
            break;
        }
    }
    if origin
        .parent()
        .is_some_and(|p| p.kind().as_ref() == "expression_statement")
    {
        return true;
    }
    let Some((b, name)) = binding(n) else {
        return false;
    };
    let Some(s) = scope(&b) else {
        return false;
    };
    !s.dfs().any(|use_site| {
        matches!(
            use_site.kind().as_ref(),
            "identifier" | "simple_identifier" | "variable_name"
        ) && use_site.text().as_ref() == name
            && !(b.range().start <= use_site.range().start && use_site.range().end <= b.range().end)
    })
}

fn quoted(n: &N<'_>) -> Option<String> {
    let t = n.text();
    let t = t.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
        && !t[1..t.len() - 1].contains(['\\', '{', '$'])
    {
        Some(t[1..t.len() - 1].into())
    } else {
        None
    }
}

fn pairs<'a>(n: &N<'a>) -> Option<Vec<(String, N<'a>)>> {
    let n = unwrap(n);
    if !matches!(
        n.kind().as_ref(),
        "object" | "dictionary" | "array_creation_expression" | "literal_value"
    ) {
        return None;
    }
    let mut pairs = vec![];
    let mut keys = BTreeSet::new();
    for p in n
        .children()
        .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
    {
        let (key, value) = if let (Some(k), Some(v)) = (p.field("key"), p.field("value")) {
            (k, v)
        } else if matches!(
            p.kind().as_ref(),
            "array_element_initializer" | "keyed_element"
        ) {
            let children = p.children().filter(|n| n.is_named()).collect::<Vec<_>>();
            if children.len() != 2 {
                return None;
            }
            (unwrap(&children[0]), unwrap(&children[1]))
        } else {
            return None;
        };
        let key = quoted(&key).or_else(|| {
            (key.kind().as_ref() == "property_identifier").then(|| key.text().into_owned())
        })?;
        if !keys.insert(key.clone()) {
            return None;
        }
        pairs.push((key, value));
    }
    (!pairs.is_empty()).then_some(pairs)
}

fn equality<'a>(root: &N<'a>, n: &N<'a>, lang: Language, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    let n = unwrap(n);
    if let Some(fields) = pairs(&n) {
        return fields.iter().all(|(key, value)| {
            !key.starts_with('$')
                && !matches!(key.as_str(), "__proto__" | "prototype" | "constructor")
                && (scalar(root, value, lang, 2)
                    || pairs(value).is_some_and(|p| {
                        p.len() == 1 && p[0].0 == "$eq" && scalar(root, &p[0].1, lang, 2)
                    }))
        });
    }
    if let Some((receiver, method, args)) = call(&n) {
        if args.len() == 2 && matches!(method.as_str(), "Eq" | "eq") {
            let owned = match lang {
                Language::Java | Language::Kotlin => receiver.as_ref().is_some_and(|r| {
                    super::extended_database::exact_symbol(
                        root,
                        &n,
                        r.text().as_ref(),
                        "com.mongodb.client.model.Filters",
                        lang,
                    )
                }),
                Language::Csharp => receiver.as_ref().is_some_and(|r| {
                    let t = r.text();
                    let Some(b) = t.strip_suffix(".Filter") else {
                        return false;
                    };
                    super::extended_database::exact_symbol(
                        root,
                        &n,
                        b,
                        "MongoDB.Driver.Builders",
                        lang,
                    )
                }),
                _ => false,
            };
            let field = quoted(&args[0]).is_some_and(|s| !s.starts_with('$'))
                || (lang == Language::Csharp && direct_lambda_member(&args[0]));
            return owned && field && scalar(root, &args[1], lang, 2);
        }
    }
    if n.kind().as_ref() == "object_creation_expression" {
        if let Some(t) = n.field("type") {
            let owned = match lang {
                Language::Java => super::extended_database::exact_symbol(
                    root,
                    &n,
                    t.text().as_ref(),
                    "org.bson.Document",
                    lang,
                ),
                Language::Csharp => super::extended_database::exact_symbol(
                    root,
                    &n,
                    t.text().as_ref(),
                    "MongoDB.Bson.BsonDocument",
                    lang,
                ),
                _ => false,
            };
            let args = n
                .field("arguments")
                .map(|args| {
                    args.children()
                        .filter(|a| a.is_named())
                        .map(|a| {
                            if a.kind().as_ref() == "argument" {
                                a.children().filter(|n| n.is_named()).last().unwrap_or(a)
                            } else {
                                a
                            }
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            return owned
                && args.len() == 2
                && quoted(&args[0]).is_some_and(|s| !s.starts_with('$'))
                && scalar(root, &args[1], lang, 2);
        }
    }
    if matches!(
        n.kind().as_ref(),
        "identifier" | "variable_name" | "simple_identifier"
    ) {
        if let Some((b, value)) = local_value(root, &n) {
            return unchanged(&b, &n) && equality(root, &value, lang, depth - 1);
        }
    }
    false
}

fn scalar<'a>(root: &N<'a>, n: &N<'a>, lang: Language, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    let n = unwrap(n);
    if matches!(
        n.kind().as_ref(),
        "string"
            | "string_literal"
            | "interpreted_string_literal"
            | "raw_string_literal"
            | "template_string"
            | "interpolated_string_expression"
            | "integer"
            | "integer_literal"
            | "int_literal"
            | "decimal_integer_literal"
            | "real_literal"
            | "float"
            | "float_literal"
            | "number"
            | "true"
            | "false"
            | "boolean_literal"
            | "null"
            | "null_literal"
            | "nil"
    ) {
        return true;
    }
    if let Some((receiver, method, args)) = call(&n) {
        if matches!(
            (lang, method.as_str()),
            (Language::Csharp, "ToString") | (Language::Kotlin, "toString")
        ) && receiver
            .as_ref()
            .is_some_and(|r| scalar(root, r, lang, depth - 1))
        {
            return true;
        }
        let builtin = receiver.is_none()
            && args.len() == 1
            && match lang {
                Language::Javascript | Language::Typescript | Language::Tsx => {
                    matches!(method.as_str(), "String" | "Number" | "Boolean")
                }
                Language::Python => matches!(method.as_str(), "str" | "int" | "float" | "bool"),
                _ => false,
            };
        if builtin && !shadowed(root, &n, &method) {
            return true;
        }
    }
    if lang == Language::Php && n.kind().as_ref() == "cast_expression" {
        return n.field("type").is_some_and(|t| {
            matches!(
                t.text().trim(),
                "string" | "int" | "integer" | "float" | "double" | "bool" | "boolean"
            )
        });
    }
    if matches!(
        n.kind().as_ref(),
        "identifier" | "variable_name" | "simple_identifier"
    ) {
        let bindings = visible_bindings(root, &n);
        if bindings.len() != 1 {
            return false;
        }
        let b = &bindings[0];
        let kind = b
            .field("type")
            .or_else(|| b.parent().and_then(|p| p.field("type")))
            .or_else(|| {
                (lang == Language::Kotlin)
                    .then(|| {
                        b.children()
                            .find(|c| matches!(c.kind().as_ref(), "user_type" | "nullable_type"))
                    })
                    .flatten()
            })
            .map(|t| t.text().into_owned())
            .unwrap_or_default();
        let typed = match lang {
            Language::Csharp => {
                matches!(
                    kind.as_str(),
                    "string"
                        | "int"
                        | "long"
                        | "short"
                        | "byte"
                        | "sbyte"
                        | "uint"
                        | "ulong"
                        | "ushort"
                        | "double"
                        | "float"
                        | "decimal"
                        | "bool"
                        | "char"
                ) || [
                    "System.String",
                    "System.Guid",
                    "System.DateTime",
                    "System.DateOnly",
                    "System.TimeOnly",
                    "System.TimeSpan",
                    "System.DateTimeOffset",
                ]
                .iter()
                .any(|canonical| {
                    super::extended_database::exact_symbol(root, &n, &kind, canonical, lang)
                })
            }
            Language::Kotlin => [
                "kotlin.String",
                "kotlin.Int",
                "kotlin.Long",
                "kotlin.Short",
                "kotlin.Byte",
                "kotlin.Double",
                "kotlin.Float",
                "kotlin.Boolean",
                "kotlin.Char",
            ]
            .iter()
            .any(|canonical| super::kotlin::exact_symbol(root, &n, &kind, canonical)),
            Language::Java => {
                matches!(
                    kind.as_str(),
                    "String"
                        | "java.lang.String"
                        | "int"
                        | "long"
                        | "short"
                        | "byte"
                        | "double"
                        | "float"
                        | "boolean"
                        | "char"
                ) && !shadowed_type(root, kind.split('.').next_back().unwrap_or(&kind))
                    && !(kind == "String"
                        && root
                            .children()
                            .filter(|n| n.kind().as_ref() == "import_declaration")
                            .any(|n| {
                                let t = n.text();
                                let t = t.trim().trim_end_matches(';');
                                t.ends_with(".String") && t != "import java.lang.String"
                            }))
            }
            Language::Php => matches!(kind.as_str(), "string" | "int" | "float" | "bool"),
            _ => false, // TS/Python annotations do not enforce runtime scalar shape.
        };
        if typed {
            return true;
        }
        if let Some((b, value)) = local_value(root, &n) {
            return (if lang == Language::Php {
                unchanged(&b, &n)
            } else {
                primitive_unchanged(&b, &n)
            }) && scalar(root, &value, lang, depth - 1);
        }
    }
    false
}

fn direct_lambda_member(n: &N<'_>) -> bool {
    if n.kind().as_ref() != "lambda_expression" {
        return false;
    }
    let Some(body) = n.field("body") else {
        return false;
    };
    if body.kind().as_ref() != "member_access_expression" {
        return false;
    }
    let Some(receiver) = body.field("expression") else {
        return false;
    };
    let parameter = n.field("parameters").or_else(|| {
        n.children()
            .find(|p| matches!(p.kind().as_ref(), "implicit_parameter" | "parameter_list"))
    });
    parameter.is_some_and(|p| p.text().trim_matches(['(', ')', ' ']) == receiver.text())
}

fn shadowed_type(root: &N<'_>, name: &str) -> bool {
    root.dfs().any(|n| {
        matches!(
            n.kind().as_ref(),
            "class_declaration" | "struct_declaration" | "struct_item" | "type_spec"
        ) && n.field("name").is_some_and(|n| n.text().as_ref() == name)
    })
}

fn shadowed(root: &N<'_>, use_site: &N<'_>, name: &str) -> bool {
    root.dfs().any(|n| {
        (n.field("name")
            .or_else(|| n.field("left"))
            .is_some_and(|n| n.text().as_ref() == name)
            || n.kind().as_ref() == "identifier"
                && n.text().as_ref() == name
                && n.parent().is_some_and(|p| {
                    matches!(p.kind().as_ref(), "parameters" | "formal_parameters")
                }))
            && (scope(&n).is_none()
                || scope(&n).map(|s| s.range()) == scope(use_site).map(|s| s.range()))
    })
}

fn visible_bindings<'a>(root: &N<'a>, use_site: &N<'a>) -> Vec<N<'a>> {
    let name = use_site.text();
    scope(use_site)
        .unwrap_or_else(|| root.clone())
        .dfs()
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "variable_declarator"
                    | "assignment"
                    | "assignment_expression"
                    | "parameter"
                    | "formal_parameter"
                    | "typed_parameter"
                    | "required_parameter"
                    | "simple_parameter"
                    | "parameter_declaration"
                    | "property_declaration"
                    | "let_declaration"
            )
        })
        .filter(|n| {
            n.range().start < use_site.range().start
                && scope(n).map(|s| s.range()) == scope(use_site).map(|s| s.range())
        })
        .filter(|n| {
            n.field("name")
                .or_else(|| n.field("left"))
                .or_else(|| n.field("pattern"))
                .or_else(|| {
                    (n.kind().as_ref() == "parameter")
                        .then(|| {
                            n.children()
                                .find(|c| c.kind().as_ref() == "simple_identifier")
                        })
                        .flatten()
                })
                .is_some_and(|n| n.text() == name)
                || n.kind().as_ref() == "property_declaration"
                    && n.children()
                        .find(|n| n.kind().as_ref() == "variable_declaration")
                        .is_some_and(|d| d.children().any(|n| n.text() == name))
        })
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "parameter"
                    | "formal_parameter"
                    | "typed_parameter"
                    | "required_parameter"
                    | "simple_parameter"
                    | "parameter_declaration"
            ) || locally_visible(n, use_site)
        })
        .collect()
}

fn locally_visible(binding: &N<'_>, site: &N<'_>) -> bool {
    super::context::lexical_declaration_visible_at(binding, site)
        || binding
            .ancestors()
            .find(|p| matches!(p.kind().as_ref(), "statement_block" | "statements"))
            .is_some_and(|p| {
                p.range().start <= site.range().start && site.range().end <= p.range().end
            })
}

fn local_value<'a>(root: &N<'a>, use_site: &N<'a>) -> Option<(N<'a>, N<'a>)> {
    let bindings = visible_bindings(root, use_site);
    let [b] = bindings.as_slice() else {
        return None;
    };
    let value = b.field("value").or_else(|| b.field("right")).or_else(|| {
        (b.kind().as_ref() == "property_declaration")
            .then(|| b.children().filter(|n| n.is_named()).last())
            .flatten()
    })?;
    Some((b.clone(), value))
}

fn unchanged(binding: &N<'_>, target: &N<'_>) -> bool {
    let Some(s) = scope(binding) else {
        return false;
    };
    let name = target.text();
    !s.dfs().any(|n| {
        n.range().start >= binding.range().end
            && n.range() != target.range()
            && matches!(
                n.kind().as_ref(),
                "identifier" | "simple_identifier" | "variable_name"
            )
            && n.text() == name
    })
}

fn primitive_unchanged(binding: &N<'_>, target: &N<'_>) -> bool {
    let Some(s) = scope(binding) else {
        return false;
    };
    let name = target.text();
    if s.dfs().any(|n| {
        n.range().start >= binding.range().end
            && n.range().start <= target.range().start
            && n.kind().as_ref() == "argument"
            && n.children().any(|c| c.text() == name)
            && n.children()
                .any(|c| matches!(c.text().as_ref(), "ref" | "out"))
    }) {
        return false;
    }
    !s.dfs().any(|n| {
        n.range().start >= binding.range().end
            && n.range().start <= target.range().start
            && n.field("left")
                .or_else(|| n.field("name"))
                .is_some_and(|v| v.text() == name)
            && matches!(
                n.kind().as_ref(),
                "assignment"
                    | "assignment_expression"
                    | "variable_declarator"
                    | "augmented_assignment"
            )
    })
}

fn statement<'a>(n: &N<'a>) -> Option<N<'a>> {
    n.ancestors().find(|n| {
        matches!(
            n.kind().as_ref(),
            "expression_statement"
                | "local_declaration_statement"
                | "lexical_declaration"
                | "return_statement"
        )
    })
}

fn attach_reloads<'a>(
    lang: Language,
    root: &N<'a>,
    nodes: &BTreeMap<(usize, usize), N<'a>>,
    evidence: &mut [Evidence],
) {
    let lookups = evidence
        .iter()
        .enumerate()
        .filter(|(_, e)| orm(e))
        .filter_map(|(i, e)| {
            let c = e.captures.get("filter")?;
            let n = nodes.get(&(c.location.start.byte_offset, c.location.end.byte_offset))?;
            let origin = n
                .ancestors()
                .find(|n| call(n).is_some())
                .or_else(|| call(n).is_some().then(|| n.clone()))?;
            let (receiver, method, args) = call(&origin)?;
            let receiver = receiver?;
            let selector = match lang {
                Language::Csharp
                    if matches!(method.as_str(), "Find" | "FindAsync") && args.len() == 1 =>
                {
                    args[0].clone()
                }
                Language::Python
                    if method == "get"
                        && args.len() == 1
                        && args[0].kind().as_ref() == "keyword_argument" =>
                {
                    if !args[0]
                        .field("name")
                        .is_some_and(|n| matches!(n.text().as_ref(), "pk" | "id"))
                    {
                        return None;
                    }
                    args[0].field("value")?
                }
                Language::Javascript | Language::Typescript | Language::Tsx
                    if method == "findOne" && args.len() == 1 =>
                {
                    let options = pairs(&args[0])?;
                    if options.len() != 1 || options[0].0 != "where" {
                        return None;
                    }
                    let fields = pairs(&options[0].1)?;
                    if fields.len() != 1 || fields[0].0 != "id" {
                        return None;
                    }
                    fields[0].1.clone()
                }
                _ => return None,
            };
            if !scalar(root, &selector, lang, 3) {
                return None;
            }
            Some((
                i,
                origin,
                receiver.text().into_owned(),
                method,
                selector.text().into_owned(),
            ))
        })
        .collect::<Vec<_>>();
    let mut attached = BTreeSet::new();
    for (i, initial, receiver, method, selector) in &lookups {
        if attached.contains(i) || binding(initial).is_none() {
            continue;
        }
        let Some(first_statement) = statement(initial) else {
            continue;
        };
        let Some(block) = first_statement.parent() else {
            continue;
        };
        let siblings = block
            .children()
            .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
            .collect::<Vec<_>>();
        let Some(next) = siblings
            .windows(2)
            .find(|w| w[0].range() == first_statement.range())
            .map(|w| w[1].clone())
        else {
            continue;
        };
        for (j, reload, r, m, key) in &lookups {
            if j == i
                || r != receiver
                || m != method
                || key != selector
                || scope(initial).map(|s| s.range()) != scope(reload).map(|s| s.range())
            {
                continue;
            }
            if !statement(reload).is_some_and(|s| s.range() == next.range()) {
                continue;
            }
            // Same stable scalar selector, manager/context and adjacent straight
            // line lookup: retain the original unknown authority verdict once.
            evidence[*i].related_evidence.push(evidence[*j].id.clone());
            evidence[*i].captures.insert(
                "resource_reload".into(),
                super::node_operands::capture_at("", &evidence[*i], reload),
            );
            evidence[*i].context.operand_facts.push(OperandFact {
                kind: OperandFactKind::QueryStructure,
                role: "filter".into(),
                location: evidence[*j].location.clone(),
                value: "identity_preserving_adjacent_reload".into(),
                remaining_checks: vec![
                    "original_resource_authority".into(),
                    "operation_effects".into(),
                ],
            });
            evidence[*j].kind = EvidenceKind::Resource;
            evidence[*j]
                .tags
                .push("resource-review:original-lookup".into());
            attached.insert(*j);
            break;
        }
    }
}
