//! Identity gates for the extended database rules. Query construction is a
//! consumer fact, not proof that a document or constant is injectable.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::Language;
use std::collections::BTreeMap;

type DbNode<'a> = Node<'a, StrDoc<SupportLang>>;

/// Parser/constructor occurrences are context, not database interpretation.
/// Attach bounded construction origins to real database operations. Source
/// lookups can find other producers without persisting unused construction rows.
pub(super) fn attach_query_construction(
    root: &DbNode<'_>,
    evidence: &mut Vec<mehscan_core::Evidence>,
) {
    use mehscan_core::{EvidenceKind, OperandFact, OperandFactKind};
    let builders = evidence
        .iter()
        .filter(|e| construction(e))
        .cloned()
        .collect::<Vec<_>>();
    if builders.is_empty() {
        evidence.retain(|e| !e.rule_id.ends_with("-extended-nosql-dispatch"));
        return;
    }
    let queries = evidence
        .iter()
        .filter(|e| e.kind == EvidenceKind::Sink && !construction(e)
            && matches!(e.cwe_candidates.as_slice(), [cwe] if cwe == "CWE-943" || cwe == "CWE-89"))
        .filter_map(|e| e.captures.get(query_role(e)))
        .collect::<Vec<_>>();
    if queries.is_empty() && !builders.iter().any(sql_construction) {
        evidence.retain(|e| !construction(e));
        return;
    }
    let ranges = builders
        .iter()
        .map(|e| (e.location.start.byte_offset, e.location.end.byte_offset))
        .chain(
            queries
                .iter()
                .map(|q| (q.location.start.byte_offset, q.location.end.byte_offset)),
        )
        .collect::<std::collections::BTreeSet<_>>();
    let names = queries
        .iter()
        .flat_map(|q| {
            [
                q.text.trim(),
                q.text
                    .split_once('(')
                    .map_or(q.text.trim(), |(name, _)| name.trim()),
            ]
        })
        .collect::<std::collections::BTreeSet<_>>();
    let mut nodes = BTreeMap::new();
    let mut uses = BTreeMap::<String, Vec<std::ops::Range<usize>>>::new();
    let mut declarations = BTreeMap::<String, Vec<DbNode<'_>>>::new();
    for node in root.dfs() {
        let range = node.range();
        if ranges.contains(&(range.start, range.end)) {
            nodes.insert((range.start, range.end), node.clone());
        }
        if matches!(
            node.kind().as_ref(),
            "identifier" | "simple_identifier" | "variable_name"
        ) && names.contains(node.text().as_ref())
        {
            uses.entry(node.text().into_owned())
                .or_default()
                .push(node.range());
        }
        if let Some(name) = declaration_name(&node)
            && names.contains(name.as_str())
        {
            declarations.entry(name).or_default().push(node);
        }
    }
    drop(names);
    drop(queries);
    let mut used = std::collections::BTreeSet::new();
    let mut dispatched = std::collections::BTreeSet::new();
    for sink in evidence.iter_mut().filter(|e| {
        e.kind == EvidenceKind::Sink
            && !construction(e)
            && matches!(e.cwe_candidates.as_slice(), [cwe] if cwe == "CWE-943" || cwe == "CWE-89")
    }) {
        let role = query_role(sink);
        let Some(query) = sink.captures.get(role).cloned() else {
            continue;
        };
        for builder in &builders {
            if builder.cwe_candidates != sink.cwe_candidates {
                continue;
            }
            let inline = query.location.start.byte_offset <= builder.location.start.byte_offset
                && query.location.end.byte_offset >= builder.location.end.byte_offset;
            let pair = nodes
                .get(&(
                    builder.location.start.byte_offset,
                    builder.location.end.byte_offset,
                ))
                .zip(nodes.get(&(
                    query.location.start.byte_offset,
                    query.location.end.byte_offset,
                )));
            let local = (!inline)
                .then(|| {
                    pair.and_then(|(node, target)| {
                        direct_document_origin(node, target, &query, &uses)
                    })
                })
                .flatten();
            let helper = !inline
                && local.is_none()
                && pair.is_some_and(|(node, target)| {
                    returned_document_origin(node, target, &declarations)
                });
            let alias = !inline
                && local.is_none()
                && !helper
                && pair.is_some_and(|(node, target)| {
                    declarations
                        .get(target.text().as_ref())
                        .into_iter()
                        .flatten()
                        .any(|binding| {
                            binding.kind().as_ref() == "variable_declarator"
                                && visible(binding, target)
                                && binding.field("value").is_some_and(|value| {
                                    let operand =
                                        super::node_operands::capture_at("", sink, &value);
                                    direct_document_origin(node, &value, &operand, &uses).is_some()
                                })
                        })
                });
            if !inline && local.is_none() && !helper && !alias {
                continue;
            }
            let direct_inline = inline
                && pair.is_some_and(|(node, target)| {
                    python_binding_wrapper(node).range() == target.range()
                });
            used.insert(builder.id.clone());
            dispatched.insert(sink.id.clone());
            sink.related_evidence.push(builder.id.clone());
            sink.context.operand_facts.push(OperandFact {
                kind: OperandFactKind::QueryStructure,
                role: role.into(),
                location: builder.location.clone(),
                value: format!(
                    "{}:{}",
                    if role == "query" {
                        "raw_sql_construction"
                    } else {
                        "raw_document_construction"
                    },
                    builder.captures[role].text
                ),
                remaining_checks: vec![
                    if role == "query" {
                        "parameter_binding"
                    } else {
                        "operator_shape"
                    }
                    .into(),
                    "input_types".into(),
                    "record_authority".into(),
                    if helper {
                        "helper_input_binding"
                    } else if local == Some(false) || alias || (inline && !direct_inline) {
                        "construction_stability"
                    } else {
                        "consumer_contract"
                    }
                    .into(),
                ],
            });
            // Transfer operands only for unchanged direct construction. A prior
            // use/mutation or helper result remains an unresolved whole operand.
            if (direct_inline || local == Some(true))
                && (sink.rule_id.ends_with("-extended-nosql-dispatch")
                    || sink.rule_id == "php-extended-nosql-execution"
                    || builder.rule_id == "python-extended-sql-expression")
            {
                sink.captures
                    .insert("query_container".into(), query.clone());
                for role in ["query", "nosql_query", "nosql_expression"] {
                    if let Some(value) = builder.captures.get(role) {
                        sink.captures.insert(role.into(), value.clone());
                    }
                    if let Some(value) = builder.context.literals.get(role) {
                        sink.context.literals.insert(role.into(), value.clone());
                    }
                }
                if sink.rule_id.ends_with("-extended-nosql-dispatch") {
                    sink.captures
                        .entry("nosql_expression".into())
                        .or_insert_with(|| builder.captures["nosql_query"].clone());
                    if let Some(value) = builder.context.literals.get("nosql_query") {
                        sink.context
                            .literals
                            .entry("nosql_expression".into())
                            .or_insert_with(|| value.clone());
                    }
                }
            }
        }
    }
    // Unbound SQL construction is retained only as an actual escaped/embedded
    // lead. A discarded expression or unread function-local binding is not work.
    let unused_sql = builders
        .iter()
        .filter(|e| sql_construction(e))
        .filter(|e| {
            nodes
                .get(&(e.location.start.byte_offset, e.location.end.byte_offset))
                .is_some_and(|node| {
                    if e.rule_id == "python-extended-sql-expression" {
                        python_sql_constructor_is_unused(node)
                    } else {
                        super::database_cleanup::unused_local_builder(node)
                    }
                })
        })
        .map(|e| e.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for item in evidence.iter_mut().filter(|e| construction(e)) {
        if used.contains(&item.id) {
            item.kind = EvidenceKind::Resource;
            item.tags.push("query-construction:consumed".into());
        } else if sql_construction(item) && !unused_sql.contains(&item.id) {
            item.tags.push(
                if item.captures.contains_key("query_execution") {
                    "query-consumer:local-execution-lead"
                } else {
                    "query-consumer:unresolved"
                }
                .into(),
            );
        }
    }
    evidence.retain(|e| {
        (!construction(e)
            || used.contains(&e.id)
            || (sql_construction(e) && !unused_sql.contains(&e.id)))
            && (!e.rule_id.ends_with("-extended-nosql-dispatch") || dispatched.contains(&e.id))
    });
}

fn query_role(evidence: &mehscan_core::Evidence) -> &'static str {
    if evidence.cwe_candidates == ["CWE-89"] {
        "query"
    } else {
        "nosql_query"
    }
}

fn python_sql_constructor_is_unused(node: &DbNode<'_>) -> bool {
    let origin = python_binding_wrapper(node);
    let Some(parent) = origin.parent() else {
        return false;
    };
    if parent.kind().as_ref() == "expression_statement" {
        return true;
    }
    if parent.kind().as_ref() != "assignment" {
        return false;
    }
    let Some(name) = parent
        .field("left")
        .filter(|n| n.kind().as_ref() == "identifier")
    else {
        return false;
    };
    let Some(function) = parent
        .ancestors()
        .find(|n| n.kind().as_ref() == "function_definition")
    else {
        return false;
    };
    // Module/class bindings and returned/passed/embedded expressions can escape.
    // Only a local result with no represented name use can be discarded here,
    // including closure reads declared before this assignment.
    !function.dfs().any(|n| {
        n.kind().as_ref() == "identifier"
            && n.text() == name.text()
            && n.range() != name.range()
            && !(node.range().start <= n.range().start && n.range().end <= node.range().end)
    })
}

// These SQLAlchemy modifiers preserve text; they bind values/describe columns.
// Never unwrap arbitrary transforms or string compilation.
fn python_binding_wrapper<'a>(node: &DbNode<'a>) -> DbNode<'a> {
    let mut origin = node.clone();
    for _ in 0..2 {
        let Some(attribute) = origin.parent().filter(|n| {
            n.kind().as_ref() == "attribute"
                && n.field("object")
                    .is_some_and(|o| o.range() == origin.range())
                && n.field("attribute")
                    .is_some_and(|n| matches!(n.text().as_ref(), "bindparams" | "columns"))
        }) else {
            break;
        };
        let Some(call) = attribute.parent().filter(|n| {
            n.kind().as_ref() == "call"
                && n.field("function")
                    .is_some_and(|n| n.range() == attribute.range())
        }) else {
            break;
        };
        origin = call;
    }
    origin
}

fn construction_rule(rule: &str) -> bool {
    rule.ends_with("-extended-nosql-json")
        || rule.ends_with("-extended-nosql-command")
        || rule == "php-extended-nosql-query"
        || rule == "python-extended-sql-expression"
}

fn construction(item: &mehscan_core::Evidence) -> bool {
    construction_rule(&item.rule_id)
        || item
            .tags
            .iter()
            .any(|t| t == "query-construction:sql-builder")
}

fn sql_construction(item: &mehscan_core::Evidence) -> bool {
    item.rule_id == "python-extended-sql-expression"
        || item
            .tags
            .iter()
            .any(|t| t == "query-construction:sql-builder")
}

fn direct_document_origin(
    node: &DbNode<'_>,
    target: &DbNode<'_>,
    query: &mehscan_core::Capture,
    uses: &BTreeMap<String, Vec<std::ops::Range<usize>>>,
) -> Option<bool> {
    let origin = python_binding_wrapper(node);
    let Some(parent) = origin.parent() else {
        return None;
    };
    let binding = if parent.kind().as_ref() == "equals_value_clause" {
        parent.parent()
    } else {
        Some(parent)
    };
    let Some(binding) = binding.filter(|n| {
        matches!(
            n.kind().as_ref(),
            "variable_declarator" | "property_declaration" | "assignment_expression" | "assignment"
        )
    }) else {
        return None;
    };
    let name = binding
        .field("name")
        .or_else(|| binding.field("left"))
        .or_else(|| {
            binding
                .children()
                .find(|n| n.kind().as_ref() == "variable_declaration")
                .and_then(|n| {
                    n.children()
                        .find(|n| n.kind().as_ref() == "simple_identifier")
                })
        });
    if !name.is_some_and(|n| n.text().trim() == query.text.trim()) {
        return None;
    }
    let Some(function) = binding.ancestors().find(|n| {
        matches!(
            n.kind().as_ref(),
            "method_declaration"
                | "function_declaration"
                | "function_definition"
                | "arrow_function"
                | "function_expression"
                | "method_definition"
        )
    }) else {
        return None;
    };
    if query.location.start.byte_offset < binding.range().end
        || query.location.end.byte_offset > function.range().end
    {
        return None;
    }
    if binding
        .ancestors()
        .find(|n| {
            matches!(
                n.kind().as_ref(),
                "block" | "statement_block" | "compound_statement" | "control_structure_body"
            )
        })
        .is_some_and(|scope| !target.ancestors().any(|n| n.range() == scope.range()))
    {
        return None;
    }
    if target
        .ancestors()
        .take_while(|n| n.range() != function.range())
        .any(|n| {
            matches!(
                n.kind().as_ref(),
                "lambda_expression"
                    | "lambda_literal"
                    | "method_declaration"
                    | "function_declaration"
                    | "function_definition"
                    | "arrow_function"
                    | "function_expression"
                    | "method_definition"
            )
        })
    {
        return None;
    }
    // Prior uses include writes, aliases and helpers. Preserve a construction
    // lead, but transfer operands only through an unchanged first local use.
    Some(
        !uses
            .get(query.text.trim())
            .into_iter()
            .flatten()
            .any(|range| {
                range.start >= binding.range().end && range.start < query.location.start.byte_offset
            }),
    )
}

/// One directly returned constructor in a uniquely named local helper. This
/// establishes a construction lead, not the helper's argument/input contract.
fn returned_document_origin(
    builder: &DbNode<'_>,
    target: &DbNode<'_>,
    indexed_declarations: &BTreeMap<String, Vec<DbNode<'_>>>,
) -> bool {
    let Some(returned) = builder
        .parent()
        .filter(|n| n.kind().as_ref() == "return_statement")
    else {
        return false;
    };
    let Some(function) = returned.ancestors().find(|n| {
        matches!(
            n.kind().as_ref(),
            "function_declaration" | "function_definition"
        )
    }) else {
        return false;
    };
    let Some(name) = function.field("name") else {
        return false;
    };
    if function
        .ancestors()
        .find(|n| {
            matches!(
                n.kind().as_ref(),
                "function_declaration"
                    | "function_definition"
                    | "method_definition"
                    | "arrow_function"
            )
        })
        .is_some_and(|scope| !target.ancestors().any(|n| n.range() == scope.range()))
    {
        return false;
    }
    if !matches!(target.kind().as_ref(), "call_expression" | "call")
        || target
            .field("function")
            .is_none_or(|n| n.text() != name.text())
        || function
            .dfs()
            .filter(|n| n.kind().as_ref() == "return_statement")
            .count()
            != 1
    {
        return false;
    }
    let declarations = indexed_declarations
        .get(name.text().as_ref())
        .into_iter()
        .flatten()
        .filter(|n| n.range() == function.range() || visible(n, target))
        .collect::<Vec<_>>();
    declarations.len() == 1 && declarations[0].range() == function.range()
}

/// File-local AST references only; visibility is still checked at each use.
pub(super) struct ExactSymbolIndex<'a> {
    declarations: BTreeMap<String, Vec<DbNode<'a>>>,
    imports: Vec<DbNode<'a>>,
}

impl<'a> ExactSymbolIndex<'a> {
    pub(super) fn new(root: &DbNode<'a>) -> Self {
        let mut index = Self {
            declarations: BTreeMap::new(),
            imports: Vec::new(),
        };
        for node in root.dfs() {
            if let Some(name) = declaration_name(&node) {
                index
                    .declarations
                    .entry(name)
                    .or_default()
                    .push(node.clone());
            }
            if matches!(
                node.kind().as_ref(),
                "import_statement"
                    | "import_from_statement"
                    | "import_declaration"
                    | "using_directive"
                    | "import_spec"
            ) {
                index.imports.push(node);
            }
        }
        index
    }
}

fn declaration_name(node: &DbNode<'_>) -> Option<String> {
    let bare_parameter = node.kind().as_ref() == "identifier"
        && node
            .parent()
            .is_some_and(|p| matches!(p.kind().as_ref(), "parameters" | "formal_parameters"));
    if bare_parameter {
        return Some(compact(node.text().as_ref()));
    }
    if !matches!(
        node.kind().as_ref(),
        "class_declaration"
            | "class_definition"
            | "struct_item"
            | "function_definition"
            | "function_declaration"
            | "variable_declarator"
            | "assignment"
            | "parameter"
            | "formal_parameter"
            | "typed_parameter"
            | "default_parameter"
            | "required_parameter"
            | "optional_parameter"
    ) {
        return None;
    }
    node.field("name")
        .or_else(|| node.field("left"))
        .or_else(|| node.field("pattern"))
        .map(|name| compact(name.text().as_ref()))
}

pub(super) fn is_rule(rule: &str) -> bool {
    let Some((language, boundary)) = rule.split_once("-extended-") else {
        return false;
    };
    match language {
        "javascript" | "typescript" | "tsx" => matches!(
            boundary,
            "sql-query" | "nosql-query" | "nosql-command" | "nosql-request" | "nosql-dispatch"
        ),
        "python" => matches!(
            boundary,
            "sql-query" | "sql-expression" | "django-query" | "nosql-query" | "nosql-expression"
        ),
        "java" | "kotlin" => matches!(boundary, "sql-query" | "nosql-query" | "nosql-json"),
        "csharp" => matches!(boundary, "nosql-query" | "nosql-json"),
        "php" => matches!(
            boundary,
            "nosql-query" | "nosql-execution" | "sql-facade" | "sql-builder" | "pgsql-query"
        ),
        "c" => boundary == "nosql-native",
        "cpp" => matches!(boundary, "nosql-native" | "nosql-query"),
        "rust" => matches!(boundary, "sql-query" | "nosql-query"),
        "go" => matches!(boundary, "pgx-query" | "sqlx-query"),
        _ => false,
    }
}

pub(super) fn accepts(
    root: &DbNode<'_>,
    node: &DbNode<'_>,
    rule: &str,
    language: Language,
    receiver: Option<&DbNode<'_>>,
    symbol: Option<&DbNode<'_>>,
    symbols: Option<&ExactSymbolIndex<'_>>,
) -> bool {
    if rule.ends_with("-extended-nosql-dispatch") {
        return receiver
            .is_some_and(|receiver| dynamodb_dispatch_receiver(root, receiver, language, 4));
    }
    if rule == "python-extended-django-query" {
        let Some(receiver) = receiver else {
            return false;
        };
        let text = compact(receiver.text().as_ref());
        let Some(model) = text.strip_suffix(".objects") else {
            return false;
        };
        return root
            .dfs()
            .filter(|n| n.kind().as_ref() == "class_definition")
            .any(|class| {
                class.field("name").is_some_and(|n| n.text() == model)
                    && class.field("superclasses").is_some_and(|bases| {
                        bases.children().any(|base| {
                            exact_symbol(
                                root,
                                &base,
                                base.text().as_ref(),
                                "django.db.models.Model",
                                Language::Python,
                            )
                        })
                    })
            });
    }
    if rule.ends_with("nosql-native") {
        return matches!(language, Language::C | Language::Cpp);
    }
    if receiver.is_none() && symbol.is_none() {
        return matches!(language, Language::C | Language::Cpp);
    }
    if matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx | Language::Python
    ) && let Some(receiver) = receiver
    {
        return if rule.contains("nosql") {
            super::database_receiver::document_receiver(root, receiver, language)
        } else {
            super::database_receiver::proven(root, receiver, language)
        };
    }
    if let Some(symbol) = symbol {
        let canonical: &[&str] = match language {
            Language::Javascript | Language::Typescript | Language::Tsx => &[
                "@aws-sdk/lib-dynamodb.QueryCommand",
                "@aws-sdk/lib-dynamodb.ScanCommand",
                "@aws-sdk/lib-dynamodb.ExecuteStatementCommand",
                "@aws-sdk/client-dynamodb.QueryCommand",
                "@aws-sdk/client-dynamodb.ScanCommand",
                "@aws-sdk/client-dynamodb.ExecuteStatementCommand",
            ],
            Language::Python => &[
                "sqlalchemy.text",
                "django.db.models.expressions.RawSQL",
                "django.db.models.RawSQL",
            ],
            Language::Java => &[
                "org.bson.Document",
                "com.mongodb.BasicDBObject",
                "org.springframework.data.mongodb.core.query.BasicQuery",
            ],
            Language::Csharp => &[
                "MongoDB.Bson.BsonDocument",
                "MongoDB.Driver.JsonFilterDefinition",
            ],
            _ => &[],
        };
        return canonical.iter().any(|canonical| {
            exact_symbol_with_index(
                root,
                node,
                symbol.text().as_ref(),
                canonical,
                language,
                symbols,
            )
        });
    }
    let Some(receiver) = receiver else {
        return false;
    };
    let canonical: &[&str] = match language {
        Language::Java if rule.contains("nosql") => &[
            "com.mongodb.client.MongoCollection",
            "org.springframework.data.mongodb.core.MongoOperations",
            "org.springframework.data.mongodb.core.MongoTemplate",
        ],
        Language::Java => &[
            "org.hibernate.Session",
            "javax.jdo.Query",
            "io.vertx.sqlclient.SqlConnection",
            "io.vertx.sqlclient.Pool",
            "io.vertx.ext.sql.SQLConnection",
        ],
        Language::Csharp => &["MongoDB.Driver.IMongoCollection"],
        Language::Rust if rule.contains("nosql") => {
            &["mongodb::Collection", "mongodb::sync::Collection"]
        }
        Language::Rust => &[
            "rusqlite::Connection",
            "tokio_postgres::Client",
            "postgres::Client",
            "mysql::Conn",
            "mysql::PooledConn",
        ],
        Language::Go if rule.contains("pgx") => &[
            "github.com/jackc/pgx/v5.Conn",
            "github.com/jackc/pgx/v5/pgxpool.Pool",
            "github.com/jackc/pgx/v4.Conn",
            "github.com/jackc/pgx/v4/pgxpool.Pool",
        ],
        Language::Go => &["github.com/jmoiron/sqlx.DB", "github.com/jmoiron/sqlx.Tx"],
        Language::Cpp => &["mongocxx::collection"],
        _ => &[],
    };
    canonical.iter().any(|canonical| {
        if language == Language::Java {
            super::java_persistence::typed_database_receiver(root, receiver, canonical, 8)
        } else {
            typed_receiver(root, node, receiver, canonical, language)
        }
    })
}

pub(super) fn exact_symbol(
    root: &DbNode<'_>,
    use_site: &DbNode<'_>,
    observed: &str,
    canonical: &str,
    language: Language,
) -> bool {
    exact_symbol_with_index(root, use_site, observed, canonical, language, None)
}

/// SDK v3 send belongs to DynamoDB only when its client producer is owned.
/// No conventional receiver names or arbitrary factory-name inference.
fn dynamodb_dispatch_receiver(
    root: &DbNode<'_>,
    receiver: &DbNode<'_>,
    language: Language,
    depth: usize,
) -> bool {
    if depth == 0 {
        return false;
    }
    if receiver.kind().as_ref() == "new_expression" {
        return receiver.field("constructor").is_some_and(|name| {
            exact_symbol(
                root,
                receiver,
                name.text().as_ref(),
                "@aws-sdk/client-dynamodb.DynamoDBClient",
                language,
            )
        });
    }
    if receiver.kind().as_ref() == "call_expression" {
        return receiver.field("function").is_some_and(|function| {
            function.kind().as_ref() == "member_expression"
                && function
                    .field("property")
                    .is_some_and(|name| name.text() == "from")
                && function.field("object").is_some_and(|name| {
                    exact_symbol(
                        root,
                        receiver,
                        name.text().as_ref(),
                        "@aws-sdk/lib-dynamodb.DynamoDBDocumentClient",
                        language,
                    )
                })
                && receiver
                    .field("arguments")
                    .and_then(|args| args.children().find(|n| n.is_named()))
                    .is_some_and(|client| {
                        dynamodb_dispatch_receiver(root, &client, language, depth - 1)
                    })
        });
    }
    if receiver.kind().as_ref() != "identifier" {
        return false;
    }
    let bindings = root
        .dfs()
        .filter(|n| {
            declaration_name(n).is_some_and(|name| name == receiver.text()) && visible(n, receiver)
        })
        .collect::<Vec<_>>();
    let [binding] = bindings.as_slice() else {
        return false;
    };
    binding.kind().as_ref() == "variable_declarator"
        && binding
            .field("value")
            .is_some_and(|value| dynamodb_dispatch_receiver(root, &value, language, depth - 1))
}

fn exact_symbol_with_index(
    root: &DbNode<'_>,
    use_site: &DbNode<'_>,
    observed: &str,
    canonical: &str,
    language: Language,
    symbols: Option<&ExactSymbolIndex<'_>>,
) -> bool {
    let observed = compact(observed)
        .split('<')
        .next()
        .unwrap_or("")
        .to_string();
    if language == Language::Kotlin {
        return super::kotlin::exact_symbol(root, use_site, &observed, canonical);
    }
    let head = observed.split('.').next().unwrap_or(&observed);
    // A local name or declared lookalike must not inherit an imported SDK identity.
    let shadowed = if let Some(symbols) = symbols {
        symbols
            .declarations
            .get(head)
            .into_iter()
            .flatten()
            .any(|n| visible(n, use_site))
    } else {
        root.dfs()
            .any(|n| declaration_name(&n).is_some_and(|name| name == head) && visible(&n, use_site))
    };
    if shadowed {
        return false;
    }
    if observed == canonical {
        return true;
    }
    if language == Language::Rust {
        return super::rust_context::canonical_path(root, &observed)
            .split('<')
            .next()
            == Some(canonical);
    }
    let is_import = |node: &DbNode<'_>| match language {
        Language::Javascript | Language::Typescript | Language::Tsx | Language::Python => {
            matches!(
                node.kind().as_ref(),
                "import_statement" | "import_from_statement"
            )
        }
        Language::Java => node.kind().as_ref() == "import_declaration",
        Language::Csharp => node.kind().as_ref() == "using_directive",
        Language::Go => node.kind().as_ref() == "import_spec",
        _ => false,
    };
    let matches_import = |import: &DbNode<'_>| {
        if !visible(import, use_site) {
            return false;
        }
        let text = import.text();
        let text = text.trim().trim_end_matches(';');
        match language {
            Language::Javascript | Language::Typescript | Language::Tsx => {
                let Some((module, constructor)) = canonical.rsplit_once('.') else {
                    return false;
                };
                if import.kind().as_ref() == "import_statement" {
                    let Some(source) = import.field("source") else {
                        return false;
                    };
                    if source.text().trim_matches(['\'', '"']) != module {
                        return false;
                    }
                    return import
                        .dfs()
                        .filter(|n| n.kind().as_ref() == "import_specifier")
                        .any(|n| {
                            n.field("name").is_some_and(|n| n.text() == constructor)
                                && n.field("alias")
                                    .or_else(|| n.field("name"))
                                    .is_some_and(|n| n.text() == observed)
                        });
                }
                false
            }
            Language::Java => {
                import.kind().as_ref() == "import_declaration"
                    && (text.strip_prefix("import ") == Some(canonical)
                        && observed == canonical.rsplit('.').next().unwrap_or(canonical)
                        || canonical.rsplit_once('.').is_some_and(|(package, short)| {
                            text == format!("import {package}.*") && observed == short
                        }))
            }
            Language::Csharp => {
                if import.kind().as_ref() != "using_directive" {
                    return false;
                }
                let text = text
                    .strip_prefix("global ")
                    .unwrap_or(text)
                    .strip_prefix("using ")
                    .unwrap_or("");
                if let Some((alias, path)) = text.split_once('=') {
                    compact(alias) == observed && compact(path) == canonical
                } else {
                    canonical
                        .rsplit_once('.')
                        .is_some_and(|(namespace, short)| text == namespace && observed == short)
                }
            }
            Language::Python => {
                if import.kind().as_ref() == "import_statement" {
                    let text = text.strip_prefix("import ").unwrap_or("");
                    let (module, alias) = text.split_once(" as ").unwrap_or((text, text));
                    observed
                        .strip_prefix(alias)
                        .is_some_and(|tail| format!("{module}{tail}") == canonical)
                } else if import.kind().as_ref() == "import_from_statement" {
                    let Some((module, names)) = text
                        .strip_prefix("from ")
                        .and_then(|t| t.split_once(" import "))
                    else {
                        return false;
                    };
                    names.trim_matches(['(', ')']).split(',').any(|name| {
                        let name = name.trim();
                        let (original, alias) = name.split_once(" as ").unwrap_or((name, name));
                        observed
                            .strip_prefix(alias)
                            .is_some_and(|tail| format!("{module}.{original}{tail}") == canonical)
                    })
                } else {
                    false
                }
            }
            Language::Go => {
                if import.kind().as_ref() != "import_spec" {
                    return false;
                }
                let Some(path) = import.field("path") else {
                    return false;
                };
                let path = path.text();
                let path = path.trim_matches('"');
                let package = import
                    .field("name")
                    .map(|n| n.text().to_string())
                    .unwrap_or_else(|| {
                        let last = path.rsplit('/').next().unwrap_or(path);
                        if last.starts_with('v') && last[1..].chars().all(|c| c.is_ascii_digit()) {
                            path.rsplit('/').nth(1).unwrap_or(last).to_string()
                        } else {
                            last.to_string()
                        }
                    });
                observed
                    .strip_prefix(&format!("{package}."))
                    .is_some_and(|name| format!("{path}.{name}") == canonical)
            }
            _ => false,
        }
    };
    if let Some(symbols) = symbols {
        symbols
            .imports
            .iter()
            .filter(|n| is_import(n))
            .any(matches_import)
    } else {
        root.dfs().filter(is_import).any(|n| matches_import(&n))
    }
}

pub(super) fn typed_receiver(
    root: &DbNode<'_>,
    use_site: &DbNode<'_>,
    receiver: &DbNode<'_>,
    canonical: &str,
    language: Language,
) -> bool {
    let name = compact(receiver.text().as_ref());
    if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return false;
    }
    let mut bindings = Vec::new();
    for n in root.dfs().filter(|n| {
        matches!(
            n.kind().as_ref(),
            "parameter"
                | "parameter_declaration"
                | "let_declaration"
                | "declaration"
                | "variable_declaration"
                | "short_var_declaration"
        )
    }) {
        if !visible(&n, use_site) {
            continue;
        }
        let ty = n.field("type");
        let declarator = n
            .field("name")
            .or_else(|| n.field("pattern"))
            .or_else(|| n.field("declarator"));
        let declarator = declarator.or_else(|| n.field("left"));
        let matches = declarator
            .is_some_and(|d| compact(d.text().as_ref()).trim_start_matches(['&', '*']) == name)
            || n.children().any(|d| {
                d.kind().as_ref() == "variable_declarator"
                    && d.field("name").is_some_and(|v| v.text() == name)
            });
        if matches {
            bindings.push((n.range().start, ty));
        }
    }
    bindings.sort_by_key(|(start, _)| *start);
    bindings.last().is_some_and(|(_, ty)| {
        ty.as_ref().is_some_and(|ty| {
            let text = compact(ty.text().as_ref());
            let text = text
                .trim_start_matches(['&', '*'])
                .trim_start_matches("mut");
            exact_symbol(root, use_site, text, canonical, language)
        })
    })
}

fn visible(binding: &DbNode<'_>, use_site: &DbNode<'_>) -> bool {
    if binding.range().start > use_site.range().start {
        return false;
    }
    binding
        .ancestors()
        .find(|n| {
            matches!(
                n.kind().as_ref(),
                "function_definition"
                    | "function_declaration"
                    | "function_item"
                    | "method_declaration"
                    | "method_definition"
                    | "constructor_declaration"
                    | "lambda_expression"
                    | "arrow_function"
                    | "block"
            )
        })
        .is_none_or(|scope| {
            scope.range().start <= use_site.range().start
                && use_site.range().end <= scope.range().end
        })
}

fn compact(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

pub(super) fn dynamodb_operands<'a>(query: &DbNode<'a>) -> Vec<DbNode<'a>> {
    if !matches!(query.kind().as_ref(), "object" | "object_expression") {
        return vec![query.clone()];
    }
    let mut keys = std::collections::BTreeSet::new();
    for property in query
        .children()
        .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
    {
        let key = property.field("key");
        if property.kind().as_ref() != "pair"
            || key.as_ref().is_none_or(|key| {
                !matches!(key.kind().as_ref(), "property_identifier" | "string")
                    || key.text().contains('\\')
                    || !keys.insert(key.text().trim_matches(['\'', '"']).to_string())
            })
        {
            return vec![query.clone()];
        }
    }
    let mut values: Vec<_> = query
        .children()
        .filter(|n| n.kind().as_ref() == "pair")
        .filter_map(|n| {
            let key = n.field("key")?;
            matches!(
                key.text().trim_matches(['\'', '"']),
                "KeyConditionExpression"
                    | "FilterExpression"
                    | "QueryFilter"
                    | "ScanFilter"
                    | "Statement"
            )
            .then(|| n.field("value"))
            .flatten()
        })
        .collect();
    // Prefer unknown syntax over a constant expression when both are supplied.
    values.sort_by_key(|n| matches!(n.kind().as_ref(), "string" | "string_literal"));
    values
}

pub(super) fn request_objects<'a>(root: &DbNode<'a>, sink: &DbNode<'a>) -> Vec<DbNode<'a>> {
    let Some(scope) = sink.ancestors().find(|n| {
        matches!(
            n.kind().as_ref(),
            "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
        )
    }) else {
        return vec![];
    };
    let parameters = scope
        .field("parameters")
        .or_else(|| scope.field("parameter"));
    let Some(parameters) = parameters else {
        return vec![];
    };
    root.dfs()
        .filter(|n| {
            if n.kind().as_ref() != "member_expression"
                || !visible(&scope, n)
                || !(scope.range().start <= n.range().start && n.range().end <= scope.range().end)
            {
                return false;
            }
            if n.ancestors()
                .find(|owner| {
                    matches!(
                        owner.kind().as_ref(),
                        "function_declaration"
                            | "function_expression"
                            | "arrow_function"
                            | "method_definition"
                    )
                })
                .is_none_or(|owner| owner.range() != scope.range())
            {
                return false;
            }
            let text = compact(n.text().as_ref());
            if !matches!(
                text.as_str(),
                "req.body" | "req.query" | "request.body" | "request.query"
            ) {
                return false;
            }
            let request = text.split('.').next().unwrap_or("");
            if !parameters
                .dfs()
                .any(|p| p.kind().as_ref() == "identifier" && p.text() == request)
            {
                return false;
            }
            // Reading an individual field or invoking a conversion is not reading
            // the whole operator-capable request object.
            !n.parent().is_some_and(|parent| {
                matches!(
                    parent.kind().as_ref(),
                    "member_expression" | "subscript_expression"
                ) && parent
                    .field("object")
                    .is_some_and(|object| object.range() == n.range())
            })
        })
        .collect()
}

pub(super) fn pgx_receiver(root: &DbNode<'_>, node: &DbNode<'_>, receiver: &DbNode<'_>) -> bool {
    accepts(
        root,
        node,
        "go-extended-pgx-query",
        Language::Go,
        Some(receiver),
        None,
        None,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn identity_registry_covers_the_catalog_without_intercepting_custom_rule_names() {
        let rules = crate::rules::load_builtin_rules().unwrap();
        let extended: Vec<_> = rules
            .iter()
            .filter(|r| {
                r.tags.iter().any(|tag| tag == "extended-rules")
                    && r.tags.iter().any(|tag| tag == "database")
            })
            .collect();
        assert_eq!(extended.len(), 40);
        assert!(extended.iter().all(|r| super::is_rule(&r.id)));
        for custom in [
            "my-extended-http",
            "javascript-extended-http-request",
            "cpp-extended-custom-query",
        ] {
            assert!(!super::is_rule(custom));
        }
    }
}
