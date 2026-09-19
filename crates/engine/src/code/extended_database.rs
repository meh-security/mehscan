//! Identity gates for the extended database rules. Query construction is an
//! investigation boundary, not proof that a document or constant is injectable.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::Language;

type DbNode<'a> = Node<'a, StrDoc<SupportLang>>;

pub(super) fn is_rule(rule: &str) -> bool {
    let Some((language, boundary)) = rule.split_once("-extended-") else {
        return false;
    };
    match language {
        "javascript" | "typescript" | "tsx" => matches!(
            boundary,
            "sql-query" | "nosql-query" | "nosql-command" | "nosql-request"
        ),
        "python" => matches!(
            boundary,
            "sql-query" | "sql-expression" | "django-query" | "nosql-query" | "nosql-expression"
        ),
        "java" | "kotlin" => matches!(boundary, "sql-query" | "nosql-query" | "nosql-json"),
        "csharp" => matches!(boundary, "nosql-query" | "nosql-json"),
        "php" => matches!(
            boundary,
            "nosql-query" | "sql-facade" | "sql-builder" | "pgsql-query"
        ),
        "c" => boundary == "nosql-native",
        "cpp" => matches!(boundary, "nosql-native" | "nosql-query"),
        "rust" => matches!(boundary, "sql-query" | "nosql-query"),
        "go" => matches!(boundary, "pgx-query" | "sqlx-query"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn identity_registry_covers_the_catalog_without_intercepting_custom_rule_names() {
        let rules = crate::rules::load_builtin_rules().unwrap();
        let extended: Vec<_> = rules
            .iter()
            .filter(|r| r.tags.iter().any(|tag| tag == "extended-rules"))
            .collect();
        assert_eq!(extended.len(), 36);
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

pub(super) fn accepts(
    root: &DbNode<'_>,
    node: &DbNode<'_>,
    rule: &str,
    language: Language,
    receiver: Option<&DbNode<'_>>,
    symbol: Option<&DbNode<'_>>,
) -> bool {
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
            exact_symbol(root, node, symbol.text().as_ref(), canonical, language)
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
    let observed = compact(observed)
        .split('<')
        .next()
        .unwrap_or("")
        .to_string();
    let head = observed.split('.').next().unwrap_or(&observed);
    // A local name or declared lookalike must not inherit an imported SDK identity.
    if root.dfs().any(|n| {
        let declaration = matches!(
            n.kind().as_ref(),
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
        );
        let bare_parameter = n.kind().as_ref() == "identifier"
            && n.parent()
                .is_some_and(|p| matches!(p.kind().as_ref(), "parameters" | "formal_parameters"));
        if !declaration && !bare_parameter {
            return false;
        }
        let name = n
            .field("name")
            .or_else(|| n.field("left"))
            .or_else(|| n.field("pattern"));
        let name = if bare_parameter {
            Some(n.clone())
        } else {
            name
        };
        name.is_some_and(|name| compact(name.text().as_ref()) == head) && visible(&n, use_site)
    }) {
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
    root.dfs().any(|import| {
        if !visible(&import, use_site) {
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
    })
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
    if query
        .children()
        .any(|n| n.kind().as_ref() == "spread_element")
    {
        return vec![query.clone()];
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
    )
}
