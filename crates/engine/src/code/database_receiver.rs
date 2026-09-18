//! Bounded receiver construction for broad DB-API / Node method vocabulary.
//! Retain established conventional receivers; new names require an imported
//! database producer and a unique assignment. This is identity, not value flow.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::Language;
use std::collections::BTreeSet;

type DbNode<'a> = Node<'a, StrDoc<SupportLang>>;

pub(super) fn accepts(root: &DbNode<'_>, receiver: &DbNode<'_>, language: Language) -> bool {
    let text = compact(receiver.text().as_ref());
    // Compatibility with the original syntax-only rules and their fixtures.
    let conventional = if language == Language::Python {
        matches!(text.as_str(), "cursor" | "connection")
    } else {
        matches!(
            text.as_str(),
            "pool" | "connection" | "sequelize" | "prisma"
        ) || text.ends_with(".sequelize")
    };
    if conventional {
        return true;
    }
    proven(root, receiver, language)
}

pub(super) fn proven(root: &DbNode<'_>, receiver: &DbNode<'_>, language: Language) -> bool {
    proven_family(root, receiver, language, false)
}

pub(super) fn document_receiver(
    root: &DbNode<'_>,
    receiver: &DbNode<'_>,
    language: Language,
) -> bool {
    proven_family(root, receiver, language, true)
}

fn proven_family(
    root: &DbNode<'_>,
    receiver: &DbNode<'_>,
    language: Language,
    document: bool,
) -> bool {
    let mut modules = BTreeSet::new();
    let mut factories = BTreeSet::new();
    for import in root.dfs().filter(|n| {
        matches!(
            n.kind().as_ref(),
            "import_statement" | "import_from_statement" | "variable_declarator"
        )
    }) {
        if lexical_owner(&import).is_some_and(|scope| {
            !(scope.start <= receiver.range().start && receiver.range().end <= scope.end)
        }) {
            continue;
        }
        let source = import.text();
        let source = source.as_ref();
        if language == Language::Python {
            let sql_modules = [
                "sqlite3",
                "psycopg",
                "psycopg2",
                "pymysql",
                "mysql.connector",
                "sqlalchemy",
                "sqlalchemy.orm",
                "duckdb",
                "asyncpg",
                "aiopg",
                "aiosqlite",
                "pg8000",
                "pymssql",
                "pyodbc",
                "oracledb",
            ];
            let document_modules = ["pymongo", "motor.motor_asyncio", "boto3"];
            let candidates: &[&str] = if document {
                &document_modules
            } else {
                &sql_modules
            };
            for &module in candidates {
                let prefix = format!("import {module}");
                if source == prefix || source.starts_with(&format!("{prefix} as ")) {
                    modules.insert(
                        source
                            .split_once(" as ")
                            .map_or(module, |(_, alias)| alias.trim())
                            .to_string(),
                    );
                }
                if let Some(names) = source.strip_prefix(&format!("from {module} import ")) {
                    for name in names.split(',') {
                        let name = name.trim();
                        let (original, alias) = name.split_once(" as ").unwrap_or((name, name));
                        if matches!(
                            original,
                            "connect"
                                | "create_engine"
                                | "Session"
                                | "sessionmaker"
                                | "MongoClient"
                                | "AsyncIOMotorClient"
                        ) {
                            factories.insert(alias.trim().to_string());
                        }
                    }
                }
            }
        } else {
            let compact_source = compact(source);
            let sql_modules = [
                "pg",
                "mysql",
                "mysql2",
                "mysql2/promise",
                "sequelize",
                "@prisma/client",
                "sqlite3",
                "better-sqlite3",
                "knex",
                "mssql",
            ];
            let document_modules = ["mongodb", "mongoose", "aws-sdk", "aws-sdk/clients/dynamodb"];
            let candidates: &[&str] = if document {
                &document_modules
            } else {
                &sql_modules
            };
            let database_module = candidates.iter().any(|module| {
                compact_source.contains(&format!("'{module}'"))
                    || compact_source.contains(&format!("\"{module}\""))
            });
            if !database_module {
                continue;
            }
            if import.kind().as_ref() == "variable_declarator" {
                if let (Some(name), Some(value)) = (import.field("name"), import.field("value")) {
                    if compact(value.text().as_ref()).starts_with("require(") {
                        if name.kind().as_ref() == "identifier" {
                            let name = compact(name.text().as_ref());
                            if ["knex", "better-sqlite3"].iter().any(|m| {
                                compact_source.contains(&format!("'{m}'"))
                                    || compact_source.contains(&format!("\"{m}\""))
                            }) {
                                factories.insert(name.clone());
                            }
                            modules.insert(name);
                        } else {
                            for part in name.dfs().filter(|n| {
                                n.kind().as_ref() == "shorthand_property_identifier_pattern"
                            }) {
                                if matches!(
                                    part.text().as_ref(),
                                    "Pool"
                                        | "Client"
                                        | "Sequelize"
                                        | "PrismaClient"
                                        | "Database"
                                        | "ConnectionPool"
                                        | "Request"
                                        | "MongoClient"
                                ) {
                                    factories.insert(part.text().to_string());
                                }
                            }
                        }
                    }
                }
            } else {
                for part in import.dfs() {
                    if part.kind().as_ref() == "namespace_import" {
                        for name in part
                            .children()
                            .filter(|n| n.kind().as_ref() == "identifier")
                        {
                            modules.insert(name.text().to_string());
                        }
                    } else if part.kind().as_ref() == "import_specifier" {
                        if let Some(name) = part.field("name") {
                            if matches!(
                                name.text().as_ref(),
                                "Pool"
                                    | "Client"
                                    | "Sequelize"
                                    | "PrismaClient"
                                    | "Database"
                                    | "ConnectionPool"
                                    | "Request"
                                    | "MongoClient"
                                    | "knex"
                            ) {
                                factories
                                    .insert(part.field("alias").unwrap_or(name).text().to_string());
                            }
                        }
                    } else if part.kind().as_ref() == "import_clause" {
                        for name in part
                            .children()
                            .filter(|n| n.kind().as_ref() == "identifier")
                        {
                            let name = name.text().to_string();
                            if ["knex", "better-sqlite3"].iter().any(|m| {
                                compact_source.contains(&format!("'{m}'"))
                                    || compact_source.contains(&format!("\"{m}\""))
                            }) {
                                factories.insert(name.clone());
                            }
                            modules.insert(name);
                        }
                    }
                }
            }
        }
    }
    known(root, receiver, &modules, &factories, 8)
}

fn known(
    root: &DbNode<'_>,
    expression: &DbNode<'_>,
    modules: &BTreeSet<String>,
    factories: &BTreeSet<String>,
    depth: usize,
) -> bool {
    if depth == 0 {
        return false;
    }
    if matches!(
        expression.kind().as_ref(),
        "await_expression" | "await" | "parenthesized_expression"
    ) {
        return expression
            .children()
            .find(|n| n.is_named())
            .is_some_and(|n| known(root, &n, modules, factories, depth - 1));
    }
    if expression.kind().as_ref() == "subscript" {
        return expression
            .field("value")
            .is_some_and(|n| known(root, &n, modules, factories, depth - 1));
    }
    let text = compact(expression.text().as_ref());
    let text = if expression.kind().as_ref() == "new_expression" {
        text.strip_prefix("new").unwrap_or(&text)
    } else {
        &text
    };
    if let Some((callee, _)) = text.split_once('(') {
        if factories.contains(callee) {
            return producer_unshadowed(root, expression, callee);
        }
        if matches!(expression.kind().as_ref(), "call_expression" | "call") && !callee.contains('.')
        {
            return expression
                .field("function")
                .is_some_and(|f| known(root, &f, modules, factories, depth - 1));
        }
        if let Some((base, method)) = callee.rsplit_once('.') {
            if (modules.contains(base)
                || base
                    .strip_suffix(".DynamoDB")
                    .is_some_and(|base| modules.contains(base)))
                && matches!(
                    method,
                    "connect"
                        | "create_engine"
                        | "Session"
                        | "sessionmaker"
                        | "createPool"
                        | "createConnection"
                        | "Pool"
                        | "Client"
                        | "Database"
                        | "Sequelize"
                        | "PrismaClient"
                        | "ConnectionPool"
                        | "Request"
                        | "MongoClient"
                        | "AsyncIOMotorClient"
                        | "create_client"
                        | "knex"
                        | "DocumentClient"
                        | "DynamoDB"
                        | "model"
                )
            {
                return producer_unshadowed(
                    root,
                    expression,
                    base.split('.').next().unwrap_or(base),
                );
            }
            if modules.contains(base) && matches!(method, "resource" | "client") {
                return text.contains("('dynamodb'") || text.contains("(\"dynamodb\"");
            }
            if matches!(
                method,
                "cursor"
                    | "connect"
                    | "getConnection"
                    | "promise"
                    | "request"
                    | "db"
                    | "collection"
                    | "get_database"
                    | "get_collection"
                    | "model"
                    | "select"
                    | "from"
                    | "where"
                    | "Table"
            ) {
                // Find the exact receiver node to trace a proven connection.
                return expression
                    .dfs()
                    .find(|n| compact(n.text().as_ref()) == base)
                    .is_some_and(|base| known(root, &base, modules, factories, depth - 1));
            }
        }
        return false;
    }
    let owner = class_owner(expression);
    let bindings: Vec<_> = root
        .dfs()
        .filter_map(|node| {
            let (left, right) = match node.kind().as_ref() {
                "variable_declarator" => (node.field("name"), node.field("value")),
                "assignment" | "assignment_expression" | "augmented_assignment" => {
                    (node.field("left"), node.field("right"))
                }
                _ => return None,
            };
            let left = left?;
            if compact(left.text().as_ref()) != text {
                return None;
            }
            if class_owner(&node) != owner {
                return None;
            }
            if !(text.starts_with("this.") || text.starts_with("self."))
                && lexical_owner(&node).is_some_and(|owner| {
                    !(owner.start <= expression.range().start
                        && expression.range().end <= owner.end)
                })
            {
                return None;
            }
            Some(right)
        })
        .collect();
    let [Some(value)] = bindings.as_slice() else {
        return false;
    };
    known(root, value, modules, factories, depth - 1)
}

fn compact(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

fn producer_unshadowed(root: &DbNode<'_>, use_site: &DbNode<'_>, symbol: &str) -> bool {
    !root.dfs().any(|n| {
        let bare_parameter = n.kind().as_ref() == "identifier"
            && n.parent()
                .is_some_and(|p| matches!(p.kind().as_ref(), "parameters" | "formal_parameters"));
        let declaration = matches!(
            n.kind().as_ref(),
            "variable_declarator"
                | "assignment"
                | "assignment_expression"
                | "function_declaration"
                | "function_definition"
                | "required_parameter"
                | "optional_parameter"
                | "typed_parameter"
                | "default_parameter"
        );
        if !bare_parameter && !declaration {
            return false;
        }
        let name = if bare_parameter {
            Some(n.clone())
        } else {
            n.field("name")
                .or_else(|| n.field("left"))
                .or_else(|| n.field("pattern"))
        };
        if name.is_none_or(|name| compact(name.text().as_ref()) != symbol) {
            return false;
        }
        if lexical_owner(&n).is_some_and(|scope| {
            !(scope.start <= use_site.range().start && use_site.range().end <= scope.end)
        }) {
            return false;
        }
        // The unique require producer itself is not a shadow; reassignments are.
        !(n.kind().as_ref() == "variable_declarator"
            && n.field("value")
                .is_some_and(|v| compact(v.text().as_ref()).starts_with("require(")))
    })
}
fn class_owner(node: &DbNode<'_>) -> Option<std::ops::Range<usize>> {
    node.ancestors()
        .find(|n| matches!(n.kind().as_ref(), "class_declaration" | "class_definition"))
        .map(|n| n.range())
}
fn lexical_owner(node: &DbNode<'_>) -> Option<std::ops::Range<usize>> {
    node.ancestors()
        .find(|n| {
            matches!(
                n.kind().as_ref(),
                "function_definition"
                    | "function_declaration"
                    | "method_definition"
                    | "arrow_function"
                    | "function_expression"
            )
        })
        .map(|n| n.range())
}
