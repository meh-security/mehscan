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
    let mut modules = BTreeSet::new();
    let mut factories = BTreeSet::new();
    for import in root.dfs().filter(|n| {
        matches!(
            n.kind().as_ref(),
            "import_statement" | "import_from_statement" | "variable_declarator"
        )
    }) {
        let source = import.text();
        let source = source.as_ref();
        if language == Language::Python {
            for module in [
                "sqlite3",
                "psycopg",
                "psycopg2",
                "pymysql",
                "mysql.connector",
                "sqlalchemy",
                "duckdb",
            ] {
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
                        if matches!(original, "connect" | "create_engine") {
                            factories.insert(alias.trim().to_string());
                        }
                    }
                }
            }
        } else {
            let compact_source = compact(source);
            let database_module = [
                "pg",
                "mysql",
                "mysql2",
                "mysql2/promise",
                "sequelize",
                "@prisma/client",
                "sqlite3",
                "better-sqlite3",
            ]
            .iter()
            .any(|module| {
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
                            modules.insert(compact(name.text().as_ref()));
                        } else {
                            for part in name.dfs().filter(|n| {
                                n.kind().as_ref() == "shorthand_property_identifier_pattern"
                            }) {
                                if matches!(
                                    part.text().as_ref(),
                                    "Pool" | "Client" | "Sequelize" | "PrismaClient" | "Database"
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
                                "Pool" | "Client" | "Sequelize" | "PrismaClient" | "Database"
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
                            modules.insert(name.text().to_string());
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
    let text = compact(expression.text().as_ref());
    let text = if expression.kind().as_ref() == "new_expression" {
        text.strip_prefix("new").unwrap_or(&text)
    } else {
        &text
    };
    if let Some((callee, _)) = text.split_once('(') {
        if factories.contains(callee) {
            return true;
        }
        if let Some((base, method)) = callee.rsplit_once('.') {
            if modules.contains(base)
                && matches!(
                    method,
                    "connect"
                        | "create_engine"
                        | "createPool"
                        | "createConnection"
                        | "Pool"
                        | "Client"
                        | "Database"
                        | "Sequelize"
                        | "PrismaClient"
                )
            {
                return true;
            }
            if matches!(method, "cursor" | "connect" | "getConnection" | "promise") {
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
