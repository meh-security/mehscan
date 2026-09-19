use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind};

fn temp_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("mehscan-{label}-{}", std::process::id()))
}

#[test]
fn marks_composed_sql_without_promoting_plain_unknown_query_parameters() {
    let root = temp_root("multilanguage-origins");
    std::fs::create_dir_all(&root).unwrap();
    let cases = [
        (
            "Probe.java",
            r#"class Probe { void run(java.sql.Connection conn, String name) throws Exception { java.sql.Statement stm = conn.createStatement(); String sql = "SELECT * FROM users WHERE name='" + name + "'"; stm.execute(sql); } }"#,
        ),
        (
            "app.php",
            r#"<?php function run($db, $name) { mysqli_query($db, "SELECT * FROM users WHERE name='" . $name . "'"); }"#,
        ),
        (
            "app.js",
            r#"const mysql = require('mysql2'); const db = mysql.createConnection({}); function run(name) { db.query(`SELECT * FROM users WHERE name='${name}'`); }"#,
        ),
        (
            "app.ts",
            r#"import mysql from 'mysql2'; const db = mysql.createConnection({}); function run(name: string) { db.query(`SELECT * FROM users WHERE name='${name}'`); }"#,
        ),
        (
            "app.tsx",
            r#"import mysql from 'mysql2'; const db = mysql.createConnection({}); function run(name: string) { db.query(`SELECT * FROM users WHERE name='${name}'`); }"#,
        ),
        (
            "app.py",
            "import sqlite3\ndef run(name):\n    db = sqlite3.connect('x')\n    db.execute(f\"SELECT * FROM users WHERE name='{name}'\")\n",
        ),
        (
            "app.go",
            "package app\nimport \"fmt\"\nfunc run(name string) { db.Query(fmt.Sprintf(\"SELECT * FROM users WHERE name='%s'\", name)) }\n",
        ),
        (
            "app.rs",
            r#"use postgres::Client; fn run(name: &str) { let mut client = Client::connect("host=x", postgres::NoTls).unwrap(); client.batch_execute(&format!("SELECT * FROM users WHERE name='{name}'")); }"#,
        ),
        (
            "app.kt",
            "import java.sql.Statement\nclass Store(val db: Statement) { fun run(name: String) { db.executeQuery(\"SELECT * FROM users WHERE name='$name'\") } }\n",
        ),
        (
            "app.c",
            r#"void run(char *name) { char sql[256]; snprintf(sql, 256, "SELECT * FROM users WHERE name='%s'", name); PQexec(db, sql); }"#,
        ),
        (
            "app.cpp",
            r#"void run(char *name) { char sql[256]; snprintf(sql, 256, "SELECT * FROM users WHERE name='%s'", name); PQexec(db, sql); }"#,
        ),
    ];
    for (path, source) in cases {
        std::fs::write(root.join(path), source).unwrap();
    }

    let result = mehscan_engine::scan_path(&root).unwrap();
    for (path, _) in cases {
        assert!(
            result.evidence.iter().any(|item| {
                item.location.path == path
                    && item.kind == EvidenceKind::Sink
                    && item.capability == Capability::DatabaseQuery
                    && item
                        .tags
                        .iter()
                        .any(|tag| tag == "review-origin:decision-critical")
            }),
            "missing composed-query marker for {path}: {:#?}",
            result
                .evidence
                .iter()
                .filter(|item| item.location.path == path)
                .collect::<Vec<_>>()
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn supplies_two_bounded_unique_caller_layers_for_repository_review() {
    let root = temp_root("repository-review-context");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("repository.js"),
        r#"const mysql = require('mysql2'); const db = mysql.createConnection({});
function findUser(name) { return db.query(`SELECT * FROM users WHERE name='${name}'`); }
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("service.js"),
        "function searchService(name) { return findUser(name); }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("controller.js"),
        "function searchController(req) { return searchService(req.query.name); }\n\
         function unrelatedController(req) { return searchService(normalize(req.query.name)); }\n",
    )
    .unwrap();

    let reviews =
        mehscan_engine::investigation::build_path_review_jobs(&root, Some(8), Some(100)).unwrap();
    let review = reviews
        .observation_reviews
        .iter()
        .find(|review| {
            review
                .review_basis
                .as_ref()
                .is_some_and(|basis| basis.relationship == "bounded_dynamic_query_composition")
        })
        .expect("dynamic repository query review");
    assert!(review.facts.iter().any(|fact| {
        fact.role == "exact_caller_context" && fact.excerpt.contains("searchService")
    }));
    assert!(review.facts.iter().any(|fact| {
        fact.role == "upstream_caller_context" && fact.excerpt.contains("searchController")
    }));
    assert!(
        !review
            .facts
            .iter()
            .any(|fact| fact.excerpt.contains("unrelatedController"))
    );
    assert_eq!(review.decision_facts.unresolved.len(), 1);

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn keeps_local_query_aliases_inside_their_callable_and_honors_latest_mutation() {
    let root = temp_root("local-query-aliases");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("aliases.js"),
        r#"const mysql = require('mysql2'); const db = mysql.createConnection({});
function earlier(name) { const sql = `SELECT * FROM users WHERE name='${name}'`; return sql; }
function plain(sql) { return db.query(sql); }
function reset(name) { let sql = `SELECT * FROM users WHERE name='${name}'`; sql = "SELECT 1"; return db.query(sql); }
function built(name) { let sql = "SELECT * FROM users WHERE name='"; sql += name; return db.query(sql); }
"#,
    )
    .unwrap();

    let result = mehscan_engine::scan_path(&root).unwrap();
    let queries = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::DatabaseQuery)
        .collect::<Vec<_>>();
    assert_eq!(
        queries
            .iter()
            .filter(|item| item
                .tags
                .iter()
                .any(|tag| tag == "review-origin:decision-critical"))
            .count(),
        1,
        "{queries:#?}"
    );
    assert!(queries.iter().any(|item| {
        item.tags
            .iter()
            .any(|tag| tag == "query-composition:bounded-local-builder")
    }));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn retains_dynamic_interpreter_operands_but_not_fixed_or_structured_ones() {
    let root = temp_root("multilanguage-critical-boundaries");
    std::fs::create_dir_all(&root).unwrap();
    for (path, source) in [
        (
            "app.js",
            "function run(code, args) { eval(code); eval('2 + 2'); child_process.exec(code); child_process.spawn('tool', args); document.body.innerHTML = code; }\n",
        ),
        (
            "app.py",
            "import os, pickle\ndef run(command, payload):\n    os.system(command)\n    return pickle.loads(payload)\n",
        ),
        (
            "app.php",
            "<?php function run($payload) { return unserialize($payload); }\n",
        ),
        (
            "Probe.java",
            "import java.io.ObjectInputStream; import java.io.InputStream; class Probe { Object run(InputStream input) throws Exception { return new ObjectInputStream(input).readObject(); } Object structured(ObjectMapper mapper, String payload) { return mapper.readValue(payload, User.class); } }\n",
        ),
        (
            "app.c",
            "void run(char *format, char *value) { printf(format, value); printf(\"%s\", format); }\n",
        ),
        (
            "app.rs",
            "fn run(payload: &str) { let value: Value = serde_json::from_str(payload).unwrap(); }\n",
        ),
    ] {
        std::fs::write(root.join(path), source).unwrap();
    }

    let result = mehscan_engine::scan_path(&root).unwrap();
    let marked = result
        .evidence
        .iter()
        .filter(|item| {
            item.tags
                .iter()
                .any(|tag| tag == "review-origin:decision-critical")
        })
        .collect::<Vec<_>>();
    for rule in [
        "javascript-dynamic-code",
        "javascript-child-process",
        "javascript-browser-dom-html-output",
        "python-process-execution",
        "python-pickle-deserialization",
        "php-deserialization",
        "java-native-object-deserialization",
        "c-format-string-output",
    ] {
        assert!(
            marked.iter().any(|item| item.rule_id == rule),
            "missing marker for {rule}: {marked:#?}"
        );
    }
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "rust-data-deserialization"
            && !item
                .tags
                .iter()
                .any(|tag| tag == "review-origin:decision-critical")
    }));
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "javascript-child-process"
            && item
                .captures
                .get("command")
                .is_some_and(|capture| capture.text == "'tool'")
            && !item
                .tags
                .iter()
                .any(|tag| tag == "review-origin:decision-critical")
    }));

    let reviews =
        mehscan_engine::investigation::build_path_review_jobs(&root, Some(8), Some(100)).unwrap();
    let relationships = reviews
        .observation_reviews
        .iter()
        .filter_map(|review| review.review_basis.as_ref())
        .map(|basis| basis.relationship.as_str())
        .collect::<BTreeSet<_>>();
    for relationship in [
        "bounded_shell_command_interpretation",
        "bounded_native_format_interpretation",
        "bounded_dynamic_code_interpretation",
        "bounded_executable_object_deserialization",
        "bounded_trusted_html_interpretation",
    ] {
        assert!(relationships.contains(relationship), "{relationships:#?}");
    }

    std::fs::remove_dir_all(root).unwrap();
}
