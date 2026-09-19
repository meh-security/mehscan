use mehscan_core::Capability;

#[test]
fn database_query_variants_preserve_sql_operand_across_languages() {
    let root = std::env::temp_dir().join(format!("mehscan-query-mechanics-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let cases = [
        (
            "Probe.java",
            "class Probe { void f(java.sql.Connection conn, String sql) throws Exception { java.sql.Statement stm = conn.createStatement(); stm.execute(sql); stm.execute(sql, 1); stm.executeLargeUpdate(sql); stm.addBatch(sql); conn.prepareCall(sql); } }",
            5,
        ),
        (
            "app.php",
            "<?php class Store { private $db; function __construct() { $this->db = new mysqli('host', 'user', 'pass'); } function run($sql) { $this->db->query($sql); $this->db->real_query($sql); $this->db->multi_query($sql); } } class PdoStore { private $db; function __construct() { $this->db = new PDO('sqlite:app.db'); } function run($sql) { $this->db->exec($sql); $this->db->prepare($sql); } }",
            5,
        ),
        (
            "app.js",
            "const mysql = require('mysql2'); function f(sql) { const renamed = mysql.createConnection({}); const store = mysql.createPool({}); store.query(sql); renamed.execute(sql, []); const client = mysql.createConnection({}); client.execute(sql); }",
            3,
        ),
        (
            "app.ts",
            "import mysql from 'mysql2'; function f(sql: string) { const renamed = mysql.createConnection({}); const store = mysql.createPool({}); store.query(sql); renamed.execute(sql, []); const client = mysql.createConnection({}); client.execute(sql); }",
            3,
        ),
        (
            "app.tsx",
            "import mysql from 'mysql2'; function f(sql: string) { const renamed = mysql.createConnection({}); const store = mysql.createPool({}); store.query(sql); renamed.execute(sql, []); const client = mysql.createConnection({}); client.execute(sql); }",
            3,
        ),
        (
            "app.py",
            "import sqlite3\nclass Store:\n    def __init__(self):\n        self.db = sqlite3.connect('app.db')\n    def run(self, sql):\n        renamed = self.db.cursor()\n        self.db.execute(sql)\n        renamed.executemany(sql, [])\n        renamed.callproc(sql, [])\n        self.db.executescript(sql)\n",
            4,
        ),
        (
            "app.go",
            "package app\nfunc run(sql string) { db.QueryRow(sql); db.QueryRowContext(ctx, sql); db.Prepare(sql); db.PrepareContext(ctx, sql) }",
            4,
        ),
        (
            "app.rs",
            "use postgres::Client; fn run(sql: &str) { let mut client = Client::connect(\"host=x\", postgres::NoTls).unwrap(); client.simple_query(sql); client.batch_execute(sql); }",
            2,
        ),
        (
            "app.kt",
            "import java.sql.Statement\nclass Store(val db: Statement) { fun run(sql: String) { this.db.execute(sql); this.db.executeLargeUpdate(sql); this.db.addBatch(sql) } }",
            3,
        ),
        (
            "Probe.cs",
            "class Store { void Run(string sql) { var cmd = new NpgsqlCommand(); cmd.CommandText = sql; var pg = new NpgsqlCommand(sql, connection); db.ExecuteSqlRawAsync(sql); } }",
            3,
        ),
        (
            "app.c",
            "void run(char *sql) { PQexec(db, sql); PQexecParams(db, sql, 0, 0, 0, 0, 0, 0); mysql_real_query(db, sql, 10); mysql_stmt_prepare(stmt, sql, 10); SQLExecDirect(stmt, sql, 10); SQLPrepareW(stmt, sql, 10); }",
            6,
        ),
        (
            "app.cpp",
            "void run(char *sql) { PQexec(db, sql); PQexecParams(db, sql, 0, 0, 0, 0, 0, 0); mysql_real_query(db, sql, 10); mysql_stmt_prepare(stmt, sql, 10); SQLExecDirect(stmt, sql, 10); SQLPrepareW(stmt, sql, 10); }",
            6,
        ),
    ];
    for (path, source, _) in cases {
        std::fs::write(root.join(path), source).unwrap();
    }
    let result = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    for (path, _, expected) in cases {
        let sinks: Vec<_> = result
            .evidence
            .iter()
            .filter(|e| e.location.path == path && e.capability == Capability::DatabaseQuery)
            .collect();
        assert_eq!(sinks.len(), expected, "{path}: {sinks:#?}");
        assert!(
            sinks
                .iter()
                .all(|e| e.captures["query"].text == "sql" || e.captures["query"].text == "$sql"),
            "{path}"
        );
        assert!(
            sinks.iter().all(|e| {
                e.tags
                    .iter()
                    .any(|tag| tag == "review-origin:decision-critical")
            }),
            "{path}: nonliteral query operands must remain reviewable"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn php_property_identity_excludes_lookalikes_other_classes_and_reassignments() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-query-property-negative-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("app.php"), r#"<?php
class NativeStore { private $db; function __construct() { $this->db = new mysqli('h','u','p'); } }
class OtherStore { private $db; function run($sql) { $this->db->query($sql); } }
class Reassigned { private $db; function __construct() { $this->db = new mysqli('h','u','p'); } function replace() { $this->db = new OtherStore(); } function run($sql) { $this->db->query($sql); } }
class Conditional { private $db; function __construct($flag) { if ($flag) { $this->db = new mysqli('h','u','p'); } } function run($sql) { $this->db->query($sql); } }
namespace App { class mysqli {} class Shadow { private $db; function __construct() { $this->db = new mysqli(); } function run($sql) { $this->db->query($sql); } } }
"#).unwrap();
    let result = mehscan_engine::scan_path(&root).unwrap();
    assert!(
        !result
            .evidence
            .iter()
            .any(|e| e.capability == Capability::DatabaseQuery)
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn generic_database_method_names_require_receiver_identity() {
    let root =
        std::env::temp_dir().join(format!("mehscan-query-lookalikes-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("app.js"), "const mysql = require('mysql2'); function f(sql) { unrelated.query(sql); unrelated.execute(sql); const renamed = mysql.createConnection({}); renamed = other; renamed.query(sql); }").unwrap();
    std::fs::write(root.join("app.py"), "import sqlite3\ndef f(sql):\n    unrelated.execute(sql)\n    unrelated.executemany(sql, [])\n    renamed = sqlite3.connect('x')\n    renamed = other\n    renamed.execute(sql)\n").unwrap();
    let result = mehscan_engine::scan_path(&root).unwrap();
    assert!(
        !result
            .evidence
            .iter()
            .any(|e| e.capability == Capability::DatabaseQuery)
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn reported_java_execute_and_php_property_query_shapes_reach_security_paths() {
    let root = std::env::temp_dir().join(format!("mehscan-query-paths-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("Probe.java"), "class Probe { void run(HttpServletRequest request, java.sql.Connection conn) throws Exception { java.sql.Statement stm = conn.createStatement(); String sql = \"SELECT * FROM users WHERE name='\" + request.getParameter(\"name\") + \"'\"; stm.execute(sql); } }").unwrap();
    std::fs::write(root.join("app.php"), "<?php class Store { private $db; function __construct() { $this->db = new mysqli('h','u','p'); } function run() { $sql = \"SELECT * FROM users WHERE name='\" . $_GET['name'] . \"'\"; $this->db->query($sql); } }").unwrap();
    let result = mehscan_engine::scan_path(&root).unwrap();
    for path in ["Probe.java", "app.php"] {
        assert!(
            result
                .security_paths
                .iter()
                .any(|p| p.capability == Capability::DatabaseQuery
                    && result
                        .evidence
                        .iter()
                        .any(|e| e.id == p.sink_evidence_id && e.location.path == path)),
            "{path}: {:#?}",
            result.security_paths
        );
    }
    let sink = result
        .evidence
        .iter()
        .find(|e| e.rule_id == "php-mysqli-method-query")
        .unwrap();
    assert!(
        sink.captures["database_receiver_origin"]
            .text
            .contains("new mysqli")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn module_scoped_and_namespace_import_database_receivers_survive_handler_scope() {
    let root = std::env::temp_dir().join(format!("mehscan-query-imports-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("app.ts"), "import * as driver from 'mysql2'; const handle = driver.createConnection({}); function run(sql: string) { handle.query(sql); handle.execute(sql, []); } function make() { const local = driver.createConnection({}); return (sql: string) => local.query(sql); }").unwrap();
    std::fs::write(root.join("app.py"), "import sqlite3 as driver\nhandle = driver.connect('x')\ndef run(sql):\n    handle.execute(sql)\n").unwrap();
    let result = mehscan_engine::scan_path(&root).unwrap();
    for (path, expected) in [("app.ts", 3), ("app.py", 1)] {
        assert_eq!(
            result
                .evidence
                .iter()
                .filter(|e| e.location.path == path && e.capability == Capability::DatabaseQuery)
                .count(),
            expected,
            "{path}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn java_execute_identity_keeps_factories_and_fields_but_excludes_other_apis() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-query-java-identity-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("Probe.java"), "import java.sql.Statement; class Probe { private java.sql.Statement db; void run(java.sql.Connection conn, Statement stmt, String sql) throws Exception { var local = conn.createStatement(); local.execute(sql); this.db.execute(sql); stmt.execute(sql); } void unrelated(Executor stmt, HttpClient client, String value) { stmt.execute(value); client.execute(value); } interface FakeExecutor { void execute(String value); } <Statement extends FakeExecutor> void generic(Statement statement, String value) { statement.execute(value); } }").unwrap();
    let result = mehscan_engine::scan_path(&root).unwrap();
    let sinks: Vec<_> = result
        .evidence
        .iter()
        .filter(|e| e.capability == Capability::DatabaseQuery)
        .collect();
    assert_eq!(sinks.len(), 3, "{sinks:#?}");
    assert!(sinks.iter().all(|e| e.captures["query"].text == "sql"));
    std::fs::remove_dir_all(root).unwrap();
}
