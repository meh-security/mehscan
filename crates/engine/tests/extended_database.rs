use mehscan_core::Capability;

fn scan(label: &str, cases: &[(&str, &str)]) -> mehscan_core::ScanResult {
    let root =
        std::env::temp_dir().join(format!("mehscan-extended-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    for (path, source) in cases {
        std::fs::write(root.join(path), source).unwrap();
    }
    let result = mehscan_engine::scan_path(&root).unwrap();
    std::fs::remove_dir_all(root).unwrap();
    assert_eq!(
        result.coverage.totals.parse_failed, 0,
        "{:?}",
        result.coverage
    );
    result
}

#[test]
fn extended_nosql_filters_preserve_operand_for_every_supported_language() {
    let cases = [
        (
            "app.js",
            "const { MongoClient } = require('mongodb'); const client = new MongoClient('uri'); const store = client.db('app').collection('users'); function run(filter) { store.findOne(filter); store.updateOne(filter, { $set: { active: true } }); }",
            2,
        ),
        (
            "app.ts",
            "import { MongoClient } from 'mongodb'; const client = new MongoClient('uri'); const store = client.db('app').collection('users'); function run(filter: any) { store.findOne(filter); store.aggregate(filter); }",
            2,
        ),
        (
            "app.tsx",
            "import { MongoClient } from 'mongodb'; const client = new MongoClient('uri'); const store = client.db('app').collection('users'); function run(filter: any) { store.findOne(filter); store.deleteMany(filter); }",
            2,
        ),
        (
            "app.py",
            "from pymongo import MongoClient as Client\nclient = Client('uri')\nstore = client['app']['users']\ndef run(filter):\n    store.find_one(filter)\n    store.update_many(filter, {'$set': {'active': True}})\n",
            2,
        ),
        (
            "Probe.java",
            "import com.mongodb.client.MongoCollection; import org.bson.Document; class Probe { void run(MongoCollection<Document> store, String filter, Document selector) { store.find(selector); store.deleteMany(selector); Document.parse(filter); } }",
            3,
        ),
        (
            "app.kt",
            "import com.mongodb.client.MongoCollection\nimport org.bson.Document\nfun run(store: MongoCollection<Document>, filter: String, selector: Document) { store.find(selector); store.deleteMany(selector); Document.parse(filter) }",
            3,
        ),
        (
            "Probe.cs",
            "using MongoDB.Driver; using MongoDB.Bson; class Probe { void Run(IMongoCollection<BsonDocument> store, string filter, BsonDocument selector) { store.Find(selector); store.DeleteMany(selector); BsonDocument.Parse(filter); } }",
            3,
        ),
        (
            "app.php",
            "<?php use MongoDB\\Driver\\Query as Filter; function run($filter) { new Filter($filter); new \\MongoDB\\Driver\\Query($filter, []); }",
            2,
        ),
        (
            "app.rs",
            "use mongodb::Collection; use mongodb::bson::Document; async fn run(store: &Collection<Document>, filter: Document) { store.find(filter.clone()).await; store.delete_many(filter).await; }",
            2,
        ),
        (
            "app.c",
            "void run(void *store, void *filter) { mongoc_collection_find_with_opts(store, filter, 0, 0); mongoc_collection_delete_many(store, filter, 0, 0, 0); }",
            2,
        ),
        (
            "app.cpp",
            "void run(mongocxx::collection &store, bsoncxx::document::view filter) { store.find(filter); store.delete_many(filter); }",
            2,
        ),
        (
            "app.go",
            "package app\nimport \"go.mongodb.org/mongo-driver/v2/mongo\"\nfunc run(store *mongo.Collection, filter any) { store.DeleteMany(ctx, filter); store.Aggregate(ctx, filter) }",
            2,
        ),
    ];
    let sources: Vec<_> = cases
        .iter()
        .map(|(path, source, _)| (*path, *source))
        .collect();
    let result = scan("nosql", &sources);
    for (path, _, expected) in cases {
        let hits: Vec<_> = result
            .evidence
            .iter()
            .filter(|e| {
                e.location.path == path
                    && e.capability == Capability::DatabaseQuery
                    && e.cwe_candidates.iter().any(|c| c == "CWE-943")
            })
            .collect();
        assert_eq!(hits.len(), expected, "{path}: {hits:#?}");
        assert!(
            hits.iter()
                .all(|hit| hit.captures.values().any(|c| matches!(
                    c.text.trim_start_matches('$'),
                    "filter" | "filter.clone()" | "selector"
                ))),
            "{path}: {hits:#?}"
        );
        assert!(
            hits.iter()
                .all(|hit| !hit.cwe_candidates.iter().any(|c| c == "CWE-89"))
        );
        assert!(
            hits.iter().all(|hit| hit
                .tags
                .iter()
                .any(|tag| tag == "review-origin:decision-critical")),
            "dynamic NoSQL structure must remain reviewable for {path}: {hits:#?}"
        );
    }
}

#[test]
fn extended_sql_drivers_capture_query_text_instead_of_context_or_binding_values() {
    let cases = [
        (
            "app.js",
            "const knex = require('knex'); const db = knex({client:'pg'}); const sqlite = require('better-sqlite3'); const store = new sqlite('db'); function run(sql, value) { db('users').whereRaw(sql, [value]); db.raw(sql); store.prepare(sql); }",
            3,
        ),
        (
            "app.ts",
            "import sqlserver from 'mssql'; const db = new sqlserver.ConnectionPool({}); function run(sql: string) { const request = db.request(); request.query(sql); request.batch(sql); }",
            2,
        ),
        (
            "app.py",
            "import asyncpg\nfrom sqlalchemy import text as raw\nfrom django.db.models.expressions import RawSQL as Expression\nasync def run(sql, value):\n    db = await asyncpg.connect('uri')\n    await db.fetch(sql, value)\n    await db.fetchrow(sql)\n    db.prepare(sql)\n    raw(sql)\n    Expression(sql, [value])\n",
            5,
        ),
        (
            "Probe.java",
            "import org.hibernate.Session; import javax.jdo.Query; import io.vertx.sqlclient.SqlConnection; class Probe { void run(Session session, Query query, SqlConnection db, String sql) { session.createNativeQuery(sql); query.setFilter(sql); db.preparedQuery(sql); } }",
            3,
        ),
        (
            "app.kt",
            "import org.hibernate.Session\nimport javax.jdo.Query\nimport io.vertx.sqlclient.SqlConnection\nfun run(session: Session, query: Query, db: SqlConnection, sql: String) { session.createNativeQuery(sql); query.setFilter(sql); db.preparedQuery(sql) }",
            3,
        ),
        (
            "app.php",
            "<?php use Illuminate\\Support\\Facades\\DB as Database; function run($sql, $values) { Database::select($sql, $values); Database::unprepared($sql); pg_query($conn, $sql); pg_query_params($conn, $sql, $values); pg_prepare($conn, 'name', $sql); }",
            5,
        ),
        (
            "app.go",
            "package app\nimport p \"github.com/jackc/pgx/v5\"\nimport \"github.com/jmoiron/sqlx\"\nfunc run(db *p.Conn, other *sqlx.DB, sql string) { db.Query(ctx, sql, value); db.Exec(ctx, sql); db.Prepare(ctx, \"name\", sql); other.Get(&dest, sql, value); other.NamedExec(sql, values); other.Get(&dest, sql); other.SelectContext(ctx, &dest, sql); other.NamedExecContext(ctx, sql, values) }",
            8,
        ),
    ];
    let sources: Vec<_> = cases
        .iter()
        .map(|(path, source, _)| (*path, *source))
        .collect();
    let result = scan("sql", &sources);
    for (path, _, expected) in cases {
        let hits: Vec<_> = result
            .evidence
            .iter()
            .filter(|e| {
                e.location.path == path
                    && e.capability == Capability::DatabaseQuery
                    && e.cwe_candidates.iter().any(|c| c == "CWE-89")
            })
            .collect();
        assert_eq!(hits.len(), expected, "{path}: {hits:#?}");
        assert!(
            hits.iter().all(|e| e
                .captures
                .get("query")
                .is_some_and(|c| c.text.trim_start_matches('$') == "sql")),
            "{path}: {hits:#?}"
        );
    }
}

#[test]
fn extended_rules_reject_unrelated_collection_and_raw_expression_lookalikes() {
    let result = scan(
        "negative",
        &[
            (
                "app.js",
                "const store = new FakeCollection(); function run(filter) { store.find(filter); store.deleteMany(filter); store.raw(filter); }",
            ),
            (
                "app.py",
                "class Store:\n    def find_one(self, value): pass\nstore = Store()\nstore.find_one(filter)\ndef RawSQL(value): pass\nRawSQL(filter)\n",
            ),
            (
                "Probe.java",
                "class Document { static Object parse(String value) { return value; } } class Probe { void run(FakeCollection store, String filter) { store.find(filter); Document.parse(filter); } }",
            ),
            (
                "app.kt",
                "class Document {\n    companion object {\n        fun parse(value: String): String { return value }\n    }\n}\nfun run(store: FakeCollection, filter: String) { store.find(filter); Document.parse(filter) }",
            ),
            (
                "Probe.cs",
                "class BsonDocument { public static string Parse(string value) { return value; } } class Probe { void Run(FakeCollection store, string filter) { store.Find(filter); BsonDocument.Parse(filter); } }",
            ),
            (
                "app.rs",
                "struct Collection; fn run(store: &Collection, filter: String) { store.find(filter); }",
            ),
            (
                "app.cpp",
                "void run(FakeCollection &store, int filter) { store.find(filter); }",
            ),
            (
                "app.php",
                "<?php namespace App; class Query {} class DB { static function select($sql) {} } function run($filter) { new Query($filter); DB::select($filter); }",
            ),
            (
                "app.go",
                "package app\nfunc run(db *FakeConn, sql string) { db.Get(dest, sql); db.Prepare(ctx, \"name\", sql) }",
            ),
        ],
    );
    let hits: Vec<_> = result
        .evidence
        .iter()
        .filter(|e| e.rule_id.contains("-extended-"))
        .collect();
    assert!(hits.is_empty(), "{hits:#?}");
}

#[test]
fn extended_dynamodb_rules_separate_expression_syntax_from_bound_attribute_values() {
    let result = scan(
        "dynamodb",
        &[
            (
                "app.ts",
                "import { QueryCommand as Query, ScanCommand } from '@aws-sdk/lib-dynamodb'; function run(expression: string, value: unknown, input: any) { new Query({ TableName: 't', KeyConditionExpression: expression, ExpressionAttributeValues: { ':id': value } }); new ScanCommand(input); new Query({TableName: 't', KeyConditionExpression: 'id = :id', ExpressionAttributeValues: { ':id': value }}); }",
            ),
            (
                "app.js",
                "const AWS = require('aws-sdk'); const store = new AWS.DynamoDB.DocumentClient({}); function run(expression, value) { store.query({TableName: 't', KeyConditionExpression: expression, ExpressionAttributeValues: { ':id': value }}); store.scan({TableName: 't', FilterExpression: expression}); }",
            ),
            (
                "app.py",
                "import boto3\nstore = boto3.resource('dynamodb').Table('users')\ndef run(expression, value):\n    store.query(KeyConditionExpression=expression, ExpressionAttributeValues={':id': value})\n    store.scan(FilterExpression=expression)\n",
            ),
        ],
    );
    for (path, expected) in [("app.ts", 3), ("app.js", 2), ("app.py", 2)] {
        let hits: Vec<_> = result
            .evidence
            .iter()
            .filter(|e| e.location.path == path && e.rule_id.contains("-extended-nosql-"))
            .collect();
        assert_eq!(hits.len(), expected, "{path}: {hits:#?}");
        assert!(
            hits.iter().all(|hit| hit
                .captures
                .get("nosql_query")
                .is_some_and(|c| matches!(c.text.as_str(), "expression" | "input" | "'id = :id'"))),
            "{path}: {hits:#?}"
        );
        assert!(hits.iter().all(|hit| {
            hit.captures
                .get("nosql_query")
                .is_none_or(|c| !c.text.contains("value"))
        }));
    }
}

#[test]
fn imported_sdk_names_do_not_override_local_parameter_or_producer_shadows() {
    let result = scan(
        "shadows",
        &[
            (
                "app.ts",
                "import { MongoClient } from 'mongodb'; import { QueryCommand } from '@aws-sdk/lib-dynamodb'; function run(MongoClient: any, QueryCommand: any, input: any) { const store = new MongoClient().db('app').collection('users'); store.find(input); new QueryCommand(input); }",
            ),
            (
                "app.py",
                "import asyncpg\nfrom sqlalchemy import text\ndef run(asyncpg, text, sql):\n    db = asyncpg.connect('uri')\n    db.fetch(sql)\n    text(sql)\n",
            ),
            (
                "app.rs",
                "use mongodb::Collection; fn run(store: &Collection<String>, filter: String) { let store = FakeCollection::new(); store.find(filter); }",
            ),
            (
                "app.go",
                "package app\nimport \"github.com/jmoiron/sqlx\"\nfunc run(db *sqlx.DB, sql string) { if ready { db := newFake(); db.Get(dest, sql) } }",
            ),
        ],
    );
    assert!(
        !result
            .evidence
            .iter()
            .any(|e| e.rule_id.contains("-extended-")),
        "{:?}",
        result.evidence
    );
}

#[test]
fn extended_php_query_builders_and_native_typed_parameters_are_bounded() {
    let result = scan(
        "php-builders",
        &[(
            "app.php",
            "<?php use Doctrine\\DBAL\\Connection; use Illuminate\\Support\\Facades\\DB; function run(Connection $db, PDO $pdo, mysqli $mysqli, $sql, $values) { $db->executeQuery($sql, $values); $builder = $db->createQueryBuilder(); $builder->where($sql); DB::table('users')->whereRaw($sql, $values); $pdo->query($sql); $mysqli->execute_query($sql, $values); } function other(Fake $db, $sql) { $db->executeQuery($sql); } function overwritten(Connection $db, $sql) { $db = new Fake; $db->executeQuery($sql); } function altered(PDO $pdo, $sql) { include 'unknown.php'; $pdo->query($sql); } function alteredSdk(Connection $db, $sql) { include 'unknown.php'; $db->executeQuery($sql); }",
        )],
    );
    let hits: Vec<_> = result
        .evidence
        .iter()
        .filter(|e| e.capability == Capability::DatabaseQuery)
        .collect();
    assert_eq!(hits.len(), 5, "{hits:#?}");
    assert!(
        hits.iter()
            .all(|hit| hit.captures.get("query").is_some_and(|q| q.text == "$sql"))
    );
}

#[test]
fn extended_python_orm_and_rust_client_text_entrypoints_preserve_binding_roles() {
    let result = scan(
        "orm-rust",
        &[
            (
                "app.py",
                "from django.db import models\nfrom sqlalchemy.orm import Session\nclass User(models.Model):\n    pass\ndef run(sql, values):\n    User.objects.raw(sql, values)\n    session = Session()\n    session.execute(sql, values)\n",
            ),
            (
                "app.rs",
                "use rusqlite::Connection; use tokio_postgres::Client; async fn run(db: &Connection, client: &Client, sql: &str, values: &[&(dyn tokio_postgres::types::ToSql + Sync)]) { db.prepare(sql); db.execute_batch(sql); client.query(sql, values).await; }",
            ),
        ],
    );
    for (path, expected) in [("app.py", 2), ("app.rs", 3)] {
        let hits: Vec<_> = result
            .evidence
            .iter()
            .filter(|e| e.location.path == path && e.capability == Capability::DatabaseQuery)
            .collect();
        assert_eq!(hits.len(), expected, "{path}: {hits:#?}");
        assert!(
            hits.iter()
                .all(|hit| hit.captures.get("query").is_some_and(|q| q.text == "sql"))
        );
    }
}

#[test]
fn extended_raw_document_query_constructors_keep_the_executable_or_json_operand() {
    let result = scan(
        "documents",
        &[
            (
                "Probe.java",
                "import com.mongodb.BasicDBObject; import org.springframework.data.mongodb.core.query.BasicQuery; class Probe { void run(String filter) { new BasicDBObject(\"$where\", filter); new BasicQuery(filter); } }",
            ),
            (
                "app.kt",
                "import com.mongodb.BasicDBObject\nimport org.springframework.data.mongodb.core.query.BasicQuery\nfun run(filter: String) { BasicDBObject(\"\\$where\", filter); BasicQuery(filter) }",
            ),
            (
                "Probe.cs",
                "using MongoDB.Driver; class Probe { void Run(string filter) { new JsonFilterDefinition<Document>(filter); } }",
            ),
        ],
    );
    for (path, expected) in [("Probe.java", 2), ("app.kt", 2), ("Probe.cs", 1)] {
        let hits: Vec<_> = result
            .evidence
            .iter()
            .filter(|e| e.location.path == path && e.rule_id.ends_with("extended-nosql-json"))
            .collect();
        assert_eq!(hits.len(), expected, "{path}: {hits:#?}");
        assert!(hits.iter().all(|hit| {
            hit.captures
                .get("nosql_query")
                .is_some_and(|q| q.text == "filter")
        }));
    }
}

#[test]
fn extended_whole_mongodb_request_filters_reach_nosql_security_paths() {
    let result = scan(
        "nosql-paths",
        &[(
            "app.js",
            "const { MongoClient } = require('mongodb'); const client = new MongoClient('uri'); const store = client.db('app').collection('users'); function handler(req, res) { store.findOne(req.body); }",
        )],
    );
    let sink = result
        .evidence
        .iter()
        .find(|e| e.rule_id == "javascript-extended-nosql-query")
        .expect("proven collection filter");
    assert!(
        result
            .security_paths
            .iter()
            .any(|p| p.sink_evidence_id == sink.id
                && p.cwe_candidates.iter().any(|c| c == "CWE-943")),
        "{:?}",
        result.security_paths
    );
    assert!(
        !result.security_paths.iter().any(
            |p| p.sink_evidence_id == sink.id && p.cwe_candidates.iter().any(|c| c == "CWE-89")
        )
    );
}

#[test]
fn extended_dynamodb_secondary_expressions_reach_only_nosql_security_paths() {
    let result = scan(
        "dynamodb-paths",
        &[(
            "app.ts",
            "import { QueryCommand } from '@aws-sdk/lib-dynamodb'; function handler(req: any, res: any) { new QueryCommand({TableName: 't', KeyConditionExpression: req.body.key, FilterExpression: req.body.filter, ExpressionAttributeValues: {':value': req.body.value}}); }",
        )],
    );
    let sink = result
        .evidence
        .iter()
        .find(|e| e.rule_id == "typescript-extended-nosql-command")
        .unwrap();
    let paths: Vec<_> = result
        .security_paths
        .iter()
        .filter(|p| p.sink_evidence_id == sink.id)
        .collect();
    assert_eq!(paths.len(), 2, "{paths:#?}");
    assert!(paths.iter().all(|p| p.cwe_candidates == ["CWE-943"]));
}

#[test]
fn extended_php_entrypoints_do_not_guess_named_or_unpacked_query_positions() {
    let result = scan(
        "php-positions",
        &[(
            "app.php",
            "<?php use Illuminate\\Support\\Facades\\DB; use MongoDB\\Driver\\Query; function run($sql, $values) { DB::select(bindings: $values, query: $sql); DB::statement(...$values); pg_query(connection: $values, query: $sql); new Query(...$values); }",
        )],
    );
    assert!(
        !result
            .evidence
            .iter()
            .any(|e| e.capability == Capability::DatabaseQuery),
        "{:?}",
        result.evidence
    );
}
