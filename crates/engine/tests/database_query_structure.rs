use mehscan_core::Capability;

#[test]
fn normalizes_query_envelopes_and_preserves_only_dynamic_grammar() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-database-query-structure-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("app.js"),
        r#"const pg = require('pg');
const client = new pg.Client();
function run(sql, value) {
  client.query({ text: sql, values: [value] });
  client.query({ text: 'select * from users where id = $1', values: [value] });
}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("App.cs"),
        r#"using System.Data;
using Dapper;
class App { void Run(IDbConnection db, string sql, object value) {
  db.Query(new CommandDefinition(commandText: sql, parameters: new { value }));
  db.Query(new CommandDefinition("select * from users where id = @value", new { value }));
  db.Query(sql, commandType: CommandType.StoredProcedure);
} }"#,
    )
    .unwrap();

    let result = mehscan_engine::scan_path(&root).unwrap();
    let sinks = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::DatabaseQuery)
        .collect::<Vec<_>>();
    for path in ["app.js", "App.cs"] {
        assert!(
            sinks.iter().any(|item| {
                item.location.path == path
                    && item
                        .captures
                        .get("query")
                        .is_some_and(|query| query.text == "sql")
                    && item.captures.contains_key("query_envelope")
                    && item
                        .tags
                        .iter()
                        .any(|tag| tag == "review-origin:decision-critical")
            }),
            "missing normalized dynamic query for {path}: {sinks:#?}"
        );
        assert!(
            sinks.iter().any(|item| {
                item.location.path == path
                    && item
                        .captures
                        .get("query")
                        .is_some_and(|query| query.text.starts_with(['\'', '"']))
                    && !item
                        .tags
                        .iter()
                        .any(|tag| tag == "review-origin:decision-critical")
            }),
            "fixed query envelope should remain outside review for {path}: {sinks:#?}"
        );
    }
    assert!(sinks.iter().any(|item| {
        item.location.path == "app.js"
            && item.tags.iter().any(|tag| tag == "query-bindings:separate")
    }));
    assert!(sinks.iter().any(|item| {
        item.location.path == "App.cs"
            && item
                .tags
                .iter()
                .any(|tag| tag == "query-role:stored-procedure-name")
    }));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn unknown_nosql_structure_and_untyped_fixed_key_values_remain_reviewable() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-nosql-query-structure-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("app.js"),
        r#"const { MongoClient } = require('mongodb');
const client = new MongoClient('mongodb://localhost');
const users = client.db('app').collection('users');
function run(req, filter, code) {
  users.findOne(filter);
  users.findOne({ id: req.body.id });
  users.findOne({ $where: code });
}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("Probe.java"),
        r#"import com.mongodb.client.MongoCollection;
import org.bson.Document;
class Probe { void run(MongoCollection<Document> users, Document filter) { users.find(filter); } }"#,
    )
    .unwrap();
    std::fs::write(
        root.join("app.rs"),
        r#"use mongodb::Collection;
use mongodb::bson::Document;
async fn run(users: &Collection<Document>, filter: Document) { users.find(filter).await; }"#,
    )
    .unwrap();

    let result = mehscan_engine::scan_path(&root).unwrap();
    let sinks = result
        .evidence
        .iter()
        .filter(|item| {
            item.capability == Capability::DatabaseQuery
                && item.cwe_candidates.iter().any(|cwe| cwe == "CWE-943")
        })
        .collect::<Vec<_>>();
    for path in ["app.js", "Probe.java", "app.rs"] {
        assert!(
            sinks.iter().any(|item| {
                item.location.path == path
                    && item.tags.iter().any(|tag| tag == "dynamic-nosql-structure")
                    && item
                        .tags
                        .iter()
                        .any(|tag| tag == "review-origin:decision-critical")
            }),
            "missing unknown document review for {path}: {sinks:#?}"
        );
    }
    let fixed = sinks
        .iter()
        .find(|item| {
            item.location.path == "app.js"
                && item
                    .captures
                    .get("nosql_query")
                    .is_some_and(|query| query.text.contains("id: req.body.id"))
        })
        .expect("fixed-key filter should remain visible");
    assert!(
        fixed
            .tags
            .iter()
            .any(|tag| tag == "query-shape:fixed-document-keys")
    );
    assert!(
        fixed
            .tags
            .iter()
            .any(|tag| tag == "review-origin:decision-critical")
    );
    assert!(
        result
            .security_paths
            .iter()
            .any(|path| path.sink_evidence_id == fixed.id),
        "{:?}",
        result.security_paths
    );

    let jobs = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(4), false)
        .expect("NoSQL structure reviews should build");
    assert!(jobs.observation_reviews.iter().any(|review| {
        review
            .review_basis
            .as_ref()
            .is_some_and(|basis| basis.relationship == "bounded_raw_nosql_interpretation")
    }));

    std::fs::remove_dir_all(root).unwrap();
}
