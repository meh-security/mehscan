use mehscan_core::Capability;
use std::fs;

#[test]
fn returned_selector_keeps_its_executable_predicate_review() {
    let root =
        std::env::temp_dir().join(format!("mehscan-returned-selector-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("query-store.js"), r#"
const QueryStore = function(db) {
  const rows = db.collection('rows');
  this.select = (ownerId, threshold, callback) => {
    const parsedOwnerId = parseInt(ownerId, 10);
    const selector = () => {
      if (threshold) return { $where: `this.ownerId == ${parsedOwnerId} && this.value > '${threshold}'` };
      return { ownerId: parsedOwnerId };
    };
    rows.find(selector()).toArray((err, result) => callback(err, result));
  };
}
module.exports.QueryStore = QueryStore;
"#).unwrap();
    fs::write(
        root.join("handler.js"),
        r#"
const QueryStore = require('./query-store').QueryStore;
function Handler(db) {
  const store = new QueryStore(db);
  this.get = (req, res) => {
    const { ownerId } = req.params;
    const { threshold } = req.query;
    return store.select(ownerId, threshold, (_err, rows) => res.json(rows));
  };
}
module.exports = Handler;
"#,
    )
    .unwrap();
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let queries = scan
        .evidence
        .iter()
        .filter(|e| e.capability == Capability::DatabaseQuery && e.cwe_candidates == ["CWE-943"])
        .collect::<Vec<_>>();
    assert!(
        !queries.is_empty(),
        "missing executable query: {:#?}",
        scan.evidence
    );
    assert!(
        queries.iter().any(|e| e.location.path == "handler.js"
            && e.captures.values().any(|c| c.text == "threshold"))
    );
    let inventory = mehscan_engine::investigation::build_review_inventory(&root, false).unwrap();
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| e.capability == Capability::DatabaseQuery && e.value_hint.is_none())
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn nonconstructors_static_calls_and_reassigned_bindings_do_not_gain_query_contracts() {
    let body = r#"const rows = db.collection('rows');
        this.select = (threshold, done) => rows.find({$where: `this.value > '${threshold}'`}).toArray(done);"#;
    for (label, declaration, effect) in [
        (
            "arrow",
            format!("const QueryStore = (db) => {{ {body} }};"),
            "new QueryStore(db)",
        ),
        (
            "async-expression",
            format!("const QueryStore = async function(db) {{ {body} }};"),
            "new QueryStore(db)",
        ),
        (
            "async-declaration",
            format!("async function QueryStore(db) {{ {body} }}"),
            "new QueryStore(db)",
        ),
        (
            "static",
            format!("const QueryStore = function(db) {{ {body} }};"),
            "QueryStore",
        ),
        (
            "reassigned",
            format!("let QueryStore = function(db) {{ {body} }}; QueryStore = replacement;"),
            "new QueryStore(db)",
        ),
        (
            "nested",
            format!("const QueryStore = function(db) {{ function unused() {{ {body} }} }};"),
            "new QueryStore(db)",
        ),
    ] {
        let root = std::env::temp_dir().join(format!(
            "mehscan-constructor-control-{label}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("store.js"),
            format!("{declaration}\nmodule.exports.QueryStore = QueryStore;"),
        )
        .unwrap();
        fs::write(
            root.join("handler.js"),
            format!(
                r#"
const QueryStore = require('./store').QueryStore;
function run(db, req, done) {{
  const store = {effect};
  store.select(req.query.threshold, done);
}}
module.exports = run;
"#
            ),
        )
        .unwrap();
        let scan = mehscan_engine::scan_path(&root).unwrap();
        assert_eq!(scan.coverage.totals.parse_failed, 0, "{label}");
        assert!(
            !scan.evidence.iter().any(|e| e.location.path == "handler.js"
                && e.capability == Capability::DatabaseQuery
                && e.cwe_candidates == ["CWE-943"]),
            "invented contract for {label}: {:#?}",
            scan.evidence
        );
        fs::remove_dir_all(root).unwrap();
    }
}
