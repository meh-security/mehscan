use mehscan_core::Capability;
use mehscan_engine::investigation::build_review_inventory;

#[test]
fn native_local_literal_queries_close_but_writes_escapes_and_other_origins_stay() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-query-cleanup-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let source = r#"
#include <sqlite3.h>
void fixed(sqlite3* db) {
    const char* sql = "SELECT * " "FROM games WHERE id = ?";
    sqlite3_prepare_v2(db, sql, -1, 0, 0);
}
void overwritten(sqlite3* db, const char* input) {
    const char* sql = "SELECT 1";
    sql = input;
    sqlite3_prepare_v2(db, sql, -1, 0, 0);
}
void escaped(sqlite3* db) {
    const char* sql = "SELECT 1";
    replace(&sql);
    sqlite3_prepare_v2(db, sql, -1, 0, 0);
}
void aliased(sqlite3* db, const char* input) {
    const char* sql = "SELECT 1";
    const char** alias = &sql;
    *alias = input;
    sqlite3_prepare_v2(db, sql, -1, 0, 0);
}
void dynamic(sqlite3* db, const char* input) {
    const char* sql = input;
    sqlite3_prepare_v2(db, sql, -1, 0, 0);
}
const char* global_sql = "SELECT 1";
void global(sqlite3* db) { sqlite3_prepare_v2(db, global_sql, -1, 0, 0); }
void conditional(sqlite3* db) {
#ifdef CUSTOM_SQL
    const char* sql = "SELECT 1";
    sqlite3_prepare_v2(db, sql, -1, 0, 0);
#endif
}
void same_declaration(sqlite3* db, const char* input) {
    const char* sql = "SELECT 1", **alias = &sql;
    *alias = input;
    sqlite3_prepare_v2(db, sql, -1, 0, 0);
}
"#;
    for extension in ["c", "cpp"] {
        std::fs::write(root.join(format!("app.{extension}")), source).unwrap();
    }
    let inventory = build_review_inventory(&root, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    for extension in ["c", "cpp"] {
        let path = format!("app.{extension}");
        let fixed = inventory
            .scan
            .evidence
            .iter()
            .find(|e| {
                e.location.path == path
                    && e.capability == Capability::DatabaseQuery
                    && e.location.start.line == 5
            })
            .expect("fixed native SQL evidence");
        assert!(
            fixed
                .tags
                .iter()
                .any(|t| t == "query-closure:native-local-literal")
        );
        assert_eq!(fixed.captures["query"].text, "sql");
        assert_eq!(
            fixed.captures["query_origin"].text,
            "\"SELECT * \" \"FROM games WHERE id = ?\""
        );
        assert!(
            !inventory
                .entries
                .iter()
                .any(|e| e.path == path && e.line == 5)
        );
        for line in [10, 15, 21, 25, 28, 32, 38] {
            assert!(
                inventory
                    .entries
                    .iter()
                    .any(|e| e.path == path && e.line == line),
                "lost unresolved {path}:{line}"
            );
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
