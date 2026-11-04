use mehscan_core::EvidenceKind;
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str, files: &[(&str, &str)]) -> Self {
        let root = std::env::temp_dir().join(format!(
            "mehscan-go-operation-{name}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        for (name, text) in files {
            let path = root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn sql_summaries_require_calls_with_query_operands_not_url_queries_or_source_text() {
    let fixture = Fixture::new(
        "signatures",
        &[(
            "app.go",
            r#"package app
import ("database/sql"; "fmt"; "net/url")
var db *sql.DB
func URL(value string) { u, _ := url.Parse(value); _ = u.Query(); _ = fmt.Sprintf("value=%s", value) }
func Comment(value string) { /* db.Query(fmt.Sprintf("SELECT %s", value)) */ _ = "db.Exec(value)?"; _ = fmt.Sprintf("%s", value) }
func Unsafe(value string) { db.Query(fmt.Sprintf("SELECT * FROM records WHERE id='%s'", value)) }
func Prepared(value string) { stmt, _ := db.Prepare(fmt.Sprintf("SELECT * FROM records WHERE id='%s'", value)); stmt.Query() }
func Bound(value string) { db.Query("SELECT * FROM records WHERE id=?", value) }
func Calls(value string) { URL(value); Comment(value); Unsafe(value); Prepared(value); Bound(value) }
"#,
        )],
    );
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    let summaries = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id.starts_with("go-sql-") && e.rule_id.contains("summary"))
        .collect::<Vec<_>>();
    let targets = summaries
        .iter()
        .filter_map(|e| e.captures.get("target").map(|c| c.text.as_str()))
        .collect::<Vec<_>>();
    assert!(
        !targets.contains(&"URL") && !targets.contains(&"Comment"),
        "{targets:?}"
    );
    for target in ["Unsafe", "Prepared", "Bound"] {
        assert!(targets.contains(&target), "{target}: {targets:?}");
    }
    assert!(
        summaries
            .iter()
            .any(|e| e.captures["target"].text == "Bound" && e.kind == EvidenceKind::Sanitizer)
    );
    assert!(scan.evidence.iter().any(
        |e| e.rule_id == "go-database-query" && e.enclosing_symbol.as_deref() == Some("Unsafe")
    ));
}

#[test]
fn summaries_bind_local_receivers_factories_and_package_aliases_without_name_leakage() {
    let fixture = Fixture::new(
        "owners",
        &[
            (
                "local/model.go",
                r#"package local
import ("database/sql"; "fmt")
var db *sql.DB
type Repository struct{}
type Other struct{}
var shared Repository
func NewRepository() *Repository { return &Repository{} }
func OpenRepository() (*Repository, error) { return &Repository{}, nil }
func (r *Repository) Lookup(value string) { db.Query(fmt.Sprintf("SELECT * FROM records WHERE id='%s'", value)) }
func (r *Repository) Update(value string) { db.Exec("UPDATE records SET value=? WHERE id=?", value, value) }
func (r *Other) Lookup(value string) {}
func (r *Other) Update(value string) {}
"#,
            ),
            (
                "local/calls.go",
                r#"package local
var stored Repository
func Constructed(value string) { r := NewRepository(); r.Lookup(value) }
func Tuple(value string) { r, err := OpenRepository(); _ = err; r.Lookup(value) }
func Composite(value string) { r := &Repository{}; r.Update(value) }
func Typed(r *Repository, value string) { r.Lookup(value) }
func Global(value string) { stored.Lookup(value) }
func CrossFile(value string) { shared.Lookup(value) }
func Wrong(r *Other, value string) { r.Lookup(value); r.Update(value) }
func Unknown(r interface{ Lookup(string) }, value string) { r.Lookup(value) }
func Shadow(NewRepository func() *Other, value string) { r := NewRepository(); r.Lookup(value) }
func Nested(value string) { r := NewRepository(); { r := new(Other); r.Lookup(value) }; r.Lookup(value) }
func Mutated(value string) { r := NewRepository(); r = replacement; r.Lookup(value) }
func Branch(value string) { r := NewRepository(); if r := new(Other); true { r.Lookup(value) }; r.Lookup(value) }
func TypeShadow(value string) { type Repository Other; r := new(Repository); r.Lookup(value) }
"#,
            ),
            (
                "store/query.go",
                r#"package persistence
import ("database/sql"; "fmt")
var db *sql.DB
func Find(value string) { db.Query(fmt.Sprintf("SELECT * FROM records WHERE id='%s'", value)) }
"#,
            ),
            (
                "api/good.go",
                r#"package api
import q "example.test/app/store"
func Aliased(value string) { q.Find(value) }
func Shadowed(q interface{ Find(string) }, value string) { q.Find(value) }
"#,
            ),
            (
                "unrelated/calls.go",
                r#"package api
import q "example.test/unrelated"
func Foreign(value string) { q.Find(value) }
func Find(value string) {}
func Local(value string) { Find(value) }
"#,
            ),
        ],
    );
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    let summaries = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id.starts_with("go-sql-") && e.rule_id.contains("summary"))
        .collect::<Vec<_>>();
    let symbols = summaries
        .iter()
        .filter_map(|e| e.enclosing_symbol.as_deref())
        .collect::<Vec<_>>();
    for name in [
        "Constructed",
        "Tuple",
        "Composite",
        "Typed",
        "Global",
        "Nested",
        "Aliased",
        "CrossFile",
        "Branch",
    ] {
        assert!(symbols.contains(&name), "lost {name}: {symbols:?}");
    }
    for name in [
        "Wrong",
        "Unknown",
        "Shadow",
        "Mutated",
        "Shadowed",
        "Foreign",
        "Local",
        "TypeShadow",
    ] {
        assert!(!symbols.contains(&name), "leaked {name}: {symbols:?}");
    }
    assert_eq!(
        summaries
            .iter()
            .filter(|e| e.enclosing_symbol.as_deref() == Some("Nested"))
            .count(),
        2
    ); // one query and one resource fact, outer receiver only
    for name in ["Lookup", "Update", "Find"] {
        assert!(
            scan.evidence
                .iter()
                .any(|e| e.rule_id == "go-database-query"
                    && e.enclosing_symbol.as_deref() == Some(name)),
            "lost underlying {name}"
        );
    }
}

#[test]
fn http_dispatch_keeps_real_and_unknown_requests_but_rejects_callback_signatures() {
    let fixture = Fixture::new(
        "http",
        &[(
            "app.go",
            r#"package app
import (web "net/http"; "sync")
func Real(client *web.Client, req *web.Request) { client.Do(req) }
func Unknown(client Custom, req Request) { client.Do(req) }
func Shutdown(once *sync.Once) { once.Do(func() {}) }
func Parenthesized(once *sync.Once) { once.Do((func() {})) }
func Named(once *sync.Once) { callback := func() {}; once.Do(callback) }
type Server struct { once sync.Once }
func (s *Server) stop() {}
func (s *Server) Stop() { s.once.Do(s.stop) }
"#,
        )],
    );
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    let symbols = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "go-outbound-http")
        .filter_map(|e| e.enclosing_symbol.as_deref())
        .collect::<Vec<_>>();
    assert!(
        symbols.contains(&"Real") && symbols.contains(&"Unknown"),
        "{symbols:?}"
    );
    assert!(
        !symbols.contains(&"Shutdown") && !symbols.contains(&"Parenthesized"),
        "{symbols:?}"
    );
    assert!(
        !symbols.contains(&"Named") && !symbols.contains(&"Stop"),
        "{symbols:?}"
    );
}
