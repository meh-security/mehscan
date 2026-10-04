use mehscan_core::OperandFactKind;
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str, file: &str, source: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("mehscan-jvm-uses-{label}-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(file), source).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn kotlin_use_cache_stops_after_handoffs_and_keeps_alias_origin() {
    let source = r#"import java.sql.Connection
fun normal(c: Connection, q: String) { val p = c.prepareStatement(q); p.setString(1,q); p.clearParameters(); p.executeQuery() }
fun escaped(c: Connection, q: String) { val p = c.prepareStatement(q); adjust(p); p.executeQuery() }
fun aliasEscaped(c: Connection, q: String) { val p = c.prepareStatement(q); val a = p; adjust(a); p.executeQuery() }
fun alias(c: Connection, q: String) { val p = c.prepareStatement(q); val a = p; a.executeQuery() }
fun captured(c: Connection, q: String) { val p = c.prepareStatement(q); val r = { adjust(p) }; p.executeQuery() }
fun changed(c: Connection, q: String) { var p = c.prepareStatement(q); p = build(); p.executeQuery() }
"#;
    let fixture = Fixture::new("kotlin", "Review.kt", source);
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let sinks = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "kotlin-jdbc-prepare-query")
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 6);
    for sink in sinks {
        let uses = sink
            .context
            .operand_facts
            .iter()
            .filter(|f| f.kind == OperandFactKind::PreparedStatementUse)
            .collect::<Vec<_>>();
        let owner = sink.enclosing_symbol.as_deref().unwrap();
        assert_eq!(
            uses.len(),
            match owner {
                "normal" => 3,
                "alias" => 1,
                _ => 0,
            },
            "{owner}"
        );
        for fact in uses {
            assert!(
                source[fact.location.start.byte_offset..fact.location.end.byte_offset]
                    .starts_with(&format!("{}.", fact.value))
            );
        }
    }
}

#[test]
fn java_preparations_own_exact_local_uses_and_stop_at_ambiguous_handoffs() {
    let source = r#"import java.sql.Connection;
import java.sql.PreparedStatement;
class Review {
void bound(Connection c, String v) throws Exception { var p = c.prepareStatement(v); p.setString(1, v); p.clearParameters(); p.setString(1, v); p.executeQuery(); p.close(); }
void mixed(Connection c, String v) throws Exception { var a = c.prepareStatement("SELECT " + v); var b = c.prepareStatement("SELECT ?"); b.setString(1,v); a.executeQuery(); }
void alias(Connection c, String v) throws Exception { var p = c.prepareStatement(v); var a = p; a.executeQuery(); }
void resource(Connection c, String v) throws Exception { try (PreparedStatement p = c.prepareStatement("SELECT ?")) { p.setString(1,v); p.executeQuery(); } }
void resourceConnection(String v) throws Exception { try (Connection c = open(); PreparedStatement p = c.prepareStatement(v)) { p.executeQuery(); } }
void resourceShadow(String v) throws Exception { try (Connection c = open()) { } var p = c.prepareStatement(v); p.executeQuery(); }
void loopConnectionShadow(String v) throws Exception { for (Connection c = open(); running();) { } var p = c.prepareStatement(v); p.executeQuery(); }
void changed(Connection c, String v) throws Exception { var p = c.prepareStatement(v); p = build(); p.executeQuery(); }
void escaped(Connection c, String v) throws Exception { var p = c.prepareStatement(v); adjust(p); p.executeQuery(); }
void captured(Connection c, String v) throws Exception { var p = c.prepareStatement(v); Runnable r = () -> adjust(p); p.executeQuery(); }
void nested(Connection c, String v) throws Exception { var p = c.prepareStatement(v); Runnable r = () -> p.executeQuery(); }
void afterAlias(Connection c, String v) throws Exception { var p = c.prepareStatement(v); var a = p; adjust(a); p.executeQuery(); }
void unknown(Object c, String v) throws Exception { var p = c.prepareStatement(v); p.executeQuery(); }
void lazy(Connection c, String v) throws Exception { var p = c.prepareStatement(v); p.close(); }
void conditional(Connection c, String v, boolean run) throws Exception { var p = c.prepareStatement(v); if(run) p.executeQuery(); }
void shadow(Connection c, String v) throws Exception { var p = c.prepareStatement(v); { var p = build(); p.executeQuery(); } }
}
"#;
    let fixture = Fixture::new("java", "Review.java", source);
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let sinks = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "java-database-query")
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 17);
    let facts = |name: &str| {
        sinks
            .iter()
            .filter(|e| e.enclosing_symbol.as_deref() == Some(name))
            .flat_map(|e| &e.context.operand_facts)
            .filter(|f| f.kind == OperandFactKind::PreparedStatementUse)
            .collect::<Vec<_>>()
    };
    assert_eq!(facts("bound").len(), 5);
    assert_eq!(facts("resource").len(), 2);
    assert_eq!(facts("resourceConnection").len(), 1);
    assert_eq!(facts("alias").len(), 1);
    assert_eq!(facts("conditional").len(), 1);
    assert_eq!(facts("lazy").len(), 1);
    for name in [
        "changed",
        "escaped",
        "captured",
        "nested",
        "afterAlias",
        "unknown",
        "shadow",
        "resourceShadow",
        "loopConnectionShadow",
    ] {
        assert!(facts(name).is_empty(), "{name}");
    }
    let raw = sinks
        .iter()
        .find(|e| e.captures["query"].text == "\"SELECT \" + v")
        .unwrap();
    assert_eq!(raw.context.operand_facts.len(), 1);
    assert_eq!(
        raw.context.operand_facts[0].role,
        "prepared_statement_execution_context"
    );
    for sink in sinks {
        for fact in &sink.context.operand_facts {
            if fact.kind != OperandFactKind::PreparedStatementUse {
                continue;
            }
            let text = &source[fact.location.start.byte_offset..fact.location.end.byte_offset];
            assert!(text.starts_with(&format!("{}.", fact.value)), "{text}");
            assert_eq!(
                fact.remaining_checks,
                ["conditions_order_resets_and_execution"]
            );
        }
    }
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture.0, None, true).unwrap();
    let facts = jobs
        .reviews
        .iter()
        .flat_map(|r| &r.facts)
        .chain(jobs.observation_reviews.iter().flat_map(|r| &r.facts));
    assert!(
        facts
            .filter(|f| f.role == "prepared_statement_lifecycle_context")
            .any(|f| f.excerpt == "p.clearParameters()")
    );
}
