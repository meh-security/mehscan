use mehscan_core::OperandFactKind;
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str, source: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "mehscan-go-operands-{label}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("review.go"), source).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn local_origins_preserve_operands_and_stop_at_ownership_and_intervening_uses() {
    let source = r#"package review
import ("html/template"; "html"; "fmt"; "database/sql"; "os/exec")
func raw(value string) template.HTML { output := fmt.Sprintf("<b>%s</b>", value); return template.HTML(output) }
func escaped(value string) template.HTML { output := html.EscapeString(value); return template.HTML(output) }
func factory(value string) template.HTML { output := policy(value); return template.HTML(output) }
func changed(value string) template.HTML { output := "fixed"; output = value; return template.HTML(output) }
func handoff(value string) template.HTML { output := value; inspect(&output); return template.HTML(output) }
func capture(value string) template.HTML { output := value; _ = func() { inspect(output) }; return template.HTML(output) }
func alias(value string) template.HTML { output := value; other := output; inspect(other); return template.HTML(output) }
func shadow(value string) template.HTML { output := "fixed"; { output := value; return template.HTML(output) } }
func otherBlock(value string) template.HTML { { output := value; inspect(output) }; output := html.EscapeString(value); return template.HTML(output) }
func tuple(value string) template.HTML { output, err := policyPair(value); inspect(err); return template.HTML(output) }
func conditional(value string) template.HTML { if output := value; output != "" { return template.HTML(output) }; return "" }
func repeated(value string) template.HTML { output := value; inspect(template.HTML(output)); return template.HTML(output) }
func parameters(output string) template.HTML { return template.HTML(output) }
func query(db *sql.DB, value string) { query := fmt.Sprintf("SELECT * FROM users WHERE name='%s'", value); db.Query(query) }
func fixed(db *sql.DB, value string) { query := "SELECT * FROM users WHERE name=?"; db.Query(query, value) }
func program(value string) { command := policy(value); exec.Command(command).Run() }
"#;
    let fixture = Fixture::new("edges", source);
    let result = mehscan_engine::scan_path(&fixture.0).unwrap();
    let sink = |name: &str, rule: &str| {
        result
            .evidence
            .iter()
            .find(|e| {
                e.kind == mehscan_core::EvidenceKind::Sink
                    && e.rule_id == rule
                    && e.enclosing_symbol.as_deref() == Some(name)
            })
            .unwrap()
    };
    for (name, rule, role) in [
        ("raw", "go-html-output", "content"),
        ("escaped", "go-html-output", "content"),
        ("factory", "go-html-output", "content"),
        ("otherBlock", "go-html-output", "content"),
        ("query", "go-database-query", "query"),
        ("fixed", "go-database-query", "query"),
        ("program", "go-process-execution", "command"),
    ] {
        let e = sink(name, rule);
        let fact = e
            .context
            .operand_facts
            .iter()
            .find(|f| f.kind == OperandFactKind::LocalOperandOrigin)
            .unwrap_or_else(|| panic!("missing origin for {name}: {:?}", e.context.operand_facts));
        assert_eq!(fact.role, role);
        assert_eq!(
            &source[fact.location.start.byte_offset..fact.location.end.byte_offset],
            fact.value
        );
        assert!(!fact.remaining_checks.is_empty());
        assert!(
            !e.captures[role].text.contains('('),
            "original operand should remain a name"
        );
    }
    for name in [
        "changed",
        "handoff",
        "capture",
        "alias",
        "shadow",
        "tuple",
        "conditional",
    ] {
        let e = sink(name, "go-html-output");
        assert!(
            !e.context
                .operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::LocalOperandOrigin),
            "unsafe origin reuse in {name}"
        );
        assert!(
            e.context
                .operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::OperandBoundary),
            "missing stop for {name}"
        );
    }
    let repeated: Vec<_> = result
        .evidence
        .iter()
        .filter(|e| {
            e.rule_id == "go-html-output" && e.enclosing_symbol.as_deref() == Some("repeated")
        })
        .collect();
    assert_eq!(repeated.len(), 2);
    assert_eq!(
        repeated[0].context.operand_facts[0].kind,
        OperandFactKind::LocalOperandOrigin
    );
    assert_eq!(
        repeated[1].context.operand_facts[0].kind,
        OperandFactKind::OperandBoundary
    );
    assert!(
        sink("parameters", "go-html-output")
            .context
            .operand_facts
            .is_empty()
    );
}

#[test]
fn large_and_unsupported_declarations_remain_navigation_boundaries() {
    let source = format!(
        "package review\nimport \"html/template\"\nvar global = \"fixed\"\n\
         func globalUse() template.HTML {{ return template.HTML(global) }}\n\
         func declared(value string) template.HTML {{ var output = value; return template.HTML(output) }}\n\
         func bigInitializer() template.HTML {{ output := \"{}\"; return template.HTML(output) }}\n\
         func bigCallable(value string) template.HTML {{ /*{}*/ output := value; return template.HTML(output) }}\n\
         type Renderer struct {{}}\n\
         func (r Renderer) render(value string) template.HTML {{ output := value; return template.HTML(output) }}\n",
        "x".repeat(2200),
        "x".repeat(33 * 1024),
    );
    let fixture = Fixture::new("bounds", &source);
    let result = mehscan_engine::scan_path(&fixture.0).unwrap();
    let fact_kinds = |name: &str| {
        result
            .evidence
            .iter()
            .find(|e| e.rule_id == "go-html-output" && e.enclosing_symbol.as_deref() == Some(name))
            .unwrap()
            .context
            .operand_facts
            .iter()
            .map(|f| f.kind.clone())
            .collect::<Vec<_>>()
    };
    assert!(fact_kinds("globalUse").is_empty());
    assert!(fact_kinds("declared").is_empty());
    assert_eq!(
        fact_kinds("bigInitializer"),
        [OperandFactKind::OperandBoundary]
    );
    assert_eq!(
        fact_kinds("bigCallable"),
        [OperandFactKind::OperandBoundary]
    );
    assert_eq!(fact_kinds("render"), [OperandFactKind::LocalOperandOrigin]);
}
