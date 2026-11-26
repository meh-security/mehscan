use ast_grep_core::{AstGrep, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{Capability, FileStatus};
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str, source: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("mehscan-go-syntax-{label}-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("main.go"), source).unwrap();
        Self(root)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn expression_allocations_and_generic_methods_keep_their_subtrees() {
    let source = r#"package review
import "strings"
type Box[T any] struct { Value T }
func values(s string, flag bool) {
 _ = new(42)
 _ = new(flag)
 _ = new(strings.TrimSpace(s))
 _ = new(func(v string) string { return strings.TrimSpace(v) })
 _ = new(string)
 _ = new([]string)
 _ = make([]string, 2)
}
func (b *Box[T]) Convert[U any](f func(T) U) U { return f(b.Value) }
"#;
    let ast = AstGrep::doc(StrDoc::try_new(source, SupportLang::Go).unwrap());
    let root = ast.root();
    assert!(!root.dfs().any(|n| n.is_error() || n.is_missing()));
    for (text, kind) in [
        ("42", "int_literal"),
        ("strings.TrimSpace(s)", "call_expression"),
        (
            "func(v string) string { return strings.TrimSpace(v) }",
            "func_literal",
        ),
        ("[]string", "slice_type"),
    ] {
        let node = root
            .dfs()
            .find(|n| n.kind() == kind && n.text() == text)
            .unwrap_or_else(|| panic!("missing {kind}: {text}"));
        assert_eq!(&source[node.range()], text);
        assert_eq!(node.parent().unwrap().kind(), "argument_list");
    }
    // A syntax-only parser cannot decide whether a bare identifier denotes a
    // type or a value. Both forms must remain visible without inventing a type.
    for argument in ["flag", "string"] {
        assert!(root.dfs().any(|n| {
            n.text() == argument && n.parent().is_some_and(|p| p.kind() == "argument_list")
        }));
    }
    let method = root
        .dfs()
        .find(|n| n.kind() == "method_declaration")
        .unwrap();
    assert_eq!(method.field("name").unwrap().text(), "Convert");
    assert_eq!(method.field("type_parameters").unwrap().text(), "[U any]");
    assert_eq!(
        method.field("body").unwrap().text(),
        "{ return f(b.Value) }"
    );
}

#[test]
fn nested_effects_in_current_syntax_keep_exact_evidence() {
    let source = r#"package review
import ("html/template"; "net/http"; "os/exec")
type Service struct{}
func allocations(r *http.Request) {
 _ = new(template.HTML(r.FormValue("html")))
 _ = new(func() { exec.Command("sh", "-c", r.FormValue("cmd")).Run() })
}
func (s *Service) Render[T string | template.HTML](msg T) {
 _ = template.HTML(msg)
}
"#;
    let fixture = Fixture::new("effects", source);
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let html = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "go-html-output")
        .collect::<Vec<_>>();
    assert_eq!(html.len(), 2);
    assert!(html.iter().any(|e| {
        e.enclosing_symbol.as_deref() == Some("Render") && e.captures["content"].text == "msg"
    }));
    assert!(scan.evidence.iter().any(|e| {
        e.capability == Capability::ProcessExecution && e.rule_id == "go-process-execution"
    }));
    for evidence in &scan.evidence {
        for capture in evidence.captures.values() {
            assert_eq!(
                &source[capture.location.start.byte_offset..capture.location.end.byte_offset],
                capture.text
            );
        }
    }
    let outline = mehscan_engine::investigation::get_file_outline(&fixture.0, "main.go").unwrap();
    assert!(outline.results.symbols.iter().any(|s| s.name == "Render"));
    // Retaining a call in an uninvoked function literal is source coverage,
    // not proof that the function body executes.
}

#[test]
fn legacy_and_shadowed_calls_parse_but_malformed_source_stays_visible() {
    for source in [
        "package review\nfunc old() { _ = new(string); _ = new([]string); _ = make(map[string]int, 2) }",
        "package review\nfunc shadow(new func(int) int, make func(int) int) { _ = new(42); _ = make(12) }",
    ] {
        let ast = AstGrep::doc(StrDoc::try_new(source, SupportLang::Go).unwrap());
        assert!(!ast.root().dfs().any(|n| n.is_error() || n.is_missing()));
    }
    let source = "package review\nfunc broken( { return new( }\n";
    let ast = AstGrep::doc(StrDoc::try_new(source, SupportLang::Go).unwrap());
    assert!(ast.root().dfs().any(|n| n.is_error() || n.is_missing()));
    let fixture = Fixture::new("malformed", source);
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 1);
    assert!(
        scan.coverage
            .files
            .iter()
            .any(|f| f.status == FileStatus::ParseFailed)
    );
}
