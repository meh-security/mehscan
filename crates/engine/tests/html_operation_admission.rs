use mehscan_core::Capability;
use mehscan_engine::investigation::build_review_inventory;
use std::{collections::BTreeSet, fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str, source: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "mehscan-html-operations-{label}-{}",
            std::process::id()
        ));
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
fn distinct_fields_and_branches_keep_separate_casts_for_the_same_input() {
    let source = r#"package review
import ("fmt"; "html/template"; "net/http")
func render(r *http.Request, flag bool) {
 value := r.FormValue("message")
 plain := fmt.Sprintf("%s", value)
 bold := fmt.Sprintf("<b>%s</b>", value)
 italic := fmt.Sprintf("<i>%s</i>", value)
 data := map[string]interface{}{}
 data["caption"] = template.HTML(plain)
 if flag { data["note"] = template.HTML(bold) } else { data["note"] = template.HTML(italic) }
 _ = data
}
"#;
    let fixture = Fixture::new("fields", source);
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    let summaries = inventory
        .scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "go-request-fmt-to-trusted-html")
        .collect::<Vec<_>>();
    assert_eq!(summaries.len(), 3);
    let entries = inventory
        .entries
        .iter()
        .filter(|e| e.capability == Capability::HtmlOutput)
        .collect::<Vec<_>>();
    assert_eq!(
        entries.len(),
        3,
        "raw/summary evidence must not double reviews"
    );
    for sink in summaries {
        assert_eq!(
            entries
                .iter()
                .filter(|e| e.identity.as_ref().is_some_and(|i| i.anchor_id == sink.id))
                .count(),
            1
        );
        for capture in sink.captures.values() {
            assert_eq!(
                &source[capture.location.start.byte_offset..capture.location.end.byte_offset],
                capture.text
            );
        }
    }
    assert_eq!(
        entries
            .iter()
            .map(|e| &e.review_id)
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );
}

#[test]
fn a_nearby_unlinked_html_cast_is_not_covered_by_another_candidate() {
    let source = r#"package review
import ("fmt"; "html/template"; "net/http")
func render(r *http.Request, unresolved string) {
 value := r.FormValue("message")
 markup := fmt.Sprintf("%s", value)
 first := template.HTML(markup)
 second := template.HTML(unresolved)
 _ = first; _ = second
}
"#;
    let fixture = Fixture::new("unlinked", source);
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    let sink = inventory
        .scan
        .evidence
        .iter()
        .find(|e| e.rule_id == "go-html-output" && e.captures["content"].text == "unresolved")
        .unwrap();
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| e.identity.as_ref().is_some_and(|i| i.anchor_id == sink.id))
    );
    assert_eq!(
        inventory
            .entries
            .iter()
            .filter(|e| e.capability == Capability::HtmlOutput)
            .count(),
        2
    );
}

#[test]
fn repeated_operands_and_fixed_output_do_not_create_duplicate_reviews() {
    let source = r#"package review
import ("fmt"; "html/template"; "net/http"; "database/sql")
func render(r *http.Request, db *sql.DB) {
 value := r.FormValue("message")
 markup := fmt.Sprintf("<b>%s%s</b>", value, value)
 _ = template.HTML(markup)
 _ = template.HTML("<b>fixed</b>")
 db.Query("SELECT name FROM users WHERE id = ?", value)
}

"#;
    let fixture = Fixture::new("duplicates", source);
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert_eq!(
        inventory
            .scan
            .evidence
            .iter()
            .filter(|e| e.rule_id == "go-request-fmt-to-trusted-html")
            .count(),
        1
    );
    assert_eq!(
        inventory
            .entries
            .iter()
            .filter(|e| e.capability == Capability::HtmlOutput)
            .count(),
        1
    );
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .any(|e| e.rule_id == "go-database-query")
    );
}

#[test]
fn a_summary_does_not_hide_an_additional_request_source_at_the_same_cast() {
    let source = r#"package review
import ("fmt"; "html/template"; "net/http")
func render(r *http.Request) {
 first := r.FormValue("first")
 second := r.FormValue("second")
 markup := fmt.Sprintf("%s%s", first, second)
 _ = template.HTML(markup)
}
"#;
    let fixture = Fixture::new("sources", source);
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    let summary_sources = inventory
        .scan
        .security_paths
        .iter()
        .filter(|p| {
            p.sink_evidence_id
                .ends_with(":go-request-fmt-to-trusted-html")
        })
        .map(|p| p.source_evidence_id.as_str())
        .collect::<BTreeSet<_>>();
    let raw = inventory
        .scan
        .evidence
        .iter()
        .find(|e| e.rule_id == "go-html-output")
        .unwrap();
    assert!(
        inventory.scan.security_paths.iter().any(|p| {
            p.sink_evidence_id == raw.id && !summary_sources.contains(p.source_evidence_id.as_str())
        }),
        "control must contain an uncovered raw source path"
    );
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| { e.identity.as_ref().is_some_and(|i| i.anchor_id == raw.id) }),
        "a summary of one source must not hide the other source path"
    );
}
