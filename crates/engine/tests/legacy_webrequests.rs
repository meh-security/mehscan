use mehscan_core::{Capability, EvidenceKind};
use mehscan_engine::investigation::build_review_inventory;
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str, source: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "mehscan-legacy-request-{name}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("App.cs"), source).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn factories_are_context_and_initiators_keep_destinations() {
    let fixture = Fixture::new(
        "effects",
        r#"using System.Net;
class App {
void Lazy(dynamic Request) {WebRequest.Create(Request.Query["url"]);}
WebRequest Factory(dynamic Request) {return WebRequest.Create(Request.Query["url"]);}
void Read(dynamic Request) {var r=WebRequest.Create(Request.Query["url"]);r.GetResponse();r.GetResponseAsync();}
void Write(dynamic Request) {var r=WebRequest.CreateHttp(Request.Query["url"]);r.GetRequestStream();r.GetRequestStreamAsync();}
void Begin(dynamic Request) {var r=WebRequest.CreateDefault(Request.Query["url"]);r.BeginGetResponse(null,null);r.BeginGetRequestStream(null,null);}
void Inline(dynamic Request) {((HttpWebRequest)WebRequest.Create(Request.Query["url"])).GetResponse();}
}"#,
    );
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let sinks = scan
        .evidence
        .iter()
        .filter(|e| {
            e.kind == EvidenceKind::Sink && e.capability == Capability::OutboundNetworkRequest
        })
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 7, "{sinks:#?}");
    assert!(
        sinks.iter().all(|e| e
            .captures
            .get("endpoint")
            .is_some_and(|c| c.text == "Request.Query[\"url\"]")
            && !e.related_evidence.is_empty()),
        "{sinks:#?}"
    );
    assert_eq!(
        scan.security_paths
            .iter()
            .filter(|p| p.capability == Capability::OutboundNetworkRequest)
            .count(),
        7,
        "{:#?}",
        scan.security_paths
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| e.rule_id == "csharp-outbound-http"
                || matches!(e.symbol.as_deref(), Some("Lazy" | "Factory")))
    );
}

#[test]
fn fixed_authority_closes_only_unchanged_requests() {
    let fixture = Fixture::new(
        "unknown",
        r#"using System.Net;
class App {
WebRequest Build() { return WebRequest.Create("https://example.com"); }
void Fixed() {var r=WebRequest.Create("https://example.com");r.Method="POST";r.Timeout=1000;r.GetResponse();r.GetRequestStream();}
void Helper() {var r=Build();r.GetResponse();}
void Unknown(WebRequest r) {r.GetResponseAsync();}
void Replaced(WebRequest input) {var r=WebRequest.Create("https://example.com");r=input;r.GetResponse();}
void Hook() {var r=WebRequest.Create("https://example.com");Rewrite(r);r.GetResponse();}
void Proxy(IWebProxy input) {var r=WebRequest.Create("https://example.com");r.Proxy=input;r.GetResponse();}
}"#,
    );
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    let sinks = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "csharp-webrequest-dispatch")
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 7, "{sinks:#?}");
    assert!(
        sinks
            .iter()
            .filter(|e| e.enclosing_symbol.as_deref() != Some("Fixed"))
            .all(|e| !e.captures.contains_key("endpoint")),
        "{sinks:#?}"
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| e.symbol.as_deref() == Some("Fixed")),
        "{:#?}",
        inventory.entries
    );
    for method in ["Helper", "Unknown", "Replaced", "Hook", "Proxy"] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.rule_id == "csharp-webrequest-dispatch"
                    && e.symbol.as_deref() == Some(method)),
            "missing {method}: {:#?}",
            inventory.entries
        );
    }
}

#[test]
fn ownership_accepts_sdk_aliases_and_rejects_lookalikes() {
    let fixture = Fixture::new(
        "ownership",
        r#"using System.Net;
using WR = global::System.Net.WebRequest;
class Fake {public void GetResponse() {}}
class App {
WebRequest field;
void Alias(WR r) {r.GetResponse();}
void Qualified(global::System.Net.HttpWebRequest r) {r.GetResponse();}
void Local(Fake field) {field.GetResponse();this.field.GetResponse();}
void Generic<WebRequest>(WebRequest r) {r.GetResponse();}
void Fake(Fake r) {r.GetResponse();}
}"#,
    );
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    let sinks = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "csharp-webrequest-dispatch")
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 3, "{sinks:#?}");
    assert!(
        sinks.iter().all(|e| matches!(
            e.enclosing_symbol.as_deref(),
            Some("Alias" | "Qualified" | "Local")
        )),
        "{sinks:#?}"
    );
}
