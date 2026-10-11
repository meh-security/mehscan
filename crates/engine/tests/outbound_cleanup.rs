use mehscan_core::{Capability, EvidenceKind, SecurityPathState};
use mehscan_engine::investigation::build_review_inventory;
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str, files: &[(&str, &str)]) -> Self {
        let root = std::env::temp_dir().join(format!(
            "mehscan-outbound-cleanup-{name}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        for (path, text) in files {
            fs::write(root.join(path), text).unwrap();
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
fn builders_are_context_and_each_send_owns_its_endpoint_relationship() {
    let fixture = Fixture::new(
        "consumers",
        &[
            (
                "app.go",
                r#"package app
import "net/http"
func dead(input string) { http.NewRequest("GET",input,nil) }
func factory(input string) (*http.Request,error) { return http.NewRequest("GET",input,nil) }
func actual(r *http.Request, client *http.Client) { req,_:=http.NewRequest("GET",r.FormValue("url"),nil); client.Do(req); client.Do(req) }
func unknown(client *http.Client, req *http.Request) { client.Do(req) }
"#,
            ),
            (
                "App.java",
                r#"import java.net.URI; import java.net.http.HttpRequest; import java.net.http.HttpClient; import java.net.http.HttpResponse;
class App {
void dead(String input) { HttpRequest.newBuilder(URI.create(input)); }
HttpRequest factory(String input) { return HttpRequest.newBuilder(URI.create(input)).build(); }
void actual(HttpServletRequest request,HttpClient client) throws Exception { HttpRequest req=HttpRequest.newBuilder(URI.create(request.getParameter("url"))).build(); client.send(req,HttpResponse.BodyHandlers.ofString()); client.sendAsync(req,HttpResponse.BodyHandlers.ofString()); }
void unknown(HttpClient client,HttpRequest req) throws Exception { client.send(req,HttpResponse.BodyHandlers.ofString()); }
}"#,
            ),
            (
                "app.rs",
                r#"fn dead(input: &str){reqwest::Client::new().get(input);}
fn factory(input: &str) -> reqwest::RequestBuilder { reqwest::Client::new().get(input) }
async fn actual(request: actix_web::HttpRequest){ let input=request.query_string(); let req=reqwest::Client::new().get(input).header("Accept","text/plain"); req.send().await; }
async fn inline(request: actix_web::HttpRequest){reqwest::Client::new().post(request.query_string()).json(&data).send().await;}
async fn free(request: actix_web::HttpRequest){reqwest::get(request.query_string()).await;}
async fn alias(input: &str){let req=reqwest::Client::new().get(input);let other=req;other.send().await;}
async fn built(input: &str){let client=reqwest::Client::new();let req=client.get(input).build().unwrap();client.execute(req).await;}
fn lookalike(other: Other){other.get(value).send();}
"#,
            ),
        ],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    for symbol in ["dead", "factory", "lookalike"] {
        assert!(
            !inventory
                .entries
                .iter()
                .any(|e| e.capability == Capability::OutboundNetworkRequest
                    && e.symbol.as_deref() == Some(symbol)),
            "unexpected builder/lookalike review {symbol}"
        );
    }
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    for (path, expected) in [("app.go", 3), ("App.java", 3), ("app.rs", 5)] {
        let sends = scan
            .evidence
            .iter()
            .filter(|e| {
                e.location.path == path
                    && e.capability == Capability::OutboundNetworkRequest
                    && e.kind == EvidenceKind::Sink
            })
            .collect::<Vec<_>>();
        assert_eq!(sends.len(), expected, "{path}: {sends:#?}");
        assert!(
            sends
                .iter()
                .filter(|e| e.enclosing_symbol.as_deref() == Some("actual"))
                .all(|e| e.captures.contains_key("endpoint") && !e.related_evidence.is_empty()),
            "{path}"
        );
        assert!(scan.evidence.iter().any(|e| e.location.path == path
            && e.kind == EvidenceKind::Resource
            && e.enclosing_symbol.as_deref() == Some("dead")));
        let actual = scan
            .security_paths
            .iter()
            .filter(|p| {
                p.capability == Capability::OutboundNetworkRequest
                    && p.steps.last().is_some_and(|s| s.location.path == path)
            })
            .collect::<Vec<_>>();
        assert!(!actual.is_empty(), "lost input/effect relationship: {path}");
        assert!(
            actual
                .iter()
                .all(|p| p.state != SecurityPathState::Protected)
        );
    }
    assert_eq!(
        inventory
            .entries
            .iter()
            .filter(|e| e.capability == Capability::OutboundNetworkRequest
                && e.symbol.as_deref() == Some("actual"))
            .count(),
        5,
        "one review per dispatch, no constructor duplicates"
    );
    for symbol in ["alias", "built"] {
        assert!(
            inventory.entries.iter().any(|e| e.path == "app.rs"
                && e.capability == Capability::OutboundNetworkRequest
                && e.symbol.as_deref() == Some(symbol)),
            "lost {symbol} dispatch"
        );
    }
}

#[test]
fn fixed_construction_does_not_close_mutated_or_helper_replaced_requests() {
    let fixture = Fixture::new(
        "identity",
        &[
            (
                "app.go",
                r#"package app
import "net/http"
func fixed(client *http.Client){req,_:=http.NewRequest("GET","https://example.test/",nil);client.Do(req)}
func mutation(client *http.Client,input string){req,_:=http.NewRequest("GET","https://example.test/",nil);req.URL=destination(input);client.Do(req)}
func hook(client *http.Client,input string){req,_:=http.NewRequest("GET","https://example.test/",nil);prepare(req,input);client.Do(req)}
func replaced(client *http.Client,input string){req,_:=http.NewRequest("GET","https://example.test/",nil);req=build(input);client.Do(req)}
"#,
            ),
            (
                "App.java",
                r#"import java.net.URI; import java.net.http.HttpRequest; import java.net.http.HttpClient;
class App {
void fixed(HttpClient client) throws Exception { HttpRequest req=HttpRequest.newBuilder(URI.create("https://example.test/")).build(); client.send(req,handler); }
void hook(HttpClient client,String input) throws Exception { HttpRequest req=HttpRequest.newBuilder(URI.create("https://example.test/")).build(); prepare(req,input); client.send(req,handler); }
void replaced(HttpClient client,String input) throws Exception { HttpRequest req=HttpRequest.newBuilder(URI.create("https://example.test/")).build(); req=build(input); client.send(req,handler); }
}"#,
            ),
            (
                "app.rs",
                r#"async fn fixed(){let req=reqwest::Client::new().get("https://example.test/");req.send().await;}
async fn replaced(input: &str){let mut req=reqwest::Client::new().get("https://example.test/");req=build(input);req.send().await;}
fn shadow(input: &str){let req=reqwest::Client::new().get(input);{let req=Other::new();req.send();}}
"#,
            ),
        ],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    for path in ["app.go", "App.java", "app.rs"] {
        assert!(
            !inventory.entries.iter().any(|e| e.path == path
                && e.capability == Capability::OutboundNetworkRequest
                && e.symbol.as_deref() == Some("fixed")),
            "fixed request must retain existing closure: {path}"
        );
        assert!(
            inventory.entries.iter().any(|e| e.path == path
                && e.capability == Capability::OutboundNetworkRequest
                && e.symbol.as_deref() == Some("replaced")),
            "replacement needs research: {path}"
        );
    }
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    for e in scan.evidence.iter().filter(|e| {
        e.capability == Capability::OutboundNetworkRequest
            && e.kind == EvidenceKind::Sink
            && matches!(
                e.enclosing_symbol.as_deref(),
                Some("hook" | "mutation" | "replaced")
            )
    }) {
        assert!(
            !e.captures.contains_key("endpoint"),
            "stale endpoint: {e:#?}"
        );
        assert!(
            e.tags
                .iter()
                .any(|t| t == "outbound-request:unresolved-producer")
        );
    }
    assert!(
        !scan.evidence.iter().any(
            |e| e.kind == EvidenceKind::Sink && e.enclosing_symbol.as_deref() == Some("shadow")
        )
    );
}

#[test]
fn apache_construction_is_context_but_unknown_java_requests_still_dispatch() {
    let fixture = Fixture::new(
        "apache",
        &[(
            "App.java",
            r#"import org.apache.http.client.methods.HttpGet; import org.apache.http.impl.client.CloseableHttpClient;
class App {
void dead(String url){new HttpGet(url);}
void actual(CloseableHttpClient client,String url) throws Exception {HttpGet req=new HttpGet(url);client.execute(req);}
void unknown(CloseableHttpClient client,HttpGet req) throws Exception {client.execute(req);}
}"#,
        )],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert_eq!(
        inventory
            .entries
            .iter()
            .filter(|e| e.capability == Capability::OutboundNetworkRequest)
            .count(),
        2
    );
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    assert!(
        scan.evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Resource && e.rule_id == "java-apache-http-request")
    );
    let sends = scan
        .evidence
        .iter()
        .filter(|e| e.kind == EvidenceKind::Sink && e.rule_id == "java-apache-http-dispatch")
        .collect::<Vec<_>>();
    assert_eq!(sends.len(), 2);
    assert!(
        sends
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("actual")
                && e.captures["endpoint"].text == "url")
    );
    assert!(
        sends
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("unknown")
                && !e.captures.contains_key("endpoint"))
    );
}
