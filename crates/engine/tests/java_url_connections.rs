use mehscan_core::{Capability, EvidenceKind, SecurityPathState};
use mehscan_engine::investigation::build_review_inventory;
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str, files: &[(&str, &str)]) -> Self {
        let root = std::env::temp_dir().join(format!(
            "mehscan-java-connection-{name}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        for (name, source) in files {
            fs::write(root.join(name), source).unwrap();
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
fn construction_is_context_and_each_actual_consumer_keeps_input() {
    let fixture = Fixture::new(
        "effects",
        &[(
            "App.java",
            r#"import java.net.URL;
import java.net.URI;
import java.net.URLConnection;
import java.net.HttpURLConnection;
class App {
void lazy(HttpServletRequest request) throws Exception { new URL(request.getParameter("url")).openConnection(); }
URLConnection factory(HttpServletRequest request) throws Exception {return URI.create(request.getParameter("url")).toURL().openConnection();}
void connection(HttpServletRequest request) throws Exception {URL address=new URL(request.getParameter("url"));URLConnection c=address.openConnection();c.setConnectTimeout(1000);c.connect();c.getInputStream();}
void direct(HttpServletRequest request) throws Exception {new URL(request.getParameter("url")).openStream();URI.create(request.getParameter("url")).toURL().getContent();}
void cast(HttpServletRequest request) throws Exception {var c=(HttpURLConnection) new URL(request.getParameter("url")).openConnection();c.getResponseCode();}
}
"#,
        )],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| matches!(e.symbol.as_deref(), Some("lazy" | "factory")))
    );
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| e.rule_id == "java-url-connection")
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
    assert_eq!(sinks.len(), 5, "{sinks:#?}");
    assert!(
        sinks
            .iter()
            .all(|e| e.captures["endpoint"].text == "request.getParameter(\"url\")"),
        "{sinks:#?}"
    );
    assert!(
        sinks
            .iter()
            .filter(|e| e.rule_id == "java-url-connection-consumer")
            .all(|e| !e.related_evidence.is_empty())
    );
    assert_eq!(
        scan.security_paths
            .iter()
            .filter(|p| p.capability == Capability::OutboundNetworkRequest)
            .count(),
        5,
        "{:#?}",
        scan.security_paths
    );
    assert!(
        scan.security_paths
            .iter()
            .all(|p| p.state != SecurityPathState::Protected)
    );
    assert_eq!(
        inventory
            .entries
            .iter()
            .filter(|e| e.capability == Capability::OutboundNetworkRequest)
            .count(),
        5
    );
}

#[test]
fn fixed_selection_closes_but_replacements_helpers_and_unknown_consumers_survive() {
    let fixture = Fixture::new(
        "origins",
        &[(
            "App.java",
            r#"import java.net.URL;
import java.net.URI;
import java.net.URLConnection;
import java.net.HttpURLConnection;
import java.net.Proxy;
class App {
void fixed() throws Exception {URLConnection c=new URL("https://example.test/").openConnection();c.connect();c.getInputStream();}
void replaced(String input) throws Exception {URLConnection c=new URL("https://example.test/").openConnection();c=connection(input);c.connect();}
void branch(String input,boolean flag) throws Exception {URLConnection c=new URL("https://example.test/").openConnection();if(flag)c=connection(input);c.getInputStream();}
void helper(String input) throws Exception {URLConnection c=new URL("https://example.test/").openConnection();configure(c,input);c.connect();}
void alias(String input) throws Exception {URLConnection c=new URL("https://example.test/").openConnection();URLConnection other=c;configure(other,input);c.connect();other.getInputStream();}
void rewrite(String input) throws Exception {URL url=new URL("https://example.test/");url=new URL(input);url.openConnection().getInputStream();}
void parameter(URLConnection c) throws Exception {c.connect();c.getContent();}
void headers(HttpURLConnection c) throws Exception {c.getHeaderFields();c.getHeaderField("Location");c.getHeaderFieldKey(0);c.getContentLengthLong();c.getResponseMessage();c.getOutputStream();}
void metadata() throws Exception {URLConnection c=new URL("https://example.test/").openConnection();c.getURL();c.getConnectTimeout();c.getRequestProperty("Host");}
void proxied(String input,Proxy proxy) throws Exception {new URL(input).openConnection(proxy).getInputStream();}
void proxyFixed(Proxy proxy) throws Exception {new URL("https://example.test/").openConnection(proxy).getInputStream();}
void noProxy() throws Exception {new URL("https://example.test/").openConnection(Proxy.NO_PROXY).getInputStream();}
}
"#,
        )],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| matches!(e.symbol.as_deref(), Some("fixed" | "metadata" | "noProxy")))
    );
    for name in [
        "replaced",
        "branch",
        "helper",
        "alias",
        "rewrite",
        "parameter",
        "headers",
        "proxied",
        "proxyFixed",
    ] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some(name)),
            "{name}"
        );
    }
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    for name in ["replaced", "branch", "helper", "alias"] {
        let sink = scan
            .evidence
            .iter()
            .find(|e| {
                e.rule_id == "java-url-connection-consumer"
                    && e.enclosing_symbol.as_deref() == Some(name)
            })
            .unwrap();
        assert!(!sink.captures.contains_key("endpoint"), "{name}");
        assert!(
            sink.tags
                .iter()
                .any(|t| t == "outbound-request:unresolved-producer")
        );
    }
}

#[test]
fn lexical_sdk_ownership_rejects_lookalikes_shadowing_and_unrelated_names() {
    let fixture = Fixture::new(
        "ownership",
        &[
            (
                "App.java",
                r#"import java.net.URL;
import java.net.URLConnection;
class App {
URLConnection field;
void unknown() throws Exception {this.field.getInputStream();}
void shadow(Other field) throws Exception {field.getInputStream();this.field.getInputStream();}
void other(Other c) throws Exception {c.connect();c.getInputStream();c.getContent();}
void block(Other c) throws Exception {if(flag){URLConnection c=build();c.connect();}c.connect();}
void wrong(URLConnection c) throws Exception {c.getResponseCode();c.getInputStream("invalid");}
<URLConnection> void generic(URLConnection c){c.connect();}
}
class Other {void connect(){} Object getInputStream(){return null;}Object getContent(){return null;}}
"#,
            ),
            (
                "Shadow.java",
                r#"import java.net.URL;
class URL {URL(String value){} URLConnection openConnection(){return null;} Object openStream(){return null;}}
class URLConnection {void connect(){}}
class Shadow {void f(String input){new URL(input).openConnection().connect();new URL(input).openStream();}}
"#,
            ),
            (
                "Qualified.java",
                r#"class Qualified {
void f(String input) throws Exception {new java.net.URL(input).openConnection().getInputStream();}
void typed(java.net.URLConnection c) throws Exception {c.connect();}
void uri(String input) throws Exception {java.net.URI.create(input).toURL().openStream();}
}"#,
            ),
        ],
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
    assert_eq!(sinks.len(), 6, "{sinks:#?}");
    assert!(!sinks.iter().any(|e| e.location.path == "Shadow.java"
        || matches!(
            e.enclosing_symbol.as_deref(),
            Some("other" | "wrong" | "generic")
        )));
    assert_eq!(
        sinks
            .iter()
            .filter(|e| e.enclosing_symbol.as_deref() == Some("shadow"))
            .count(),
        1
    );
    assert_eq!(
        sinks
            .iter()
            .filter(|e| e.enclosing_symbol.as_deref() == Some("block"))
            .count(),
        1
    );
}
