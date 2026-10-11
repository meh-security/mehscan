use mehscan_core::{Capability, EvidenceKind, SecurityPathState};
use mehscan_engine::investigation::build_review_inventory;
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str, source: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "mehscan-kotlin-dispatch-{name}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("app.kt"), source).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn lazy_construction_has_no_job_and_real_consumers_keep_source_endpoints() {
    let fixture = Fixture::new(
        "consumers",
        r#"import java.net.URL
import java.net.URI
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Callback
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
@RestController
class Routes {
 @GetMapping("/lazy") fun lazy(@RequestParam url:String) {URL(url).openConnection();OkHttpClient().newCall(Request.Builder().url(url).build())}
 @GetMapping("/return") fun factory(@RequestParam url:String)=OkHttpClient().newCall(Request.Builder().url(url).build())
 @GetMapping("/connection") fun connection(@RequestParam url:String) {val c=URI.create(url).toURL().openConnection();c.connect();c.getInputStream()}
 @GetMapping("/sync") fun sync(@RequestParam url:String) {val client=OkHttpClient();val req=Request.Builder().url(url).header("Accept","text/plain").build();val call=client.newCall(req);val alias=call;alias.execute()}
 @GetMapping("/async") fun async(@RequestParam url:String,callback:Callback) {OkHttpClient.Builder().build().newCall(Request.Builder().url(url).build()).enqueue(callback)}
 @GetMapping("/clone") fun copy(@RequestParam url:String) {val call=OkHttpClient().newCall(Request.Builder().url(url).build());call.clone().execute()}
}
"#,
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(!inventory.entries.iter().any(|e| matches!(
        e.rule_id.as_str(),
        "kotlin-url-connection" | "kotlin-okhttp-request"
    )));
    for name in ["lazy", "factory"] {
        assert!(
            !inventory
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some(name))
        );
    }
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let sends = scan
        .evidence
        .iter()
        .filter(|e| {
            e.kind == EvidenceKind::Sink && e.capability == Capability::OutboundNetworkRequest
        })
        .collect::<Vec<_>>();
    assert_eq!(sends.len(), 5, "{sends:#?}");
    assert!(
        sends
            .iter()
            .all(|e| e.captures["endpoint"].text == "url" && !e.related_evidence.is_empty()),
        "{sends:#?}"
    );
    assert_eq!(scan.security_paths.len(), 5, "{:#?}", scan.security_paths);
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
fn property_and_method_consumers_are_owned_and_safe_selectors_do_not_reopen() {
    let fixture = Fixture::new(
        "properties",
        r#"import java.net.URL
import java.net.URLConnection
import java.net.HttpURLConnection
import javax.net.ssl.HttpsURLConnection
import okhttp3.Call
import okhttp3.Callback
fun fixed(){val c=URL("https://example.test/").openConnection();c.inputStream}
fun property(url:String){val c=URL(url).openConnection() as HttpURLConnection;c.inputStream;c.outputStream;c.content;c.headerFields;c.responseCode;c.responseMessage}
fun methods(c:HttpURLConnection){c.getResponseCode();c.getResponseMessage();c.getOutputStream();c.getHeaderField("Location");c.getHeaderFields();c.getContent(arrayOf(String::class.java))}
fun unknown(c:URLConnection){c.connect();c.getInputStream()}
fun unknownCall(call:Call,callback:Callback){call.execute();call.enqueue(callback)}
fun cast(url:String)=(URL(url).openConnection() as HttpsURLConnection).inputStream
class Other {val inputStream="text";fun execute()={};fun enqueue(a:Any)={}}
fun lookalike(c:Other){c.inputStream;c.execute();c.enqueue("other")}
fun wrong(c:URLConnection){c.responseCode;c.getResponseCode()}
fun shadow(call:Call){val call=Other();call.execute()}
"#,
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(!inventory.entries.iter().any(|e| matches!(
        e.symbol.as_deref(),
        Some("fixed" | "lookalike" | "wrong" | "shadow")
    )));
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    for (name, count) in [
        ("property", 6),
        ("methods", 6),
        ("unknown", 2),
        ("unknownCall", 2),
        ("cast", 1),
    ] {
        let sinks = scan
            .evidence
            .iter()
            .filter(|e| {
                e.kind == EvidenceKind::Sink
                    && e.capability == Capability::OutboundNetworkRequest
                    && e.enclosing_symbol.as_deref() == Some(name)
            })
            .collect::<Vec<_>>();
        assert_eq!(sinks.len(), count, "{name}: {sinks:#?}");
        if matches!(name, "property" | "cast") {
            assert!(
                sinks.iter().all(|e| e.captures["endpoint"].text == "url"),
                "{name}"
            );
        }
    }
}

#[test]
fn opaque_client_preserves_initial_input_relationship_without_final_authority_claim() {
    let fixture = Fixture::new(
        "initial-input",
        r#"import okhttp3.OkHttpClient
import okhttp3.Request
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
@RestController
class Routes(private val client:OkHttpClient) {
 @GetMapping("/fetch") fun fetch(@RequestParam url:String){client.newCall(Request.Builder().url(url).build()).execute()}
}
"#,
    );
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    assert_eq!(scan.security_paths.len(), 1);
    let path = &scan.security_paths[0];
    assert_eq!(path.state, SecurityPathState::Propagated);
    assert!(
        path.uncertainty_reasons
            .iter()
            .any(|r| r.contains("initial request URL"))
    );
    let sink = scan
        .evidence
        .iter()
        .find(|e| e.id == path.sink_evidence_id)
        .unwrap();
    assert_eq!(sink.captures["initial_endpoint"].text, "url");
    assert_eq!(sink.captures["client"].text, "client");
    assert!(!sink.captures.contains_key("endpoint"));
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert_eq!(
        inventory
            .entries
            .iter()
            .filter(|e| e.rule_id == "kotlin-okhttp-dispatch")
            .count(),
        1
    );
}

#[test]
fn fixed_initial_requests_do_not_close_opaque_client_policy_or_mutable_builders() {
    let fixture = Fixture::new(
        "policy",
        r#"import okhttp3.OkHttpClient
import okhttp3.Request
fun fixed(){val client=OkHttpClient();val req=Request.Builder().url("https://example.test/").build();client.newCall(req).execute()}
fun unknown(client:OkHttpClient){val req=Request.Builder().url("https://example.test/").build();client.newCall(req).execute()}
fun modified(client:OkHttpClient,url:String){val builder=Request.Builder().url("https://example.test/");builder.url(url);val req=builder.build();client.newCall(req).execute()}
fun overwritten(url:String){val req=Request.Builder().url("https://example.test/").url(url).build();OkHttpClient().newCall(req).execute()}
fun helper(client:OkHttpClient,url:String){client.newCall(buildRequest(url)).execute()}
"#,
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| e.symbol.as_deref() == Some("fixed"))
    );
    for symbol in ["unknown", "modified", "overwritten", "helper"] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.rule_id == "kotlin-okhttp-dispatch"
                    && e.symbol.as_deref() == Some(symbol)),
            "{symbol}"
        );
    }
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    for e in scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "kotlin-okhttp-dispatch")
    {
        match e.enclosing_symbol.as_deref().unwrap() {
            "unknown" => {
                assert_eq!(e.captures["client"].text, "client");
                assert!(e.captures.contains_key("initial_endpoint"));
                assert!(!e.captures.contains_key("endpoint"));
                assert!(
                    e.tags
                        .iter()
                        .any(|t| t == "outbound-request:unresolved-client-policy")
                );
            }
            "modified" | "helper" => {
                assert!(!e.captures.contains_key("endpoint"));
                assert!(
                    e.tags
                        .iter()
                        .any(|t| t == "outbound-request:unresolved-producer")
                );
            }
            "overwritten" => assert_eq!(e.captures["endpoint"].text, "url"),
            _ => {}
        }
    }
}
