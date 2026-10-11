use mehscan_core::{Capability, EvidenceKind};
use mehscan_engine::investigation::build_review_inventory;
use std::{fs, path::PathBuf};
struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str, source: &str) -> Self {
        let path = std::env::temp_dir().join(format!("mehscan-curl-{name}-{}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        for file in ["App.c", "App.cpp"] {
            fs::write(path.join(file), source).unwrap();
        }
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn options_are_context_and_easy_multi_consumers_keep_destinations() {
    let fixture = Fixture::new(
        "effects",
        r#"#include <curl/curl.h>
void lazy(CURL *h,const char *url) {curl_easy_setopt(h,CURLOPT_URL,url);}
void easy(CURL *h) {curl_easy_setopt(h,CURLOPT_URL,getenv("URL"));curl_easy_perform(h);}
void multi(CURL *h,CURLM *m,int *running) {curl_easy_setopt(h,CURLOPT_URL,getenv("URL"));curl_multi_add_handle(m,h);curl_multi_perform(m,running);}
void other(CURL *h,CURL *other,CURLM *m,int *running) {curl_easy_setopt(h,CURLOPT_URL,getenv("URL"));curl_multi_add_handle(m,other);curl_multi_socket_action(m,0,0,running);}
"#,
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
    assert_eq!(
        scan.security_paths
            .iter()
            .filter(|p| p.capability == Capability::OutboundNetworkRequest)
            .count(),
        4,
        "{:#?}",
        scan.security_paths
    );
    assert_eq!(
        sinks
            .iter()
            .filter(|e| e
                .captures
                .get("endpoint")
                .is_some_and(|c| c.text == "getenv(\"URL\")"))
            .count(),
        4,
        "{sinks:#?}"
    );
    assert!(
        sinks
            .iter()
            .filter(|e| e.enclosing_symbol.as_deref() == Some("other"))
            .all(|e| !e.captures.contains_key("endpoint"))
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| e.rule_id.ends_with("libcurl-outbound-request")
                || e.symbol.as_deref() == Some("lazy")),
        "{:#?}",
        inventory.entries
    );
}
#[test]
fn changes_do_not_inherit_stale_fixed_authority() {
    let fixture = Fixture::new(
        "changes",
        r#"#include <curl/curl.h>
void fixed(CURL *h) {curl_easy_setopt(h,CURLOPT_URL,"https://example.com");curl_easy_setopt(h,CURLOPT_TIMEOUT,1);curl_easy_perform(h);}
void replace(CURL *h,const char *url) {curl_easy_setopt(h,CURLOPT_URL,"https://example.com");curl_easy_setopt(h,CURLOPT_URL,url);curl_easy_perform(h);}
void branch(CURL *h,const char *url,int b) {curl_easy_setopt(h,CURLOPT_URL,url);if(b)curl_easy_setopt(h,CURLOPT_URL,"https://example.com");curl_easy_perform(h);}
void proxy(CURL *h,const char *p) {curl_easy_setopt(h,CURLOPT_PROXY,p);curl_easy_setopt(h,CURLOPT_URL,"https://example.com");curl_easy_perform(h);}
void reset(CURL *h) {curl_easy_setopt(h,CURLOPT_URL,"https://example.com");curl_easy_reset(h);curl_easy_perform(h);}
void hook(CURL *h) {curl_easy_setopt(h,CURLOPT_URL,"https://example.com");rewrite(h);curl_easy_perform(h);}
void unknown(CURL *h) {curl_easy_perform(h);}
"#,
    );
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    let sinks = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id.ends_with("libcurl-request-dispatch"))
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 14, "{sinks:#?}");
    assert!(
        sinks
            .iter()
            .filter(|e| matches!(
                e.enclosing_symbol.as_deref(),
                Some("branch" | "proxy" | "reset" | "hook" | "unknown")
            ))
            .all(|e| !e.captures.contains_key("endpoint")),
        "{sinks:#?}"
    );
    assert!(
        sinks
            .iter()
            .filter(|e| e.enclosing_symbol.as_deref() == Some("replace"))
            .all(|e| e.captures.get("endpoint").is_some_and(|c| c.text == "url")),
        "{sinks:#?}"
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| e.symbol.as_deref() == Some("fixed"))
    );
}
#[test]
fn multi_does_not_mix_handles_and_local_functions_are_not_libcurl() {
    let fixture = Fixture::new(
        "multi",
        r#"#include <curl/curl.h>
void multi(CURL *a,CURL *b,CURLM *m,int *running) {
curl_easy_setopt(a,CURLOPT_URL,"https://example.com");curl_multi_add_handle(m,a);curl_multi_add_handle(m,b);curl_multi_perform(m,running);
}
void removed(CURL *h,CURLM *m,int *running) {curl_easy_setopt(h,CURLOPT_URL,"https://example.com");curl_multi_add_handle(m,h);curl_multi_remove_handle(m,h);curl_multi_perform(m,running);}
"#,
    );
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    let sinks = scan
        .evidence
        .iter()
        .filter(|e| {
            e.rule_id.ends_with("libcurl-request-dispatch")
                && e.enclosing_symbol.as_deref() == Some("multi")
        })
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 4, "{sinks:#?}");
    assert!(
        sinks
            .iter()
            .filter(|e| e.captures["client"].text == "b")
            .all(|e| !e.captures.contains_key("endpoint")),
        "{sinks:#?}"
    );
    assert!(
        scan.evidence
            .iter()
            .filter(|e| e.rule_id.ends_with("libcurl-request-dispatch")
                && e.enclosing_symbol.as_deref() == Some("removed"))
            .all(|e| !e.captures.contains_key("endpoint"))
    );
    let fake = Fixture::new(
        "fake",
        "int curl_easy_perform(void *h){return 0;} void fake(void *h){curl_easy_perform(h);}",
    );
    assert!(
        !mehscan_engine::scan_path(&fake.0)
            .unwrap()
            .evidence
            .iter()
            .any(|e| e.rule_id.ends_with("libcurl-request-dispatch"))
    );
}
