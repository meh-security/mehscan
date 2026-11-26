use std::{collections::BTreeSet, fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("mehscan-typed-http-{}", std::process::id()));
        fs::create_dir_all(root.join("src")).unwrap();
        Self(root)
    }
    fn write(&self, name: &str, source: &str) {
        fs::write(self.0.join("src").join(name), source).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn typed_clients_preserve_dispatch_ownership_and_exact_source_without_method_lookalikes() {
    let f = Fixture::new();
    f.write(
        "context.rs",
        r#"
use reqwest_middleware::ClientWithMiddleware as Http;
use std::sync::Arc;
pub struct SharedState { transport: Arc<Http> }
impl SharedState { pub fn outbound(&self) -> &Http { &self.transport } }
"#,
    );
    f.write("operations.rs", r#"
use reqwest::Client as Net;
use reqwest_middleware::ClientWithMiddleware as Wrapped;
use crate::context::SharedState as State;
async fn direct(c: &reqwest::Client, direct_url: &str) { c.get(direct_url).send().await; }
async fn alias(c: &Net, alias_url: &str) { c.post(alias_url).send().await; }
async fn wrapped(c: &Wrapped, wrapped_url: &str) { c.get(wrapped_url).send().await; }
async fn forwarded(state: &State, forwarded_url: &str) { state.outbound().get(forwarded_url).send().await; }
async fn literal(c: &Net) { c.get("https://api.example.invalid/health").send().await; }
async fn construct_only(c: &Net, unused_url: &str) { c.get(unused_url); }
struct Worker { transport: Wrapped }
impl Worker {
 async fn field(&self, field_url: &str) { self.transport.get(field_url).send().await; }
 fn outbound(&self) -> &Wrapped { &self.transport }
 async fn accessor(&self, accessor_url: &str) { self.outbound().get(accessor_url).send().await; }
}
"#);
    f.write(
        "lookalikes.rs",
        r#"
use reqwest::Client as Net;
struct Other;
impl Other { fn get(&self, s: &str) -> Other { Other } fn send(&self) {} }
fn unrelated(x: &Other, value: &str) { x.get(value).send(); }
fn generic_shadow<Net>(x: &Net, value: &str) { x.get(value).send(); }
fn closure_shadow(c: &Net, value: &str) { let task = |c: Other| c.get(value).send(); }
fn local_shadow(c: &Net, value: &str) { let c = Other; c.get(value).send(); }
fn loop_shadow(c: &Net, xs: Vec<Other>, value: &str) { for c in xs { c.get(value).send(); } }
fn match_shadow(c: &Net, x: Other, value: &str) { match x { c => c.get(value).send() } }
fn if_shadow(c: &Net, x: Option<Other>, value: &str) { if let Some(c) = x { c.get(value).send(); } }
struct Wrong { transport: Other }
impl Wrong { fn outbound(&self) -> &Other { &self.transport }
 fn wrong(&self, value: &str) { self.outbound().get(value).send(); } }
mod inner { struct Client; fn local(c: &Client, s: &str) { c.get(s).send(); } }
"#,
    );
    f.write(
        "module_shadow.rs",
        r#"
use reqwest::Client as Net;
mod reqwest { pub struct Client; }
fn module_shadow(c: &reqwest::Client, s: &str) { c.get(s).send(); }
fn imported_local_module(c: &Net, s: &str) { c.get(s).send(); }
"#,
    );
    f.write(
        "conditional.rs",
        r#"
use reqwest::Client;
struct Conditional { http: Client }
impl Conditional {
 #[cfg(feature="first")] fn transport(&self) -> &Client { &self.http }
 #[cfg(feature="second")] fn transport(&self) -> &Client { &self.http }
 async fn ambiguous(&self, url: &str) { self.transport().get(url).send().await; }
}
#[cfg(test)] mod tests {
 async fn hidden(c: &reqwest::Client, url: &str) { c.get(url).send().await; }
}
"#,
    );
    let scan = mehscan_engine::scan_path(&f.0).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let sends: Vec<_> = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "rust-reqwest-request-dispatch")
        .collect();
    let endpoints = sends
        .iter()
        .map(|e| e.captures["endpoint"].text.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        endpoints,
        BTreeSet::from([
            "direct_url",
            "alias_url",
            "wrapped_url",
            "forwarded_url",
            "\"https://api.example.invalid/health\"",
            "field_url",
            "accessor_url"
        ])
    );
    assert_eq!(sends.len(), 7);
    for send in sends {
        assert!(send.captures.contains_key("http_client_type"));
        assert!(
            send.captures["request"].text.contains(".get(")
                || send.captures["request"].text.contains(".post(")
        );
        for capture in send.captures.values() {
            let source = fs::read_to_string(f.0.join(&capture.location.path)).unwrap();
            assert_eq!(
                capture.text,
                source[capture.location.start.byte_offset..capture.location.end.byte_offset]
            );
        }
    }
    assert!(!scan.evidence.iter().any(|e| {
        e.kind == mehscan_core::EvidenceKind::Sink
            && e.captures
                .get("endpoint")
                .is_some_and(|c| c.text == "unused_url")
    }));
}
