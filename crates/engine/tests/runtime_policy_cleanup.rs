use mehscan_core::EvidenceKind;
use mehscan_engine::investigation::build_review_inventory;
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn fixture(name: &str, files: &[(&str, &str)]) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "mehscan-runtime-policy-{name}-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    for (name, source) in files {
        fs::write(root.join(name), source).unwrap();
    }
    Fixture(root)
}

#[test]
fn ordinary_settings_leave_both_queues_and_explicit_weak_decisions_survive() {
    let f = fixture(
        "defaults",
        &[
            (
                "settings.py",
                "REST_FRAMEWORK = {}\nMIDDLEWARE = []\nSECURE_SSL_REDIRECT = False\nDEBUG = True\n",
            ),
            (
                "App.cs",
                r#"using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
class App { void Configure(IServiceCollection services) {
services.AddAuthorization(options => { options.DefaultPolicy = null; options.FallbackPolicy = null; });
services.AddSession(options => { options.Cookie.HttpOnly = true; options.Cookie.SecurePolicy = CookieSecurePolicy.Always; options.Cookie.SameSite = SameSiteMode.None; });
} }"#,
            ),
            (
                "Security.java",
                r#"import org.springframework.security.config.annotation.web.builders.HttpSecurity;
class Security {void policy(HttpSecurity http) { http.authorizeHttpRequests().requestMatchers("/public").permitAll().anyRequest().authenticated(); }
void weak(HttpSecurity http) { http.authorizeHttpRequests().anyRequest().permitAll(); }}"#,
            ),
            (
                "server.go",
                r#"package app
import("net/http"; "github.com/gorilla/sessions")
func setup(key []byte) { store := sessions.NewCookieStore(key); _ = store; server := http.Server{Addr:":8080"}; _ = server; http.ListenAndServe(":8080", nil) }
func weak() { _ = sessions.NewCookieStore([]byte("hardcoded-session-signing-key-32")) }
"#,
            ),
            (
                "package.json",
                r#"{"dependencies":{"express":"4.21.2","express-session":"1.18.1"}}"#,
            ),
            (
                "app.js",
                r#"const express=require('express'); const session=require('express-session'); const app=express();
app.use(session({secret:process.env.SESSION_SECRET}));
app.use(session({secret:process.env.SESSION_SECRET,cookie:{secure:true,httpOnly:true,sameSite:'none'}}));
app.use(session({secret:process.env.SESSION_SECRET,cookie:{secure:false,httpOnly:false}}));"#,
            ),
        ],
    );
    let inventory = build_review_inventory(&f.0, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    for rule in [
        "python-drf-default-allow-any-review",
        "python-django-csrf-middleware-not-observed-review",
        "python-django-https-redirect-review",
        "csharp-null-default-authorization-review",
        "csharp-null-fallback-authorization-review",
        "csharp-session-cookie-policy-review",
        "java-spring-security-route-policy",
        "go-cookie-store-default-options-review",
        "go-cookie-store-signing-only-review",
        "go-http-server-plaintext-fallback-review",
        "go-http-server-timeout-review",
        "javascript-session-cookie-policy-review",
    ] {
        let evidence = inventory
            .scan
            .evidence
            .iter()
            .filter(|item| item.rule_id == rule)
            .collect::<Vec<_>>();
        assert!(!evidence.is_empty(), "missing control fixture for {rule}");
        assert!(
            evidence
                .iter()
                .all(|item| item.kind == EvidenceKind::Resource),
            "{rule}: {evidence:#?}"
        );
        assert!(
            !inventory.entries.iter().any(|entry| entry.rule_id == rule),
            "ordinary work admitted: {rule}"
        );
    }
    for rule in [
        "python-django-debug-enabled",
        "java-spring-security-broad-permit-all",
        "go-cookie-store-hardcoded-key",
        "javascript-session-cookie-policy-risk",
    ] {
        assert!(
            inventory.entries.iter().any(|entry| entry.rule_id == rule),
            "lost explicit weak decision: {rule}"
        );
    }
}

#[test]
fn cookie_decoding_and_unrelated_issuance_do_not_invent_identity_flows() {
    let f = fixture(
        "binding",
        &[
            (
                "decode.py",
                r#"from flask import Flask
import base64
import json
from cryptography.fernet import Fernet
fernet = Fernet(KEY)
def unrelated(request, data):
    cookie = request.cookies.get('session')
    return json.loads(base64.b64decode(data))
def session_data(request):
    cookie = request.cookies.get('session')
    return json.loads(base64.b64decode(cookie))

def wrong_decryptor(request, other):
    cookie = request.cookies.get('session')
    return other.decrypt(cookie)

def shadowed_decryptor(request, fernet):
    return fernet.decrypt(request.cookies.get('session'))

def authenticated_data(request):
    return fernet.decrypt(request.cookies.get('session'), ttl=3600)
"#,
            ),
            (
                "Cookie.cs",
                r#"using System;
using Newtonsoft.Json.Linq;
class App {
object Unrelated() {
var input = Request.Cookies["session"];
var decoded = Convert.FromBase64String(input);
var data = JObject.Parse(System.Text.Encoding.UTF8.GetString(decoded));
var user = data["auth_user"];
return tokens.GenerateToken("server-selected-user");
}
object Bound() {
var input = Request.Cookies["session"];
var decoded = Convert.FromBase64String(input);
var data = JObject.Parse(System.Text.Encoding.UTF8.GetString(decoded));
var user = data["auth_user"];
return tokens.GenerateToken(user);
}
}"#,
            ),
        ],
    );
    let inventory = build_review_inventory(&f.0, false).unwrap();
    let decoded = inventory
        .scan
        .evidence
        .iter()
        .filter(|item| item.rule_id == "python-flask-unsigned-client-session")
        .collect::<Vec<_>>();
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].kind, EvidenceKind::Resource);
    let authenticated = inventory
        .scan
        .evidence
        .iter()
        .filter(|item| item.rule_id == "python-flask-authenticated-session-control")
        .collect::<Vec<_>>();
    assert_eq!(authenticated.len(), 1);
    assert_eq!(
        authenticated[0].enclosing_symbol.as_deref(),
        Some("authenticated_data")
    );
    assert!(
        !inventory
            .entries
            .iter()
            .any(|item| item.rule_id == "python-flask-unsigned-client-session")
    );
    let issued = inventory
        .scan
        .evidence
        .iter()
        .filter(|item| item.rule_id == "csharp-unverified-sso-cookie-token-issuance")
        .collect::<Vec<_>>();
    assert_eq!(issued.len(), 1, "{issued:#?}");
    assert_eq!(issued[0].enclosing_symbol.as_deref(), Some("Bound"));
    assert!(
        inventory
            .entries
            .iter()
            .any(|entry| entry.rule_id == "csharp-unverified-sso-cookie-token-issuance")
    );
}

#[test]
fn an_unrelated_body_limiter_does_not_hide_an_unbounded_read() {
    let f = fixture(
        "limit",
        &[(
            "app.go",
            r#"package app
import("net/http"; "io")
func unrelated(w http.ResponseWriter, r *http.Request, other *http.Request) {
other.Body = http.MaxBytesReader(w, other.Body, 1024)
_, _ = io.ReadAll(r.Body)
}
func bounded(w http.ResponseWriter, r *http.Request) {
r.Body = http.MaxBytesReader(w, r.Body, 1024)
_, _ = io.ReadAll(r.Body)
}
func optional(w http.ResponseWriter, r *http.Request, enabled bool) {
if enabled { r.Body = http.MaxBytesReader(w, r.Body, 1024) }
_, _ = io.ReadAll(r.Body)
}
func replaced(w http.ResponseWriter, r *http.Request, other *http.Request, enabled bool) {
r.Body = http.MaxBytesReader(w, r.Body, 1024)
if enabled { r.Body = other.Body }
_, _ = io.ReadAll(r.Body)
}
"#,
        )],
    );
    let inventory = build_review_inventory(&f.0, false).unwrap();
    let reads = inventory
        .scan
        .evidence
        .iter()
        .filter(|item| item.rule_id == "go-unbounded-request-body-read-review")
        .collect::<Vec<_>>();
    assert_eq!(reads.len(), 3, "{reads:#?}");
    for symbol in ["unrelated", "optional", "replaced"] {
        assert!(
            reads
                .iter()
                .any(|item| item.enclosing_symbol.as_deref() == Some(symbol))
        );
    }
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .any(|item| item.rule_id == "go-request-body-size-limit-control")
    );
}
