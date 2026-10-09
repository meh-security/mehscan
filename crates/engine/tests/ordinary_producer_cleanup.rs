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
        "mehscan-ordinary-producer-{name}-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    for (name, code) in files {
        fs::write(root.join(name), code).unwrap();
    }
    Fixture(root)
}
#[test]
fn unused_signing_is_context_but_credential_handoffs_and_callbacks_remain() {
    let js = r#"const jwt=require('jsonwebtoken');
function unused(key){const token=jwt.sign({sub:'a'},key);}
function discarded(key){jwt.sign({sub:'a'},key,{expiresIn:'5m'});}
function issued(key){return jwt.sign({sub:'a'},key);}
function delivered(key,done){jwt.sign({sub:'a'},key,{},done);}
function callback(key,done){const token=jwt.sign({sub:'a'},key,done);}
function escaped(key,send){const token=jwt.sign({sub:'a'},key);send(token);}
function shadow(jwt,key){const token=jwt.sign({sub:'a'},key);}
function foreign(custom,key){const token=custom.sign({sub:'a'},key);}
"#;
    let f = fixture(
        "jwt",
        &[
            ("app.js", js),
            ("app.ts", js),
            ("app.tsx", js),
            (
                "App.kt",
                r#"import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
fun unused(a:Algorithm){val token=JWT.create().sign(a)}
fun issued(a:Algorithm):String {val token=JWT.create().sign(a);return token}
fun escaped(a:Algorithm, send:(String)->Unit){val token=JWT.create().sign(a);send(token)}
"#,
            ),
        ],
    );
    let inventory = build_review_inventory(&f.0, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    for file in ["app.js", "app.ts", "app.tsx", "App.kt"] {
        let items = inventory
            .scan
            .evidence
            .iter()
            .filter(|e| e.location.path == file && e.rule_id.ends_with("jwt-token-generation"))
            .collect::<Vec<_>>();
        assert_eq!(items.len(), if file == "App.kt" { 3 } else { 6 }, "{file}");
        assert_eq!(
            items
                .iter()
                .filter(|e| e.kind == EvidenceKind::Resource)
                .count(),
            if file == "App.kt" { 1 } else { 2 },
            "{file}: {items:#?}"
        );
        for item in &items {
            assert_eq!(
                inventory
                    .entries
                    .iter()
                    .any(|e| e.path == item.location.path
                        && e.line == item.location.start.line
                        && e.rule_id == item.rule_id),
                item.kind != EvidenceKind::Resource,
                "{}",
                item.enclosing_symbol.as_deref().unwrap_or("")
            );
        }
    }
    assert!(!inventory.entries.iter().any(|e| e.capability
        == mehscan_core::Capability::TokenGeneration
        && matches!(
            e.symbol.as_deref(),
            Some("unused" | "discarded" | "shadow" | "foreign")
        )));
}
#[test]
fn signing_aliases_keep_real_delivery_and_expiry_absence_is_only_context() {
    let f = fixture(
        "aliases",
        &[(
            "app.ts",
            r#"import {sign as issue} from 'jsonwebtoken';
export function issued(payload:object,key:string){return issue(payload,key);}
function unused(payload:object,key:string){const token=issue(payload,key);}
import {verify as check} from 'jsonwebtoken';
function ordinary(token:string,key:string){return check(token,key);}
function disabled(token:string,key:string){return check(token,key,{ignoreExpiration:true,algorithms:['none']});}
"#,
        )],
    );
    let inventory = build_review_inventory(&f.0, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| e.symbol.as_deref() == Some("issued")
                && e.rule_id == "typescript-jwt-token-generation")
    );
    assert!(!inventory.entries.iter().any(|e| e.capability
        == mehscan_core::Capability::TokenGeneration
        && e.symbol.as_deref() == Some("unused")));
    assert!(
        !inventory
            .scan
            .security_paths
            .iter()
            .any(|p| p.cwe_candidates == ["CWE-613"])
    );
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .filter(|e| e.rule_id == "typescript-jwt-without-expiry")
            .all(|e| e.kind == EvidenceKind::Resource)
    );
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| e.symbol.as_deref() == Some("ordinary"))
    );
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| e.symbol.as_deref() == Some("disabled")
                && e.rule_id == "typescript-jwt-algorithm-validation-weakened")
    );
    assert!(
        !inventory
            .scan
            .evidence
            .iter()
            .any(|e| e.rule_id == "typescript-jwt-token-input")
    );
}
#[test]
fn console_and_string_buffers_are_not_browser_sinks_but_response_streams_stay() {
    let f = fixture(
        "writers",
        &[
            (
                "App.cs",
                r#"using System;
using System.IO;
using Microsoft.AspNetCore.Http;
class App {
void ConsoleOutput(string value){Console.Out.WriteAsync(value);System.Console.Error.WriteAsync(value);}
void Buffer(StringWriter writer,string value){writer.WriteAsync(value);}
void Response(HttpResponse response,string value){response.WriteAsync(value);}
void ResponseStream(StreamWriter writer,string value){writer.WriteAsync(value);}
void Text(TextWriter writer,string value){writer.WriteAsync(value);}
void Forward(StringWriter writer,HttpResponse response,string value){writer.WriteAsync(value);response.WriteAsync(writer.ToString());}
}
"#,
            ),
            (
                "Shadow.cs",
                r#"using System.IO;
class StringWriter {public void WriteAsync(string v){}}
class App {void Shadow(StringWriter writer,string value){writer.WriteAsync(value);}}
"#,
            ),
        ],
    );
    let inventory = build_review_inventory(&f.0, false).unwrap();
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&f.0, None, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    let items = inventory
        .scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "csharp-html-output")
        .collect::<Vec<_>>();
    assert_eq!(items.len(), 9);
    assert_eq!(
        items
            .iter()
            .filter(|e| e.kind == EvidenceKind::Resource)
            .count(),
        4
    );
    for item in items {
        assert_eq!(
            jobs.observation_reviews
                .iter()
                .any(|r| r.anchor_evidence_ids.contains(&item.id)),
            item.kind != EvidenceKind::Resource
        );
    }
}
