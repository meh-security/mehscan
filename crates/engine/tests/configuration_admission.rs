use mehscan_core::Capability;
use mehscan_engine::investigation::build_review_inventory;
use std::{fs, path::PathBuf};
struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str, files: &[(&str, &str)]) -> Self {
        let root = std::env::temp_dir().join(format!(
            "mehscan-config-admission-{name}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        for (file, source) in files {
            fs::write(root.join(file), source).unwrap();
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
fn affirmative_tls_controls_are_context_and_disabled_verification_survives() {
    let fixture = Fixture::new(
        "tls",
        &[
            (
                "App.cs",
                r#"using System.Net.Http; class App {
void Good(HttpClientHandler h){h.ServerCertificateCustomValidationCallback=(r,c,ch,e)=>false;}
void Bad(HttpClientHandler h){h.ServerCertificateCustomValidationCallback=(r,c,ch,e)=>true;}
}"#,
            ),
            (
                "App.java",
                r#"class App {void good(Client client){client.hostnameVerifier((host,session)->false);}void bad(Client client){client.hostnameVerifier((host,session)->true);}}"#,
            ),
            (
                "app.js",
                "const tls=require('tls');function good(){tls.connect({rejectUnauthorized:true});}function bad(){tls.connect({rejectUnauthorized:false});}",
            ),
            (
                "app.ts",
                "import * as tls from 'tls';function good(){tls.connect({rejectUnauthorized:true});}function bad(){tls.connect({rejectUnauthorized:false});}",
            ),
            (
                "app.tsx",
                "import * as tls from 'tls';function good(){tls.connect({rejectUnauthorized:true});}function bad(){tls.connect({rejectUnauthorized:false});}",
            ),
            (
                "app.py",
                "import ssl\ndef good(ctx):\n    ctx.check_hostname=True\ndef bad(ctx):\n    ctx.check_hostname=False\n",
            ),
            (
                "app.go",
                "package app\nimport \"crypto/tls\"\nfunc good(){_ = tls.Config{InsecureSkipVerify:false}}\nfunc bad(){_ = tls.Config{InsecureSkipVerify:true}}",
            ),
            (
                "app.rs",
                "fn good(){reqwest::Client::builder().danger_accept_invalid_certs(false);} fn bad(){reqwest::Client::builder().danger_accept_invalid_certs(true);}",
            ),
            (
                "app.kt",
                "import javax.net.ssl.SSLContext\nfun good(ctx:SSLContext){ctx.init(null,null,null)}\nfun bad(ctx:SSLContext,trust:Array<javax.net.ssl.TrustManager>){ctx.init(null,trust,null)}",
            ),
        ],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    for file in [
        "App.cs", "App.java", "app.js", "app.ts", "app.tsx", "app.py", "app.go", "app.rs", "app.kt",
    ] {
        assert!(
            inventory
                .scan
                .evidence
                .iter()
                .any(|e| e.location.path == file
                    && e.capability == Capability::TlsConfiguration
                    && matches!(e.enclosing_symbol.as_deref(), Some("good" | "Good"))),
            "missing positive observation for {file}"
        );
        assert!(
            !inventory.entries.iter().any(|e| e.path == file
                && e.capability == Capability::TlsConfiguration
                && matches!(e.symbol.as_deref(), Some("good" | "Good"))),
            "retained positive {file}: {:#?}",
            inventory.entries
        );
        assert!(
            inventory.entries.iter().any(|e| e.path == file
                && e.capability == Capability::TlsConfiguration
                && matches!(e.symbol.as_deref(), Some("bad" | "Bad"))),
            "lost negative {file}: {:#?}",
            inventory.entries
        );
    }
}
#[test]
fn parser_hardening_is_context_not_a_new_xxe_job() {
    let fixture = Fixture::new(
        "xml",
        &[(
            "app.kt",
            r#"import javax.xml.parsers.DocumentBuilderFactory
fun good(){val f=DocumentBuilderFactory.newInstance();f.setFeature("http://xml.org/sax/features/external-general-entities",false);f.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);f.setExpandEntityReferences(false)}
fun bad(){val f=DocumentBuilderFactory.newInstance();f.setFeature("http://xml.org/sax/features/external-general-entities",true)}
fun unknown(value:Boolean){val f=DocumentBuilderFactory.newInstance();f.setFeature("http://xml.org/sax/features/external-general-entities",value)}
"#,
        )],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .any(|e| e.rule_id == "kotlin-xml-configuration"
                && e.enclosing_symbol.as_deref() == Some("good"))
    );
    assert!(!inventory.entries.iter().any(|e|e.rule_id=="kotlin-xml-configuration"&&e.symbol.as_deref()==Some("good")),"{:#?}",inventory.entries);
    for method in ["bad", "unknown"] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.rule_id == "kotlin-xml-configuration"
                    && e.symbol.as_deref() == Some(method)),
            "missing {method}"
        );
    }
}

#[test]
fn suitable_integrity_digests_do_not_hide_weak_or_fast_password_hashes() {
    let fixture = Fixture::new(
        "digests",
        &[
            (
                "app.js",
                "const crypto=require('crypto');function integrity(){return crypto.createHash('sha256');}function passwordHash(){return crypto.createHash('sha256');}function weakSignature(){return crypto.createHash('md5');}function tokenHash(algorithm){return crypto.createHash(algorithm);}",
            ),
            (
                "app.py",
                "import hashlib\ndef integrity():\n    return hashlib.new('sha256')\ndef passwordHash():\n    return hashlib.new('sha256')\ndef weakSignature():\n    return hashlib.new('md5')\ndef tokenHash(algorithm):\n    return hashlib.new(algorithm)\n",
            ),
            (
                "App.kt",
                "import java.security.MessageDigest\nfun tokenIntegrity()=MessageDigest.getInstance(\"SHA-256\")\nfun passwordHash()=MessageDigest.getInstance(\"SHA-256\")\nfun weakSignature()=MessageDigest.getInstance(\"MD5\")\nfun tokenHash(algorithm:String)=MessageDigest.getInstance(algorithm)\n",
            ),
        ],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(
        !inventory.entries.iter().any(|e| matches!(
            e.symbol.as_deref(),
            Some("integrity" | "tokenIntegrity")
        ) && e.capability == Capability::CryptographicHash),
        "{:#?}",
        inventory.entries
    );
    for file in ["app.js", "app.py", "App.kt"] {
        for method in ["passwordHash", "weakSignature", "tokenHash"] {
            assert!(
                inventory.entries.iter().any(|e| e.path == file
                    && e.symbol.as_deref() == Some(method)
                    && e.capability == Capability::CryptographicHash),
                "lost {file}/{method}: {:#?}",
                inventory.entries
            );
        }
    }
}
#[test]
fn unrelated_known_file_signatures_cannot_close_a_dynamic_sink() {
    let fixture = Fixture::new(
        "no-app-shortcuts",
        &[(
            "app.ts",
            r#"import * as fs from 'fs';
const SNIPPET_PATHS=Object.freeze([]);
function findFilesWithCodeChallenges(){} function lstat(currPath){} function readdir(currPath){}
function read(req,res){const currPath=req.query.path;fs.readFile(currPath,(err,data)=>res.send(data));}
function promotion(req,res){const a=config.get<string>('application.promotion.video');const b=config.get<string>('application.promotion.subtitles');const base='frontend/dist/frontend/assets/public/videos/';utils.extractFilename(a);res.send(fs.readFileSync(req.query.path));}
function configured(){const message=config.get('message');return message;}
function response(req,res){const message=req.query.html;res.send(message);}
"#,
        )],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    for method in ["read", "promotion", "response"] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some(method)),
            "closed {method} by unrelated text: {:#?}",
            inventory.entries
        );
    }
}
