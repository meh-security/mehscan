use mehscan_core::{Capability, ReviewAdmissionDisposition};
use mehscan_engine::investigation::build_review_inventory;
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str, files: &[(&str, &str)]) -> Self {
        let root =
            std::env::temp_dir().join(format!("mehscan-impact-{name}-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        for (path, source) in files {
            fs::write(root.join(path), source).unwrap();
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
fn ordinary_directories_are_context_in_both_modes_but_file_effects_survive() {
    let fixture = Fixture::new(
        "directories",
        &[
            (
                "app.js",
                "const fs=require('fs'); function setup(req){fs.mkdirSync(req.query.path);} function write(req){fs.writeFileSync(req.query.path,req.body);}",
            ),
            (
                "app.php",
                "<?php function setup(){mkdir($_GET['path'],0755);} function write_file(){file_put_contents($_GET['path'],$_POST['data']);}",
            ),
            (
                "App.cs",
                "using System.IO; class App { void Setup(string path){Directory.CreateDirectory(path);} string Read(string path){return File.ReadAllText(path);} string[] List(string path){return Directory.GetFiles(path);} }",
            ),
            (
                "App.java",
                "import java.nio.file.Files; import java.nio.file.Path; class App { void setup(Path path) throws Exception {Files.createDirectories(path);} void write(Path path,byte[] data) throws Exception {Files.write(path,data);} }",
            ),
            (
                "app.kt",
                "import java.nio.file.Files\nimport java.nio.file.Path\nfun setup(path: Path) { Files.createDirectories(path) }\nfun write(path: Path, data: ByteArray) { Files.write(path, data) }",
            ),
            (
                "app.go",
                "package app\nimport \"os\"\nfunc setup(path string){os.MkdirAll(path,0755)}\nfunc write(path string,data []byte){os.WriteFile(path,data,0600)}",
            ),
            (
                "app.rs",
                "fn setup(path: &str){std::fs::create_dir_all(path).unwrap();} fn list(path: &str){std::fs::read_dir(path).unwrap();} fn write(path: &str,data: &str){std::fs::write(path,data).unwrap();}",
            ),
        ],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    for path in [
        "app.js", "app.php", "App.cs", "App.java", "app.kt", "app.go", "app.rs",
    ] {
        assert!(
            inventory.entries.iter().any(|e| e.path == path
                && matches!(
                    e.capability,
                    Capability::FilesystemRead | Capability::FilesystemWrite
                )),
            "lost content effect {path}"
        );
    }
    for entry in &inventory.entries {
        assert!(
            !matches!(
                entry.symbol.as_deref(),
                Some("setup" | "Setup" | "list" | "List")
            ),
            "ordinary job retained: {entry:?}; evidence: {:#?}",
            inventory
                .scan
                .evidence
                .iter()
                .filter(|e| e.location.path == entry.path
                    && e.enclosing_symbol == entry.symbol
                    && e.capability == entry.capability)
                .collect::<Vec<_>>()
        );
    }
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .any(|e| e.rule_id == "rust-filesystem-write"
                && e.enclosing_symbol.as_deref() == Some("setup"))
    );
    assert!(
        inventory
            .admission_audit
            .counts
            .iter()
            .any(|c| c.disposition == ReviewAdmissionDisposition::InventoryOnly && c.count > 0)
    );
    let mut previous = inventory.clone();
    previous.schema_version = "2".into();
    assert!(
        mehscan_engine::investigation::validate_review_inventory(&fixture.0, &previous).is_err()
    );
}

#[test]
fn normal_decoders_and_syntax_are_context_but_executable_loaders_survive() {
    let fixture = Fixture::new(
        "decoders",
        &[
            (
                "app.rs",
                "fn parse(input: &str){let _: serde_json::Value=serde_json::from_str(input).unwrap();} unsafe fn boundary(p: *const u8) -> u8 { unsafe { *p } } extern \"C\" { fn foreign(); }",
            ),
            (
                "App.java",
                "import com.fasterxml.jackson.databind.ObjectMapper; import java.io.ObjectInputStream; class App { Object parse(ObjectMapper mapper,String input) throws Exception {return mapper.readValue(input, Object.class);} Object dangerous(ObjectInputStream stream) throws Exception {return stream.readObject();} }",
            ),
            (
                "app.py",
                "import pickle\nimport marshal\ndef parse(data):\n    return marshal.loads(data)\ndef dangerous(data):\n    return pickle.loads(data)\n",
            ),
            (
                "app.php",
                "<?php function dangerous($data){return unserialize($data);}",
            ),
        ],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .any(|e| e.rule_id == "rust-data-deserialization")
    );
    for rule in [
        "rust-data-deserialization",
        "rust-unsafe-boundary",
        "rust-native-interop-boundary",
        "java-jackson-object-deserialization",
        "python-marshal-deserialization",
    ] {
        assert!(
            !inventory.entries.iter().any(|e| e.rule_id == rule),
            "retained ordinary {rule}"
        );
    }
    for path in ["App.java", "app.py", "app.php"] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.path == path && e.capability == Capability::Deserialization),
            "lost executable loader {path}"
        );
    }
}

#[test]
fn metadata_and_nonsecurity_hashes_are_not_reviews_but_credentials_are() {
    let fixture = Fixture::new(
        "metadata",
        &[
            (
                "App.cs",
                "using Microsoft.Extensions.Logging; class App { ILogger logger; void Version(long runId){logger.LogDebug($\"Run {runId}\");} void Expiry(Tokens tokens){logger.LogDebug(\"Token expires {Expiry}\",tokens.AccessTokenExpiresAt);} void Secret(string accessToken){logger.LogDebug(\"Token {Token}\",accessToken);} void Personal(Person person){logger.LogDebug(\"DOB {DOB}\",person.DateOfBirth);} }",
            ),
            (
                "app.php",
                "<?php function cache_key($value){return md5($value);} function reset_token($value){return md5($value);}",
            ),
            (
                "app.js",
                "const http=require('http'); http.createServer(handler).listen(8080);",
            ),
        ],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(
        !inventory.entries.iter().any(|e| matches!(
            e.symbol.as_deref(),
            Some("Version" | "Expiry" | "cache_key")
        )),
        "{:#?}",
        inventory.entries
    );
    for symbol in ["Secret", "Personal", "reset_token"] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some(symbol)),
            "lost {symbol}"
        );
    }
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| e.rule_id.ends_with("http-listener-deployment-review"))
    );
}

#[test]
fn request_setter_is_context_and_actual_typed_dispatch_is_reviewed() {
    let fixture = Fixture::new(
        "dispatch",
        &[(
            "App.cs",
            "using System; using System.Net.Http; class App { HttpClient client; void Unused(string url){var request=new HttpRequestMessage(); request.RequestUri=new Uri(url);} void Send(string url){var request=new HttpRequestMessage(); request.RequestUri=new Uri(url); client.SendAsync(request);} void AliasedSend(string url){var local=client; var request=new HttpRequestMessage(); request.RequestUri=new Uri(url); local.SendAsync(request);} void Hook(string url){var request=new HttpRequestMessage(); request.RequestUri=new Uri(\"https://example.test\"); Prepare(request,url); client.SendAsync(request);} void Prepare(HttpRequestMessage request,string url){request.RequestUri=new Uri(url);} }",
        )],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .any(|e| e.rule_id == "csharp-http-request-uri")
    );
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| e.rule_id == "csharp-http-request-uri")
    );
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| e.rule_id == "csharp-http-request-dispatch"
                && e.symbol.as_deref() == Some("Send")),
        "{:#?}",
        inventory.entries
    );
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| e.rule_id == "csharp-http-request-dispatch"
                && e.symbol.as_deref() == Some("Hook")),
        "request hook must remain reviewable"
    );
    let hook = inventory
        .scan
        .evidence
        .iter()
        .find(|e| {
            e.rule_id == "csharp-http-request-dispatch"
                && e.enclosing_symbol.as_deref() == Some("Hook")
        })
        .unwrap();
    assert!(
        hook.tags
            .iter()
            .any(|tag| tag == "request-authority-after-hook-unresolved")
    );
    assert!(hook.context.literals.is_empty());
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| e.rule_id == "csharp-http-request-dispatch"
                && e.symbol.as_deref() == Some("AliasedSend")),
        "aliased client dispatch must survive"
    );
}

#[test]
fn helper_and_parameter_request_objects_keep_actual_dispatches() {
    let fixture = Fixture::new(
        "request-producers",
        &[(
            "App.cs",
            "using System; using System.Net.Http; class App { HttpClient client; HttpRequestMessage Build(string url){return new HttpRequestMessage(){RequestUri=new Uri(url)};} void FromHelper(string url){client.SendAsync(Build(url));} void FromParameter(HttpRequestMessage request){client.SendAsync(request);} }",
        )],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    for symbol in ["FromHelper", "FromParameter"] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.rule_id == "csharp-http-request-dispatch"
                    && e.symbol.as_deref() == Some(symbol)),
            "lost actual dispatch {symbol}"
        );
        assert!(
            inventory
                .scan
                .evidence
                .iter()
                .any(|e| e.rule_id == "csharp-http-request-dispatch"
                    && e.enclosing_symbol.as_deref() == Some(symbol)
                    && e.captures.contains_key("request"))
        );
    }
}

#[test]
fn preserves_dangerous_effects_without_requiring_a_known_caller() {
    let fixture = Fixture::new(
        "effects",
        &[
            (
                "app.php",
                "<?php function query($db,$value){return mysqli_query($db,\"SELECT * FROM users WHERE name='\".$value.\"'\");} function raw($value){echo $value;}",
            ),
            (
                "app.rs",
                "fn execute(program: &str){std::process::Command::new(program)\n.arg(\"--version\")\n.output().unwrap();} fn separate(program: &str){let mut cmd=std::process::Command::new(program); cmd.output().unwrap();}",
            ),
            (
                "App.cs",
                "using System.IO; class App { void Delete(string path){File.Delete(path);} }",
            ),
            (
                "App.java",
                "import java.net.URI; import java.net.http.HttpClient; import java.net.http.HttpRequest; class App { void unused(String url){HttpRequest.newBuilder(URI.create(url));} void send(HttpClient client,String url)throws Exception {HttpRequest request=HttpRequest.newBuilder(URI.create(url)).build();client.send(request,HttpResponse.BodyHandlers.ofString());} }",
            ),
        ],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    for (path, capability) in [
        ("app.php", Capability::DatabaseQuery),
        ("app.php", Capability::HtmlOutput),
        ("app.rs", Capability::ProcessExecution),
        ("App.cs", Capability::FilesystemWrite),
        ("App.java", Capability::OutboundNetworkRequest),
    ] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.path == path && e.capability == capability),
            "lost dangerous effect {path}: {capability:?}; {:#?}",
            inventory.entries
        );
    }
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| e.rule_id == "java-jdk-http-request-builder")
    );
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| e.path == "app.rs" && e.symbol.as_deref() == Some("separate"))
    );
}

#[test]
fn jackson_policy_in_a_separate_dto_keeps_the_loader_review() {
    let fixture = Fixture::new(
        "jackson-policy",
        &[
            (
                "App.java",
                "import com.fasterxml.jackson.databind.ObjectMapper; class App { Object parse(ObjectMapper mapper,String input) throws Exception { return mapper.readValue(input, Object.class); } }",
            ),
            (
                "Dto.java",
                "import com.fasterxml.jackson.annotation.JsonTypeInfo; @JsonTypeInfo(use=JsonTypeInfo.Id.CLASS) class Dto {}",
            ),
        ],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .any(|e| e.rule_id == "java-jackson-class-name-polymorphism")
    );
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| e.rule_id == "java-jackson-object-deserialization")
    );
}

#[test]
fn default_yaml_v4_is_context_but_custom_or_old_loader_policy_stays_reviewable() {
    for (label, version, call, retained) in [
        ("default", "^4.1.0", "yaml.load(input)", false),
        (
            "custom",
            "^4.1.0",
            "yaml.load(input,{schema: customSchema})",
            true,
        ),
        ("old", "^3.14.0", "yaml.load(input)", true),
    ] {
        let source =
            format!("const yaml=require('js-yaml'); function parse(input){{return {call};}}");
        let package = format!("{{\"dependencies\":{{\"js-yaml\":\"{version}\"}}}}");
        let fixture = Fixture::new(
            &format!("yaml-{label}"),
            &[("app.js", &source), ("package.json", &package)],
        );
        let inventory = build_review_inventory(&fixture.0, false).unwrap();
        assert!(
            inventory
                .scan
                .evidence
                .iter()
                .any(|e| e.rule_id == "javascript-yaml-deserialization")
        );
        assert_eq!(
            inventory
                .entries
                .iter()
                .any(|e| e.rule_id == "javascript-yaml-deserialization"),
            retained,
            "{label}"
        );
    }
}

#[test]
fn connected_credentialed_cors_keeps_its_relationship() {
    let fixture = Fixture::new(
        "cors",
        &[(
            "app.js",
            "const cors=require('cors'); app.use(cors({origin:true,credentials:true}));",
        )],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| e.cwe_candidates == ["CWE-942"]),
        "credentialed origin relationships must survive: {:#?}",
        inventory.entries
    );
}

#[test]
fn kotlin_mapper_policy_vetoes_the_ordinary_decoder_cut() {
    let fixture = Fixture::new(
        "kotlin-policy",
        &[
            (
                "app.kt",
                "import com.fasterxml.jackson.databind.ObjectMapper\nfun parse(mapper: ObjectMapper, input: String): Any = mapper.readValue(input, Any::class.java)",
            ),
            (
                "policy.kt",
                "import com.fasterxml.jackson.databind.ObjectMapper\nfun configure(mapper: ObjectMapper) { mapper.enableDefaultTyping() }",
            ),
        ],
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| e.rule_id == "kotlin-jackson-deserialization"),
        "{:#?}",
        inventory.entries
    );
}
