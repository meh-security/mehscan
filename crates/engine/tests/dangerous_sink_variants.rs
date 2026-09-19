use mehscan_core::Capability;

#[test]
fn dangerous_api_siblings_and_local_mutations_preserve_review_operands() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-dangerous-sink-variants-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();

    for path in ["native.c", "native.cpp"] {
        std::fs::write(
            root.join(path),
            r#"void run(void *db, void *token, wchar_t *wide, char *program, char *command, char **argv, char **env, char *sql) {
    _wsystem(wide); _popen(command, "r"); execlpe(program, program, command, env);
    CreateProcessAsUserW(token, wide, wide, 0, 0, 0, 0, 0, 0, 0, 0);
    CreateProcessWithTokenW(token, 0, wide, wide, 0, 0, 0, 0, 0);
    CreateProcessWithLogonW(wide, wide, wide, 0, wide, wide, 0, 0, 0, 0, 0);
    PQsendQuery(db, sql); PQsendQueryParams(db, sql, 0, 0, 0, 0, 0, 0);
    sqlite3_prepare16_v2(db, sql, -1, 0, 0); mysql_send_query(db, sql, 1);
}"#,
        )
        .unwrap();
    }
    std::fs::write(
        root.join("Probe.cs"),
        r#"using System; using System.Net.Http;
class Probe { void Run(string url) {
    var first = new HttpRequestMessage { RequestUri = new Uri(url) };
    HttpRequestMessage second = new(); second.RequestUri = new UriBuilder(url).Uri;
} }"#,
    )
    .unwrap();
    std::fs::write(
        root.join("Probe.java"),
        r#"import java.net.URI; import java.net.http.HttpRequest;
class Probe { void run(String program, String url) {
    ProcessBuilder process = new ProcessBuilder(); process.command(program);
    HttpRequest.Builder request = HttpRequest.newBuilder(); request.uri(URI.create(url));
    HttpRequest.newBuilder().uri(URI.create(url));
} }"#,
    )
    .unwrap();
    for path in ["app.js", "app.ts", "app.tsx"] {
        std::fs::write(
            root.join(path),
            "function run(modulePath, url) { child_process.fork(modulePath); child_process.execFileSync(modulePath); axios({ url: url }); axios.request({ url: url, timeout: 10 }); axios.patch(url); }",
        )
        .unwrap();
    }
    std::fs::write(
        root.join("app.py"),
        r#"import os, subprocess, asyncio, requests, httpx
from lxml import etree
def run(command, program, argv, expression, payload):
    subprocess.getoutput(command)
    subprocess.getstatusoutput(command)
    asyncio.create_subprocess_shell(command)
    asyncio.create_subprocess_exec(program, '--version')
    asyncio.create_subprocess_exec(program)
    os.execvp(program, argv)
    os.posix_spawnp(program, argv, os.environ)
    os.spawnvp(os.P_WAIT, program, argv)
    requests.delete(command)
    httpx.patch(command)
    tree = etree.fromstring(payload)
    tree.xpath(expression)
    etree.XPath(expression)
    etree.ETXPath(expression)
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("app.php"),
        r#"<?php
class Probe {
    private $xpath;
    function __construct($document) { $this->xpath = new DOMXPath($document); }
    function run($expression, $command) { $this->xpath->query($expression); `$command`; proc_open($command, [], $pipes); pcntl_exec($command); }
}
function local($document, $expression) { $xpath = new DOMXPath($document); $xpath->evaluate($expression); }
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("app.go"),
        r#"package app
import ("html/template"; "net/http"; "os"; "syscall")
func run(program string, argv []string, content string) {
    os.StartProcess(program, argv, nil); syscall.Exec(program, argv, os.Environ())
    http.Head(program)
    _ = template.HTMLAttr(content); _ = template.JS(content); _ = template.JSStr(content)
    _ = template.URL(content); _ = template.CSS(content)
}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("app.rs"),
        r#"use tokio::process::Command as TokioCommand;
fn run(command: &str, url: &str) { TokioCommand::new(command); tokio::process::Command::new(command); let client = reqwest::Client::new(); client.put(url); }"#,
    )
    .unwrap();

    let result = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);

    for path in ["native.c", "native.cpp"] {
        assert_eq!(
            result
                .evidence
                .iter()
                .filter(|item| item.location.path == path
                    && item.capability == Capability::ProcessExecution)
                .count(),
            6,
            "{path}: native process family"
        );
        assert_eq!(
            result
                .evidence
                .iter()
                .filter(|item| item.location.path == path
                    && item.capability == Capability::DatabaseQuery)
                .count(),
            4,
            "{path}: native database family"
        );
    }
    assert_eq!(count_rule(&result, "csharp-http-request-uri"), 2);
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.location.path == "Probe.java"
                && item
                    .tags
                    .iter()
                    .any(|tag| tag == "process-builder-command-mutation"))
            .count(),
        1
    );
    assert_eq!(count_rule(&result, "java-jdk-http-request-builder"), 2);
    for path in ["app.js", "app.ts", "app.tsx"] {
        assert_eq!(
            result
                .evidence
                .iter()
                .filter(|item| item.location.path == path
                    && item.capability == Capability::ProcessExecution)
                .count(),
            2,
            "{path}"
        );
        assert_eq!(
            result
                .evidence
                .iter()
                .filter(|item| item.location.path == path
                    && item.capability == Capability::OutboundNetworkRequest)
                .count(),
            3,
            "{path}"
        );
    }
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.location.path == "app.py"
                && item.capability == Capability::ProcessExecution)
            .count(),
        8
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.location.path == "app.py"
                && item.capability == Capability::OutboundNetworkRequest)
            .count(),
        2
    );
    assert_eq!(count_rule(&result, "python-lxml-xpath-query"), 3);
    assert_eq!(count_rule(&result, "php-extended-xpath-query"), 2);
    assert_eq!(count_rule(&result, "php-shell-command-operator"), 1);
    assert_eq!(count_rule(&result, "php-command-execution"), 2);
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.location.path == "app.go"
                && item.capability == Capability::ProcessExecution)
            .count(),
        2
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(
                |item| item.location.path == "app.go" && item.capability == Capability::HtmlOutput
            )
            .count(),
        5
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.location.path == "app.go"
                && item.capability == Capability::OutboundNetworkRequest)
            .count(),
        1
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.location.path == "app.rs"
                && item.capability == Capability::ProcessExecution)
            .count(),
        2
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.location.path == "app.rs"
                && item.capability == Capability::OutboundNetworkRequest)
            .count(),
        1
    );
    assert!(
        result
            .evidence
            .iter()
            .filter(|item| {
                matches!(
                    item.capability,
                    Capability::DatabaseQuery | Capability::XpathQuery
                ) && item.captures.values().any(|capture| {
                    matches!(capture.text.as_str(), "sql" | "expression" | "$expression")
                })
            })
            .all(|item| item
                .tags
                .iter()
                .any(|tag| tag == "review-origin:decision-critical"))
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn generic_mutation_names_require_framework_receiver_identity() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-dangerous-sink-lookalikes-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("Probe.cs"),
        "class HttpRequestMessage { public object RequestUri; } class Probe { void Run(object value) { var request = new HttpRequestMessage(); request.RequestUri = value; } }",
    )
    .unwrap();
    std::fs::write(
        root.join("Probe.java"),
        "class ProcessBuilder { ProcessBuilder command(String value) { return this; } } class Probe { void run(ProcessBuilder fake, String value) { fake.command(value); } }",
    )
    .unwrap();
    std::fs::write(
        root.join("app.py"),
        "def run(tree, expression):\n    tree.xpath(expression)\n",
    )
    .unwrap();
    std::fs::write(
        root.join("app.php"),
        "<?php class DOMXPath { function query($value) {} } function run($value) { $xpath = new DOMXPath(); $xpath->query($value); }",
    )
    .unwrap();

    let result = mehscan_engine::scan_path(&root).unwrap();
    for rule in [
        "csharp-http-request-uri",
        "java-process-execution",
        "python-lxml-xpath-query",
        "php-extended-xpath-query",
    ] {
        assert_eq!(count_rule(&result, rule), 0, "{rule}");
    }
    std::fs::remove_dir_all(root).unwrap();
}

fn count_rule(result: &mehscan_core::ScanResult, rule: &str) -> usize {
    result
        .evidence
        .iter()
        .filter(|item| item.rule_id == rule)
        .count()
}
