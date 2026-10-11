use mehscan_core::{Capability, EvidenceKind, SecurityPathState};
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str, files: &[(&str, &str)]) -> Self {
        let root = std::env::temp_dir().join(format!(
            "mehscan-process-cleanup-{name}-{}",
            std::process::id()
        ));
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
fn builders_anchor_to_launches_and_unused_or_unowned_producers_leave_evidence() {
    let f = Fixture::new(
        "consumers",
        &[
            (
                "app.go",
                r#"package app
import "os/exec"
func dead(input string) { exec.Command(input); unused := exec.Command(input) }
func actual(input string) { cmd := exec.Command(input, "--version"); cmd.Run(); cmd.Output() }
func factory(input string) *exec.Cmd { return exec.Command(input) }
func helper(input string) { register(exec.Command(input)) }
func assigned_helper(input string) { unused := register(exec.Command(input)) }
"#,
            ),
            (
                "App.java",
                r#"class App {
void dead(String input) { new ProcessBuilder(input); ProcessBuilder unused = new ProcessBuilder(input); }
void actual(String input) throws Exception { ProcessBuilder pb = new ProcessBuilder("tool"); pb.command(input, "--version"); pb.start(); }
ProcessBuilder factory(String input) { return new ProcessBuilder(input); }
void helper(String input) { register(new ProcessBuilder(input)); }
void assigned_helper(String input) { Object unused = register(new ProcessBuilder(input)); }
}"#,
            ),
            (
                "app.rs",
                r#"use std::process::Command;
fn dead(input: &str) { Command::new(input); let unused = Command::new(input); let mut configured = Command::new(input); configured.arg("-v"); }
fn actual(input: &str) { let mut cmd = Command::new(input); cmd.arg("-v"); cmd.spawn(); cmd.output(); }
fn factory(input: &str) -> Command { let mut cmd = Command::new("sh"); cmd.arg("-c"); cmd.arg(input); cmd }
fn helper(input: &str) { register(Command::new(input)); }
fn assigned_helper(input: &str) { let unused = register(Command::new(input)); }
fn unrelated(other: Other, input: &str) { other.arg(input); other.args(input); }
fn typed(cmd: &mut Command, input: &str) { cmd.arg(input); }
fn shadow(cmd: &mut Command, input: &str) { let cmd = Other::new(); cmd.arg(input); }
fn selected(input: &str) { register(Command::new(input).arg("-v")); }
fn earlier(input: &str) { register(Command::new("sh").arg("-c").arg(input).arg("--quiet")); }
"#,
            ),
        ],
    );
    let scan = mehscan_engine::scan_path(&f.0).unwrap();
    let sinks = scan
        .evidence
        .iter()
        .filter(|e| e.capability == Capability::ProcessExecution && e.kind == EvidenceKind::Sink)
        .collect::<Vec<_>>();
    assert!(
        !sinks
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("dead")
                || e.enclosing_symbol.as_deref() == Some("unrelated"))
    );
    assert!(
        !sinks
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("shadow"))
    );
    for name in ["selected", "earlier"] {
        let group = sinks
            .iter()
            .filter(|e| e.location.path == "app.rs" && e.enclosing_symbol.as_deref() == Some(name))
            .collect::<Vec<_>>();
        assert_eq!(group.len(), 1, "{name}");
        assert!(
            group[0]
                .tags
                .iter()
                .any(|t| t == "review-origin:decision-critical"),
            "lost strong {name}"
        );
    }
    for (path, launches) in [("app.go", 2), ("App.java", 1), ("app.rs", 2)] {
        let actual = sinks
            .iter()
            .filter(|e| e.location.path == path && e.enclosing_symbol.as_deref() == Some("actual"))
            .collect::<Vec<_>>();
        assert_eq!(
            actual.len(),
            launches,
            "{path}: {:?}",
            actual
                .iter()
                .map(|e| (&e.captures, &e.tags))
                .collect::<Vec<_>>()
        );
        assert!(actual.iter().all(|e| {
            e.tags
                .iter()
                .any(|t| t == "process-invocation:actual-launch")
                && e.captures["command"].text == "input"
                && e.captures.contains_key("arguments")
        }));
        for name in ["factory", "helper", "assigned_helper"] {
            assert!(
                sinks.iter().any(|e| e.location.path == path
                    && e.enclosing_symbol.as_deref() == Some(name)
                    && e.tags
                        .iter()
                        .any(|t| t == "process-invocation:unresolved-execution")),
                "missing {path}/{name}"
            );
        }
    }
    assert!(
        sinks
            .iter()
            .any(|e| e.location.path == "app.rs" && e.enclosing_symbol.as_deref() == Some("typed"))
    );
    assert_eq!(
        sinks
            .iter()
            .filter(
                |e| e.location.path == "app.rs" && e.enclosing_symbol.as_deref() == Some("factory")
            )
            .count(),
        1
    );
    assert!(sinks.iter().any(|e| {
        e.location.path == "app.rs"
            && e.enclosing_symbol.as_deref() == Some("factory")
            && e.captures
                .get("shell_command")
                .is_some_and(|c| c.text.contains("input"))
    }));
    assert!(scan.evidence.iter().any(|e| {
        e.kind == EvidenceKind::Resource
            && e.tags
                .iter()
                .any(|t| t == "process-context:consumed-builder")
    }));
    assert!(
        scan.security_paths
            .iter()
            .all(|p| sinks.iter().any(|e| e.id == p.sink_evidence_id))
    );
}

#[test]
fn fixed_executables_do_not_hide_dynamic_arguments_or_unresolved_options() {
    let f = Fixture::new(
        "arguments",
        &[
            (
                "app.js",
                "const cp = require('node:child_process'); function dynamic(input, options) { cp.spawn('tool', ['--output', input]); cp.spawn('tool', [], options); } function fixed() { cp.spawn('tool', ['--version']); }",
            ),
            (
                "App.cs",
                "using System.Diagnostics; class App { void dynamic(string input) { Process.Start(\"tool\", input); } void fixed() { Process.Start(\"tool\", \"--version\"); } }",
            ),
            (
                "app.py",
                "import subprocess\ndef dynamic(input, options):\n    subprocess.run(['tool', input])\n    subprocess.run('tool', **options)\ndef fixed():\n    subprocess.run(['tool', '--version'])\n",
            ),
            (
                "app.rs",
                "use std::process::Command; fn dynamic(input: &str) { Command::new(\"tool\").env(\"KEY\", input).spawn(); } fn fixed() { Command::new(\"tool\").env(\"KEY\", \"value\").current_dir(\"work\").spawn(); }",
            ),
        ],
    );
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&f.0, Some(5), false).unwrap();
    for path in ["app.js", "App.cs", "app.py", "app.rs"] {
        assert!(
            jobs.observation_reviews.iter().any(|r| r
                .evidence
                .iter()
                .any(|e| r.anchor_evidence_ids.contains(&e.id) && e.location.path == path)),
            "missing dynamic argv review for {path}"
        );
        assert!(
            !jobs
                .observation_reviews
                .iter()
                .any(|r| r
                    .evidence
                    .iter()
                    .any(|e| r.anchor_evidence_ids.contains(&e.id)
                        && e.location.path == path
                        && e.enclosing_symbol.as_deref() == Some("fixed"))),
            "fixed invocation still owns a review: {path}"
        );
    }
}

#[test]
fn separated_arguments_are_not_protection_for_explicit_shell_or_shell_options() {
    let f = Fixture::new(
        "shell",
        &[
            (
                "app.go",
                "package app\nimport \"os/exec\"\nfunc run(r *Request) { exec.Command(\"sh\", \"-c\", r.FormValue(\"cmd\")).Run() }\nfunc selected(r *Request) { exec.Command(r.FormValue(\"program\"), \"--version\").Run() }",
            ),
            (
                "App.java",
                "class App { void run(HttpServletRequest request) throws Exception { new ProcessBuilder(\"sh\", \"-c\", request.getParameter(\"cmd\")).start(); } void selected(HttpServletRequest request) throws Exception { new ProcessBuilder(request.getParameter(\"program\"), \"--version\").start(); } }",
            ),
            (
                "app.js",
                "const cp = require('node:child_process'); function run(req, res) { cp.spawn('tool', [req.query.cmd], {shell: true}); } function selected(req, res) { cp.spawn(req.query.program, ['--version']); }",
            ),
            (
                "app.py",
                "import subprocess\ndef run(request):\n    subprocess.run(['tool', request.args.get('cmd')], shell=True)\ndef selected(request):\n    subprocess.run(['tool'], executable=request.args.get('program'), shell=False)\n",
            ),
        ],
    );
    let scan = mehscan_engine::scan_path(&f.0).unwrap();
    let paths = scan
        .security_paths
        .iter()
        .filter(|p| p.capability == Capability::ProcessExecution)
        .collect::<Vec<_>>();
    for path in ["app.go", "App.java", "app.js", "app.py"] {
        assert!(
            paths
                .iter()
                .any(|p| p.steps.iter().any(|s| s.location.path == path)),
            "missing shell path {path}"
        );
    }
    for path in ["app.go", "App.java", "app.js", "app.py"] {
        assert!(
            paths
                .iter()
                .any(|p| scan.evidence.iter().any(|e| e.id == p.sink_evidence_id
                    && e.location.path == path
                    && e.enclosing_symbol.as_deref() == Some("selected"))),
            "missing executable-selection path {path}"
        );
    }
    assert!(
        paths.iter().all(
            |p| p.state != SecurityPathState::Protected && p.protection_evidence_ids.is_empty()
        )
    );
}

#[test]
fn builder_mutations_and_escapes_never_transfer_a_fixed_launch_closure() {
    let f = Fixture::new(
        "mutation",
        &[
            (
                "app.go",
                "package app\nimport \"os/exec\"\nfunc run(input string) { cmd := exec.Command(\"tool\"); cmd.Path = input; cmd.Run() }",
            ),
            (
                "App.java",
                "class App { void run(String input, boolean condition) throws Exception { ProcessBuilder pb = new ProcessBuilder(\"tool\"); if (condition) pb.command(input); change(pb); pb.start(); } }",
            ),
            (
                "app.rs",
                "use std::process::Command; fn run(input: &str) { let mut cmd = Command::new(\"tool\"); change(&mut cmd); cmd.env(\"PLUGIN\", input); cmd.spawn(); }",
            ),
        ],
    );
    let scan = mehscan_engine::scan_path(&f.0).unwrap();
    for path in ["app.go", "App.java", "app.rs"] {
        assert!(
            scan.evidence.iter().any(|e| e.location.path == path
                && e.kind == EvidenceKind::Sink
                && e.tags
                    .iter()
                    .any(|t| t == "process-invocation:unresolved-builder-state")),
            "lost mutable launch {path}"
        );
    }
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&f.0, Some(5), false).unwrap();
    for path in ["app.go", "App.java", "app.rs"] {
        assert!(
            jobs.observation_reviews.iter().any(|r| r
                .evidence
                .iter()
                .any(|e| r.anchor_evidence_ids.contains(&e.id) && e.location.path == path)),
            "missing unresolved launch {path}"
        );
    }
}

#[test]
fn php_direct_exec_keeps_argv_and_does_not_claim_shell_parsing() {
    let f = Fixture::new(
        "php",
        &[(
            "app.php",
            r#"<?php
use function pcntl_exec as replace;
function direct($input) { replace('/usr/bin/tool', [$input], []); }
function vector($input) { proc_open(['tool', $input], [], $pipes); }
function shell($input) { exec('tool ' . $input); }
function opaque($input) { proc_open($input, [], $pipes); }
function optioned($input) { proc_open('tool ' . $input, [], $pipes, null, null, ['bypass_shell' => true]); }
"#,
        )],
    );
    let scan = mehscan_engine::scan_path(&f.0).unwrap();
    for name in ["direct", "vector"] {
        let e = scan
            .evidence
            .iter()
            .find(|e| {
                e.rule_id == "php-command-execution" && e.enclosing_symbol.as_deref() == Some(name)
            })
            .unwrap();
        assert!(e.captures["arguments"].text.contains("$input"));
        assert!(!e.tags.iter().any(|t| t == "shell-command-text"), "{name}");
    }
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&f.0, Some(5), false).unwrap();
    let optioned = scan
        .evidence
        .iter()
        .find(|e| {
            e.rule_id == "php-command-execution"
                && e.enclosing_symbol.as_deref() == Some("optioned")
        })
        .unwrap();
    assert!(
        optioned
            .tags
            .iter()
            .any(|t| t == "process-invocation:unresolved-shell")
    );
    assert!(!optioned.tags.iter().any(|t| t == "shell-command-text"));
    for name in ["direct", "vector", "shell", "opaque", "optioned"] {
        assert!(
            jobs.observation_reviews.iter().any(|r| r
                .evidence
                .iter()
                .any(|e| r.anchor_evidence_ids.contains(&e.id)
                    && e.enclosing_symbol.as_deref() == Some(name))),
            "missing PHP {name}"
        );
    }
}

#[test]
fn actual_invocations_keep_argument_operands_in_every_profile() {
    let f = Fixture::new(
        "languages",
        &[
            (
                "app.ts",
                "import * as cp from 'node:child_process'; function run(input: string) { cp.spawn('tool', [input]); }",
            ),
            (
                "app.tsx",
                "import * as cp from 'node:child_process'; function run(input: string) { cp.execFile('tool', [input]); }",
            ),
            (
                "App.kt",
                "fun run(input: String) { ProcessBuilder(\"tool\", input).start() }",
            ),
            (
                "app.c",
                "#include <unistd.h>\nvoid run(char *input) { execl(\"/usr/bin/tool\", \"tool\", \"--output\", input, (char*)0); }",
            ),
            (
                "app.cpp",
                "#include <unistd.h>\nvoid run(char *input) { execl(\"/usr/bin/tool\", \"tool\", \"--output\", input, (char*)0); }",
            ),
        ],
    );
    let scan = mehscan_engine::scan_path(&f.0).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    for path in ["app.ts", "app.tsx", "App.kt", "app.c", "app.cpp"] {
        assert!(
            scan.evidence.iter().any(|e| e.kind == EvidenceKind::Sink
                && e.capability == Capability::ProcessExecution
                && e.location.path == path
                && e.captures.values().any(|c| c.text.contains("input"))),
            "lost argv in {path}"
        );
    }
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&f.0, Some(5), false).unwrap();
    for path in ["app.ts", "app.tsx", "App.kt", "app.c", "app.cpp"] {
        assert!(
            jobs.observation_reviews.iter().any(|r| r
                .evidence
                .iter()
                .any(|e| r.anchor_evidence_ids.contains(&e.id) && e.location.path == path)),
            "missing actual invocation {path}"
        );
    }
}
