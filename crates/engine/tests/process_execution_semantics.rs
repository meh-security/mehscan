use std::collections::BTreeSet;

use mehscan_core::Capability;

#[test]
fn preserves_shell_payloads_and_instance_launches_without_builder_false_positives() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-process-execution-semantics-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    for (path, source) in [
        (
            "app.js",
            r#"const cp = require('node:child_process');
const { exec } = require('node:child_process');
const { promisify } = require('node:util');
const execAsync = promisify(exec);
function run(user, args) {
  cp.spawn('tool', args, { shell: true });
  cp.execFile('tool', args, { shell: true });
  cp.spawn(user, args);
  execAsync(user);
}"#,
        ),
        (
            "app.go",
            r#"package app
import "os/exec"
func run(user string, args []string) {
  exec.Command("sh", "-c", user)
  exec.Command("tool", args...)
  exec.Command(user, "--version")
}"#,
        ),
        (
            "app.rs",
            r#"use std::process::Command;
fn run(user: &str, args: Vec<String>) {
  Command::new("sh").arg("-c").arg(user).spawn();
  Command::new("tool").args(args).spawn();
  Command::new(user).arg("--version").spawn();
}"#,
        ),
        (
            "App.java",
            r#"import java.io.File;
class App { void run(String command, String[] env, File dir, java.util.List<String> argv) throws Exception {
  Runtime.getRuntime().exec(command, env);
  Runtime.getRuntime().exec(command, env, dir);
  new ProcessBuilder(argv).start();
  ProcessBuilder pb = new ProcessBuilder(); pb.command(argv); pb.start();
} }"#,
        ),
        (
            "App.kt",
            r#"import java.io.File
fun run(command: String, env: Array<String>, dir: File) {
  Runtime.getRuntime().exec(command, env)
  Runtime.getRuntime().exec(command, env, dir)
}"#,
        ),
        (
            "App.cs",
            r#"using System.Diagnostics;
class App { void Run(string command, string argument) {
  var psi = new ProcessStartInfo("cmd.exe");
  psi.ArgumentList.Add("/c"); psi.ArgumentList.Add(argument);
  var process = new Process { StartInfo = psi }; process.Start();
  Process second = new(); second.StartInfo = new ProcessStartInfo(command); second.Start();
} }"#,
        ),
    ] {
        std::fs::write(root.join(path), source).unwrap();
    }

    let result = mehscan_engine::scan_path(&root).expect("process fixture should scan");
    let process = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::ProcessExecution)
        .collect::<Vec<_>>();
    assert_eq!(
        process
            .iter()
            .filter(|item| item.location.path == "App.java")
            .count(),
        4,
        "Runtime overloads and both ProcessBuilder shapes should remain visible"
    );
    assert_eq!(
        process
            .iter()
            .filter(|item| item.location.path == "App.kt")
            .count(),
        2
    );
    assert_eq!(
        process
            .iter()
            .filter(|item| item.location.path == "App.cs")
            .count(),
        2,
        "instance Process.Start should resolve its exact local StartInfo"
    );
    for path in ["app.js", "app.go", "app.rs", "App.cs"] {
        assert!(
            process.iter().any(|item| {
                item.location.path == path
                    && item.captures.get("shell_command").is_some_and(|capture| {
                        matches!(capture.text.as_str(), "args" | "user" | "argument")
                    })
                    && item.tags.iter().any(|tag| tag == "shell-command-text")
                    && item
                        .tags
                        .iter()
                        .any(|tag| tag == "review-origin:decision-critical")
            }),
            "missing exact shell payload for {path}: {process:#?}"
        );
    }
    assert!(process.iter().all(|item| {
        !(item.location.path == "app.rs"
            && item
                .captures
                .get("executable")
                .is_some_and(|capture| capture.text == "\"tool\"")
            && item
                .tags
                .iter()
                .any(|tag| tag == "review-origin:decision-critical"))
    }));
    assert!(process.iter().any(|item| {
        item.location.path == "app.js"
            && item
                .captures
                .get("command")
                .is_some_and(|capture| capture.text == "user")
            && item
                .symbol_resolution
                .as_ref()
                .is_some_and(|symbol| symbol.canonical == "child_process.exec")
            && item
                .tags
                .iter()
                .any(|tag| tag == "review-origin:decision-critical")
    }));
    assert_eq!(
        process
            .iter()
            .filter(|item| {
                item.location.path == "app.rs"
                    && item
                        .captures
                        .get("executable")
                        .is_some_and(|capture| capture.text == "user")
                    && item
                        .tags
                        .iter()
                        .any(|tag| tag == "review-origin:decision-critical")
            })
            .count(),
        1,
        "a Rust builder chain should ask once about executable selection"
    );

    let job = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(5), false)
        .expect("process reviews should build");
    let relationships = job
        .observation_reviews
        .iter()
        .filter_map(|review| review.review_basis.as_ref())
        .map(|basis| basis.relationship.as_str())
        .collect::<BTreeSet<_>>();
    assert!(relationships.contains("bounded_shell_command_interpretation"));
    assert!(relationships.contains("bounded_dynamic_executable_selection"));

    std::fs::remove_dir_all(root).unwrap();
}
