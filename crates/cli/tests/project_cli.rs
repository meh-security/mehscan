use std::fs::{self, File};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::TempDir;

struct Fixture {
    root: TempDir,
    state: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        Self { root, state }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mehscan"));
        command
            .env("MEHSCAN_STATE_HOME", &self.state)
            .env("PATH", self.root.path());
        command
    }

    fn source(&self, name: &str, text: &str) -> PathBuf {
        let path = self.root.path().join(name);
        fs::create_dir(&path).unwrap();
        fs::write(path.join("app.js"), text).unwrap();
        path
    }

    fn config(&self, path: &Path, data: Value) {
        fs::write(path, data.to_string()).unwrap();
    }

    fn prepare_command(
        &self,
        source: &Path,
        config: &Path,
        output: &Path,
        extra: &[&str],
    ) -> Command {
        let mut command = self.command();
        command
            .args(["project", "prepare"])
            .arg(source)
            .arg("--config")
            .arg(config)
            .arg("--output")
            .arg(output)
            .args(extra);
        command
    }

    fn prepare(&self, source: &Path, config: &Path, output: &Path, extra: &[&str]) -> Output {
        self.prepare_command(source, config, output, extra)
            .output()
            .unwrap()
    }
}

fn ok(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn rejected(output: Output, message: &str) {
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(message), "{stderr}");
}

fn prepare_before(mut command: Command, timeout: Duration) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + timeout;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("project prepare did not finish within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn linked_source_folders_keep_project_memory_and_compare_an_explicit_baseline() {
    let fixture = Fixture::new();
    let config = fixture.root.path().join("payments.json");
    fixture.config(
        &config,
        json!({"repository_key": "onprem:payments", "stream": "main"}),
    );
    let source = fixture.source("managed", "export const version = 'one';\n");
    fs::write(source.join("removed.js"), "export const oldItem = true;\n").unwrap();
    let output = fixture.root.path().join("first");
    let original = ok(fixture.prepare(&source, &config, &output, &["--artifact", "first-export"]));
    let saved: Value =
        serde_json::from_slice(&fs::read(output.join("project.json")).unwrap()).unwrap();
    assert_eq!(original, saved);
    assert_eq!(original["repository_key"], "onprem:payments");
    assert_eq!(original["stream"], "main");
    assert_eq!(original["artifact"], "first-export");
    assert_eq!(original["memory"]["status"], "captured");
    assert!(Path::new(original["memory_store"].as_str().unwrap()).is_file());
    let claimed = ok(fixture
        .command()
        .args(["state", "claim"])
        .args([
            "--store",
            original["state_store"].as_str().unwrap(),
            "--stream",
            "main",
        ])
        .arg("--inventory")
        .arg(&output)
        .arg("--source-root")
        .arg(&source)
        .args([
            "--attempt-id",
            "first",
            "--expected-generation",
            "0",
            "--operation-key",
            "claim",
        ])
        .output()
        .unwrap());
    assert_eq!(claimed["result"]["generation"], 1);

    let manual = fixture.source("manual", "export const version = 'one';\n");
    fs::copy(source.join("removed.js"), manual.join("removed.js")).unwrap();
    let unchanged = ok(fixture.prepare(&manual, &config, &fixture.root.path().join("repeat"), &[]));
    for key in [
        "inventory_fingerprint",
        "snapshot",
        "state_store",
        "memory_store",
    ] {
        assert_eq!(original[key], unchanged[key]);
    }
    assert_eq!(unchanged["memory"]["capture"]["reused"], true);

    fs::write(manual.join("app.js"), "export const version = 'two';\n").unwrap();
    fs::remove_file(manual.join("removed.js")).unwrap();
    fs::write(manual.join("added.js"), "export const newItem = true;\n").unwrap();
    let baseline = original["snapshot"].as_str().unwrap();
    let branch = ok(fixture.prepare(
        &manual,
        &config,
        &fixture.root.path().join("branch"),
        &["--stream", "release:2.x", "--base", baseline],
    ));
    assert_eq!(branch["stream"], "release:2.x");
    assert_eq!(branch["memory_store"], original["memory_store"]);
    assert_ne!(branch["snapshot"], original["snapshot"]);
    assert_eq!(
        branch["memory"]["capture"]["changes"],
        json!({"added":["added.js"],"modified":["app.js"],"removed":["removed.js"]})
    );

    rejected(
        fixture.prepare(&manual, &config, &output, &[]),
        "new directory",
    );
    let bad_baseline = fixture.root.path().join("unknown-baseline");
    rejected(
        fixture.prepare(&manual, &config, &bad_baseline, &["--base", "unknown"]),
        "base snapshot does not exist",
    );
    assert!(!bad_baseline.exists());

    let foreign_config = fixture.root.path().join("foreign.json");
    fixture.config(&foreign_config, json!({"repository_key": "onprem:foreign"}));
    let foreign_output = fixture.root.path().join("foreign");
    rejected(
        fixture.prepare(
            &manual,
            &foreign_config,
            &foreign_output,
            &["--base", baseline],
        ),
        "base snapshot does not exist",
    );
    assert!(!foreign_output.exists());
}

#[test]
fn project_preparation_handles_temporary_memory_and_unavailable_upstream() {
    let fixture = Fixture::new();
    let source = fixture.source("source", "export const value = 1;\n");
    let config = fixture.root.path().join("project.json");
    fixture.config(
        &config,
        json!({"repository_key": "onprem:fixture", "remote": "http://127.0.0.1:0"}),
    );
    let output = fixture.root.path().join("prepared");
    let prepared = ok(fixture.prepare(
        &source,
        &config,
        &output,
        &["--memory-mode", "temporary", "--pull", "true"],
    ));
    assert_eq!(prepared["stream"], "imported");
    assert_eq!(prepared["memory"]["status"], "skipped");
    assert_eq!(prepared["upstream"]["sync"]["status"], "unavailable");
    assert!(!Path::new(prepared["memory_store"].as_str().unwrap()).exists());
    assert!(output.join("inventory.json").is_file());

    fs::create_dir_all(prepared["memory_store"].as_str().unwrap()).unwrap();
    let local = fixture.root.path().join("local-only");
    let unavailable = ok(fixture.prepare(&source, &config, &local, &[]));
    assert_eq!(unavailable["memory"]["status"], "unavailable");
    assert_eq!(unavailable["upstream"]["sync"]["status"], "configured");
    assert!(local.join("inventory.json").is_file());

    let replica = Path::new(prepared["upstream"]["replica"].as_str().unwrap());
    let lock = File::options()
        .read(true)
        .write(true)
        .open(replica.with_file_name("context.turso.lock"))
        .unwrap();
    fs2::FileExt::lock_exclusive(&lock).unwrap();
    let busy_output = fixture.root.path().join("busy");
    let busy = ok(prepare_before(
        fixture.prepare_command(&source, &config, &busy_output, &["--pull", "true"]),
        Duration::from_secs(10),
    ));
    assert_eq!(busy["upstream"]["sync"]["status"], "unavailable");
    assert_eq!(
        busy["upstream"]["sync"]["reason"],
        "project context replica is busy"
    );
    assert!(busy_output.join("project.json").is_file());

    let inside = source.join("project.json");
    fs::copy(&config, &inside).unwrap();
    let fresh = fixture.root.path().join("new");
    rejected(
        fixture.prepare(&source, &inside, &fresh, &[]),
        "config must be outside",
    );
    rejected(
        fixture.prepare(&source, &config, &source.join("nested"), &[]),
        "output must be outside",
    );
    assert!(!fresh.exists());
    assert!(!source.join("nested").exists());
}

#[test]
fn project_preparation_finishes_when_the_upstream_stops_responding() {
    let fixture = Fixture::new();
    let source = fixture.source("source", "export const value = 1;\n");
    let config = fixture.root.path().join("project.json");
    // Keep the port open without replying to any request.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = format!("http://{}", listener.local_addr().unwrap());
    fixture.config(
        &config,
        json!({"repository_key":"onprem:timeout","remote":remote}),
    );
    let output = fixture.root.path().join("prepared");
    let prepared = ok(prepare_before(
        fixture.prepare_command(&source, &config, &output, &["--pull", "true"]),
        Duration::from_secs(35),
    ));
    assert_eq!(prepared["memory"]["status"], "captured");
    assert_eq!(prepared["upstream"]["sync"]["status"], "unavailable");
    assert!(
        prepared["upstream"]["sync"]["reason"]
            .as_str()
            .unwrap()
            .contains("timed out")
    );
    assert!(output.join("inventory.json").is_file());
}
