use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use mehscan_engine::investigation::{bind_inventory_repository, build_review_inventory};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    Operation, checked_store, fingerprint, is_local_folder_key, operate, repository_locations,
    snapshot_from_inventory, temporary_mode, upstream,
};
use crate::{
    ParsedArguments, engine, print_json, review_state::outside_source, write_review_inventory,
};

const MAX_CONFIG_BYTES: u64 = 8 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectConfig {
    repository_key: String,
    stream: Option<String>,
    remote: Option<String>,
}

/// The prepared reference carries the project bindings shared by journal and worker commands.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct PreparedProject {
    schema_version: u32,
    pub(crate) source_root: PathBuf,
    pub(crate) inventory: PathBuf,
    pub(crate) inventory_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    report_manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) admitted_report: Option<AdmittedReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) routed_source_generation: Option<u64>,
    pub(crate) repository_key: String,
    pub(crate) state_store: PathBuf,
    pub(crate) memory_store: PathBuf,
    pub(crate) stream: String,
    memory: ProjectMemory,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct AdmittedReport {
    pub(crate) generation: u64,
    pub(crate) findings_sha256: String,
}

#[derive(Deserialize)]
pub(crate) struct CloseReceipt {
    pub(crate) sequence: u64,
    result: CloseResult,
    memory: Option<CloseMemory>,
    pub(crate) project_run: PathBuf,
    pub(crate) admitted_report: AdmittedReport,
}

#[derive(Deserialize)]
struct CloseMemory {
    status: String,
    batch: Option<String>,
    snapshot: Option<String>,
}

#[derive(Deserialize)]
struct CloseResult {
    status: mehscan_core::ReviewAttemptStatus,
    generation: u64,
}

impl CloseReceipt {
    pub(crate) fn read(path: &Path) -> Result<Self, String> {
        let receipt: Self = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|e| format!("expected a project close receipt with admitted findings: {e}"))?;
        if !receipt.project_run.is_absolute()
            || receipt.result.status == mehscan_core::ReviewAttemptStatus::Running
            || receipt.result.generation != receipt.admitted_report.generation
        {
            return Err("invalid attempt or generation in close receipt".into());
        }
        Ok(receipt)
    }

    /// Bind publication to the retained batch at the exact journal close, including historical closes.
    pub(super) fn supply_publication(
        args: &mut ParsedArguments,
        peer: bool,
    ) -> Result<Option<super::Snapshot>, String> {
        let Some(path) = args.optional("--close-receipt") else {
            return Ok(None);
        };
        let close = Self::read(Path::new(&path))?;
        let project = PreparedProject::read(&close.project_run)?;
        outside_source(Path::new(&path), &project.source_root)?;
        close.validate_project(&project)?;
        close.findings()?;
        let memory = close
            .memory
            .filter(|m| m.status == "retained")
            .ok_or("publication requires a retained close receipt")?;
        let snapshot = super::load_snapshot(&project.source_root, &project.inventory, false)?;
        let id = snapshot.id(&fingerprint(&snapshot.repository)?)?;
        let admission = crate::review_state::memory_admission(
            &project.state_store,
            &project.stream,
            close.result.generation,
            &snapshot.repository,
            &snapshot.source,
            &snapshot.inventory,
            Some(close.sequence),
        )?;
        let batch =
            super::assessments::batch_id(&id, &snapshot.inventory, &project.stream, &admission)?;
        if project.temporary()
            || !admission.matches_close(close.sequence, &close.admitted_report.findings_sha256)
            || admission.status != close.result.status
            || memory.batch.as_ref() != Some(&batch)
            || memory.snapshot.as_ref() != Some(&id)
        {
            return Err("retained batch differs from the journal close".into());
        }
        if let Some(root) = args.optional("--source-root") {
            if fs::canonicalize(root).map_err(|e| e.to_string())? != project.source_root {
                return Err("publication checkout differs from the closed project".into());
            }
        }
        let mut supply = |key: &str, value: String| {
            if args.options.insert(key.into(), value).is_some() {
                Err(format!("--close-receipt already supplies {key}"))
            } else {
                Ok(())
            }
        };
        supply("--source-root", project.source_root.display().to_string())?;
        supply("--inventory", project.inventory.display().to_string())?;
        supply("--stream", project.stream)?;
        supply("--store", project.memory_store.display().to_string())?;
        supply("--batch", batch)?;
        if peer {
            supply("--repository-key", project.repository_key)?;
        }
        Ok(Some(snapshot))
    }

    pub(crate) fn validate_project(&self, project: &PreparedProject) -> Result<(), String> {
        if project.admitted_report.as_ref() != Some(&self.admitted_report) {
            return Err("admitted project run differs from the close receipt".into());
        }
        project.report_run(&self.project_run)?;
        outside_source(
            &self.project_run.with_file_name("findings.json"),
            &project.source_root,
        )
    }

    pub(crate) fn findings(&self) -> Result<mehscan_core::FindingReport, String> {
        let findings = self
            .admitted_report
            .read_findings(&self.project_run.with_file_name("findings.json"))?;
        serde_json::from_slice(&findings).map_err(|e| e.to_string())
    }
}

impl AdmittedReport {
    pub(crate) fn read_findings(&self, path: &Path) -> Result<Vec<u8>, String> {
        use sha2::{Digest, Sha256};
        let findings =
            fs::read(path).map_err(|e| format!("could not read the admitted findings: {e}"))?;
        if format!("{:x}", Sha256::digest(&findings)) != self.findings_sha256 {
            return Err("findings differ from the admitted report".into());
        }
        Ok(findings)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct ProjectMemory {
    reason: Option<String>,
}

impl PreparedProject {
    /// Stage only the bundle inputs that the native record command will validate.
    pub(crate) fn stage_manual(&self, run: &Path) -> Result<tempfile::TempDir, String> {
        let directory = self.state_store.join("manual-admissions");
        outside_source(&directory, &self.source_root)?;
        fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
        let stage = tempfile::tempdir_in(directory).map_err(|e| e.to_string())?;
        let target = stage.path().join("run");
        let source = run.canonicalize().map_err(|e| e.to_string())?;
        outside_source(&source, &self.source_root)?;
        for name in ["requests", "responses"] {
            fs::create_dir_all(target.join(name)).map_err(|e| e.to_string())?;
        }
        let copy = |relative: &Path| -> Result<(), String> {
            let path = source
                .join(relative)
                .canonicalize()
                .map_err(|e| e.to_string())?;
            if !path.starts_with(&source) || !path.is_file() {
                return Err("manual bundle file escapes the supplied run".into());
            }
            fs::copy(path, target.join(relative)).map_err(|e| e.to_string())?;
            Ok(())
        };
        copy(Path::new("manifest.json"))?;
        let manifest: mehscan_core::PathReviewBundleManifest = serde_json::from_reader(
            fs::File::open(target.join("manifest.json")).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        if manifest.impact_scope.is_some() {
            copy(Path::new("input-binding.json"))?;
        }
        for entry in manifest.bundles {
            let name = Path::new(&entry.filename);
            if name.file_name() != Some(name.as_os_str()) {
                return Err("invalid manual bundle filename".into());
            }
            copy(&Path::new("requests").join(name))?;
            let response = Path::new("responses").join(name);
            if source
                .join(&response)
                .try_exists()
                .map_err(|e| e.to_string())?
            {
                copy(&response)?;
            }
        }
        Ok(stage)
    }

    pub(crate) fn seal_manual(
        &mut self,
        stage: &Path,
        generation: u64,
        report: &mehscan_core::FindingReport,
        work: Option<&mehscan_core::ReviewWorkPackage>,
    ) -> Result<(), String> {
        use sha2::{Digest, Sha256};
        let findings = serde_json::to_vec_pretty(report).map_err(|e| e.to_string())?;
        let manifest = fs::read(stage.join("run/manifest.json")).map_err(|e| e.to_string())?;
        self.report_manifest_sha256 = Some(format!("{:x}", Sha256::digest(manifest)));
        self.admitted_report = Some(AdmittedReport {
            generation,
            findings_sha256: format!("{:x}", Sha256::digest(&findings)),
        });
        self.routed_source_generation = None;
        fs::write(stage.join("findings.json"), findings).map_err(|e| e.to_string())?;
        if let Some(work) = work {
            crate::write_json(work, Some(&stage.join("work.json")))?;
        }
        crate::write_json(self, Some(&stage.join("project-run.json")))
    }

    pub(crate) fn publish_manual(
        &self,
        stage: tempfile::TempDir,
        sequence: u64,
    ) -> Result<PathBuf, String> {
        let destination = self
            .state_store
            .join("manual-admissions")
            .join(sequence.to_string());
        let path = destination.join("project-run.json");
        if let Err(error) = fs::rename(stage.path(), &destination) {
            // A replay can return the same journal sequence after a successful rename.
            if !path.is_file()
                || fs::read(&path).map_err(|e| e.to_string())?
                    != fs::read(stage.path().join("project-run.json")).map_err(|e| e.to_string())?
            {
                return Err(error.to_string());
            }
            self.report_run(&path)?;
            self.admitted_report
                .as_ref()
                .ok_or("missing manual report")?
                .read_findings(&destination.join("findings.json"))?;
        }
        Ok(path)
    }

    pub(crate) fn temporary(&self) -> bool {
        self.memory.reason.as_deref() == Some("temporary_mode")
    }

    pub(crate) fn report_run(&self, receipt: &Path) -> Result<PathBuf, String> {
        use sha2::{Digest, Sha256};
        let expected = self
            .report_manifest_sha256
            .as_deref()
            .ok_or("report requires the admitted attempt’s project-run.json")?;
        let run = receipt
            .canonicalize()
            .map_err(|error| error.to_string())?
            .with_file_name("run");
        outside_source(&run, &self.source_root)?;
        let manifest = fs::read(run.join("manifest.json")).map_err(|error| error.to_string())?;
        if format!("{:x}", Sha256::digest(manifest)) != expected {
            return Err("report manifest differs from the admitted project run".into());
        }
        Ok(run)
    }

    pub(crate) fn read(path: &Path) -> Result<Self, String> {
        fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
            let file = fs::File::open(path)
                .map_err(|error| format!("could not open {}: {error}", path.display()))?;
            serde_json::from_reader(std::io::BufReader::new(file))
                .map_err(|error| format!("invalid {}: {error}", path.display()))
        }
        let path = path.canonicalize().map_err(|error| error.to_string())?;
        let receipt: Self = read_json(&path)?;
        if receipt.schema_version != 1
            || !receipt.source_root.is_absolute()
            || !receipt.source_root.is_dir()
        {
            return Err("unsupported or invalid project receipt".into());
        }
        for external in [
            &receipt.inventory,
            &receipt.state_store,
            &receipt.memory_store,
        ] {
            if !external.is_absolute() {
                return Err("project receipt requires absolute paths".into());
            }
            outside_source(external, &receipt.source_root)?;
        }
        let directory = receipt
            .inventory
            .canonicalize()
            .map_err(|error| error.to_string())?;
        outside_source(&path, &receipt.source_root)?;
        if receipt.report_manifest_sha256.is_none() && path.parent() != Some(directory.as_path()) {
            return Err("project receipt must accompany its prepared inventory".into());
        }
        let summary: serde_json::Value = read_json(&directory.join("overview.json"))?;
        if summary["input_fingerprint"].as_str() != Some(receipt.inventory_fingerprint.as_str())
            || summary["native_identity"]["repository"]["repository_key"].as_str()
                != Some(receipt.repository_key.as_str())
        {
            return Err("prepared project inventory differs from its receipt".into());
        }
        validate_label(&receipt.stream, "review stream")?;
        Ok(receipt)
    }
}

/// Attach the normal project reference to an inventory already prepared at its requested scope.
fn bind(mut args: ParsedArguments) -> Result<(), String> {
    let source_root =
        fs::canonicalize(args.required("--source-root")?).map_err(|e| e.to_string())?;
    let inventory = fs::canonicalize(args.required("--inventory")?).map_err(|e| e.to_string())?;
    let state_store = args.optional("--store").map(PathBuf::from);
    let stream = args.required("--stream")?;
    let memory_store = args.optional("--memory-store").map(PathBuf::from);
    let temporary = temporary_mode(
        args.optional("--memory-mode").as_deref(),
        memory_store.is_some(),
    )?;
    args.finish()?;
    validate_label(&stream, "review stream")?;
    outside_source(&inventory, &source_root)?;
    let (_, binding) = crate::review_state::inventory(&inventory, &source_root)?;
    let (journal, memory) = match (state_store, memory_store) {
        (Some(journal), Some(memory)) => (journal, memory),
        (journal, memory) => {
            let defaults = repository_locations(&source_root, &binding.repository)?;
            (
                journal.unwrap_or(defaults.state_store),
                memory.unwrap_or(defaults.memory_store),
            )
        }
    };
    let state_store = std::path::absolute(journal).map_err(|e| e.to_string())?;
    let memory_store = std::path::absolute(memory).map_err(|e| e.to_string())?;
    outside_source(&state_store, &source_root)?;
    outside_source(&memory_store, &source_root)?;
    let reference = PreparedProject {
        schema_version: 1,
        repository_key: binding
            .repository
            .repository_key
            .ok_or("missing repository key")?,
        inventory_fingerprint: binding.inventory_input_fingerprint,
        source_root,
        inventory,
        state_store,
        stream,
        memory_store,
        memory: ProjectMemory {
            reason: temporary.then(|| "temporary_mode".into()),
        },
        report_manifest_sha256: None,
        admitted_report: None,
        routed_source_generation: None,
    };
    let path = reference.inventory.join("project-run.json");
    let stage = tempfile::NamedTempFile::new_in(&reference.inventory).map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(stage.as_file(), &reference).map_err(|e| e.to_string())?;
    stage
        .persist_noclobber(&path)
        .map_err(|e| format!("could not bind inventory: {e}"))?;
    print_json(&json!({"project_run": path}))
}

pub(crate) fn run(mut arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let operation = arguments.next();
    let mut arguments = ParsedArguments::parse(arguments)?;
    if arguments.help || matches!(operation.as_deref(), None | Some("help" | "--help" | "-h")) {
        println!(
            "USAGE:\n  mehscan project resolve --project-run FILE\n  mehscan project bind --source-root ROOT --inventory DIR --stream NAME [--store DIR] [--memory-store FILE | --memory-mode temporary]\n  mehscan project prepare ROOT --config FILE --output DIR [--stream NAME] [--base SNAPSHOT [--base-inventory FINGERPRINT]] [--artifact LABEL] [--pull true|false] [--memory-mode persistent|temporary]\n\nPrepares a full review inventory and snapshot for a configured project. Keep the JSON project config and a new output directory outside ROOT. Config has repository_key, optional stream (default imported), and optional remote. Pull is opt-in and provides advisory context. With --base-inventory, --pull true also reads context for the specified baseline."
        );
        return Ok(());
    }
    if operation.as_deref() == Some("bind") {
        return bind(arguments);
    }
    if operation.as_deref() == Some("resolve") {
        let path = PathBuf::from(arguments.required("--project-run")?);
        arguments.finish()?;
        return print_json(&PreparedProject::read(&path)?);
    }
    if operation.as_deref() != Some("prepare") {
        return Err("unknown project operation; use 'mehscan project --help'".into());
    }

    let config_path = PathBuf::from(arguments.required("--config")?);
    let output = PathBuf::from(arguments.required("--output")?);
    let stream = arguments.optional("--stream");
    let base = arguments.optional("--base");
    let base_inventory = arguments.optional("--base-inventory");
    let artifact = arguments.optional("--artifact");
    let pull = arguments.optional_bool("--pull")?.unwrap_or(false);
    let temporary = temporary_mode(arguments.optional("--memory-mode").as_deref(), false)?;
    let root = arguments
        .root
        .canonicalize()
        .map_err(|error| error.to_string())?;
    arguments.finish()?;
    if !root.is_dir() {
        return Err("project preparation requires a source directory".into());
    }
    if temporary && base.is_some() {
        return Err("--base requires persistent project memory".into());
    }
    let baseline = if let Some(inventory) = base_inventory {
        let snapshot = base
            .clone()
            .filter(|_| pull)
            .ok_or("--base-inventory requires --base and --pull true")?;
        if inventory.len() != 64 || !inventory.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("--base-inventory requires an inventory fingerprint".into());
        }
        Some(upstream::Baseline {
            snapshot,
            inventory,
        })
    } else {
        None
    };

    let config = read_config(&config_path, &root)?;
    let stream = stream
        .or(config.stream)
        .unwrap_or_else(|| "imported".into());
    validate_label(&stream, "review stream")?;
    if let Some(artifact) = &artifact {
        validate_label(artifact, "artifact label")?;
    }
    if let Some(remote) = &config.remote {
        upstream::validate_remote(remote)?;
    } else if pull {
        return Err("--pull requires a remote in the project config".into());
    }
    if output.components().any(|part| part == Component::ParentDir) {
        return Err("project output paths must omit parent traversal".into());
    }
    let output = std::path::absolute(output).map_err(|error| error.to_string())?;
    outside_source(&output, &root)
        .map_err(|_| "project output must be outside the source directory")?;
    ensure_new(&output)?;

    let mut inventory = engine(build_review_inventory(&root, false))?;
    engine(bind_inventory_repository(
        &mut inventory,
        Some(config.repository_key.clone()),
        None,
    ))?;
    let inventory_fingerprint = engine(inventory.input_fingerprint())?;
    let snapshot =
        snapshot_from_inventory(&root, &inventory, inventory_fingerprint.clone(), false)?;
    let locations = repository_locations(&root, &snapshot.repository)?;
    let snapshot_id = snapshot.id(&fingerprint(&snapshot.repository)?)?;
    let memory = if temporary {
        json!({"status": "skipped", "reason": "temporary_mode"})
    } else {
        let comparing = base.is_some();
        match checked_store(&locations.memory_store, &root)
            .and_then(|store| operate(&store, &snapshot, Operation::Snapshot { base }))
        {
            Ok(capture) => json!({"status": "captured", "capture": capture}),
            Err(reason) if !comparing => json!({"status": "unavailable", "reason": reason}),
            Err(reason) => return Err(reason),
        }
    };

    let mut upstream = None;
    if let Some(remote) = &config.remote {
        let replica = locations
            .memory_store
            .parent()
            .unwrap()
            .join("replicas")
            .join(fingerprint(remote)?)
            .join("publications.turso");
        outside_source(&replica, &root)?;
        let result = if pull {
            // A writable replica includes its own staged changes after a pull.
            let context_replica = replica.with_file_name("context.turso");
            outside_source(&context_replica, &root)?;
            upstream::pull_project(
                &context_replica,
                remote,
                &config.repository_key,
                snapshot,
                stream.clone(),
                baseline,
            )
            .unwrap_or_else(|reason| json!({"status": "unavailable", "reason": reason}))
        } else {
            json!({"status": "configured"})
        };
        upstream = Some(json!({"remote": remote, "replica": replica, "sync": result}));
    }

    let receipt = json!({
        "schema_version": 1,
        "project_run": output.join("project-run.json"),
        "repository_key": config.repository_key,
        "stream": stream,
        "source_root": root,
        "artifact": artifact,
        "inventory": output,
        "inventory_fingerprint": inventory_fingerprint,
        "snapshot": snapshot_id,
        "state_store": locations.state_store,
        "memory_store": locations.memory_store,
        "memory": memory,
        "upstream": upstream,
    });
    let parent = output
        .parent()
        .ok_or("project output must have a parent directory")?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    outside_source(parent, &root)
        .map_err(|_| "project output must be outside the source directory")?;
    let stage = tempfile::Builder::new()
        .prefix(".mehscan-project-")
        .tempdir_in(parent)
        .map_err(|error| error.to_string())?;
    write_review_inventory(stage.path(), &inventory, &inventory_fingerprint)?;
    let bindings = PreparedProject::deserialize(&receipt).map_err(|error| error.to_string())?;
    fs::write(
        stage.path().join("project-run.json"),
        serde_json::to_vec_pretty(&bindings).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("could not write project run reference: {error}"))?;
    fs::write(
        stage.path().join("project.json"),
        serde_json::to_vec_pretty(&receipt).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    ensure_new(&output)?;
    fs::rename(stage.path(), &output)
        .map_err(|error| format!("could not publish project inventory: {error}"))?;
    print_json(&receipt)
}

fn read_config(path: &Path, root: &Path) -> Result<ProjectConfig, String> {
    let path = path
        .canonicalize()
        .map_err(|error| format!("could not open project config: {error}"))?;
    outside_source(&path, root)
        .map_err(|_| "project config must be outside the source directory")?;
    if !path.is_file() {
        return Err("project config must be a regular file".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(&path)
        .and_then(|file| file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("could not read project config: {error}"))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err("project config exceeds 8 KiB".into());
    }
    let config: ProjectConfig = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid project config: {error}"))?;
    if is_local_folder_key(&config.repository_key) {
        return Err("project config requires an explicit shared repository key".into());
    }
    Ok(config)
}

fn validate_label(label: &str, name: &str) -> Result<(), String> {
    if label.is_empty()
        || label.len() > 512
        || label.trim() != label
        || label.chars().any(char::is_control)
    {
        return Err(format!(
            "{name} must be nonempty, bounded text without control characters"
        ));
    }
    Ok(())
}

fn ensure_new(output: &Path) -> Result<(), String> {
    match fs::symlink_metadata(output) {
        Ok(_) => Err("project output must be a new directory".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}
