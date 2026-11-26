use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use mehscan_engine::investigation::{bind_inventory_repository, build_review_inventory};
use serde::Deserialize;
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

pub(crate) fn run(mut arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let operation = arguments.next();
    let mut arguments = ParsedArguments::parse(arguments)?;
    if arguments.help || matches!(operation.as_deref(), None | Some("help" | "--help" | "-h")) {
        println!(
            "USAGE:\n  mehscan project prepare ROOT --config FILE --output DIR [--stream NAME] [--base SNAPSHOT [--base-inventory FINGERPRINT]] [--artifact LABEL] [--pull true|false] [--memory-mode persistent|temporary]\n\nPrepares a full review inventory and snapshot for a configured project. Keep the JSON project config and a new output directory outside ROOT. Config has repository_key, optional stream (default imported), and optional remote. Pull is opt-in and provides advisory context. With --base-inventory, --pull true also reads context for the specified baseline."
        );
        return Ok(());
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
    write_review_inventory(stage.path(), &inventory)?;
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
