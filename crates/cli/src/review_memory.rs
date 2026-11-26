//! Local review-memory persistence owned by the native controller.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use mehscan_core::ReviewRepositoryIdentity;
use serde::Serialize;
use sha2::{Digest, Sha256};
use turso::{Builder, Connection, transaction::TransactionBehavior};

mod assessments;
mod dependencies;
pub(super) mod knowledge;
mod legacy;
mod project;
mod shared;
mod upstream;

pub(super) use project::{CloseReceipt, PreparedProject, run as run_project};

const LOCAL_FOLDER_KEY_PREFIX: &str = "mehscan-local-folder:v1:";

fn local_folder_key(root: &Path) -> String {
    let digest = Sha256::digest(root.as_os_str().as_encoded_bytes());
    format!("{LOCAL_FOLDER_KEY_PREFIX}{digest:x}")
}

pub(super) fn standalone_repository_key(root: &Path) -> Result<Option<String>, String> {
    let root = root.canonicalize().map_err(|error| error.to_string())?;
    if !root.is_dir() || root.ancestors().any(|parent| parent.join(".git").exists()) {
        return Ok(None);
    }
    Ok(Some(local_folder_key(&root)))
}

fn is_local_folder_key(key: &str) -> bool {
    key.strip_prefix(LOCAL_FOLDER_KEY_PREFIX)
        .is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

pub(super) fn validate_repository_root(root: &Path, key: &str) -> Result<(), String> {
    if is_local_folder_key(key) {
        let root = root.canonicalize().map_err(|error| error.to_string())?;
        if key != local_folder_key(&root) {
            return Err(
                "local inventory belongs to a different source folder; regenerate inventory".into(),
            );
        }
    }
    Ok(())
}

const SCHEMA: &str = "
    CREATE TABLE review_memory_schema (
        version INTEGER PRIMARY KEY
    );
    INSERT INTO review_memory_schema VALUES (1);
    CREATE TABLE repositories (
        id TEXT NOT NULL PRIMARY KEY,
        repository_key TEXT NOT NULL,
        source_repository_key TEXT,
        path_prefix TEXT NOT NULL
    );
    CREATE TABLE snapshots (
        id TEXT NOT NULL PRIMARY KEY,
        repository_id TEXT NOT NULL REFERENCES repositories(id),
        source_fingerprint TEXT NOT NULL
    );
    CREATE TABLE snapshot_inputs (
        snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
        path TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        PRIMARY KEY (snapshot_id, path)
    );
    CREATE TABLE inventory_bindings (
        snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
        inventory_fingerprint TEXT NOT NULL,
        PRIMARY KEY (snapshot_id, inventory_fingerprint)
    );
";

#[derive(Default, Serialize)]
struct Changes<'a> {
    added: Vec<&'a str>,
    modified: Vec<&'a str>,
    removed: Vec<&'a str>,
}

#[derive(Serialize)]
struct Capture<'a> {
    snapshot: &'a str,
    source_fingerprint: &'a str,
    inventory_fingerprint: &'a str,
    files: usize,
    reused: bool,
    base: Option<&'a str>,
    changes: Option<Changes<'a>>,
}

struct Snapshot {
    prepared_inventory: Option<String>,
    repository: ReviewRepositoryIdentity,
    inventory: String,
    source: String,
    files: BTreeMap<String, String>,
    subjects: BTreeMap<String, mehscan_core::ReviewSubjectIdentity>,
    sources: Option<mehscan_engine::investigation::ReviewMemorySources>,
    comparison: Option<mehscan_core::ChangeComparison>,
    razor_render_bindings: Option<mehscan_core::RazorRenderBindings>,
}

enum Operation {
    Snapshot {
        base: Option<String>,
    },
    Retain {
        stream: String,
        admission: super::review_state::MemoryAdmission,
    },
    Assessments {
        stream: String,
    },
    Compare {
        stream: String,
        batch: String,
    },
    Reuse {
        stream: String,
        state: PathBuf,
        owner: String,
        operation_key: String,
        work: Box<mehscan_core::ReviewWorkPackage>,
        batch: String,
    },
}

pub(super) struct EndRetention {
    pub store: Option<PathBuf>,
    pub source_root: PathBuf,
    pub inventory: PathBuf,
}

impl EndRetention {
    pub(super) fn retain(
        &self,
        state: &Path,
        stream: &str,
        repository_key: &str,
        generation: u64,
        sequence: u64,
    ) -> Result<serde_json::Value, String> {
        super::review_state::outside_source(state, &self.source_root)?;
        let snapshot = load_snapshot(&self.source_root, &self.inventory, true)?;
        if snapshot.repository.repository_key.as_deref() != Some(repository_key) {
            return Err("memory inventory belongs to a different repository".into());
        }
        let store = resolve_store(
            self.store.as_deref(),
            &self.source_root,
            &snapshot.repository,
        )?;
        let admission = super::review_state::memory_admission(
            state,
            stream,
            generation,
            &snapshot.repository,
            &snapshot.source,
            &snapshot.inventory,
            Some(sequence),
        )?;
        operate(
            &store,
            &snapshot,
            Operation::Retain {
                stream: stream.into(),
                admission,
            },
        )
    }
}

pub(super) fn run(mut arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let command = arguments.next();
    match command.as_deref() {
        None | Some("--help" | "help" | "-h") => {
            help();
            return Ok(());
        }
        Some(
            "location" | "snapshot" | "retain" | "assessments" | "reuse" | "prepare" | "compare"
            | "export",
        ) => {}
        Some("import-legacy" | "legacy-history") => {
            return legacy::run(command.as_deref().unwrap(), arguments);
        }
        Some("sync") => return upstream::run(arguments),
        Some("knowledge-put" | "knowledge-list" | "knowledge-withdraw" | "shared-facts") => {}
        Some(other) => {
            return Err(format!(
                "unknown memory operation {other:?}; use 'mehscan memory --help'"
            ));
        }
    }
    let mut args = super::ParsedArguments::parse(arguments)?;
    if args.help {
        help();
        return Ok(());
    }
    if args.root != Path::new(".") {
        return Err("memory operations accept named options only".into());
    }
    let root = PathBuf::from(args.required("--source-root")?);
    let inventory = PathBuf::from(args.required("--inventory")?);
    if let Some(command) = command
        .as_deref()
        .filter(|name| name.starts_with("knowledge-"))
    {
        return super::print_json(&knowledge::run(command, args, &root, &inventory)?);
    }
    if command.as_deref() == Some("location") {
        args.finish()?;
        let (cache, _) = super::review_state::load_inventory(&inventory)?;
        let locations = default_locations(&root, &inventory_catalog(&cache, &root)?.repository)?;
        create_private_directory(locations.memory_store.parent().unwrap())?;
        return super::print_json(&json(locations)?);
    }
    let store = args.optional("--store").map(PathBuf::from);
    if command.as_deref() == Some("shared-facts") {
        let input = args.optional("--input").map(PathBuf::from);
        args.finish()?;
        let (cache, _) = super::review_state::load_inventory(&inventory)?;
        let repository = &inventory_catalog(&cache, &root)?.repository;
        let store = resolve_store(store.as_deref(), &root, repository)?;
        return super::print_json(&shared::run(&store, repository, input.as_deref(), &root)?);
    }
    let snapshot = load_snapshot(
        &root,
        &inventory,
        matches!(command.as_deref(), Some("retain" | "compare" | "prepare")),
    )?;
    if command.as_deref() == Some("prepare") {
        return super::print_json(&prepare_native(args, &root, store.as_deref(), &snapshot)?);
    }
    let store = resolve_store(store.as_deref(), &root, &snapshot.repository)?;
    if command.as_deref() == Some("export") {
        let stream = args.required("--stream")?;
        let batch = args.required("--batch")?;
        args.finish()?;
        return super::print_json(&upstream::export(&store, snapshot, stream, &batch)?);
    }
    let operation = match command.as_deref() {
        Some("snapshot") => Operation::Snapshot {
            base: args.optional("--base"),
        },
        Some("retain") => {
            let stream = args.required("--stream")?;
            let state = PathBuf::from(args.required("--state-store")?);
            let generation = args
                .required("--generation")?
                .parse::<u64>()
                .map_err(|_| "--generation requires a native generation number")?;
            super::review_state::outside_source(&state, &root)?;
            Operation::Retain {
                admission: super::review_state::memory_admission(
                    &state,
                    &stream,
                    generation,
                    &snapshot.repository,
                    &snapshot.source,
                    &snapshot.inventory,
                    None,
                )?,
                stream,
            }
        }
        Some("assessments") => Operation::Assessments {
            stream: args.required("--stream")?,
        },
        Some("compare") => Operation::Compare {
            stream: args.required("--stream")?,
            batch: args.required("--batch")?,
        },
        Some("reuse") => {
            let state = PathBuf::from(args.required("--state-store")?);
            let work_path = PathBuf::from(args.required("--work-package")?);
            super::review_state::outside_source(&state, &root)?;
            super::review_state::outside_source(&work_path, &root)?;
            let work: mehscan_core::ReviewWorkPackage =
                serde_json::from_slice(&fs::read(work_path).map_err(|error| error.to_string())?)
                    .map_err(|error| error.to_string())?;
            if work.payload.repository != snapshot.repository
                || work.payload.inventory_input_fingerprint != snapshot.inventory
            {
                return Err("work package does not match current memory inventory".into());
            }
            let contract = work
                .payload
                .runtime
                .as_ref()
                .ok_or("memory reuse requires a bound review runtime")?;
            let skill = args.required("--skill-root")?;
            let provider = args.optional("--provider-contract");
            super::review_state::validate_runtime_skill(
                contract,
                Some(&skill),
                provider.as_deref(),
                &root,
            )?;
            Operation::Reuse {
                stream: args.required("--stream")?,
                state,
                work: Box::new(work),
                owner: args.required("--owner")?,
                operation_key: args.required("--operation-key")?,
                batch: args.required("--batch")?,
            }
        }
        _ => unreachable!(),
    };
    args.finish()?;
    super::print_json(&operate(&store, &snapshot, operation)?)
}

fn prepare_native(
    mut args: super::ParsedArguments,
    root: &Path,
    store: Option<&Path>,
    snapshot: &Snapshot,
) -> Result<serde_json::Value, String> {
    let state = PathBuf::from(args.required("--state-store")?);
    let stream = args.required("--stream")?;
    let generation = args.required_usize("--generation")? as u64;
    let owner = args.required("--owner")?;
    let skill = args.required("--skill-root")?;
    let provider = args.optional("--provider-contract");
    let temporary = temporary_mode(args.optional("--memory-mode").as_deref(), store.is_some())?;
    let requested = args.optional("--review-ids").map(|ids| {
        if ids.is_empty() {
            Vec::new()
        } else {
            ids.split(',').map(str::to_owned).collect()
        }
    });
    args.finish()?;
    super::review_state::outside_source(&state, root)?;
    let reader = knowledge::Reader::lock(root, &snapshot.repository, store, temporary);
    let path = reader
        .as_ref()
        .ok()
        .and_then(|reader| reader.path.as_deref());
    let mut selection = knowledge::Selection::default();
    let retained = match (&reader, path) {
        (Err(reason), _) => Some(Err(reason.clone())),
        (Ok(_), Some(path)) if path.is_file() => Some(local_runtime()?.block_on(async {
            let (_database, connection) = open_local(path, true).await?;
            selection = knowledge::select(&connection, snapshot).await?;
            assessments::latest_finished_batch(&connection, snapshot, &stream).await
        })),
        (Ok(_), Some(_)) => Some(Ok(None)),
        (Ok(_), None) => None,
    };
    let mut prepared = super::review_state::MemoryPreparation {
        store: &state,
        stream: &stream,
        repository_key: snapshot
            .repository
            .repository_key
            .as_deref()
            .ok_or("missing repository key")?,
        inventory: &snapshot.inventory,
        generation,
        owner: &owner,
        requested: requested.as_deref(),
    }
    .prepare(root, &skill, provider.as_deref(), retained, &selection)?;
    if prepared.memory["status"] == "no_batch"
        && prepared
            .work_package
            .payload
            .expected_parents
            .values()
            .any(|parents| !parents.is_empty())
    {
        let context = (|| {
            let Some(path) = path.filter(|path| path.is_file()) else {
                return Ok(None);
            };
            local_runtime()?.block_on(async {
                let (_database, connection) = open_local(path, true).await?;
                dependencies::prepare_context(
                    &connection,
                    snapshot,
                    &stream,
                    &prepared.work_package,
                )
                .await
            })
        })();
        match context {
            Ok(Some(context)) => prepared.memory["prior_dependencies"] = context,
            Ok(None) => {}
            Err(reason) => {
                prepared.memory["prior_dependencies"] =
                    serde_json::json!({"status":"unavailable","reason":reason})
            }
        }
    }
    json(prepared)
}

fn load_snapshot(root: &Path, inventory: &Path, keep_sources: bool) -> Result<Snapshot, String> {
    let (cache, inventory) = super::review_state::load_inventory(inventory)?;
    snapshot_from_inventory(root, &cache, inventory, keep_sources)
}

fn snapshot_from_inventory(
    root: &Path,
    cache: &mehscan_engine::investigation::ReviewInventory,
    inventory: String,
    keep_sources: bool,
) -> Result<Snapshot, String> {
    let catalog = inventory_catalog(cache, root)?;
    let sources = super::engine(mehscan_engine::investigation::review_memory_sources(
        root, cache,
    ))?;
    Ok(Snapshot {
        prepared_inventory: cache
            .source_inputs
            .as_ref()
            .and_then(|binding| binding.prepared_inventory.clone()),
        files: sources.hashes(),
        subjects: catalog.subjects.clone(),
        sources: keep_sources.then_some(sources),
        repository: catalog.repository.clone(),
        source: catalog.source_fingerprint.clone(),
        comparison: cache
            .scan
            .impact_scope
            .as_ref()
            .and_then(|scope| scope.comparison.clone()),
        razor_render_bindings: cache
            .scan
            .razor_render_bindings
            .as_ref()
            .filter(|_| keep_sources)
            .cloned(),
        inventory,
    })
}

fn inventory_catalog<'a>(
    cache: &'a mehscan_engine::investigation::ReviewInventory,
    root: &Path,
) -> Result<&'a mehscan_core::ReviewIdentityCatalog, String> {
    let catalog = cache
        .identity_catalog
        .as_ref()
        .ok_or("memory requires native identity; regenerate inventory")?;
    let key = catalog.repository.repository_key.as_deref().ok_or(
        "memory requires a repository identity; regenerate a standalone inventory or supply --repository-key",
    )?;
    validate_repository_root(root, key)?;
    Ok(catalog)
}

pub(super) fn temporary_mode(mode: Option<&str>, explicit_store: bool) -> Result<bool, String> {
    match mode {
        None | Some("persistent") => Ok(false),
        Some("temporary") if !explicit_store => Ok(true),
        Some("temporary") => Err("temporary memory mode does not accept a memory store".into()),
        Some(_) => Err("--memory-mode must be persistent or temporary".into()),
    }
}

#[derive(Serialize)]
struct Locations {
    state_store: PathBuf,
    memory_store: PathBuf,
}

fn default_locations(
    root: &Path,
    repository: &ReviewRepositoryIdentity,
) -> Result<Locations, String> {
    let mut locations = repository_locations(root, repository)?;
    locations.memory_store = checked_store(&locations.memory_store, root)?;
    Ok(locations)
}

fn repository_locations(
    root: &Path,
    repository: &ReviewRepositoryIdentity,
) -> Result<Locations, String> {
    let directory = state_home()?
        .join("repositories")
        .join(fingerprint(repository)?);
    super::review_state::outside_source(&directory, root)?;
    let state_store = directory.join("journal");
    super::review_state::outside_source(&state_store, root)?;
    Ok(Locations {
        state_store,
        memory_store: directory.join("review-memory.turso"),
    })
}

fn state_home() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("MEHSCAN_STATE_HOME") {
        let directory = PathBuf::from(path);
        return if directory.is_absolute() {
            Ok(directory)
        } else {
            Err("MEHSCAN_STATE_HOME requires an absolute directory outside the source root".into())
        };
    }
    let platform = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA")
    } else if cfg!(target_os = "macos") {
        None
    } else {
        std::env::var_os("XDG_STATE_HOME")
    };
    if let Some(directory) = platform
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
    {
        return Ok(directory.join("mehscan"));
    }
    let home = std::env::home_dir()
        .filter(|path| path.is_absolute())
        .ok_or("no local state home available; set MEHSCAN_STATE_HOME")?;
    let directory = if cfg!(windows) {
        home.join("AppData/Local")
    } else if cfg!(target_os = "macos") {
        home.join("Library/Application Support")
    } else {
        home.join(".local/state")
    };
    Ok(directory.join("mehscan"))
}

fn resolve_store(
    explicit: Option<&Path>,
    root: &Path,
    repository: &ReviewRepositoryIdentity,
) -> Result<PathBuf, String> {
    match explicit {
        Some(path) => checked_store(path, root),
        None => Ok(default_locations(root, repository)?.memory_store),
    }
}

fn checked_store(path: &Path, root: &Path) -> Result<PathBuf, String> {
    let store = std::path::absolute(path).map_err(|e| e.to_string())?;
    super::review_state::outside_source(&store, root)?;
    check_store_file(&store)?;
    Ok(store)
}

fn operate(
    store: &Path,
    snapshot: &Snapshot,
    operation: Operation,
) -> Result<serde_json::Value, String> {
    if let Operation::Assessments { .. } = operation
        && !store.is_file()
    {
        return json(assessments::empty(snapshot)?);
    }
    if matches!(
        operation,
        Operation::Reuse { .. } | Operation::Compare { .. }
    ) && !store.is_file()
    {
        return Err("memory reuse and comparison require an existing local database".into());
    }
    let _lock = lock_store(store)?;
    local_runtime()?.block_on(run_local(store, snapshot, operation))
}

fn local_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|e| e.to_string())
}

fn lock_store(store: &Path) -> Result<File, String> {
    let lock = open_store_lock(store)?;
    // The SDK can lock the database as early as open, outside SQL busy handling.
    fs2::FileExt::lock_exclusive(&lock).map_err(|e| e.to_string())?;
    Ok(lock)
}

fn open_store_lock(store: &Path) -> Result<File, String> {
    if let Some(parent) = store.parent() {
        create_private_directory(parent)?;
    }
    let mut name = store
        .file_name()
        .ok_or("memory store requires a file name")?
        .to_owned();
    name.push(".lock");
    let lock_path = store.with_file_name(name);
    check_store_file(&lock_path)?;
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| e.to_string())
}

fn create_private_directory(path: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|error| error.to_string())
}

fn check_store_file(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() => {
            Err(format!("{} must be a regular file", path.display()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn help() {
    println!(
        "USAGE:\n  mehscan memory location --source-root ROOT --inventory DIR\n  mehscan memory snapshot --source-root ROOT --inventory DIR [--store FILE --base SNAPSHOT]\n  mehscan memory retain --source-root ROOT --inventory DIR --state-store STATE --stream STREAM --generation N [--store FILE]\n  mehscan memory assessments --source-root ROOT --inventory DIR --stream STREAM [--store FILE]\n\nUses a repository-specific local Turso database outside the source root by default. Set MEHSCAN_STATE_HOME to choose the local state directory."
    );
    println!(
        "  mehscan memory prepare --source-root ROOT --inventory DIR --state-store STATE --stream STREAM --generation N --owner OWNER --skill-root DIR [--provider-contract FILE] [--review-ids ID,ID] [--store FILE | --memory-mode temporary]"
    );
    legacy::help();
    upstream::help();
    println!(
        "  mehscan memory shared-facts --source-root ROOT --inventory DIR [--store FILE] [--input PAGE]"
    );
    println!(
        "  mehscan memory export --source-root ROOT --inventory DIR --stream STREAM --batch ID [--store FILE]"
    );
    println!(
        "  mehscan memory knowledge-put --source-root ROOT --inventory DIR --input FILE [--store FILE]\n  mehscan memory knowledge-list --source-root ROOT --inventory DIR [--item ID] [--history true] [--store FILE]\n  mehscan memory knowledge-withdraw --source-root ROOT --inventory DIR --item ID --author NAME --expected-revision ID [--store FILE]"
    );
    println!(
        "  mehscan memory compare --source-root ROOT --inventory DIR --stream STREAM --batch BATCH [--store FILE]"
    );
    println!(
        "\n  mehscan memory reuse --source-root ROOT --inventory DIR --state-store STATE --stream STREAM --owner OWNER --work-package WORK --skill-root DIR [--provider-contract FILE] --batch ID --operation-key KEY [--store FILE]"
    );
}

fn fingerprint(value: &impl Serialize) -> Result<String, String> {
    let encoded = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

// A history read executes the same content queries for each selected batch.
async fn query_batch(
    conn: &Connection,
    sql: &'static str,
    batch: &str,
) -> Result<turso::Rows, String> {
    conn.prepare_cached(sql)
        .await
        .map_err(db_error)?
        .query((batch,))
        .await
        .map_err(db_error)
}

fn db_error(error: turso::Error) -> String {
    format!("local review memory: {error}")
}

fn json(value: impl Serialize) -> Result<serde_json::Value, String> {
    serde_json::to_value(value).map_err(|error| error.to_string())
}

async fn schema_version(conn: &Connection) -> Result<i64, String> {
    let mut tables = conn
        .query("SELECT name FROM sqlite_schema WHERE type = 'table'", ())
        .await
        .map_err(db_error)?;
    let mut has_tables = false;
    let mut has_memory_schema = false;
    while let Some(row) = tables.next().await.map_err(db_error)? {
        has_tables = true;
        has_memory_schema |= row.get::<String>(0).map_err(db_error)? == "review_memory_schema";
    }
    drop(tables);
    if !has_tables {
        return Ok(0);
    }
    if !has_memory_schema {
        return Err("unrecognized memory store; use a new local database".into());
    }
    let mut versions = conn
        .query("SELECT version FROM review_memory_schema", ())
        .await
        .map_err(db_error)?;
    if let Some(row) = versions.next().await.map_err(db_error)? {
        let version = row.get::<i64>(0).map_err(db_error)?;
        if matches!(version, 1..=5) && versions.next().await.map_err(db_error)?.is_none() {
            return Ok(version);
        }
    }
    Err("unsupported local review memory schema".into())
}

async fn prepare_schema(conn: &Connection) -> Result<(), String> {
    let version = schema_version(conn).await?;
    if version == 0 {
        conn.execute_batch(SCHEMA).await.map_err(db_error)?;
    }
    if version < 2 {
        conn.execute_batch(assessments::SCHEMA)
            .await
            .map_err(db_error)?;
        conn.execute_batch(assessments::CONTENT_SCHEMA)
            .await
            .map_err(db_error)?;
        conn.execute("UPDATE review_memory_schema SET version = 2", ())
            .await
            .map_err(db_error)?;
    }
    Ok(())
}

async fn prepare_legacy_schema(conn: &Connection) -> Result<(), String> {
    prepare_schema(conn).await?;
    if !legacy::table_exists(conn, "legacy_imports").await? {
        legacy::install(conn).await?;
        conn.execute(
            "UPDATE review_memory_schema SET version = 3 WHERE version = 2",
            (),
        )
        .await
        .map_err(db_error)?;
    }
    Ok(())
}

async fn previous_files(
    conn: &Connection,
    base: &str,
    repository: &str,
    current: &str,
) -> Result<Option<BTreeMap<String, String>>, String> {
    let mut rows = conn
        .query(
            "SELECT id FROM snapshots WHERE id = ?1 AND repository_id = ?2",
            (base, repository),
        )
        .await
        .map_err(db_error)?;
    if rows.next().await.map_err(db_error)?.is_none() {
        return Err("base snapshot does not exist in this repository scope".into());
    }
    drop(rows);
    if base == current {
        return Ok(None);
    }
    let mut rows = conn
        .query(
            "SELECT path, sha256 FROM snapshot_inputs WHERE snapshot_id = ?1",
            (base,),
        )
        .await
        .map_err(db_error)?;
    let mut files = BTreeMap::new();
    while let Some(row) = rows.next().await.map_err(db_error)? {
        files.insert(row.get(0).map_err(db_error)?, row.get(1).map_err(db_error)?);
    }
    Ok(Some(files))
}

fn compare<'a>(
    base: &'a BTreeMap<String, String>,
    current: &'a BTreeMap<String, String>,
) -> Changes<'a> {
    let mut result = Changes::default();
    for (path, hash) in current {
        match base.get(path) {
            None => result.added.push(path),
            Some(previous) if previous != hash => result.modified.push(path),
            Some(_) => {}
        }
    }
    result.removed = base
        .keys()
        .filter(|path| !current.contains_key(*path))
        .map(String::as_str)
        .collect();
    result
}

impl Snapshot {
    fn id(&self, repository: &str) -> Result<String, String> {
        fingerprint(&(repository, &self.source, &self.files))
    }
}

async fn run_local(
    path: &Path,
    snapshot: &Snapshot,
    operation: Operation,
) -> Result<serde_json::Value, String> {
    let read_only = matches!(
        operation,
        Operation::Assessments { .. } | Operation::Reuse { .. } | Operation::Compare { .. }
    );
    let (_database, mut connection) = open_local(path, read_only).await?;
    if let Operation::Assessments { stream } = operation {
        return json(assessments::lookup(&connection, snapshot, &stream).await?);
    }
    if let Operation::Compare { stream, batch } = operation {
        return dependencies::compare(&connection, snapshot, &stream, &batch).await;
    }
    if let Operation::Reuse {
        stream,
        state,
        owner,
        operation_key,
        work,
        batch,
    } = operation
    {
        let retained = assessments::reuse_batch(&connection, snapshot, &stream, batch).await?;
        let selection = knowledge::select(&connection, snapshot).await?;
        return super::review_state::reuse_memory(
            &state,
            &stream,
            owner,
            &operation_key,
            *work,
            retained,
            &selection,
        );
    }
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await
        .map_err(db_error)?;
    prepare_schema(&tx).await?;
    let repository = fingerprint(&snapshot.repository)?;
    let id = snapshot.id(&repository)?;
    let base = match &operation {
        Operation::Snapshot { base } => base.as_deref(),
        _ => None,
    };
    let previous = match base {
        Some(base) => previous_files(&tx, base, &repository, &id).await?,
        None => None,
    };

    let created = persist_snapshot(&tx, snapshot, &repository, &id).await?;
    if let Operation::Retain { admission, stream } = &operation {
        let sharing = shared::binding(&tx).await?;
        if let Some(binding) = &sharing {
            shared::validate_binding(&snapshot.repository, binding)?;
        }
        if (!admission.records.is_empty() || admission.sharing.is_some())
            && sharing != admission.sharing
        {
            return Err(
                "review retention must use the same sharing audience as native admission".into(),
            );
        }
        let result = assessments::retain(&tx, &id, &snapshot.inventory, stream, admission).await?;
        dependencies::retain(&tx, snapshot, &id, result.batch(), &admission.records).await?;
        let observations =
            knowledge::retain(&tx, snapshot, &repository, &admission.records).await?;
        tx.commit().await.map_err(db_error)?;
        let mut receipt = json(result)?;
        receipt["new_knowledge_revisions"] = serde_json::json!(observations);
        return Ok(receipt);
    }
    tx.commit().await.map_err(db_error)?;
    let changes = base.map(|_| match previous.as_ref() {
        Some(previous) => compare(previous, &snapshot.files),
        None => Changes::default(),
    });
    json(Capture {
        snapshot: &id,
        source_fingerprint: &snapshot.source,
        inventory_fingerprint: &snapshot.inventory,
        files: snapshot.files.len(),
        reused: !created,
        base,
        changes,
    })
}

async fn open_local(path: &Path, read_only: bool) -> Result<(turso::Database, Connection), String> {
    let path = path.to_str().ok_or("memory store path must be UTF-8")?;
    let database = Builder::new_local(path)
        .read_only(read_only)
        .build()
        .await
        .map_err(db_error)?;
    let connection = database.connect().map_err(db_error)?;
    connection
        .busy_timeout(Duration::from_secs(10))
        .map_err(db_error)?;
    connection
        .execute("PRAGMA foreign_keys = ON", ())
        .await
        .map_err(db_error)?;
    Ok((database, connection))
}

async fn persist_snapshot(
    tx: &Connection,
    snapshot: &Snapshot,
    repository: &str,
    id: &str,
) -> Result<bool, String> {
    let repository_key = snapshot
        .repository
        .repository_key
        .as_deref()
        .ok_or("memory requires a repository key")?;
    tx.execute(
        "INSERT INTO repositories VALUES (?1, ?2, ?3, ?4) ON CONFLICT(id) DO NOTHING",
        (
            repository,
            repository_key,
            snapshot.repository.source_repository_key.as_deref(),
            &*snapshot.repository.path_prefix,
        ),
    )
    .await
    .map_err(db_error)?;
    let created = tx
        .execute(
            "INSERT INTO snapshots VALUES (?1, ?2, ?3) ON CONFLICT(id) DO NOTHING",
            (id, repository, &*snapshot.source),
        )
        .await
        .map_err(db_error)?
        > 0;
    if created {
        let mut insert = tx
            .prepare("INSERT INTO snapshot_inputs VALUES (?1, ?2, ?3)")
            .await
            .map_err(db_error)?;
        for (path, hash) in &snapshot.files {
            insert
                .execute((id, path.as_str(), hash.as_str()))
                .await
                .map_err(db_error)?;
        }
    }
    tx.execute(
        "INSERT INTO inventory_bindings VALUES (?1, ?2) ON CONFLICT DO NOTHING",
        (id, &*snapshot.inventory),
    )
    .await
    .map_err(db_error)?;
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assessment_schema_upgrade_preserves_existing_inventory_bindings() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let db = Builder::new_local(":memory:").build().await.unwrap();
            let mut conn = db.connect().unwrap();
            conn.execute_batch(SCHEMA).await.unwrap();
            conn.execute("INSERT INTO repositories VALUES ('repo', 'example:app', NULL, '')", ()).await.unwrap();
            conn.execute("INSERT INTO snapshots VALUES ('snapshot', 'repo', 'source')", ()).await.unwrap();
            conn.execute("INSERT INTO inventory_bindings VALUES ('snapshot', 'inventory')", ()).await.unwrap();
            assert_eq!(schema_version(&conn).await.unwrap(), 1);
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).await.unwrap();
            prepare_schema(&tx).await.unwrap();
            tx.commit().await.unwrap();
            assert_eq!(schema_version(&conn).await.unwrap(), 2);
            let mut rows = conn.query("SELECT inventory_fingerprint FROM inventory_bindings WHERE snapshot_id = 'snapshot'", ()).await.unwrap();
            assert_eq!(rows.next().await.unwrap().unwrap().get::<String>(0).unwrap(), "inventory");
        });
    }
}
