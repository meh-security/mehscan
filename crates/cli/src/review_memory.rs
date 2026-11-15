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
    repository: ReviewRepositoryIdentity,
    inventory: String,
    source: String,
    files: BTreeMap<String, String>,
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
    pub store: PathBuf,
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
        let store = checked_store(&self.store, &self.source_root)?;
        let snapshot = load_snapshot(&self.source_root, &self.inventory)?;
        if snapshot.repository.repository_key.as_deref() != Some(repository_key) {
            return Err("memory inventory belongs to a different repository".into());
        }
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
        Some("snapshot" | "retain" | "assessments" | "reuse" | "prepare") => {}
        Some(other) => {
            return Err(format!(
                "unknown memory operation {other:?}; expected snapshot, retain, assessments, reuse or prepare"
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
    let store = PathBuf::from(args.required("--store")?);
    let snapshot = load_snapshot(&root, &inventory)?;
    if command.as_deref() == Some("prepare") {
        return super::print_json(&prepare_native(args, &root, &store, &snapshot)?);
    }
    let store = checked_store(&store, &root)?;
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
    store: &Path,
    snapshot: &Snapshot,
) -> Result<serde_json::Value, String> {
    let state = PathBuf::from(args.required("--state-store")?);
    let stream = args.required("--stream")?;
    let generation = args.required_usize("--generation")? as u64;
    let owner = args.required("--owner")?;
    let skill = args.required("--skill-root")?;
    let provider = args.optional("--provider-contract");
    let requested = args.optional("--review-ids").map(|ids| {
        if ids.is_empty() {
            Vec::new()
        } else {
            ids.split(',').map(str::to_owned).collect()
        }
    });
    args.finish()?;
    super::review_state::outside_source(&state, root)?;
    let retained = checked_store(store, root).and_then(|path| {
        if !path.is_file() {
            return Ok(None);
        }
        let _lock = lock_store(&path)?;
        local_runtime()?.block_on(async {
            let (_database, connection) = open_local(&path, true).await?;
            assessments::latest_finished_batch(&connection, snapshot, &stream).await
        })
    });
    super::review_state::MemoryPreparation {
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
    .prepare(root, &skill, provider.as_deref(), retained)
}

fn load_snapshot(root: &Path, inventory: &Path) -> Result<Snapshot, String> {
    let (cache, inventory) = super::review_state::load_inventory(inventory)?;
    let catalog = cache
        .identity_catalog
        .as_ref()
        .filter(|catalog| catalog.repository.repository_key.is_some())
        .ok_or("memory requires --repository-key at inventory creation")?;
    Ok(Snapshot {
        files: super::engine(
            mehscan_engine::investigation::review_inventory_source_hashes(root, &cache),
        )?,
        repository: catalog.repository.clone(),
        source: catalog.source_fingerprint.clone(),
        inventory,
    })
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
    if matches!(operation, Operation::Reuse { .. }) && !store.is_file() {
        return Err("memory reuse requires an existing local database".into());
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
    if let Some(parent) = store.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut name = store
        .file_name()
        .ok_or("memory store requires a file name")?
        .to_owned();
    name.push(".lock");
    let lock_path = store.with_file_name(name);
    check_store_file(&lock_path)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| e.to_string())?;
    // The SDK can lock the database as early as open, outside SQL busy handling.
    fs2::FileExt::lock_exclusive(&lock).map_err(|e| e.to_string())?;
    Ok(lock)
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
        "USAGE:\n  mehscan memory snapshot --store FILE --source-root ROOT --inventory DIR [--base SNAPSHOT]\n  mehscan memory retain --store FILE --source-root ROOT --inventory DIR --state-store STATE --stream STREAM --generation N\n  mehscan memory assessments --store FILE --source-root ROOT --inventory DIR --stream STREAM\n\nRecords validated source inputs and native assessments in a local Turso database outside the source root."
    );
    println!(
        "  mehscan memory prepare --store FILE --source-root ROOT --inventory DIR --state-store STATE --stream STREAM --generation N --owner OWNER --skill-root DIR [--provider-contract FILE] [--review-ids ID,ID]"
    );
    println!(
        "\n  mehscan memory reuse --store FILE --source-root ROOT --inventory DIR --state-store STATE --stream STREAM --owner OWNER --work-package WORK --skill-root DIR [--provider-contract FILE] --batch ID --operation-key KEY"
    );
}

fn fingerprint(value: &impl Serialize) -> Result<String, String> {
    let encoded = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
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
        if matches!(version, 1 | 2) && versions.next().await.map_err(db_error)?.is_none() {
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
        conn.execute("UPDATE review_memory_schema SET version = 2", ())
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
        Operation::Assessments { .. } | Operation::Reuse { .. }
    );
    let (_database, mut connection) = open_local(path, read_only).await?;
    if let Operation::Assessments { stream } = operation {
        return json(assessments::lookup(&connection, snapshot, &stream).await?);
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
        return super::review_state::reuse_memory(
            &state,
            &stream,
            owner,
            &operation_key,
            *work,
            retained,
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
        let result = assessments::retain(&tx, &id, &snapshot.inventory, stream, admission).await?;
        tx.commit().await.map_err(db_error)?;
        return json(result);
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
