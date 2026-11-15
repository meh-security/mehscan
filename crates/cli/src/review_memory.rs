//! Local review-memory persistence owned by the native controller.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use mehscan_core::ReviewRepositoryIdentity;
use serde::Serialize;
use sha2::{Digest, Sha256};
use turso::{Builder, Connection, transaction::TransactionBehavior};

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

pub(super) fn run(mut arguments: impl Iterator<Item = String>) -> Result<(), String> {
    match arguments.next().as_deref() {
        None | Some("--help" | "help" | "-h") => {
            help();
            return Ok(());
        }
        Some("snapshot") => {}
        Some(other) => {
            return Err(format!(
                "unknown memory operation {other:?}; expected snapshot"
            ));
        }
    }
    let mut args = super::ParsedArguments::parse(arguments)?;
    if args.help {
        help();
        return Ok(());
    }
    if args.root != Path::new(".") {
        return Err("memory snapshot accepts named options only".into());
    }
    let store = std::path::absolute(args.required("--store")?).map_err(|e| e.to_string())?;
    let root = PathBuf::from(args.required("--source-root")?);
    let inventory = PathBuf::from(args.required("--inventory")?);
    let base = args.optional("--base");
    args.finish()?;

    super::review_state::outside_source(&store, &root)?;
    check_store_file(&store)?;
    let (cache, inventory) = super::review_state::load_inventory(&inventory)?;
    let catalog = cache
        .identity_catalog
        .as_ref()
        .filter(|catalog| catalog.repository.repository_key.is_some())
        .ok_or("memory requires --repository-key at inventory creation")?;
    let snapshot = Snapshot {
        files: super::engine(
            mehscan_engine::investigation::review_inventory_source_hashes(&root, &cache),
        )?,
        repository: catalog.repository.clone(),
        source: catalog.source_fingerprint.clone(),
        inventory,
    };
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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(capture(&store, &snapshot, base.as_deref()))
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
        "USAGE:\n  mehscan memory snapshot --store FILE --source-root ROOT --inventory DIR [--base SNAPSHOT]\n\nRecords the current native inventory's source hashes in a local Turso database outside the source root. With --base, also reports added, modified and removed inputs relative to a saved snapshot."
    );
}

fn fingerprint(value: &impl Serialize) -> Result<String, String> {
    let encoded = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

fn db_error(error: turso::Error) -> String {
    format!("local review memory: {error}")
}

async fn prepare_schema(conn: &Connection) -> Result<(), String> {
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
        return conn.execute_batch(SCHEMA).await.map_err(db_error);
    }
    if !has_memory_schema {
        return Err("unrecognized memory store; use a new local database".into());
    }
    let mut versions = conn
        .query("SELECT version FROM review_memory_schema", ())
        .await
        .map_err(db_error)?;
    let version = versions.next().await.map_err(db_error)?;
    if matches!(version, Some(row) if row.get::<i64>(0).map_err(db_error)? == 1)
        && versions.next().await.map_err(db_error)?.is_none()
    {
        Ok(())
    } else {
        Err("unsupported local review memory schema".into())
    }
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

async fn capture(path: &Path, snapshot: &Snapshot, base: Option<&str>) -> Result<(), String> {
    let path = path.to_str().ok_or("memory store path must be UTF-8")?;
    let database = Builder::new_local(path).build().await.map_err(db_error)?;
    let mut connection = database.connect().map_err(db_error)?;
    connection
        .busy_timeout(Duration::from_secs(10))
        .map_err(db_error)?;
    connection
        .execute("PRAGMA foreign_keys = ON", ())
        .await
        .map_err(db_error)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await
        .map_err(db_error)?;
    prepare_schema(&tx).await?;
    let repository = fingerprint(&snapshot.repository)?;
    let id = fingerprint(&(&repository, &snapshot.source, &snapshot.files))?;
    let previous = match base {
        Some(base) => previous_files(&tx, base, &repository, &id).await?,
        None => None,
    };

    let repository_key = snapshot
        .repository
        .repository_key
        .as_deref()
        .ok_or("memory requires a repository key")?;
    tx.execute(
        "INSERT INTO repositories VALUES (?1, ?2, ?3, ?4) ON CONFLICT(id) DO NOTHING",
        (
            &*repository,
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
            (&*id, &*repository, &*snapshot.source),
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
                .execute((&*id, path.as_str(), hash.as_str()))
                .await
                .map_err(db_error)?;
        }
    }
    tx.execute(
        "INSERT INTO inventory_bindings VALUES (?1, ?2) ON CONFLICT DO NOTHING",
        (&*id, &*snapshot.inventory),
    )
    .await
    .map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    let changes = base.map(|_| match previous.as_ref() {
        Some(previous) => compare(previous, &snapshot.files),
        None => Changes::default(),
    });
    super::print_json(&Capture {
        snapshot: &id,
        source_fingerprint: &snapshot.source,
        inventory_fingerprint: &snapshot.inventory,
        files: snapshot.files.len(),
        reused: !created,
        base,
        changes,
    })
}
