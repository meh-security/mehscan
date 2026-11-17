//! Advisory publications on a dedicated Turso native sync replica.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::Serialize;
use serde_json::{Value, json};
use turso::{
    Connection,
    sync::{Builder, Database},
    transaction::TransactionBehavior,
};

use super::{
    Snapshot, assessments, check_store_file, db_error, fingerprint, load_snapshot, lock_store,
    open_local, resolve_store,
};

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS upstream_repository (
        singleton INTEGER NOT NULL UNIQUE CHECK (singleton = 1),
        repository_key TEXT PRIMARY KEY NOT NULL,
        version INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS assessment_batches (
        id TEXT PRIMARY KEY NOT NULL,
        repository_key TEXT NOT NULL REFERENCES upstream_repository(repository_key),
        repository_id TEXT NOT NULL,
        snapshot_id TEXT NOT NULL,
        inventory_fingerprint TEXT NOT NULL,
        stream TEXT NOT NULL,
        publisher_label TEXT NOT NULL,
        attempt_status TEXT NOT NULL CHECK (attempt_status IN ('finished', 'incomplete'))
    );
    CREATE INDEX IF NOT EXISTS upstream_batch_scope
        ON assessment_batches(repository_id, snapshot_id, inventory_fingerprint, stream, id);
";

const DEPENDENCY_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS published_inputs (
        snapshot_id TEXT NOT NULL,
        path TEXT NOT NULL,
        sha256 TEXT,
        PRIMARY KEY (snapshot_id, path)
    );
    CREATE TABLE IF NOT EXISTS published_file_dependencies (
        publication_id TEXT NOT NULL REFERENCES assessment_batches(id),
        assessment_id TEXT NOT NULL REFERENCES assessments(id),
        snapshot_id TEXT NOT NULL,
        role TEXT NOT NULL,
        path TEXT NOT NULL,
        PRIMARY KEY (publication_id, assessment_id, role, path),
        FOREIGN KEY (snapshot_id, path) REFERENCES published_inputs(snapshot_id, path)
    );
";

const REQUIRED_TABLES: &[&str] = &[
    "assessment_batches",
    "assessment_evidence",
    "assessment_questions",
    "assessments",
    "batch_assessments",
    "published_file_dependencies",
    "published_inputs",
    "upstream_repository",
];

struct Selection {
    snapshot: Snapshot,
    repository: String,
    source_snapshot: String,
    stream: String,
}

#[derive(Serialize)]
struct FileDependency {
    #[serde(skip)]
    assessment_id: String,
    decision_id: String,
    role: String,
    path: String,
    sha256: Option<String>,
}

struct Publication {
    attempt_status: String,
    assessments: Vec<assessments::Assessment>,
    dependencies: Vec<FileDependency>,
}

enum Operation {
    Init,
    Pull,
    Push,
    Status,
    Checkpoint,
    Context(Selection),
    Stage {
        selection: Selection,
        batch: String,
        label: String,
        content: Publication,
    },
}

pub(super) fn help() {
    println!(
        "\n  mehscan memory sync init|pull|push|status|checkpoint --replica FILE --remote URL --repository-key KEY --source-root ROOT\n  mehscan memory sync context|stage --replica FILE --remote URL --repository-key KEY --source-root ROOT --inventory DIR --stream STREAM\n  Run init once per upstream. Writers pull the initialized schema before staging.\n  Stage requires --batch ID --publisher-label LABEL [--store LOCAL_FILE]. Turso credentials come from MEHSCAN_TURSO_AUTH_TOKEN."
    );
}

pub(super) fn run(mut arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let operation = arguments.next();
    let mut args = crate::ParsedArguments::parse(arguments)?;
    if args.help || matches!(operation.as_deref(), None | Some("help" | "--help" | "-h")) {
        help();
        return Ok(());
    }
    let replica = PathBuf::from(args.required("--replica")?);
    let remote = args.required("--remote")?;
    let repository_key = args.required("--repository-key")?;
    if super::is_local_folder_key(&repository_key) {
        return Err(
            "memory sync requires a shared repository key; local folder keys are local only".into(),
        );
    }
    let root = PathBuf::from(args.required("--source-root")?);
    let local_endpoint = validate_remote(&remote)?;
    crate::review_state::outside_source(&replica, &root)?;
    let operation = match operation.as_deref() {
        Some("context" | "stage") => {
            let inventory = PathBuf::from(args.required("--inventory")?);
            let stream = args.required("--stream")?;
            let snapshot = load_snapshot(&root, &inventory, false)?;
            if snapshot.repository.repository_key.as_deref() != Some(&repository_key) {
                return Err("memory sync inventory belongs to a different repository".into());
            }
            let repository = fingerprint(&snapshot.repository)?;
            let source_snapshot = snapshot.id(&repository)?;
            let selection = Selection {
                snapshot,
                repository,
                source_snapshot,
                stream,
            };
            if operation.as_deref() == Some("stage") {
                let batch = args.required("--batch")?;
                let label = args.required("--publisher-label")?;
                if label.trim().is_empty() || label.len() > 256 {
                    return Err("publisher label must be nonempty and at most 256 bytes".into());
                }
                let store = args.optional("--store").map(PathBuf::from);
                let store = resolve_store(store.as_deref(), &root, &selection.snapshot.repository)?;
                args.finish()?;
                let content = load_local(&store, &selection, &batch)?;
                Operation::Stage {
                    selection,
                    batch,
                    label,
                    content,
                }
            } else {
                args.finish()?;
                Operation::Context(selection)
            }
        }
        Some("init" | "pull" | "push" | "status" | "checkpoint") => {
            args.finish()?;
            match operation.as_deref() {
                Some("init") => Operation::Init,
                Some("pull") => Operation::Pull,
                Some("push") => Operation::Push,
                Some("status") => Operation::Status,
                _ => Operation::Checkpoint,
            }
        }
        _ => return Err("unknown memory sync operation; use 'mehscan memory sync --help'".into()),
    };
    check_store_file(&replica)?;
    let _lock = lock_store(&replica)?;
    let bootstrap = matches!(operation, Operation::Init | Operation::Pull);
    bind_replica(&replica, &remote, &repository_key, bootstrap)?;
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?
        .block_on(operate(
            &replica,
            &remote,
            &repository_key,
            local_endpoint,
            operation,
        ))?;
    crate::print_json(&result)
}

fn validate_remote(remote: &str) -> Result<bool, String> {
    let (scheme, address) = remote
        .split_once("://")
        .ok_or("memory sync requires a Turso or HTTP(S) URL")?;
    let host = address.split('/').next().unwrap_or_default();
    let local = scheme == "http"
        && host
            .split(':')
            .next()
            .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost"));
    if host.is_empty()
        || remote.chars().any(|character| {
            character.is_whitespace()
                || character.is_control()
                || matches!(character, '@' | '?' | '#' | '\\')
        })
        || !(local || matches!(scheme, "https" | "turso"))
    {
        return Err("use a Turso or HTTPS URL without credentials, or HTTP on localhost".into());
    }
    Ok(local)
}

fn bind_replica(
    replica: &Path,
    remote: &str,
    repository: &str,
    bootstrap: bool,
) -> Result<(), String> {
    let mut name = replica
        .file_name()
        .ok_or("replica requires a file name")?
        .to_owned();
    name.push(".binding");
    let binding = replica.with_file_name(name);
    check_store_file(&binding)?;
    let expected = fingerprint(&("mehscan-upstream/v1", remote, repository))?;
    if binding.is_file() {
        if fs::read_to_string(&binding).map_err(|error| error.to_string())? != expected {
            return Err("replica is bound to a different upstream or repository".into());
        }
    } else {
        if !bootstrap || replica.exists() {
            return Err("use memory sync init or pull with a new dedicated replica file".into());
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&binding)
            .map_err(|error| error.to_string())?;
        file.write_all(expected.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
    }
    if !bootstrap && !replica.is_file() {
        return Err("replica data is unavailable; run memory sync pull".into());
    }
    Ok(())
}

fn load_local(store: &Path, selection: &Selection, batch: &str) -> Result<Publication, String> {
    if !store.is_file() {
        return Err("memory sync stage requires an existing local review memory store".into());
    }
    let _lock = lock_store(store)?;
    super::local_runtime()?.block_on(async {
        let (_db, conn) = open_local(store, true).await?;
        let version = super::schema_version(&conn).await?;
        if version < 2 {
            return Err("local review memory contains no retained batches".into());
        }
        let mut rows = conn
            .query(
                "SELECT attempt_status FROM assessment_batches
             WHERE id = ?1 AND snapshot_id = ?2 AND inventory_fingerprint = ?3 AND stream = ?4",
                (
                    batch,
                    selection.source_snapshot.as_str(),
                    selection.snapshot.inventory.as_str(),
                    selection.stream.as_str(),
                ),
            )
            .await
            .map_err(db_error)?;
        let status = rows
            .next()
            .await
            .map_err(db_error)?
            .ok_or("retained batch does not match current inventory and stream")?
            .get(0)
            .map_err(db_error)?;
        drop(rows);
        let dependencies = if version >= 4 {
            read_dependencies(
                &conn,
                batch,
                "SELECT a.id, a.decision_id, d.role, d.path, f.sha256
                 FROM batch_assessments b JOIN assessment_batches s ON s.id = b.batch_id
                 JOIN assessments a ON a.id = b.assessment_id
                 JOIN assessment_file_dependencies d ON d.assessment_id = a.id
                 LEFT JOIN snapshot_inputs f ON f.snapshot_id = s.snapshot_id AND f.path = d.path
                 WHERE b.batch_id = ?1 ORDER BY a.id, d.role, d.path",
            )
            .await?
        } else {
            Vec::new()
        };
        Ok(Publication {
            attempt_status: status,
            assessments: assessments::read_assessments(&conn, batch).await?,
            dependencies,
        })
    })
}

pub(super) fn export(
    store: &Path,
    snapshot: Snapshot,
    stream: String,
    batch: &str,
) -> Result<Value, String> {
    let repository = fingerprint(&snapshot.repository)?;
    let source_snapshot = snapshot.id(&repository)?;
    let selection = Selection {
        snapshot,
        repository,
        source_snapshot,
        stream,
    };
    let content = load_local(store, &selection, batch)?;
    Ok(json!({
        "schema_version": 1,
        "batch": batch,
        "repository": selection.snapshot.repository,
        "repository_id": selection.repository,
        "snapshot_id": selection.source_snapshot,
        "source_fingerprint": selection.snapshot.source,
        "inventory_fingerprint": selection.snapshot.inventory,
        "stream": selection.stream,
        "attempt_status": content.attempt_status,
        "assessments": content.assessments,
        "file_dependencies": content.dependencies,
    }))
}

async fn open_replica(
    replica: &Path,
    remote: &str,
    local_endpoint: bool,
    bootstrap: bool,
) -> Result<(Database, Connection), String> {
    let path = replica.to_str().ok_or("replica path must be UTF-8")?;
    let mut builder = Builder::new_remote(path)
        .with_remote_url(remote)
        .with_client_name("mehscan")
        .bootstrap_if_empty(bootstrap);
    if !local_endpoint && let Ok(token) = std::env::var("MEHSCAN_TURSO_AUTH_TOKEN") {
        builder = builder.with_auth_token(token);
    }
    let db = builder.build().await.map_err(db_error)?;
    let conn = db.connect().await.map_err(db_error)?;
    conn.execute("PRAGMA foreign_keys = ON", ())
        .await
        .map_err(db_error)?;
    Ok((db, conn))
}

fn upstream_scratch(replica: &Path) -> Result<tempfile::TempDir, String> {
    let parent = replica
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    tempfile::Builder::new()
        .prefix("mehscan-sync-")
        .tempdir_in(parent)
        .map_err(|error| error.to_string())
}

async fn initialize_upstream(
    replica: &Path,
    remote: &str,
    repository_key: &str,
    local_endpoint: bool,
) -> Result<bool, String> {
    // Provision on a separate replica so init never publishes queued assessments.
    let scratch = upstream_scratch(replica)?;
    let (db, mut conn) = open_replica(
        &scratch.path().join("init.turso"),
        remote,
        local_endpoint,
        true,
    )
    .await?;
    db.pull().await.map_err(db_error)?;
    if check_repository(&conn, repository_key).await? {
        return Ok(false);
    }
    seed_schema(&mut conn, repository_key).await?;
    let push = db.push().await.map_err(db_error);
    let check = async {
        let (verifier, upstream) = open_replica(
            &scratch.path().join("verify.turso"),
            remote,
            local_endpoint,
            true,
        )
        .await?;
        verifier.pull().await.map_err(db_error)?;
        check_repository(&upstream, repository_key).await
    }
    .await;
    match (push, check) {
        (_, Ok(true)) => Ok(true),
        (Ok(()), Ok(false)) => Err("upstream did not confirm the publication schema".into()),
        (Ok(()), Err(error)) => Err(format!("could not verify upstream initialization: {error}")),
        (Err(error), Ok(false)) => Err(error),
        (Err(push), Err(check)) => Err(format!(
            "{push}; upstream initialization check failed: {check}"
        )),
    }
}

async fn seed_schema(conn: &mut Connection, repository_key: &str) -> Result<(), String> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await
        .map_err(db_error)?;
    // Sync replays inserts as upserts on the primary key. A different
    // repository key must collide with the singleton constraint instead.
    tx.execute_batch(SCHEMA).await.map_err(db_error)?;
    tx.execute_batch(assessments::CONTENT_SCHEMA)
        .await
        .map_err(db_error)?;
    tx.execute_batch(DEPENDENCY_SCHEMA)
        .await
        .map_err(db_error)?;
    tx.execute(
        "INSERT INTO upstream_repository VALUES (1,?1,1)",
        (repository_key,),
    )
    .await
    .map_err(db_error)?;
    tx.commit().await.map_err(db_error)
}

async fn operate(
    replica: &Path,
    remote: &str,
    repository_key: &str,
    local_endpoint: bool,
    operation: Operation,
) -> Result<Value, String> {
    let started = Instant::now();
    let bootstrap = matches!(operation, Operation::Init | Operation::Pull);
    let (db, mut conn) = open_replica(replica, remote, local_endpoint, bootstrap).await?;
    let initialized = check_repository(&conn, repository_key).await?;
    match operation {
        Operation::Init => {
            let created =
                initialize_upstream(replica, remote, repository_key, local_endpoint).await?;
            db.pull().await.map_err(db_error)?;
            if !check_repository(&conn, repository_key).await? {
                return Err("replica did not receive the upstream publication schema".into());
            }
            Ok(json!({"status":"initialized","initialized":true,"created":created}))
        }
        Operation::Pull => {
            let changed = db.pull().await.map_err(db_error)?;
            let initialized = check_repository(&conn, repository_key).await?;
            let stats = db.stats().await.map_err(db_error)?;
            Ok(
                json!({"status":"pulled","changed":changed,"initialized":initialized,"elapsed_ms":started.elapsed().as_millis(),"sync":stats}),
            )
        }
        Operation::Push => {
            if !initialized {
                return Err("replica contains no Mehscan publications to push".into());
            }
            let reconciled = match db.push().await {
                Ok(()) => None,
                Err(error) => {
                    let original = db_error(error);
                    let count =
                        reconcile_push(&conn, replica, remote, repository_key, local_endpoint)
                            .await
                            .map_err(|check| {
                                format!(
                                    "{original}; could not confirm publications upstream: {check}"
                                )
                            })?;
                    Some(count)
                }
            };
            let stats = db.stats().await.map_err(db_error)?;
            Ok(json!({"status":"pushed","reconciled":reconciled.is_some(),
                "confirmed_publications":reconciled,"elapsed_ms":started.elapsed().as_millis(),"sync":stats}))
        }
        Operation::Checkpoint => {
            db.checkpoint().await.map_err(db_error)?;
            Ok(json!({"status":"checkpointed"}))
        }
        Operation::Status => {
            let stats = db.stats().await.map_err(db_error)?;
            Ok(json!({"status":"ready","initialized":initialized,"sync":stats}))
        }
        Operation::Context(selection) => context(&conn, &selection, initialized).await,
        Operation::Stage {
            selection,
            batch,
            label,
            content,
        } => {
            if !initialized {
                return Err("upstream publication schema is uninitialized; run memory sync init and pull before staging".into());
            }
            let publication =
                fingerprint(&("mehscan-publication/v1", repository_key, &batch, &label))?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .await
                .map_err(db_error)?;
            let added = tx.execute(
                "INSERT INTO assessment_batches VALUES (?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(id) DO NOTHING",
                (publication.as_str(), repository_key, selection.repository.as_str(), selection.source_snapshot.as_str(),
                    selection.snapshot.inventory.as_str(), selection.stream.as_str(), label.as_str(), content.attempt_status.as_str()),
            ).await.map_err(db_error)?;
            if added != 0 {
                for assessment in &content.assessments {
                    assessments::publish_assessment(&tx, &publication, assessment).await?;
                }
                let snapshot = selection.source_snapshot.as_str();
                for dependency in &content.dependencies {
                    tx.execute(
                        "INSERT INTO published_inputs VALUES (?1,?2,?3) ON CONFLICT DO NOTHING",
                        (
                            snapshot,
                            dependency.path.as_str(),
                            dependency.sha256.as_deref(),
                        ),
                    )
                    .await
                    .map_err(db_error)?;
                    tx.execute("INSERT INTO published_file_dependencies VALUES (?1,?2,?3,?4,?5) ON CONFLICT DO NOTHING",
                        (publication.as_str(), dependency.assessment_id.as_str(), snapshot, dependency.role.as_str(), dependency.path.as_str())).await.map_err(db_error)?;
                }
            }
            tx.commit().await.map_err(db_error)?;
            Ok(
                json!({"status":"staged","publication":publication,"assessments":content.assessments.len(),"reused":added == 0}),
            )
        }
    }
}

async fn check_repository(conn: &Connection, repository: &str) -> Result<bool, String> {
    let mut tables = conn
        .query(
            "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT GLOB 'sqlite_*'
           AND name NOT GLOB 'turso_*' AND name NOT GLOB '__turso_internal_*'",
            (),
        )
        .await
        .map_err(db_error)?;
    let mut names = BTreeSet::new();
    while let Some(row) = tables.next().await.map_err(db_error)? {
        names.insert(row.get::<String>(0).map_err(db_error)?);
    }
    drop(tables);
    if names.is_empty() {
        return Ok(false);
    }
    if !names.contains("upstream_repository") {
        return Err("upstream is not a dedicated Mehscan publication database".into());
    }
    let mut rows = conn
        .query(
            "SELECT repository_key, version FROM upstream_repository WHERE singleton = 1",
            (),
        )
        .await
        .map_err(db_error)?;
    let row = rows
        .next()
        .await
        .map_err(db_error)?
        .ok_or("upstream repository metadata is missing")?;
    if row.get::<String>(0).map_err(db_error)? != repository
        || row.get::<i64>(1).map_err(db_error)? != 1
    {
        return Err("upstream belongs to another repository or uses an unsupported schema".into());
    }
    if REQUIRED_TABLES.iter().any(|table| !names.contains(*table)) {
        return Err("upstream publication schema is incomplete".into());
    }
    Ok(true)
}

async fn reconcile_push(
    local: &Connection,
    replica: &Path,
    remote: &str,
    repository_key: &str,
    local_endpoint: bool,
) -> Result<usize, String> {
    // A pull on the writer can replay pending local changes over remote data.
    // Check from a clean replica so only upstream content can confirm delivery.
    let scratch = upstream_scratch(replica)?;
    let (db, upstream) = open_replica(
        &scratch.path().join("verify.turso"),
        remote,
        local_endpoint,
        true,
    )
    .await?;
    db.pull().await.map_err(db_error)?;
    if !check_repository(&upstream, repository_key).await? {
        return Err("upstream publication schema is uninitialized".into());
    }
    confirm_publications(local, &upstream).await
}

async fn confirm_publications(local: &Connection, upstream: &Connection) -> Result<usize, String> {
    let mut ids = local
        .query("SELECT id FROM assessment_batches ORDER BY id", ())
        .await
        .map_err(db_error)?;
    let mut confirmed = 0;
    while let Some(row) = ids.next().await.map_err(db_error)? {
        let id: String = row.get(0).map_err(db_error)?;
        let expected = publication_fingerprint(local, &id).await?;
        match publication_fingerprint(upstream, &id).await? {
            None => return Err(format!("publication {id} is missing")),
            Some(actual) if Some(actual.as_str()) != expected.as_deref() => {
                return Err(format!("publication {id} content differs"));
            }
            Some(_) => confirmed += 1,
        }
    }
    if confirmed == 0 {
        return Err("replica contains no publications to confirm".into());
    }
    Ok(confirmed)
}

async fn publication_fingerprint(conn: &Connection, id: &str) -> Result<Option<String>, String> {
    let mut rows = conn
        .query(
            "SELECT repository_key, repository_id, snapshot_id, inventory_fingerprint, stream,
                    publisher_label, attempt_status FROM assessment_batches WHERE id = ?1",
            (id,),
        )
        .await
        .map_err(db_error)?;
    let Some(row) = rows.next().await.map_err(db_error)? else {
        return Ok(None);
    };
    let metadata = (0..7)
        .map(|column| row.get::<String>(column).map_err(db_error))
        .collect::<Result<Vec<_>, _>>()?;
    drop(rows);
    let (assessments, dependencies) = published_contents(conn, id).await?;
    fingerprint(&(metadata, assessments, dependencies)).map(Some)
}

async fn published_contents(
    conn: &Connection,
    id: &str,
) -> Result<(Vec<assessments::Assessment>, Vec<FileDependency>), String> {
    let assessments = assessments::read_assessments(conn, id).await?;
    let dependencies = read_dependencies(conn, id,
        "SELECT a.id, a.decision_id, d.role, d.path, f.sha256
         FROM batch_assessments b JOIN assessments a ON a.id = b.assessment_id
         JOIN published_file_dependencies d ON d.publication_id = b.batch_id AND d.assessment_id = a.id
         JOIN published_inputs f ON f.snapshot_id = d.snapshot_id AND f.path = d.path
         WHERE b.batch_id = ?1 ORDER BY a.id, d.role, d.path",
    ).await?;
    Ok((assessments, dependencies))
}

async fn context(
    conn: &Connection,
    selection: &Selection,
    initialized: bool,
) -> Result<Value, String> {
    let mut publications = Vec::new();
    let mut verdicts = BTreeMap::<String, BTreeSet<String>>::new();
    if initialized {
        let repo_key = selection
            .snapshot
            .repository
            .repository_key
            .as_deref()
            .ok_or("missing repository key")?;
        let mut rows = conn
            .query(
                "SELECT id, publisher_label, attempt_status FROM assessment_batches
             WHERE repository_key = ?1 AND repository_id = ?2 AND snapshot_id = ?3
               AND inventory_fingerprint = ?4 AND stream = ?5 ORDER BY id",
                (
                    repo_key,
                    selection.repository.as_str(),
                    selection.source_snapshot.as_str(),
                    selection.snapshot.inventory.as_str(),
                    selection.stream.as_str(),
                ),
            )
            .await
            .map_err(db_error)?;
        while let Some(row) = rows.next().await.map_err(db_error)? {
            let id: String = row.get(0).map_err(db_error)?;
            let (assessments, dependencies) = published_contents(conn, &id).await?;
            for assessment in &assessments {
                verdicts
                    .entry(assessment.subject_key.clone())
                    .or_default()
                    .insert(assessment.verdict.clone());
            }
            publications.push(
                json!({"id":id,"publisher_label":row.get::<String>(1).map_err(db_error)?,
                "attempt_status":row.get::<String>(2).map_err(db_error)?,"assessments":assessments,
                "file_dependencies":dependencies}),
            );
        }
    }
    verdicts.retain(|_, values| values.len() > 1);
    Ok(
        json!({"authority":"upstream_context","publications":publications,"conflicting_verdicts":verdicts}),
    )
}

async fn read_dependencies(
    conn: &Connection,
    batch: &str,
    query: &str,
) -> Result<Vec<FileDependency>, String> {
    let mut result = Vec::new();
    let mut rows = conn.query(query, (batch,)).await.map_err(db_error)?;
    while let Some(row) = rows.next().await.map_err(db_error)? {
        result.push(FileDependency {
            assessment_id: row.get(0).map_err(db_error)?,
            decision_id: row.get(1).map_err(db_error)?,
            role: row.get(2).map_err(db_error)?,
            path: row.get(3).map_err(db_error)?,
            sha256: row.get(4).map_err(db_error)?,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_replayed_initializer_cannot_replace_a_different_repository() {
        super::super::local_runtime().unwrap().block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let (_database, mut conn) = open_local(&temp.path().join("seed.db"), false)
                .await
                .unwrap();
            seed_schema(&mut conn, "repo:1").await.unwrap();
            let replay = "INSERT INTO upstream_repository VALUES (1, ?1, 1)
                         ON CONFLICT(repository_key) DO UPDATE
                         SET singleton = excluded.singleton, version = excluded.version";
            conn.execute(replay, ("repo:1",)).await.unwrap();
            assert!(conn.execute(replay, ("repo:2",)).await.is_err());
            assert!(check_repository(&conn, "repo:1").await.unwrap());
        });
    }

    #[test]
    fn reconciliation_requires_the_full_publication_on_the_upstream() {
        super::super::local_runtime().unwrap().block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let (_local, mut writer) = open_local(&temp.path().join("writer.db"), false).await.unwrap();
            let (_upstream, mut reader) = open_local(&temp.path().join("reader.db"), false).await.unwrap();
            for conn in [&mut writer, &mut reader] {
                seed_schema(conn, "repo:1").await.unwrap();
            }
            let publication = "
                INSERT INTO assessment_batches VALUES ('batch','repo:1','repo','snap','inv','main','writer','finished');
                INSERT INTO assessments VALUES ('assessment','decision','review','subject','basis','response','not_issue','medium','summary');
                INSERT INTO batch_assessments VALUES ('batch','assessment');
            ";
            let proof = "
                INSERT INTO assessment_evidence VALUES ('assessment','citation','ref','a.js',1,1,0,5,'hash');
                INSERT INTO assessment_questions VALUES ('assessment','check',0,'Which control applies?');
                INSERT INTO published_inputs VALUES ('snap','a.js','file-hash');
                INSERT INTO published_file_dependencies VALUES ('batch','assessment','snap','primary','a.js');
            ";
            writer.execute_batch(publication).await.unwrap();
            writer.execute_batch(proof).await.unwrap();
            assert_eq!(confirm_publications(&writer, &reader).await.unwrap_err(), "publication batch is missing");
            reader.execute_batch(publication).await.unwrap();
            assert_eq!(confirm_publications(&writer, &reader).await.unwrap_err(), "publication batch content differs");
            reader.execute_batch(proof).await.unwrap();
            assert_eq!(confirm_publications(&writer, &reader).await.unwrap(), 1);
        });
    }
}
