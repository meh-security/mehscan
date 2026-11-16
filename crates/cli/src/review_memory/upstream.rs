//! Advisory publications on a dedicated Turso native sync replica.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::Serialize;
use serde_json::{Value, json};
use turso::{Connection, sync::Builder, transaction::TransactionBehavior};

use super::{
    Snapshot, assessments, check_store_file, db_error, fingerprint, load_snapshot, lock_store,
    open_local, resolve_store,
};

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS upstream_repository (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        repository_key TEXT NOT NULL UNIQUE,
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
        "\n  mehscan memory sync pull|push|status|checkpoint --replica FILE --remote URL --repository-key KEY --source-root ROOT\n  mehscan memory sync context|stage --replica FILE --remote URL --repository-key KEY --source-root ROOT --inventory DIR --stream STREAM\n  Stage requires --batch ID --publisher-label LABEL [--store LOCAL_FILE]. Turso credentials come from MEHSCAN_TURSO_AUTH_TOKEN."
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
        Some("pull" | "push" | "status" | "checkpoint") => {
            args.finish()?;
            match operation.as_deref() {
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
    let bootstrap = matches!(operation, Operation::Pull);
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
            return Err("use memory sync pull with a new dedicated replica file".into());
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

async fn operate(
    replica: &Path,
    remote: &str,
    repository_key: &str,
    local_endpoint: bool,
    operation: Operation,
) -> Result<Value, String> {
    let started = Instant::now();
    let path = replica.to_str().ok_or("replica path must be UTF-8")?;
    let mut builder = Builder::new_remote(path)
        .with_remote_url(remote)
        .with_client_name("mehscan")
        .bootstrap_if_empty(matches!(operation, Operation::Pull));
    if !local_endpoint && let Ok(token) = std::env::var("MEHSCAN_TURSO_AUTH_TOKEN") {
        builder = builder.with_auth_token(token);
    }
    let db = builder.build().await.map_err(db_error)?;
    let mut conn = db.connect().await.map_err(db_error)?;
    conn.execute("PRAGMA foreign_keys = ON", ())
        .await
        .map_err(db_error)?;
    let initialized = check_repository(&conn, repository_key).await?;
    match operation {
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
            db.push().await.map_err(db_error)?;
            let stats = db.stats().await.map_err(db_error)?;
            Ok(json!({"status":"pushed","elapsed_ms":started.elapsed().as_millis(),"sync":stats}))
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
            let publication =
                fingerprint(&("mehscan-publication/v1", repository_key, &batch, &label))?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .await
                .map_err(db_error)?;
            if !initialized {
                tx.execute_batch(SCHEMA).await.map_err(db_error)?;
                tx.execute_batch(assessments::CONTENT_SCHEMA)
                    .await
                    .map_err(db_error)?;
                tx.execute_batch(DEPENDENCY_SCHEMA)
                    .await
                    .map_err(db_error)?;
                tx.execute("INSERT INTO upstream_repository VALUES (1,?1,1) ON CONFLICT(singleton) DO NOTHING", (repository_key,)).await.map_err(db_error)?;
            }
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
    let mut empty = true;
    let mut has_repository = false;
    while let Some(row) = tables.next().await.map_err(db_error)? {
        empty = false;
        has_repository |= row.get::<String>(0).map_err(db_error)? == "upstream_repository";
    }
    drop(tables);
    if empty {
        return Ok(false);
    }
    if !has_repository {
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
    Ok(true)
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
            let assessments = assessments::read_assessments(conn, &id).await?;
            let dependencies = read_dependencies(conn, &id,
                "SELECT a.id, a.decision_id, d.role, d.path, f.sha256
                 FROM batch_assessments b JOIN assessments a ON a.id = b.assessment_id
                 JOIN published_file_dependencies d ON d.publication_id = b.batch_id AND d.assessment_id = a.id
                 JOIN published_inputs f ON f.snapshot_id = d.snapshot_id AND f.path = d.path
                 WHERE b.batch_id = ?1 ORDER BY a.id, d.role, d.path",
            ).await?;
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
