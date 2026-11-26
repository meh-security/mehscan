//! Advisory publications on a dedicated Turso native sync replica.
mod resolution;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{Value, json};
use turso::{
    Connection,
    sync::{Builder, Database},
    transaction::TransactionBehavior,
};

use super::{
    Snapshot, assessments, check_store_file, db_error, fingerprint, load_snapshot, lock_store,
    open_local, open_store_lock, resolve_store,
};

const PROJECT_PULL_TIMEOUT: Duration = Duration::from_secs(15);

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

const LINEAGE_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS publication_lineage (
        publication_id TEXT PRIMARY KEY NOT NULL REFERENCES assessment_batches(id),
        prepared_inventory TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS upstream_prepared_inventory ON publication_lineage(prepared_inventory);
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

pub(super) struct Baseline {
    pub(super) snapshot: String,
    pub(super) inventory: String,
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
    sharing: Option<mehscan_core::ReviewSharingBinding>,
}

#[derive(Serialize)]
struct PublishedReview {
    id: String,
    publisher_label: String,
    attempt_status: String,
    assessments: Vec<assessments::Assessment>,
    file_dependencies: Vec<FileDependency>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolution: Option<Value>,
}

enum Operation {
    Init,
    Pull,
    PullContext(Selection, Option<Baseline>, String),
    Push,
    Status,
    Checkpoint,
    Context(Selection),
    Stage {
        selection: Selection,
        batch: String,
        label: String,
        content: Publication,
        resolution: Option<resolution::Record>,
    },
}

impl Operation {
    fn bootstraps(&self) -> bool {
        matches!(self, Self::Init | Self::Pull | Self::PullContext(..))
    }
}

pub(super) fn help() {
    println!(
        "\n  mehscan memory sync init|pull|push|status|checkpoint --replica FILE --remote URL --repository-key KEY --source-root ROOT\n  mehscan memory sync context|stage --replica FILE --remote URL --repository-key KEY --source-root ROOT --inventory DIR --stream STREAM\n  Run init once per upstream and again to enable shared resolutions on older upstreams. Writers pull the initialized schema before staging.\n  Stage requires --batch ID --publisher-label LABEL [--store LOCAL_FILE] [--resolution FILE]. Turso credentials come from MEHSCAN_TURSO_AUTH_TOKEN."
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
            let selection = selection(snapshot, &repository_key, stream)?;
            if operation.as_deref() == Some("stage") {
                let batch = args.required("--batch")?;
                let label = args.required("--publisher-label")?;
                if label.trim().is_empty() || label.len() > 256 {
                    return Err("publisher label must be nonempty and at most 256 bytes".into());
                }
                let store = args.optional("--store").map(PathBuf::from);
                let resolution = args
                    .optional("--resolution")
                    .map(|path| resolution::Record::load(Path::new(&path), &root))
                    .transpose()?;
                let store = resolve_store(store.as_deref(), &root, &selection.snapshot.repository)?;
                args.finish()?;
                let mut content = load_local(&store, &selection, &batch)?;
                if content.sharing.is_some() {
                    return Err(
                        "publish audience-bound reviews through the enrolled sharing service"
                            .into(),
                    );
                }
                if let Some(record) = &resolution {
                    record.select_assessment(&mut content, &selection.snapshot)?;
                }
                Operation::Stage {
                    selection,
                    batch,
                    label,
                    content,
                    resolution,
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
    crate::print_json(&run_bound(
        &replica,
        &remote,
        &repository_key,
        local_endpoint,
        operation,
    )?)
}

fn selection(
    snapshot: Snapshot,
    repository_key: &str,
    stream: String,
) -> Result<Selection, String> {
    if snapshot.repository.repository_key.as_deref() != Some(repository_key) {
        return Err("memory sync inventory belongs to a different repository".into());
    }
    let repository = fingerprint(&snapshot.repository)?;
    let source_snapshot = snapshot.id(&repository)?;
    Ok(Selection {
        snapshot,
        repository,
        source_snapshot,
        stream,
    })
}

pub(super) fn pull_project(
    replica: &Path,
    remote: &str,
    repository_key: &str,
    snapshot: Snapshot,
    stream: String,
    baseline: Option<Baseline>,
) -> Result<Value, String> {
    let local_endpoint = validate_remote(remote)?;
    let selection = selection(snapshot, repository_key, stream)?;
    let scope = fingerprint(&(
        "mehscan-project-view/v1",
        remote,
        repository_key,
        &selection.repository,
        &selection.source_snapshot,
        &selection.snapshot.inventory,
        &selection.stream,
        baseline.as_ref().map(|b| (&b.snapshot, &b.inventory)),
    ))?;
    let cached = replica.with_file_name(format!("published-{scope}.json"));
    let result = run_bound(
        replica,
        remote,
        repository_key,
        local_endpoint,
        Operation::PullContext(selection, baseline, scope.clone()),
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    match result {
        Ok(receipt) => Ok(receipt),
        Err(reason)
            if reason == "project context replica is busy"
                || reason.starts_with("project refresh failed:")
                || reason.starts_with("project context pull timed out") =>
        {
            check_store_file(&cached)?;
            let view: Value = fs::File::open(&cached)
                .ok()
                .and_then(|file| serde_json::from_reader(file).ok())
                .filter(|view: &Value| {
                    view["scope"] == scope && view["context"]["authority"] == "upstream_context"
                })
                .ok_or_else(|| reason.clone())?;
            let fetched = view["fetched_at"].as_u64().ok_or_else(|| reason.clone())?;
            let mut receipt = json!({"status":"cached", "reason":reason, "fetched_at":fetched, "age_seconds":now.saturating_sub(fetched), "context":view["context"]});
            if !view["baseline"].is_null() {
                receipt["baseline"] = view["baseline"].clone();
            }
            Ok(receipt)
        }
        Err(reason) => Err(reason),
    }
}

fn save_project_view(replica: &Path, scope: &str, receipt: &Value) -> Result<(), std::io::Error> {
    let cached = replica.with_file_name(format!("published-{scope}.json"));
    let fetched_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(std::io::Error::other)?
        .as_secs();
    let view = json!({"scope":scope, "fetched_at":fetched_at, "context":receipt["context"], "baseline":receipt["baseline"]});
    let mut file = tempfile::NamedTempFile::new_in(cached.parent().unwrap())?;
    serde_json::to_writer(&mut file, &view)?;
    file.as_file().sync_all()?;
    file.persist(cached)?;
    Ok(())
}

fn run_bound(
    replica: &Path,
    remote: &str,
    repository_key: &str,
    local_endpoint: bool,
    operation: Operation,
) -> Result<Value, String> {
    check_store_file(replica)?;
    let project_pull = matches!(&operation, Operation::PullContext(..));
    let _lock = if project_pull {
        let lock = open_store_lock(replica)?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|error| {
            if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() {
                "project context replica is busy".into()
            } else {
                error.to_string()
            }
        })?;
        lock
    } else {
        lock_store(replica)?
    };
    bind_replica(replica, remote, repository_key, operation.bootstraps())?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?
        .block_on(async {
            let operation = operate(replica, remote, repository_key, local_endpoint, operation);
            if project_pull {
                tokio::time::timeout(PROJECT_PULL_TIMEOUT, operation)
                    .await
                    .map_err(|_| {
                        format!(
                            "project context pull timed out after {} seconds",
                            PROJECT_PULL_TIMEOUT.as_secs()
                        )
                    })?
            } else {
                operation.await
            }
        })
}

pub(super) fn validate_remote(remote: &str) -> Result<bool, String> {
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
        let sharing = super::shared::binding(&conn).await?;
        if let Some(binding) = &sharing {
            super::shared::validate_binding(&selection.snapshot.repository, binding)?;
        }
        Ok(Publication {
            attempt_status: status,
            assessments: assessments::read_assessments(&conn, batch).await?,
            dependencies,
            sharing,
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
    let mut result = json!({
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
    });
    if let Some(binding) = content.sharing {
        result["sharing"] = json!(binding);
    }
    if let Some(comparison) = selection.snapshot.comparison {
        result["comparison"] = json!(comparison);
    }
    Ok(result)
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
) -> Result<(bool, bool), String> {
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
    let created = !check_repository(&conn, repository_key).await?;
    if created {
        seed_schema(&mut conn, repository_key).await?;
    } else if resolution::available(&conn).await? && lineage_available(&conn).await? {
        return Ok((false, false));
    } else {
        conn.execute_batch(LINEAGE_SCHEMA).await.map_err(db_error)?;
        conn.execute_batch(resolution::SCHEMA)
            .await
            .map_err(db_error)?;
    }
    let push = db.push().await.map_err(db_error);
    let check: Result<bool, String> = async {
        let (verifier, upstream) = open_replica(
            &scratch.path().join("verify.turso"),
            remote,
            local_endpoint,
            true,
        )
        .await?;
        verifier.pull().await.map_err(db_error)?;
        Ok(check_repository(&upstream, repository_key).await?
            && resolution::available(&upstream).await?
            && lineage_available(&upstream).await?)
    }
    .await;
    match (push, check) {
        (_, Ok(true)) => Ok((created, !created)),
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
    tx.execute_batch(LINEAGE_SCHEMA).await.map_err(db_error)?;
    tx.execute_batch(DEPENDENCY_SCHEMA)
        .await
        .map_err(db_error)?;
    tx.execute_batch(resolution::SCHEMA)
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
    let bootstrap = operation.bootstraps();
    let refresh_error = |reason: String| {
        if matches!(operation, Operation::PullContext(..)) {
            format!("project refresh failed: {reason}")
        } else {
            reason
        }
    };
    let (db, mut conn) = open_replica(replica, remote, local_endpoint, bootstrap)
        .await
        .map_err(&refresh_error)?;
    let initialized = check_repository(&conn, repository_key).await?;
    match operation {
        Operation::Init => {
            let (created, upgraded) =
                initialize_upstream(replica, remote, repository_key, local_endpoint).await?;
            db.pull().await.map_err(db_error)?;
            if !check_repository(&conn, repository_key).await?
                || !resolution::available(&conn).await?
                || !lineage_available(&conn).await?
            {
                return Err("replica did not receive the upstream publication schema".into());
            }
            Ok(
                json!({"status":"initialized","initialized":true,"created":created,"upgraded":upgraded}),
            )
        }
        Operation::Pull | Operation::PullContext(..) => {
            let changed = db.pull().await.map_err(db_error).map_err(&refresh_error)?;
            let initialized = check_repository(&conn, repository_key).await?;
            let stats = db.stats().await.map_err(db_error)?;
            if matches!(operation, Operation::PullContext(..)) && stats.cdc_operations != 0 {
                return Err("project context replica contains unpublished writes".into());
            }
            let pull = json!({"status":"pulled","changed":changed,"initialized":initialized,"elapsed_ms":started.elapsed().as_millis(),"sync":stats});
            if let Operation::PullContext(selection, baseline, scope) = operation {
                let current = context(&conn, &selection, initialized, None).await?;
                let mut receipt = json!({"status": if initialized { "pulled" } else { "uninitialized" }, "pull": pull, "context": current});
                if let Some(baseline) = baseline {
                    receipt["baseline"] = json!({"snapshot":baseline.snapshot,"inventory_fingerprint":baseline.inventory,
                        "context":context(&conn, &selection, initialized, Some(&baseline)).await?});
                }
                // Publish the cache while still holding the replica lock, so an older
                // refresh cannot overwrite a newer view after a slow serialization.
                if initialized && let Err(error) = save_project_view(replica, &scope, &receipt) {
                    receipt["cache_error"] = json!(error.to_string());
                }
                Ok(receipt)
            } else {
                Ok(pull)
            }
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
        Operation::Context(selection) => context(&conn, &selection, initialized, None).await,
        Operation::Stage {
            selection,
            batch,
            label,
            content,
            resolution,
        } => {
            if !initialized {
                return Err("upstream publication schema is uninitialized; run memory sync init and pull before staging".into());
            }
            let (publication, body) = if let Some(record) = &resolution {
                if !resolution::available(&conn).await? {
                    return Err("shared resolutions require memory sync init on the upstream, followed by pull".into());
                }
                let digest = fingerprint(&(
                    "mehscan-resolution/v1",
                    repository_key,
                    &batch,
                    &label,
                    record,
                ))?;
                let id = format!("{}{digest}", resolution::ID_PREFIX);
                let body = serde_json::to_string(record).map_err(|error| error.to_string())?;
                if let Some(existing) = resolution::body(&conn, &id).await? {
                    if existing != body {
                        return Err("staged resolution content differs".into());
                    }
                    return Ok(
                        json!({"status":"staged","publication":id,"assessments":1,"reused":true}),
                    );
                }
                let scratch = upstream_scratch(replica)?;
                let (verifier, fresh) = open_replica(
                    &scratch.path().join("parents.turso"),
                    remote,
                    local_endpoint,
                    true,
                )
                .await?;
                verifier.pull().await.map_err(db_error)?;
                if !check_repository(&fresh, repository_key).await?
                    || !resolution::available(&fresh).await?
                {
                    return Err("upstream shared resolution schema is unavailable".into());
                }
                let published = read_publications(&fresh, &selection, true, None).await?;
                // A restored replica may restage a record that the upstream already has.
                if let Some(existing) = resolution::body(&fresh, &id).await? {
                    if existing != body {
                        return Err("upstream resolution content differs".into());
                    }
                    if !published.iter().any(|item| item.id == id)
                        || !resolution::project(&published).is_applied(&id)
                    {
                        return Err("upstream resolution is incomplete".into());
                    }
                    db.pull().await.map_err(db_error)?;
                    return Ok(
                        json!({"status":"staged","publication":id,"assessments":1,"reused":true}),
                    );
                }
                record
                    .validate_parents(&content.assessments[0], &resolution::project(&published))?;
                (id, Some(body))
            } else {
                (
                    fingerprint(&("mehscan-publication/v1", repository_key, &batch, &label))?,
                    None,
                )
            };
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .await
                .map_err(db_error)?;
            let added = tx.execute(
                "INSERT INTO assessment_batches VALUES (?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(id) DO NOTHING",
                (publication.as_str(), repository_key, selection.repository.as_str(), selection.source_snapshot.as_str(),
                    selection.snapshot.inventory.as_str(), selection.stream.as_str(), label.as_str(), content.attempt_status.as_str()),
            ).await.map_err(db_error)?;
            if let Some(prepared) = &selection.snapshot.prepared_inventory
                && lineage_available(&tx).await?
            {
                tx.execute(
                    "INSERT INTO publication_lineage VALUES (?1,?2) ON CONFLICT DO NOTHING",
                    (publication.as_str(), prepared.as_str()),
                )
                .await
                .map_err(db_error)?;
            }
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
                if let Some(body) = body {
                    tx.execute(
                        "INSERT INTO review_resolutions VALUES (?1, ?2)",
                        (publication.as_str(), body.as_str()),
                    )
                    .await
                    .map_err(db_error)?;
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
    let resolution = if resolution::available(conn).await? {
        resolution::body(conn, id).await?
    } else {
        None
    };
    if id.starts_with(resolution::ID_PREFIX) && resolution.is_none() {
        return Err(format!("publication {id} is missing its resolution record"));
    }
    let lineage: Option<String> = if lineage_available(conn).await? {
        let mut rows = conn
            .query(
                "SELECT prepared_inventory FROM publication_lineage WHERE publication_id = ?1",
                (id,),
            )
            .await
            .map_err(db_error)?;
        rows.next()
            .await
            .map_err(db_error)?
            .map(|row| row.get(0))
            .transpose()
            .map_err(db_error)?
    } else {
        None
    };
    fingerprint(&(metadata, assessments, dependencies, resolution, lineage)).map(Some)
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

async fn lineage_available(conn: &Connection) -> Result<bool, String> {
    let mut rows = conn
        .query(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'publication_lineage'",
            (),
        )
        .await
        .map_err(db_error)?;
    Ok(rows.next().await.map_err(db_error)?.is_some())
}

async fn context(
    conn: &Connection,
    selection: &Selection,
    initialized: bool,
    baseline: Option<&Baseline>,
) -> Result<Value, String> {
    let resolution_enabled = initialized && resolution::available(conn).await?;
    let publications = if initialized {
        read_publications(conn, selection, resolution_enabled, baseline).await?
    } else {
        Vec::new()
    };
    let mut source_reviews = Vec::new();
    if initialized && lineage_available(conn).await? {
        let (snapshot, prepared) = baseline.map_or(
            (&selection.source_snapshot, &selection.snapshot.inventory),
            |base| (&base.snapshot, &base.inventory),
        );
        let key = selection
            .snapshot
            .repository
            .repository_key
            .as_deref()
            .ok_or("missing repository key")?;
        let mut rows = conn
            .query(
                "SELECT DISTINCT b.inventory_fingerprint FROM assessment_batches b
             JOIN publication_lineage l ON l.publication_id = b.id
             WHERE b.repository_key = ?1 AND b.repository_id = ?2 AND b.snapshot_id = ?3
                 AND b.stream = ?4 AND l.prepared_inventory = ?5 AND b.inventory_fingerprint != ?5
             ORDER BY b.inventory_fingerprint",
                (
                    key,
                    selection.repository.as_str(),
                    snapshot.as_str(),
                    selection.stream.as_str(),
                    prepared.as_str(),
                ),
            )
            .await
            .map_err(db_error)?;
        while let Some(row) = rows.next().await.map_err(db_error)? {
            let effective = Baseline {
                snapshot: snapshot.clone(),
                inventory: row.get(0).map_err(db_error)?,
            };
            let history =
                read_publications(conn, selection, resolution_enabled, Some(&effective)).await?;
            source_reviews
                .push(json!({"effective_inventory":effective.inventory,"publications":history}));
        }
    }
    let mut verdicts = BTreeMap::<String, BTreeSet<String>>::new();
    for publication in &publications {
        for assessment in &publication.assessments {
            verdicts
                .entry(assessment.subject_key.clone())
                .or_default()
                .insert(assessment.verdict.clone());
        }
    }
    verdicts.retain(|_, values| values.len() > 1);
    Ok(
        json!({"authority":"upstream_context","source_review_history":source_reviews,"publications":publications,"conflicting_verdicts":verdicts,
        "resolution_enabled":resolution_enabled,"review_state":resolution::project(&publications)}),
    )
}

async fn read_publications(
    conn: &Connection,
    selection: &Selection,
    resolution_enabled: bool,
    baseline: Option<&Baseline>,
) -> Result<Vec<PublishedReview>, String> {
    let (snapshot, inventory) = baseline.map_or(
        (
            selection.source_snapshot.as_str(),
            selection.snapshot.inventory.as_str(),
        ),
        |baseline| (baseline.snapshot.as_str(), baseline.inventory.as_str()),
    );
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
                snapshot,
                inventory,
                selection.stream.as_str(),
            ),
        )
        .await
        .map_err(db_error)?;
    let mut publications = Vec::new();
    while let Some(row) = rows.next().await.map_err(db_error)? {
        let id: String = row.get(0).map_err(db_error)?;
        let (assessments, dependencies) = published_contents(conn, &id).await?;
        let resolution = if resolution_enabled && id.starts_with(resolution::ID_PREFIX) {
            resolution::body(conn, &id)
                .await?
                .map(|body| serde_json::from_str(&body).unwrap_or(Value::Null))
        } else {
            None
        };
        publications.push(PublishedReview {
            id,
            publisher_label: row.get(1).map_err(db_error)?,
            attempt_status: row.get(2).map_err(db_error)?,
            assessments,
            file_dependencies: dependencies,
            resolution,
        });
    }
    Ok(publications)
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

            let id = format!("{}{}", resolution::ID_PREFIX, "0".repeat(64));
            for conn in [&writer, &reader] {
                conn.execute("INSERT INTO assessment_batches VALUES (?1,'repo:1','repo','snap','inv','main','writer','finished')", (id.as_str(),)).await.unwrap();
            }
            writer.execute("INSERT INTO review_resolutions VALUES (?1, 'original')", (id.as_str(),)).await.unwrap();
            assert!(confirm_publications(&writer, &reader).await.unwrap_err().contains("missing its resolution record"));
            reader.execute("INSERT INTO review_resolutions VALUES (?1, 'changed')", (id.as_str(),)).await.unwrap();
            assert_eq!(confirm_publications(&writer, &reader).await.unwrap_err(), format!("publication {id} content differs"));
            reader.execute("UPDATE review_resolutions SET body = 'original' WHERE publication_id = ?1", (id.as_str(),)).await.unwrap();
            assert_eq!(confirm_publications(&writer, &reader).await.unwrap(), 2);
        });
    }

    #[test]
    fn resolution_projection_waits_for_complete_ancestors() {
        super::super::local_runtime().unwrap().block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let (_db, mut conn) = open_local(&temp.path().join("resolution.db"), false).await.unwrap();
            seed_schema(&mut conn, "repo:1").await.unwrap();
            let pending = format!("mehscanDecision/v1:{}", "1".repeat(64));
            let final_decision = format!("mehscanDecision/v1:{}", "2".repeat(64));
            let resolution_id = format!("{}{}", resolution::ID_PREFIX, "3".repeat(64));
            for (publication, decision, verdict) in [
                ("original", pending.as_str(), "needs_review"),
                (resolution_id.as_str(), final_decision.as_str(), "not_issue"),
            ] {
                conn.execute("INSERT INTO assessment_batches VALUES (?1,'repo:1','repo','snap','inv','main','writer','finished')", (publication,)).await.unwrap();
                conn.execute("INSERT INTO assessments VALUES (?1,?1,'review','subject','basis','response',?2,'medium','summary')", (decision, verdict)).await.unwrap();
                conn.execute("INSERT INTO batch_assessments VALUES (?1,?2)", (publication, decision)).await.unwrap();
                conn.execute("INSERT INTO assessment_evidence VALUES (?1,'primary','ref','a.js',1,1,0,5,NULL)", (decision,)).await.unwrap();
            }
            let source_hash = "a".repeat(64);
            conn.execute("INSERT INTO published_inputs VALUES ('snap','a.js',?1)", (source_hash.as_str(),)).await.unwrap();
            conn.execute("INSERT INTO published_file_dependencies VALUES (?1,?2,'snap','primary','a.js')", (resolution_id.as_str(), final_decision.as_str())).await.unwrap();
            let (assessments, file_dependencies) = published_contents(&conn, &resolution_id).await.unwrap();
            let candidate = PublishedReview { id: resolution_id.clone(), publisher_label: "writer".into(), attempt_status: "finished".into(), assessments, file_dependencies, resolution: None };
            let (assessments, file_dependencies) = published_contents(&conn, "original").await.unwrap();
            let original = PublishedReview { id: "original".into(), publisher_label: "writer".into(), attempt_status: "finished".into(), assessments, file_dependencies, resolution: None };
            let mut publications = [candidate, original];
            let view = |rows: &[PublishedReview]| json!(resolution::project(rows));
            let missing = view(&publications);
            assert_eq!(missing["findings"]["subject"]["status"], "needs_review");
            assert_eq!(missing["unapplied_resolutions"], json!([resolution_id]));
            publications[0].resolution = Some(json!({"decision_id":final_decision,"parents":[resolution_id],"reviewer_kind":"engineer","rationale":"source evidence"}));
            assert_eq!(view(&publications), missing);
            publications[0].resolution.as_mut().unwrap()["parents"] = json!([pending]);
            let applied = view(&publications);
            assert_eq!(applied["findings"]["subject"]["status"], "settled");
            assert_eq!(applied["findings"]["subject"]["current"][0]["id"], resolution_id);
            assert_eq!(applied["unapplied_resolutions"], json!([]));
            publications.swap(0, 1);
            assert_eq!(view(&publications), applied);
        });
    }
}
