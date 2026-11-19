//! Attributed, revisioned context for source review.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use mehscan_core::{
    ReviewDecisionRecord, ReviewKnowledgeContext, ReviewKnowledgeOrigin, ReviewKnowledgeRevision,
    ReviewKnowledgeScope, ReviewRepositoryIdentity, ReviewSharingBinding, ReviewStateBinding,
    ReviewSubjectIdentity, ReviewWorkPayload,
};
use serde::Deserialize;
use serde_json::{Value, json};
use turso::{Connection, transaction::TransactionBehavior};

use super::{
    Snapshot, db_error, fingerprint, legacy, load_snapshot, lock_store, open_local, shared,
};

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS review_knowledge (
        repository_id TEXT NOT NULL,
        item_id TEXT NOT NULL,
        revision_id TEXT NOT NULL,
        revision_json TEXT NOT NULL,
        is_head INTEGER NOT NULL,
        PRIMARY KEY (repository_id, item_id, revision_id)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS review_knowledge_head
        ON review_knowledge(repository_id, item_id) WHERE is_head = 1;
";
const REVIEW_AUTHOR: &str = "mehscan:review";

pub(crate) fn premise_revisions(context: &ReviewKnowledgeContext, review: &str) -> Vec<String> {
    let revisions = context.revisions(review);
    context
        .items
        .iter()
        .filter(|item| item.author != REVIEW_AUTHOR && revisions.contains(&item.revision_id))
        .map(|item| item.revision_id.clone())
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Draft {
    key: String,
    author: String,
    origin: ReviewKnowledgeOrigin,
    statement: String,
    #[serde(default)]
    scope: ReviewKnowledgeScope,
    #[serde(default)]
    source_paths: Vec<String>,
    #[serde(default)]
    evidence: Vec<String>,
    observed_at: Option<u64>,
    expires_at: Option<u64>,
    parent_revision: Option<String>,
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| error.to_string())
}

fn text(value: &str, limit: usize) -> bool {
    !value.trim().is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}

fn path_scope(scope: &str, path: &str) -> bool {
    path == scope
        || path
            .strip_prefix(scope)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn applies(scope: &ReviewKnowledgeScope, subject: &ReviewSubjectIdentity) -> bool {
    if let Some(subject_key) = &scope.subject_key {
        return subject_key == &subject.subject_key;
    }
    scope.path.as_ref().is_none_or(|path| {
        path_scope(path, &subject.occurrence.operation.path)
            || matches!(&subject.relationship_scope,
                mehscan_core::ReviewRelationshipScope::SourceToOperation { source, .. }
                    if path_scope(path, &source.path))
    })
}

fn usable(revision: &ReviewKnowledgeRevision, snapshot: &Snapshot, at: u64) -> bool {
    !revision.withdrawn
        && revision.expires_at.is_none_or(|expiry| expiry > at)
        && revision
            .source_sha256
            .iter()
            .all(|(path, hash)| snapshot.files.get(path) == Some(hash))
}

fn affected(scope: &ReviewKnowledgeScope, snapshot: &Snapshot) -> Vec<String> {
    snapshot
        .subjects
        .iter()
        .filter(|(_, subject)| applies(scope, subject))
        .map(|(id, _)| id.clone())
        .collect()
}

pub(crate) struct Reader {
    pub(super) path: Option<PathBuf>,
    _lock: Option<File>,
}

impl Reader {
    pub(crate) fn lock(
        root: &Path,
        repository: &ReviewRepositoryIdentity,
        store: Option<&Path>,
        temporary: bool,
    ) -> Result<Self, String> {
        let path = (!temporary)
            .then(|| super::resolve_store(store, root, repository))
            .transpose()?;
        let lock = path.as_deref().map(lock_store).transpose()?;
        Ok(Self { path, _lock: lock })
    }

    pub(crate) fn load(&self, root: &Path, inventory: &Path) -> Result<Selection, String> {
        let Some(path) = self.path.as_deref().filter(|path| path.is_file()) else {
            return Ok(Selection::default());
        };
        super::local_runtime()?.block_on(async {
            let (_database, conn) = open_local(path, true).await?;
            if !legacy::table_exists(&conn, "review_knowledge").await?
                && !legacy::table_exists(&conn, "review_sharing").await?
            {
                return Ok(Selection::default());
            }
            let snapshot = load_snapshot(root, inventory, false)?;
            select(&conn, &snapshot).await
        })
    }
}

pub(super) async fn select(conn: &Connection, snapshot: &Snapshot) -> Result<Selection, String> {
    let at = now()?;
    let sharing = shared::binding(conn).await?;
    let mut items = revisions(conn, &fingerprint(&snapshot.repository)?, true, None).await?;
    if let Some(binding) = &sharing {
        shared::validate_binding(&snapshot.repository, binding)?;
        items.extend(
            shared::revisions(conn, true, None)
                .await?
                .into_iter()
                .filter_map(|item| shared::for_scan(item, &snapshot.repository.path_prefix)),
        );
    }
    items.retain(|item| usable(item, snapshot, at));
    Ok(Selection { items, sharing })
}

#[derive(Default)]
pub(crate) struct Selection {
    items: Vec<ReviewKnowledgeRevision>,
    pub(crate) sharing: Option<ReviewSharingBinding>,
}

impl Selection {
    pub(crate) fn validate(
        &self,
        payload: &ReviewWorkPayload,
        binding: &ReviewStateBinding,
    ) -> Result<(), String> {
        if self.context(payload, binding)? != payload.knowledge {
            return Err("applicable knowledge changed; request fresh work".into());
        }
        Ok(())
    }

    pub(crate) fn revisions_for(&self, subject: &ReviewSubjectIdentity) -> Vec<&str> {
        self.items
            .iter()
            .filter(|item| item.author != REVIEW_AUTHOR && applies(&item.scope, subject))
            .map(|item| item.revision_id.as_str())
            .collect()
    }

    pub(crate) fn context(
        &self,
        payload: &ReviewWorkPayload,
        binding: &ReviewStateBinding,
    ) -> Result<ReviewKnowledgeContext, String> {
        let mut context = ReviewKnowledgeContext {
            sharing: self.sharing.clone(),
            ..Default::default()
        };
        let mut source_links = 0;
        for item in &self.items {
            let review_ids = payload
                .review_ids
                .iter()
                .filter(|id| {
                    binding
                        .subjects
                        .get(*id)
                        .is_some_and(|subject| applies(&item.scope, subject))
                })
                .collect::<Vec<_>>();
            // Full-plan source assignments may include files with no native
            // question. Their worker narrows these notes to its source windows.
            if !review_ids.is_empty()
                || (payload.review_ids.is_empty()
                    || payload.review_ids == payload.planned_review_ids)
                    && item.scope.subject_key.is_none()
            {
                if item.author == REVIEW_AUTHOR {
                    if source_links >= 32 {
                        context.omitted_source_links += 1;
                        continue;
                    }
                    source_links += 1;
                }
                for id in review_ids {
                    context
                        .by_review
                        .entry(id.clone())
                        .or_default()
                        .push(item.revision_id.clone());
                }
                context.items.push(item.clone());
            }
        }
        if serde_json::to_vec(&context)
            .map_err(|error| error.to_string())?
            .len()
            > 256 * 1024
        {
            return Err("applicable review knowledge exceeds 256 KiB; narrow the review scope or retire old facts".into());
        }
        Ok(context)
    }
}

async fn revisions(
    conn: &Connection,
    repository: &str,
    heads_only: bool,
    item_id: Option<&str>,
) -> Result<Vec<ReviewKnowledgeRevision>, String> {
    if !legacy::table_exists(conn, "review_knowledge").await? {
        return Ok(Vec::new());
    }
    let mut rows = conn
        .query(
            "SELECT revision_json FROM review_knowledge WHERE repository_id = ?1
            AND (?2 = 0 OR is_head = 1) AND (?3 IS NULL OR item_id = ?3)
            ORDER BY item_id, revision_id",
            (repository, i64::from(heads_only), item_id),
        )
        .await
        .map_err(db_error)?;
    let mut items = Vec::new();
    while let Some(row) = rows.next().await.map_err(db_error)? {
        items.push(
            serde_json::from_str(&row.get::<String>(0).map_err(db_error)?)
                .map_err(|error| error.to_string())?,
        );
    }
    Ok(items)
}

fn make_revision(
    repository: &str,
    snapshot: &Snapshot,
    draft: Draft,
) -> Result<ReviewKnowledgeRevision, String> {
    let scope = &draft.scope;
    if !text(&draft.key, 256)
        || !text(&draft.author, 256)
        || !text(&draft.statement, 2048)
        || scope
            .environment
            .as_deref()
            .is_some_and(|env| !text(env, 128))
        || draft.evidence.len() > 8
        || draft.evidence.iter().any(|value| !text(value, 512))
        || draft.source_paths.len() > 8
    {
        return Err("invalid knowledge statement, author, key, environment, or evidence".into());
    }
    if scope
        .path
        .as_ref()
        .is_some_and(|path| !snapshot.files.keys().any(|file| path_scope(path, file)))
        || scope.subject_key.as_ref().is_some_and(|key| {
            !snapshot
                .subjects
                .values()
                .any(|subject| &subject.subject_key == key)
        })
    {
        return Err(
            "knowledge scope must name a path or subject from the current inventory".into(),
        );
    }
    if let Some(expiry) = draft.expires_at {
        if draft.observed_at.is_none_or(|observed| observed >= expiry) {
            return Err("expiring knowledge requires observed_at earlier than expires_at".into());
        }
    }
    let at = now()?;
    if (scope.environment.is_some() && draft.observed_at.is_none())
        || draft.observed_at.is_some_and(|observed| observed > at)
    {
        return Err(
            "environment-scoped knowledge requires a current or past observation time".into(),
        );
    }
    if draft.origin == ReviewKnowledgeOrigin::SourceObservation && draft.source_paths.is_empty() {
        return Err("a source observation requires current inventory source evidence".into());
    }
    let source_sha256 = draft
        .source_paths
        .into_iter()
        .map(|path| {
            let hash = snapshot
                .files
                .get(&path)
                .ok_or_else(|| format!("knowledge source is outside inventory: {path}"))?;
            Ok((path, hash.clone()))
        })
        .collect::<Result<_, String>>()?;
    let evidence = draft
        .evidence
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let item_id = fingerprint(&(
        "review-knowledge-item/v1",
        repository,
        &draft.author,
        &draft.key,
    ))?;
    Ok(ReviewKnowledgeRevision {
        item_id,
        revision_id: String::new(),
        parent_revision: draft.parent_revision,
        key: draft.key,
        author: draft.author,
        origin: draft.origin,
        statement: draft.statement,
        scope: draft.scope,
        source_sha256,
        evidence,
        observed_at: draft.observed_at,
        expires_at: draft.expires_at,
        withdrawn: false,
    })
}

async fn put(
    tx: &Connection,
    repository: &str,
    mut candidate: ReviewKnowledgeRevision,
    automatic: bool,
) -> Result<(ReviewKnowledgeRevision, bool), String> {
    let head = revisions(tx, repository, true, Some(&candidate.item_id))
        .await?
        .pop();
    if let Some(head) = head.as_ref() {
        let mut comparison = candidate.clone();
        comparison.revision_id.clone_from(&head.revision_id);
        comparison.parent_revision.clone_from(&head.parent_revision);
        if automatic {
            comparison.evidence.clone_from(&head.evidence);
        }
        if comparison == *head
            && (automatic
                || candidate.parent_revision == head.parent_revision
                || candidate.parent_revision.as_ref() == Some(&head.revision_id))
        {
            return Ok((head.clone(), false));
        }
        if automatic {
            candidate.parent_revision = Some(head.revision_id.clone());
        }
    }
    if candidate.parent_revision.as_ref() != head.as_ref().map(|item| &item.revision_id) {
        return Err("knowledge revision changed; read its current revision and retry".into());
    }
    candidate.revision_id = fingerprint(&("review-knowledge-revision/v1", &candidate))?;
    tx.execute("UPDATE review_knowledge SET is_head = 0 WHERE repository_id = ?1 AND item_id = ?2 AND is_head = 1",
        (repository, candidate.item_id.as_str())).await.map_err(db_error)?;
    let document = serde_json::to_string(&candidate).map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO review_knowledge VALUES (?1, ?2, ?3, ?4, 1)",
        (
            repository,
            candidate.item_id.as_str(),
            candidate.revision_id.as_str(),
            document,
        ),
    )
    .await
    .map_err(db_error)?;
    Ok((candidate, true))
}

pub(super) fn run(
    command: &str,
    mut args: crate::ParsedArguments,
    root: &Path,
    inventory: &Path,
) -> Result<Value, String> {
    let store = args.optional("--store").map(PathBuf::from);
    let snapshot = load_snapshot(root, inventory, false)?;
    let path = super::resolve_store(store.as_deref(), root, &snapshot.repository)?;
    let item = args.optional("--item");
    let history = args.optional_bool("--history")?.unwrap_or(false);
    let mut draft = None;
    let mut withdrawal = None;
    match command {
        "knowledge-list" => {}
        "knowledge-put" => {
            let input = PathBuf::from(args.required("--input")?);
            crate::review_state::outside_source(&input, root)?;
            if fs::metadata(&input)
                .map_err(|error| error.to_string())?
                .len()
                > 32 * 1024
            {
                return Err("knowledge input exceeds 32 KiB".into());
            }
            let parsed: Draft =
                serde_json::from_slice(&fs::read(input).map_err(|error| error.to_string())?)
                    .map_err(|error| error.to_string())?;
            if parsed.author == REVIEW_AUTHOR || item.is_some() || history {
                return Err(
                    "knowledge put requires a contributor author and an input document".into(),
                );
            }
            draft = Some(parsed);
        }
        "knowledge-withdraw" => {
            let author = args.required("--author")?;
            let parent = args.required("--expected-revision")?;
            if author == REVIEW_AUTHOR || item.is_none() || history {
                return Err("knowledge withdrawal requires a contributor author and --item".into());
            }
            withdrawal = Some((author, parent));
        }
        _ => unreachable!(),
    }
    args.finish()?;
    let _lock = lock_store(&path)?;
    let repository = fingerprint(&snapshot.repository)?;
    super::local_runtime()?.block_on(async {
        if command == "knowledge-list" {
            if !path.is_file() {
                return Ok(json!({"items":[]}));
            }
            let (_database, conn) = open_local(&path, true).await?;
            let at = now()?;
            let mut items = revisions(&conn, &repository, !history, item.as_deref())
                .await?
                .into_iter()
                .map(|revision| {
                    json!({
                        "applicable_to_current_source":usable(&revision,&snapshot,at),
                        "revision":revision
                    })
                })
                .collect::<Vec<_>>();
            if let Some(binding) = shared::binding(&conn).await? {
                shared::validate_binding(&snapshot.repository, &binding)?;
                for revision in shared::revisions(&conn, !history, item.as_deref()).await? {
                    let usable = shared::for_scan(revision.clone(), &snapshot.repository.path_prefix)
                        .is_some_and(|local| usable(&local, &snapshot, at));
                    items.push(json!({"applicable_to_current_source":usable,"sharing":binding,"revision":revision}));
                }
            }
            return Ok(json!({"items":items}));
        }
        if withdrawal.is_some() && !path.is_file() {
            return Err("unknown knowledge item".into());
        }
        let (_database, mut conn) = open_local(&path, false).await?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await
            .map_err(db_error)?;
        super::prepare_schema(&tx).await?;
        if let Some(binding) = shared::binding(&tx).await? {
            shared::validate_binding(&snapshot.repository, &binding)?;
        }
        tx.execute_batch(SCHEMA).await.map_err(db_error)?;
        let candidate = if let Some(draft) = draft {
            make_revision(&repository, &snapshot, draft)?
        } else {
            let (author, parent) = withdrawal.unwrap();
            let mut head = revisions(&tx, &repository, true, item.as_deref())
                .await?
                .pop()
                .ok_or("unknown knowledge item")?;
            if head.author != author {
                return Err("knowledge author does not match the item".into());
            }
            head.revision_id.clear();
            head.parent_revision = Some(parent);
            head.withdrawn = true;
            head
        };
        let prior = revisions(&tx, &repository, true, Some(&candidate.item_id))
            .await?
            .pop();
        let (revision, changed) = put(&tx, &repository, candidate, false).await?;
        tx.commit().await.map_err(db_error)?;
        let ids = if changed {
            affected(&revision.scope, &snapshot)
                .into_iter()
                .chain(
                    prior
                        .iter()
                        .flat_map(|item| affected(&item.scope, &snapshot)),
                )
                .collect::<BTreeSet<_>>()
        } else {
            BTreeSet::new()
        };
        Ok(json!({"revision":revision,"changed":changed,"affected_review_ids":ids}))
    })
}

pub(super) async fn retain(
    tx: &Connection,
    snapshot: &Snapshot,
    repository: &str,
    records: &[ReviewDecisionRecord],
) -> Result<usize, String> {
    tx.execute_batch(SCHEMA).await.map_err(db_error)?;
    let mut written = 0;
    for record in records {
        let Some(trace) = &record.response.investigation else {
            continue;
        };
        for artifact in trace.decisive_artifacts.iter().take(4) {
            let location = &artifact.location;
            if !snapshot.files.contains_key(&location.path) {
                continue;
            }
            let scope = ReviewKnowledgeScope {
                path: Some(location.path.clone()),
                subject_key: Some(record.identity.subject_key.clone()),
                environment: None,
            };
            let revision = make_revision(
                repository,
                snapshot,
                Draft {
                    key: fingerprint(&(
                        &scope,
                        &snapshot.files[&location.path],
                        &location.start.line,
                        &location.end.line,
                    ))?,
                    author: REVIEW_AUTHOR.into(),
                    origin: ReviewKnowledgeOrigin::SourceObservation,
                    statement: format!(
                        "Deciding source was cited in {} at lines {}–{}.",
                        location.path, location.start.line, location.end.line
                    ),
                    scope,
                    source_paths: vec![location.path.clone()],
                    evidence: vec![record.decision_id.clone(), artifact.artifact_id.clone()],
                    parent_revision: None,
                    observed_at: None,
                    expires_at: None,
                },
            )?;
            written += usize::from(put(tx, repository, revision, true).await?.1);
        }
    }
    Ok(written)
}
