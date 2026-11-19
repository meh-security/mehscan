//! The local cache of a single authenticated sharing audience.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use mehscan_core::{
    ReviewKnowledgeOrigin, ReviewKnowledgeRevision, ReviewRepositoryIdentity, ReviewSharingBinding,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use turso::{Connection, transaction::TransactionBehavior};

use super::{db_error, legacy, lock_store, open_local, prepare_schema};

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS review_sharing (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        enrollment TEXT NOT NULL,
        database_id TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS shared_fact_revisions (
        sequence INTEGER PRIMARY KEY,
        item_id TEXT NOT NULL,
        revision_id TEXT NOT NULL UNIQUE,
        is_head INTEGER NOT NULL,
        revision_json TEXT NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS shared_fact_head
        ON shared_fact_revisions(item_id) WHERE is_head = 1;
";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    sharing: ReviewSharingBinding,
    after: i64,
    facts: Vec<Event>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    seq: i64,
    id: String,
    actor: String,
    payload: ReviewKnowledgeRevision,
}

#[derive(Default, Serialize)]
struct Cursor {
    after: i64,
    event_id: Option<String>,
}

pub(super) async fn binding(conn: &Connection) -> Result<Option<ReviewSharingBinding>, String> {
    if !legacy::table_exists(conn, "review_sharing").await? {
        return Ok(None);
    }
    let mut rows = conn
        .query(
            "SELECT enrollment, database_id FROM review_sharing WHERE singleton = 1",
            (),
        )
        .await
        .map_err(db_error)?;
    rows.next()
        .await
        .map_err(db_error)?
        .map(|row| {
            Ok(ReviewSharingBinding {
                enrollment: row.get(0).map_err(db_error)?,
                database_id: row.get(1).map_err(db_error)?,
            })
        })
        .transpose()
}

async fn cursor(conn: &Connection) -> Result<Cursor, String> {
    let mut rows = conn.query(
        "SELECT sequence, revision_id FROM shared_fact_revisions ORDER BY sequence DESC LIMIT 1", (),
    ).await.map_err(db_error)?;
    Ok(match rows.next().await.map_err(db_error)? {
        None => Cursor::default(),
        Some(row) => Cursor {
            after: row.get(0).map_err(db_error)?,
            event_id: Some(row.get(1).map_err(db_error)?),
        },
    })
}

pub(super) async fn revisions(
    conn: &Connection,
    heads_only: bool,
    item_id: Option<&str>,
) -> Result<Vec<ReviewKnowledgeRevision>, String> {
    if !legacy::table_exists(conn, "shared_fact_revisions").await? {
        return Ok(Vec::new());
    }
    let mut rows = conn
        .query(
            "SELECT revision_json FROM shared_fact_revisions
         WHERE (?1 = 0 OR is_head = 1) AND (?2 IS NULL OR item_id = ?2) ORDER BY item_id, sequence",
            (i64::from(heads_only), item_id),
        )
        .await
        .map_err(db_error)?;
    let mut output = Vec::new();
    while let Some(row) = rows.next().await.map_err(db_error)? {
        output.push(
            serde_json::from_str(&row.get::<String>(0).map_err(db_error)?)
                .map_err(|error| error.to_string())?,
        );
    }
    Ok(output)
}

pub(super) fn for_scan(
    mut fact: ReviewKnowledgeRevision,
    prefix: &str,
) -> Option<ReviewKnowledgeRevision> {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return Some(fact);
    }
    let to_local = |path: &str| {
        path.strip_prefix(prefix)?
            .strip_prefix('/')
            .map(str::to_owned)
    };
    if let Some(path) = &fact.scope.path {
        fact.scope.path = if path == prefix
            || prefix
                .strip_prefix(path)
                .is_some_and(|rest| rest.starts_with('/'))
        {
            None
        } else {
            Some(to_local(path)?)
        };
    }
    fact.source_sha256 = fact
        .source_sha256
        .into_iter()
        .map(|(path, hash)| Some((to_local(&path)?, hash)))
        .collect::<Option<_>>()?;
    Some(fact)
}

pub(super) fn validate_binding(
    repository: &ReviewRepositoryIdentity,
    shared: &ReviewSharingBinding,
) -> Result<(), String> {
    let repo = repository
        .repository_key
        .as_deref()
        .ok_or("missing repository key")?;
    let id = repo
        .strip_prefix("github.com/repositories/")
        .ok_or("shared facts require a GitHub repository ID")?;
    let audience = shared
        .enrollment
        .strip_prefix(repo)
        .and_then(|suffix| suffix.strip_prefix('/'));
    if id.is_empty()
        || id.len() > 20
        || id.starts_with('0')
        || !id.bytes().all(|byte| byte.is_ascii_digit())
        || repository
            .source_repository_key
            .as_deref()
            .is_some_and(|source| source != repo)
        || !audience.is_some_and(|value| {
            value
                .as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && value.len() <= 63
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        || shared.database_id.is_empty()
        || shared.database_id.len() > 128
        || shared
            .database_id
            .chars()
            .any(|char| char.is_whitespace() || char.is_control())
    {
        return Err("sharing enrollment does not match this repository and audience".into());
    }
    Ok(())
}

fn hash64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn relative(path: &str) -> bool {
    path.chars().count() <= 1024
        && !path.contains(['\\', ':', '\0'])
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

async fn apply_event(conn: &Connection, event: Event) -> Result<(), String> {
    let fact = &event.payload;
    let actor_valid = event.actor.strip_prefix("user:").is_some_and(|name| {
        !name.is_empty()
            && name.len() <= 96
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.@-".contains(&b))
    });
    if !actor_valid
        || event.actor != fact.author
        || event.id != fact.revision_id
        || !hash64(&fact.item_id)
        || !hash64(&event.id)
        || fact.key.trim().is_empty()
        || fact.key.len() > 1024
        || fact.statement.trim().is_empty()
        || fact.statement.len() > 8192
        || fact
            .scope
            .path
            .as_deref()
            .is_some_and(|path| !relative(path))
        || fact.source_sha256.len() > 8
        || fact.evidence.len() > 8
        || fact
            .source_sha256
            .iter()
            .any(|(path, hash)| !relative(path) || !hash64(hash))
        || fact.origin == ReviewKnowledgeOrigin::SourceObservation && fact.source_sha256.is_empty()
    {
        return Err("invalid hosted fact identity, source scope, or provenance".into());
    }
    let current = revisions(conn, true, Some(&fact.item_id)).await?.pop();
    if fact.parent_revision.as_ref() != current.as_ref().map(|head| &head.revision_id)
        || current
            .as_ref()
            .is_some_and(|head| head.author != fact.author || head.key != fact.key)
        || fact.withdrawn && current.as_ref().is_none_or(|head| head.withdrawn)
    {
        return Err("hosted fact does not extend the current revision".into());
    }
    if fact.withdrawn
        && let Some(mut previous) = current
    {
        previous.parent_revision.clone_from(&fact.parent_revision);
        previous.revision_id.clone_from(&fact.revision_id);
        previous.withdrawn = true;
        if previous != *fact {
            return Err("hosted withdrawal changed the original fact contents".into());
        }
    }
    conn.execute(
        "UPDATE shared_fact_revisions SET is_head = 0 WHERE item_id = ?1 AND is_head = 1",
        (fact.item_id.as_str(),),
    )
    .await
    .map_err(db_error)?;
    let document = serde_json::to_string(fact).map_err(|error| error.to_string())?;
    conn.execute(
        "INSERT INTO shared_fact_revisions VALUES (?1, ?2, ?3, 1, ?4)",
        (
            event.seq,
            fact.item_id.as_str(),
            event.id.as_str(),
            document,
        ),
    )
    .await
    .map_err(db_error)?;
    Ok(())
}

async fn has_local_data(conn: &Connection) -> Result<bool, String> {
    for table in ["repositories", "review_knowledge"] {
        if legacy::table_exists(conn, table).await? {
            let mut rows = conn
                .query(&format!("SELECT 1 FROM {table} LIMIT 1"), ())
                .await
                .map_err(db_error)?;
            if rows.next().await.map_err(db_error)?.is_some() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub(super) fn run(
    path: &Path,
    repository: &ReviewRepositoryIdentity,
    input: Option<&Path>,
    root: &Path,
) -> Result<Value, String> {
    let page: Option<Page> = input
        .map(|input| {
            crate::review_state::outside_source(input, root)?;
            let mut bytes = Vec::new();
            File::open(input)
                .and_then(|file| file.take(1024 * 1024 + 1).read_to_end(&mut bytes))
                .map_err(|error| error.to_string())?;
            if bytes.len() > 1024 * 1024 {
                return Err("shared fact page exceeds 1 MiB".into());
            }
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())
        })
        .transpose()?;
    let _lock = lock_store(path)?;
    super::local_runtime()?.block_on(async {
        let Some(page) = page else {
            if !path.is_file() {
                return Ok(json!({"status":"unbound","sharing":null,"cursor":Cursor::default()}));
            }
            let (_db, conn) = open_local(path, true).await?;
            let sharing = binding(&conn).await?;
            let cursor = if let Some(binding) = &sharing {
                validate_binding(repository, binding)?;
                cursor(&conn).await?
            } else {
                Cursor::default()
            };
            return Ok(json!({"status":if sharing.is_some() {"bound"} else {"unbound"}, "sharing":sharing,"cursor":cursor}));
        };
        validate_binding(repository, &page.sharing)?;
        if page.after < 0 || page.facts.len() > 64
            || page.facts.first().is_some_and(|event| event.seq <= page.after)
            || page.facts.windows(2).any(|events| events[0].seq >= events[1].seq)
        {
            return Err("invalid hosted fact page cursor or order".into());
        }
        let (_db, mut conn) = open_local(path, false).await?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).await.map_err(db_error)?;
        prepare_schema(&tx).await?;
        tx.execute_batch(SCHEMA).await.map_err(db_error)?;
        let pinned = binding(&tx).await?;
        if let Some(binding) = &pinned {
            if binding != &page.sharing {
                return Err("local memory is linked to a different sharing enrollment".into());
            }
        } else {
            if has_local_data(&tx).await? {
                return Err("initialize sharing with a dedicated local state home before reviewing".into());
            }
            tx.execute("INSERT INTO review_sharing VALUES (1, ?1, ?2)",
                (page.sharing.enrollment.as_str(), page.sharing.database_id.as_str()))
                .await.map_err(db_error)?;
        }
        let previous = cursor(&tx).await?;
        if previous.after != page.after {
            return Ok(json!({"status":"cursor_changed","sharing":pinned,"cursor":previous}));
        }
        let imported = page.facts.len();
        for event in page.facts {
            apply_event(&tx, event).await?;
        }
        let cursor = cursor(&tx).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(json!({"status":"imported","sharing":page.sharing,"cursor":cursor,"imported":imported}))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_paths_are_rebased_to_the_selected_scan_root() {
        let revision: ReviewKnowledgeRevision = serde_json::from_value(json!({
            "item_id":"item","revision_id":"revision","parent_revision":null,
            "key":"routes","author":"user:assertion","origin":"source_observation",
            "statement":"A route file lives in this subtree.",
            "scope":{"path":"services"},"source_sha256":{"services/web/router.js":"hash"},
            "evidence":[],"observed_at":null,"expires_at":null,"withdrawn":false
        }))
        .unwrap();
        let web = for_scan(revision.clone(), "services/web/").unwrap();
        assert!(web.scope.path.is_none());
        assert_eq!(
            web.source_sha256.get("router.js").map(String::as_str),
            Some("hash")
        );
        assert!(for_scan(revision, "services/worker/").is_none());
    }
}
