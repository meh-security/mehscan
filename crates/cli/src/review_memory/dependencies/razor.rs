use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Serialize;
use turso::Connection;

use super::{Assessment, Snapshot, db_error, fingerprint, schema_version};

const SCHEMA: &str = "
    CREATE TABLE razor_render_inventories (
        snapshot_id TEXT NOT NULL,
        inventory_fingerprint TEXT NOT NULL,
        project_inputs_sha256 TEXT NOT NULL,
        PRIMARY KEY (snapshot_id, inventory_fingerprint),
        FOREIGN KEY (snapshot_id, inventory_fingerprint)
            REFERENCES inventory_bindings(snapshot_id, inventory_fingerprint)
    );
    CREATE TABLE razor_render_uses (
        snapshot_id TEXT NOT NULL,
        inventory_fingerprint TEXT NOT NULL,
        target TEXT NOT NULL,
        caller TEXT NOT NULL,
        PRIMARY KEY (snapshot_id, inventory_fingerprint, target, caller),
        FOREIGN KEY (snapshot_id, inventory_fingerprint)
            REFERENCES razor_render_inventories(snapshot_id, inventory_fingerprint)
    );
";

pub(super) async fn retain(
    conn: &Connection,
    snapshot: &Snapshot,
    snapshot_id: &str,
) -> Result<(), String> {
    let Some(bindings) = &snapshot.razor_render_bindings else {
        return Ok(());
    };
    if schema_version(conn).await? < 5 {
        conn.execute_batch(SCHEMA).await.map_err(db_error)?;
        conn.execute("UPDATE review_memory_schema SET version = 5", ())
            .await
            .map_err(db_error)?;
    }
    let inventory = snapshot.inventory.as_str();
    let project_inputs = fingerprint(&bindings.project_inputs)?;
    let added = conn
        .execute(
            "INSERT INTO razor_render_inventories VALUES (?1,?2,?3) ON CONFLICT DO NOTHING",
            (snapshot_id, inventory, project_inputs),
        )
        .await
        .map_err(db_error)?;
    if added != 0 {
        let mut insert = conn
            .prepare("INSERT INTO razor_render_uses VALUES (?1,?2,?3,?4)")
            .await
            .map_err(db_error)?;
        for edge in &bindings.uses {
            insert
                .execute((
                    snapshot_id,
                    inventory,
                    edge.target.as_str(),
                    edge.path.as_str(),
                ))
                .await
                .map_err(db_error)?;
        }
    }
    Ok(())
}

#[derive(Default)]
pub(super) struct RenderUses {
    project_inputs: String,
    hashes: BTreeMap<String, String>,
    callers: BTreeMap<String, BTreeSet<String>>,
    unresolved: BTreeMap<String, BTreeSet<String>>,
    dynamic: BTreeSet<String>,
}

impl RenderUses {
    fn insert(&mut self, target: String, caller: String) {
        if target == "*" {
            self.dynamic.insert(caller);
        } else if let Some(tag) = target.strip_prefix("component:") {
            let leaf = tag.rsplit('.').next().unwrap_or(tag);
            self.unresolved
                .entry(leaf.to_owned())
                .or_default()
                .insert(caller);
        } else {
            self.callers.entry(target).or_default().insert(caller);
        }
    }
}

pub(super) async fn baseline(
    conn: &Connection,
    snapshot: &str,
    inventory: &str,
) -> Result<Option<RenderUses>, String> {
    if schema_version(conn).await? < 5 {
        return Ok(None);
    }
    let mut rows = conn
        .query(
            "SELECT i.project_inputs_sha256, u.target, u.caller, f.sha256
             FROM razor_render_inventories i LEFT JOIN razor_render_uses u
               ON u.snapshot_id = i.snapshot_id AND u.inventory_fingerprint = i.inventory_fingerprint
             LEFT JOIN snapshot_inputs f ON f.snapshot_id = i.snapshot_id AND f.path = u.caller
             WHERE i.snapshot_id = ?1 AND i.inventory_fingerprint = ?2",
            (snapshot, inventory),
        )
        .await
        .map_err(db_error)?;
    let mut result = None;
    while let Some(row) = rows.next().await.map_err(db_error)? {
        if result.is_none() {
            result = Some(RenderUses {
                project_inputs: row.get(0).map_err(db_error)?,
                ..Default::default()
            });
        }
        if let Some(target) = row.get::<Option<String>>(1).map_err(db_error)? {
            let uses = result.as_mut().expect("baseline initialized");
            let caller: String = row.get(2).map_err(db_error)?;
            if let Some(hash) = row.get::<Option<String>>(3).map_err(db_error)? {
                uses.hashes.entry(caller.clone()).or_insert(hash);
            }
            uses.insert(target, caller);
        }
    }
    Ok(result)
}

pub(super) fn current(snapshot: &Snapshot) -> Result<Option<RenderUses>, String> {
    snapshot
        .razor_render_bindings
        .as_ref()
        .map(|bindings| {
            let mut uses = RenderUses {
                project_inputs: fingerprint(&bindings.project_inputs)?,
                ..Default::default()
            };
            for edge in &bindings.uses {
                uses.insert(edge.target.clone(), edge.path.clone());
            }
            Ok(uses)
        })
        .transpose()
}

pub(super) fn target(assessment: &Assessment) -> Option<&str> {
    assessment.files.iter().find_map(|file| {
        (file.role == "primary"
            && Path::new(&file.path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("razor")))
        .then_some(file.path.as_str())
    })
}

#[derive(Serialize)]
pub(super) struct Comparison {
    scope: &'static str,
    prior_available: bool,
    current_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_configuration: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    callers: Option<Vec<Caller>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unresolved_callers: Option<Vec<Caller>>,
}

#[derive(Serialize)]
struct Caller {
    path: String,
    status: &'static str,
}

pub(super) fn compare(
    prior: Option<&RenderUses>,
    current: Option<&RenderUses>,
    target: &str,
    current_files: &BTreeMap<String, String>,
) -> Comparison {
    let mut result = Comparison {
        scope: "sdk_source_render_uses/v1",
        prior_available: prior.is_some(),
        current_available: current.is_some(),
        project_configuration: None,
        callers: None,
        unresolved_callers: None,
    };
    if let (Some(prior), Some(current)) = (prior, current) {
        result.project_configuration = Some(if prior.project_inputs == current.project_inputs {
            "unchanged"
        } else {
            "modified"
        });
        let empty = BTreeSet::new();
        let stem = Path::new(target)
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        let unresolved = |uses: &RenderUses| {
            uses.dynamic
                .union(uses.unresolved.get(stem).unwrap_or(&empty))
                .cloned()
                .collect()
        };
        let statuses = |before: &BTreeSet<String>, after: &BTreeSet<String>| {
            before
                .union(after)
                .map(|path| Caller {
                    path: path.clone(),
                    status: match (before.contains(path), after.contains(path)) {
                        (false, true) => "added",
                        (true, false) => "removed",
                        _ => match (prior.hashes.get(path), current_files.get(path)) {
                            (Some(before), Some(after)) if before != after => "modified",
                            (Some(_), Some(_)) => "unchanged",
                            _ => "unavailable",
                        },
                    },
                })
                .collect()
        };
        result.callers = Some(statuses(
            prior.callers.get(target).unwrap_or(&empty),
            current.callers.get(target).unwrap_or(&empty),
        ));
        result.unresolved_callers = Some(statuses(&unresolved(prior), &unresolved(current)));
    }
    result
}
