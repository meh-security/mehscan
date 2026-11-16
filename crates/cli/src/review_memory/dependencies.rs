//! Retained proof inputs and lexical reference observations.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use mehscan_core::{ReviewDecisionRecord, ReviewRelationshipScope, SecurityPathStepKind};
use serde::Serialize;
use serde_json::{Value, json};
use turso::Connection;

use super::{Snapshot, assessments::assessment_id, db_error, fingerprint, schema_version};

const SCHEMA: &str = "
    CREATE TABLE dependency_batches (
        batch_id TEXT PRIMARY KEY NOT NULL REFERENCES assessment_batches(id)
    );
    CREATE TABLE assessment_file_dependencies (
        assessment_id TEXT NOT NULL REFERENCES assessments(id),
        role TEXT NOT NULL,
        path TEXT NOT NULL,
        PRIMARY KEY (assessment_id, role, path)
    );
    CREATE TABLE snapshot_reference_observations (
        snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
        symbol TEXT NOT NULL,
        membership_sha256 TEXT NOT NULL,
        inputs_sha256 TEXT NOT NULL,
        member_count INTEGER NOT NULL,
        PRIMARY KEY (snapshot_id, symbol)
    );
    CREATE TABLE assessment_reference_dependencies (
        assessment_id TEXT NOT NULL REFERENCES assessments(id),
        snapshot_id TEXT NOT NULL,
        symbol TEXT NOT NULL,
        PRIMARY KEY (assessment_id, symbol),
        FOREIGN KEY (snapshot_id, symbol)
            REFERENCES snapshot_reference_observations(snapshot_id, symbol)
    );
";

struct Inputs<'a> {
    files: BTreeSet<(&'static str, &'a str)>,
    names: BTreeSet<String>,
}

fn inputs(record: &ReviewDecisionRecord) -> Inputs<'_> {
    let mut files = BTreeSet::new();
    let mut names = BTreeSet::new();
    let operation = &record.identity.occurrence.operation;
    if let Some(symbol) = &operation.enclosing_symbol {
        names.extend(reference_name(symbol));
    }
    if let ReviewRelationshipScope::SourceToOperation { source, .. } =
        &record.identity.relationship_scope
        && let Some(symbol) = &source.enclosing_symbol
    {
        names.extend(reference_name(symbol));
    }
    if let Some(primary) = &record.identity.primary_location_fingerprint {
        let path = primary.location.path.as_str();
        files.insert(("primary", path));
        if Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("razor"))
            && let Some(stem) = Path::new(path).file_stem().and_then(|value| value.to_str())
        {
            names.extend(reference_name(stem));
        }
    }
    for item in &record.native_evidence {
        files.insert(("native_evidence", item.location.path.as_str()));
        for dependency in &item.context.configuration_dependencies {
            files.insert((
                "configuration",
                dependency.declaration.location.path.as_str(),
            ));
            files.insert(("configured_target", dependency.target_path.as_str()));
        }
    }
    for step in record.native_flows.iter().flatten() {
        let role = match step.kind {
            SecurityPathStepKind::Protection | SecurityPathStepKind::IneffectiveProtection => {
                "native_control"
            }
            _ => "native_flow",
        };
        files.insert((role, step.location.path.as_str()));
    }
    if let Some(trace) = &record.response.investigation {
        for artifact in &trace.decisive_artifacts {
            files.insert(("decisive_source", artifact.location.path.as_str()));
        }
    }
    Inputs { files, names }
}

fn reference_name(symbol: &str) -> Option<String> {
    let name = symbol.rsplit(['.', ':']).next()?;
    let mut bytes = name.bytes();
    let first = bytes.next()?;
    (name.len() <= 96
        && (first.is_ascii_alphabetic() || matches!(first, b'_' | b'$'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')))
    .then(|| name.to_owned())
}

struct Observation {
    membership: String,
    inputs: String,
    members: usize,
}

fn observe(
    snapshot: &Snapshot,
    names: &BTreeSet<String>,
) -> Result<BTreeMap<String, Observation>, String> {
    let sources = snapshot
        .sources
        .as_ref()
        .ok_or("missing verified source capture")?;
    sources
        .reference_files(names)
        .into_iter()
        .map(|(name, paths)| {
            let members = paths
                .iter()
                .map(|path| (*path, &snapshot.files[*path]))
                .collect::<Vec<_>>();
            let observation = Observation {
                membership: fingerprint(&("identifier-membership/v1", &paths))?,
                inputs: fingerprint(&("identifier-member-inputs/v1", &members))?,
                members: paths.len(),
            };
            Ok((name.to_owned(), observation))
        })
        .collect()
}

pub(super) async fn prepare_schema(conn: &Connection) -> Result<(), String> {
    if schema_version(conn).await? < 4 {
        conn.execute_batch(SCHEMA).await.map_err(db_error)?;
        conn.execute("UPDATE review_memory_schema SET version = 4", ())
            .await
            .map_err(db_error)?;
    }
    Ok(())
}

pub(super) async fn retain(
    conn: &Connection,
    snapshot: &Snapshot,
    snapshot_id: &str,
    batch: &str,
    records: &[ReviewDecisionRecord],
) -> Result<(), String> {
    prepare_schema(conn).await?;
    let added = conn
        .execute(
            "INSERT INTO dependency_batches VALUES (?1) ON CONFLICT(batch_id) DO NOTHING",
            (batch,),
        )
        .await
        .map_err(db_error)?;
    if added == 0 {
        return Ok(());
    }

    let bindings = records.iter().map(inputs).collect::<Vec<_>>();
    let mut names = bindings
        .iter()
        .flat_map(|entry| entry.names.iter().cloned())
        .collect();
    let mut known = conn
        .query(
            "SELECT symbol FROM snapshot_reference_observations WHERE snapshot_id = ?1",
            (snapshot_id,),
        )
        .await
        .map_err(db_error)?;
    while let Some(row) = known.next().await.map_err(db_error)? {
        let name: String = row.get(0).map_err(db_error)?;
        BTreeSet::remove(&mut names, &name);
    }
    drop(known);
    let mut insert = conn
        .prepare("INSERT INTO snapshot_reference_observations VALUES (?1,?2,?3,?4,?5)")
        .await
        .map_err(db_error)?;
    for (name, observed) in observe(snapshot, &names)? {
        insert
            .execute((
                snapshot_id,
                name,
                observed.membership,
                observed.inputs,
                i64::try_from(observed.members)
                    .map_err(|_| "reference member count exceeds storage range")?,
            ))
            .await
            .map_err(db_error)?;
    }
    let mut files = conn
        .prepare(
            "INSERT INTO assessment_file_dependencies VALUES (?1,?2,?3) ON CONFLICT DO NOTHING",
        )
        .await
        .map_err(db_error)?;
    let mut references = conn.prepare(
        "INSERT INTO assessment_reference_dependencies VALUES (?1,?2,?3) ON CONFLICT DO NOTHING",
    ).await.map_err(db_error)?;
    for (record, binding) in records.iter().zip(bindings) {
        let id = assessment_id(snapshot_id, &snapshot.inventory, &record.decision_id)?;
        for (role, path) in binding.files {
            files
                .execute((id.as_str(), role, path))
                .await
                .map_err(db_error)?;
        }
        for name in binding.names {
            references
                .execute((id.as_str(), snapshot_id, name))
                .await
                .map_err(db_error)?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct FileInput {
    path: String,
    role: String,
    status: &'static str,
}

#[derive(Serialize)]
struct ReferenceInput {
    symbol: String,
    status: &'static str,
    prior_file_count: i64,
    current_file_count: usize,
}

#[derive(Serialize)]
struct Assessment {
    review_id: String,
    decision_id: String,
    files: Vec<FileInput>,
    references: Vec<ReferenceInput>,
}

pub(super) async fn compare(
    conn: &Connection,
    snapshot: &Snapshot,
    stream: &str,
    batch: &str,
) -> Result<Value, String> {
    if schema_version(conn).await? < 4 {
        return Err(
            "review memory has no captured dependencies; retain a native attempt first".into(),
        );
    }
    let repository = fingerprint(&snapshot.repository)?;
    let current = snapshot.id(&repository)?;
    let mut rows = conn.query(
        "SELECT b.snapshot_id, d.batch_id FROM assessment_batches b JOIN snapshots s ON s.id = b.snapshot_id
         LEFT JOIN dependency_batches d ON d.batch_id = b.id
         WHERE b.id = ?1 AND b.stream = ?2 AND s.repository_id = ?3",
        (batch, stream, repository.as_str()),
    ).await.map_err(db_error)?;
    let row = rows
        .next()
        .await
        .map_err(db_error)?
        .ok_or("retained dependency batch does not match this repository and stream")?;
    let base: String = row.get(0).map_err(db_error)?;
    if row.get::<Option<String>>(1).map_err(db_error)?.is_none() {
        return Err("retained batch has no captured dependencies; re-retain it with its original inventory and source".into());
    }
    drop(rows);

    let mut results = BTreeMap::new();
    let mut rows = conn
        .query(
            "SELECT a.id, a.review_id, a.decision_id, d.role, d.path, f.sha256
         FROM batch_assessments b JOIN assessments a ON a.id = b.assessment_id
         LEFT JOIN assessment_file_dependencies d ON d.assessment_id = a.id
         LEFT JOIN snapshot_inputs f ON f.snapshot_id = ?2 AND f.path = d.path
         WHERE b.batch_id = ?1 ORDER BY a.id, d.role, d.path",
            (batch, base.as_str()),
        )
        .await
        .map_err(db_error)?;
    while let Some(row) = rows.next().await.map_err(db_error)? {
        let id: String = row.get(0).map_err(db_error)?;
        let review_id = row.get(1).map_err(db_error)?;
        let decision_id = row.get(2).map_err(db_error)?;
        let assessment = results.entry(id).or_insert_with(|| Assessment {
            review_id,
            decision_id,
            files: Vec::new(),
            references: Vec::new(),
        });
        if let Some(path) = row.get::<Option<String>>(4).map_err(db_error)? {
            let before: Option<String> = row.get(5).map_err(db_error)?;
            let status = match (before.as_ref(), snapshot.files.get(&path)) {
                (None, _) => "unavailable",
                (Some(_), None) => "removed",
                (Some(before), Some(now)) if before != now => "modified",
                _ => "unchanged",
            };
            assessment.files.push(FileInput {
                path,
                role: row.get(3).map_err(db_error)?,
                status,
            });
        }
    }
    drop(rows);
    let mut previous = Vec::new();
    let mut names = BTreeSet::new();
    let mut rows = conn.query(
        "SELECT d.assessment_id, d.symbol, r.membership_sha256, r.inputs_sha256, r.member_count
         FROM batch_assessments b JOIN assessment_reference_dependencies d ON d.assessment_id = b.assessment_id
         JOIN snapshot_reference_observations r ON r.snapshot_id = d.snapshot_id AND r.symbol = d.symbol
         WHERE b.batch_id = ?1 AND d.snapshot_id = ?2 ORDER BY d.assessment_id, d.symbol",
        (batch, base.as_str()),
    ).await.map_err(db_error)?;
    while let Some(row) = rows.next().await.map_err(db_error)? {
        let symbol: String = row.get(1).map_err(db_error)?;
        names.insert(symbol.clone());
        previous.push((
            row.get::<String>(0).map_err(db_error)?,
            symbol,
            row.get::<String>(2).map_err(db_error)?,
            row.get::<String>(3).map_err(db_error)?,
            row.get::<i64>(4).map_err(db_error)?,
        ));
    }
    drop(rows);
    let observations = (base != current)
        .then(|| observe(snapshot, &names))
        .transpose()?;
    for (id, symbol, membership, inputs, count) in previous {
        let (status, current_file_count) = match observations.as_ref().map(|rows| &rows[&symbol]) {
            Some(observed) if observed.membership != membership => {
                ("membership_changed", observed.members)
            }
            Some(observed) if observed.inputs != inputs => {
                ("member_file_changed", observed.members)
            }
            _ => (
                "unchanged",
                usize::try_from(count).map_err(|error| error.to_string())?,
            ),
        };
        results
            .get_mut(&id)
            .ok_or("reference assessment is absent from the retained batch")?
            .references
            .push(ReferenceInput {
                symbol,
                status,
                prior_file_count: count,
                current_file_count,
            });
    }
    Ok(
        json!({"authority":"dependency_observations", "reference_scope":"captured_identifier_references/v1",
              "base_snapshot":base, "snapshot":current, "batch":batch,
              "assessments":results.into_values().collect::<Vec<_>>()}),
    )
}
