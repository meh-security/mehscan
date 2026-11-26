use std::collections::HashMap;

use mehscan_core::{Location, ReviewAttemptStatus, ReviewConfidence, ReviewDecision};
use serde::Serialize;
use sha2::{Digest, Sha256};
use turso::Connection;

use super::{Snapshot, db_error, fingerprint, query_batch, schema_version};
use crate::review_state::{MemoryAdmission, RetainedBatch};

pub(super) const SCHEMA: &str = "
    CREATE TABLE assessment_batches (
        id TEXT NOT NULL PRIMARY KEY,
        snapshot_id TEXT NOT NULL,
        inventory_fingerprint TEXT NOT NULL,
        stream TEXT NOT NULL,
        generation INTEGER NOT NULL,
        native_attempt TEXT NOT NULL,
        attempt_status TEXT NOT NULL,
        FOREIGN KEY (snapshot_id, inventory_fingerprint)
            REFERENCES inventory_bindings(snapshot_id, inventory_fingerprint)
    );
    CREATE INDEX assessment_batch_inventory
        ON assessment_batches(snapshot_id, inventory_fingerprint, stream, generation, id);
";

pub(super) const CONTENT_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS assessments (
        id TEXT NOT NULL PRIMARY KEY,
        decision_id TEXT NOT NULL,
        review_id TEXT NOT NULL,
        subject_key TEXT NOT NULL,
        basis_fingerprint TEXT NOT NULL,
        response_fingerprint TEXT NOT NULL,
        verdict TEXT NOT NULL,
        confidence TEXT NOT NULL,
        summary TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS batch_assessments (
        batch_id TEXT NOT NULL REFERENCES assessment_batches(id),
        assessment_id TEXT NOT NULL REFERENCES assessments(id),
        PRIMARY KEY (batch_id, assessment_id)
    );
    CREATE TABLE IF NOT EXISTS assessment_questions (
        assessment_id TEXT NOT NULL REFERENCES assessments(id),
        kind TEXT NOT NULL,
        ordinal INTEGER NOT NULL,
        question TEXT NOT NULL,
        PRIMARY KEY (assessment_id, kind, ordinal)
    );
    CREATE TABLE IF NOT EXISTS assessment_evidence (
        assessment_id TEXT NOT NULL REFERENCES assessments(id),
        kind TEXT NOT NULL,
        reference TEXT NOT NULL,
        path TEXT NOT NULL,
        start_line INTEGER NOT NULL,
        end_line INTEGER NOT NULL,
        start_byte INTEGER NOT NULL,
        end_byte INTEGER NOT NULL,
        excerpt_sha256 TEXT,
        PRIMARY KEY (assessment_id, kind, reference)
    );
";

#[derive(Serialize)]
pub(super) struct Retention {
    batch: String,
    snapshot: String,
    assessments: usize,
    reused: bool,
}

impl Retention {
    pub(super) fn batch(&self) -> &str {
        &self.batch
    }
}

pub(super) fn assessment_id(
    snapshot: &str,
    inventory: &str,
    decision: &str,
) -> Result<String, String> {
    fingerprint(&(snapshot, inventory, decision))
}

pub(super) async fn retain(
    tx: &Connection,
    snapshot: &str,
    inventory: &str,
    stream: &str,
    admission: &MemoryAdmission,
) -> Result<Retention, String> {
    let batch = fingerprint(&(
        snapshot,
        inventory,
        stream,
        admission.generation,
        &admission.attempt,
        admission.status,
        admission
            .records
            .iter()
            .map(|r| r.decision_id.as_str())
            .collect::<Vec<_>>(),
    ))?;
    let status = match admission.status {
        ReviewAttemptStatus::Finished => "finished",
        ReviewAttemptStatus::Incomplete => "incomplete",
        _ => return Err("memory retention requires a completed native generation".into()),
    };
    let created = tx
        .execute(
            "INSERT INTO assessment_batches VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(id) DO NOTHING",
            (
                &*batch,
                snapshot,
                inventory,
                stream,
                integer(admission.generation)?,
                admission.attempt.as_str(),
                status,
            ),
        )
        .await
        .map_err(db_error)?
        > 0;
    if created {
        for record in &admission.records {
            let response = &record.response;
            // A native decision ID retains the complete decision identity. Include
            // the exact admitted inventory to avoid conflating assessment bases.
            let id = assessment_id(snapshot, inventory, &record.decision_id)?;
            let verdict = match response.decision {
                ReviewDecision::Issue => "issue",
                ReviewDecision::NotIssue => "not_issue",
                ReviewDecision::NeedsReview => "needs_review",
            };
            let confidence = match response.confidence {
                ReviewConfidence::High => "high",
                ReviewConfidence::Medium => "medium",
                ReviewConfidence::Low => "low",
            };
            let is_new = tx
                .execute(
                    "INSERT INTO assessments VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(id) DO NOTHING",
                    (
                        &*id,
                        record.decision_id.as_str(),
                        response.review_id.as_str(),
                        record.identity.subject_key.as_str(),
                        record.basis_fingerprint.as_str(),
                        record.response_fingerprint.as_str(),
                        verdict,
                        confidence,
                        response.summary.as_str(),
                    ),
                )
                .await
                .map_err(db_error)?
                > 0;
            if is_new {
                write_questions(tx, &id, "check", &response.checks).await?;
                if let Some(primary) = &record.identity.primary_location_fingerprint {
                    write_evidence(
                        tx,
                        &id,
                        "primary",
                        &record.identity.anchor_id,
                        &primary.location,
                        None,
                    )
                    .await?;
                }
                if let Some(trace) = &response.investigation {
                    write_questions(tx, &id, "blocker", &trace.blockers).await?;
                    for artifact in &trace.decisive_artifacts {
                        let sha256 = format!("{:x}", Sha256::digest(artifact.excerpt.as_bytes()));
                        write_evidence(
                            tx,
                            &id,
                            "retrieved",
                            &artifact.artifact_id,
                            &artifact.location,
                            Some(&sha256),
                        )
                        .await?;
                    }
                }
            }
            tx.execute(
                "INSERT INTO batch_assessments VALUES (?1, ?2)",
                (&*batch, &*id),
            )
            .await
            .map_err(db_error)?;
        }
    }
    Ok(Retention {
        batch,
        snapshot: snapshot.into(),
        assessments: admission.records.len(),
        reused: !created,
    })
}

fn integer<T: TryInto<i64>>(value: T) -> Result<i64, String> {
    value
        .try_into()
        .map_err(|_| "native review value exceeds local memory range".into())
}

async fn write_questions(
    tx: &Connection,
    id: &str,
    kind: &str,
    questions: &[String],
) -> Result<(), String> {
    for (order, question) in questions.iter().enumerate() {
        tx.execute(
            "INSERT INTO assessment_questions VALUES (?1, ?2, ?3, ?4)",
            (id, kind, integer(order)?, question.as_str()),
        )
        .await
        .map_err(db_error)?;
    }
    Ok(())
}

async fn write_evidence(
    tx: &Connection,
    id: &str,
    kind: &str,
    reference: &str,
    location: &Location,
    excerpt_sha: Option<&str>,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO assessment_evidence VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        (
            id,
            kind,
            reference,
            location.path.as_str(),
            integer(location.start.line)?,
            integer(location.end.line)?,
            integer(location.start.byte_offset)?,
            integer(location.end.byte_offset)?,
            excerpt_sha,
        ),
    )
    .await
    .map_err(db_error)?;
    Ok(())
}

#[derive(Serialize)]
pub(super) struct Lookup {
    authority: &'static str,
    snapshot: String,
    inventory_fingerprint: String,
    batches: Vec<Batch>,
}

#[derive(Serialize)]
struct Batch {
    id: String,
    generation: i64,
    native_attempt: String,
    attempt_status: String,
    assessments: Vec<Assessment>,
}

#[derive(Serialize)]
pub(super) struct Assessment {
    #[serde(skip)]
    id: String,
    pub(super) decision_id: String,
    pub(super) review_id: String,
    pub(super) subject_key: String,
    basis_fingerprint: String,
    response_fingerprint: String,
    pub(super) verdict: String,
    confidence: String,
    summary: String,
    questions: Vec<Question>,
    evidence: Vec<Evidence>,
}

impl Assessment {
    pub(super) fn has_open_checks(&self) -> bool {
        self.verdict == "needs_review" || !self.questions.is_empty()
    }

    pub(super) fn has_source_evidence(&self, has_input: impl Fn(&str) -> bool) -> bool {
        self.evidence.iter().any(|item| {
            (item.kind == "primary"
                || item.excerpt_sha256.as_deref().is_some_and(|hash| {
                    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                }))
                && has_input(&item.path)
        })
    }
}

#[derive(Serialize)]
struct Question {
    kind: String,
    text: String,
}

#[derive(Serialize)]
struct Evidence {
    kind: String,
    reference: String,
    path: String,
    start_line: i64,
    end_line: i64,
    start_byte: i64,
    end_byte: i64,
    excerpt_sha256: Option<String>,
}

pub(super) fn empty(snapshot: &Snapshot) -> Result<Lookup, String> {
    Ok(Lookup {
        authority: "retained_context",
        snapshot: snapshot.id(&fingerprint(&snapshot.repository)?)?,
        inventory_fingerprint: snapshot.inventory.clone(),
        batches: Vec::new(),
    })
}

pub(super) async fn lookup(
    conn: &Connection,
    snapshot: &Snapshot,
    stream: &str,
) -> Result<Lookup, String> {
    let mut result = empty(snapshot)?;
    if schema_version(conn).await? < 2 {
        return Ok(result);
    }
    let mut rows = conn
        .query(
            "SELECT id, generation, native_attempt, attempt_status FROM assessment_batches
         WHERE snapshot_id = ?1 AND inventory_fingerprint = ?2 AND stream = ?3
           AND generation = (SELECT MAX(generation) FROM assessment_batches
               WHERE snapshot_id = ?1 AND inventory_fingerprint = ?2 AND stream = ?3)
         ORDER BY id",
            (
                result.snapshot.as_str(),
                result.inventory_fingerprint.as_str(),
                stream,
            ),
        )
        .await
        .map_err(db_error)?;
    while let Some(row) = rows.next().await.map_err(db_error)? {
        let id: String = row.get(0).map_err(db_error)?;
        result.batches.push(Batch {
            assessments: read_assessments(conn, &id).await?,
            id,
            generation: row.get(1).map_err(db_error)?,
            native_attempt: row.get(2).map_err(db_error)?,
            attempt_status: row.get(3).map_err(db_error)?,
        });
    }
    Ok(result)
}

pub(super) async fn reuse_batch(
    conn: &Connection,
    snapshot: &Snapshot,
    stream: &str,
    batch: String,
) -> Result<RetainedBatch, String> {
    if schema_version(conn).await? < 2 {
        return Err("memory store has no retained assessments".into());
    }
    let id = snapshot.id(&fingerprint(&snapshot.repository)?)?;
    let mut rows = conn
        .query(
            "SELECT generation, native_attempt FROM assessment_batches
         WHERE snapshot_id = ?1 AND inventory_fingerprint = ?2 AND stream = ?3 AND id = ?4
           AND attempt_status = 'finished'",
            (
                id.as_str(),
                snapshot.inventory.as_str(),
                stream,
                batch.as_str(),
            ),
        )
        .await
        .map_err(db_error)?;
    let row = rows
        .next()
        .await
        .map_err(db_error)?
        .ok_or("retained finished batch does not match current inventory and stream")?;
    drop(rows);
    batch_with_decisions(
        conn,
        batch,
        row.get(0).map_err(db_error)?,
        row.get(1).map_err(db_error)?,
    )
    .await
}

async fn batch_with_decisions(
    conn: &Connection,
    batch: String,
    generation: i64,
    attempt: String,
) -> Result<RetainedBatch, String> {
    let generation = u64::try_from(generation).map_err(|_| "invalid retained native generation")?;
    let mut rows = conn.query(
        "SELECT a.decision_id FROM batch_assessments b JOIN assessments a ON a.id = b.assessment_id
         WHERE b.batch_id = ?1 ORDER BY a.decision_id",
        (batch.as_str(),),
    ).await.map_err(db_error)?;
    let mut decisions = Vec::new();
    while let Some(row) = rows.next().await.map_err(db_error)? {
        decisions.push(row.get(0).map_err(db_error)?);
    }
    Ok(RetainedBatch {
        id: batch,
        generation,
        attempt,
        decisions,
    })
}

pub(super) async fn latest_finished_batch(
    conn: &Connection,
    snapshot: &Snapshot,
    stream: &str,
) -> Result<Option<RetainedBatch>, String> {
    if schema_version(conn).await? < 2 {
        return Ok(None);
    }
    let id = snapshot.id(&fingerprint(&snapshot.repository)?)?;
    let mut rows = conn
        .query(
            "SELECT id, attempt_status, generation, native_attempt FROM assessment_batches
         WHERE snapshot_id = ?1 AND inventory_fingerprint = ?2 AND stream = ?3
           AND generation = (SELECT MAX(generation) FROM assessment_batches
               WHERE snapshot_id = ?1 AND inventory_fingerprint = ?2 AND stream = ?3)
         ORDER BY id LIMIT 2",
            (id.as_str(), snapshot.inventory.as_str(), stream),
        )
        .await
        .map_err(db_error)?;
    let Some(row) = rows.next().await.map_err(db_error)? else {
        return Ok(None);
    };
    if rows.next().await.map_err(db_error)?.is_some() {
        return Err("multiple retained batches match the latest generation".into());
    }
    if row.get::<String>(1).map_err(db_error)? != "finished" {
        return Ok(None);
    }
    drop(rows);
    batch_with_decisions(
        conn,
        row.get(0).map_err(db_error)?,
        row.get(2).map_err(db_error)?,
        row.get(3).map_err(db_error)?,
    )
    .await
    .map(Some)
}

pub(super) async fn read_assessments(
    conn: &Connection,
    batch: &str,
) -> Result<Vec<Assessment>, String> {
    let mut rows = query_batch(conn,
        "SELECT a.id, a.decision_id, a.review_id, a.subject_key, a.basis_fingerprint, a.response_fingerprint,
                a.verdict, a.confidence, a.summary
         FROM batch_assessments b JOIN assessments a ON a.id = b.assessment_id
         WHERE b.batch_id = ?1 ORDER BY a.review_id",
        batch,
    ).await?;
    let mut output = Vec::new();
    let mut positions = HashMap::new();
    while let Some(row) = rows.next().await.map_err(db_error)? {
        let id: String = row.get(0).map_err(db_error)?;
        positions.insert(id.clone(), output.len());
        output.push(Assessment {
            id,
            decision_id: row.get(1).map_err(db_error)?,
            review_id: row.get(2).map_err(db_error)?,
            subject_key: row.get(3).map_err(db_error)?,
            basis_fingerprint: row.get(4).map_err(db_error)?,
            response_fingerprint: row.get(5).map_err(db_error)?,
            verdict: row.get(6).map_err(db_error)?,
            confidence: row.get(7).map_err(db_error)?,
            summary: row.get(8).map_err(db_error)?,
            questions: Vec::new(),
            evidence: Vec::new(),
        });
    }
    if output.is_empty() {
        return Ok(output);
    }

    // Read each child collection independently. Joining both would repeat each
    // evidence range once for every question on the same assessment.
    let mut questions = query_batch(
        conn,
        "SELECT q.assessment_id, q.kind, q.question
         FROM batch_assessments b JOIN assessment_questions q ON q.assessment_id = b.assessment_id
         WHERE b.batch_id = ?1 ORDER BY b.assessment_id, q.kind, q.ordinal",
        batch,
    )
    .await?;
    while let Some(row) = questions.next().await.map_err(db_error)? {
        let id: String = row.get(0).map_err(db_error)?;
        let index = positions
            .get(&id)
            .ok_or("assessment question has no batch member")?;
        output[*index].questions.push(Question {
            kind: row.get(1).map_err(db_error)?,
            text: row.get(2).map_err(db_error)?,
        });
    }
    let mut evidence = query_batch(
        conn,
        "SELECT e.assessment_id, e.kind, e.reference, e.path, e.start_line, e.end_line,
                e.start_byte, e.end_byte, e.excerpt_sha256
         FROM batch_assessments b JOIN assessment_evidence e ON e.assessment_id = b.assessment_id
         WHERE b.batch_id = ?1 ORDER BY b.assessment_id, e.kind, e.reference",
        batch,
    )
    .await?;
    while let Some(row) = evidence.next().await.map_err(db_error)? {
        let id: String = row.get(0).map_err(db_error)?;
        let index = positions
            .get(&id)
            .ok_or("assessment evidence has no batch member")?;
        output[*index].evidence.push(Evidence {
            kind: row.get(1).map_err(db_error)?,
            reference: row.get(2).map_err(db_error)?,
            path: row.get(3).map_err(db_error)?,
            start_line: row.get(4).map_err(db_error)?,
            end_line: row.get(5).map_err(db_error)?,
            start_byte: row.get(6).map_err(db_error)?,
            end_byte: row.get(7).map_err(db_error)?,
            excerpt_sha256: row.get(8).map_err(db_error)?,
        });
    }
    Ok(output)
}

pub(super) async fn publish_assessment(
    conn: &Connection,
    publication: &str,
    assessment: &Assessment,
) -> Result<(), String> {
    let id = assessment.id.as_str();
    let added = conn.execute(
        "INSERT INTO assessments VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(id) DO NOTHING",
        (id, assessment.decision_id.as_str(), assessment.review_id.as_str(), assessment.subject_key.as_str(),
         assessment.basis_fingerprint.as_str(), assessment.response_fingerprint.as_str(), assessment.verdict.as_str(),
         assessment.confidence.as_str(), assessment.summary.as_str()),
    ).await.map_err(db_error)?;
    if added != 0 {
        for (ordinal, question) in assessment.questions.iter().enumerate() {
            conn.execute(
                "INSERT INTO assessment_questions VALUES (?1,?2,?3,?4)",
                (
                    id,
                    question.kind.as_str(),
                    integer(ordinal)?,
                    question.text.as_str(),
                ),
            )
            .await
            .map_err(db_error)?;
        }
        for evidence in &assessment.evidence {
            conn.execute(
                "INSERT INTO assessment_evidence VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                (
                    id,
                    evidence.kind.as_str(),
                    evidence.reference.as_str(),
                    evidence.path.as_str(),
                    evidence.start_line,
                    evidence.end_line,
                    evidence.start_byte,
                    evidence.end_byte,
                    evidence.excerpt_sha256.as_deref(),
                ),
            )
            .await
            .map_err(db_error)?;
        }
    }
    conn.execute(
        "INSERT INTO batch_assessments VALUES (?1,?2)",
        (publication, id),
    )
    .await
    .map_err(db_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_read_preserves_membership_and_child_order() {
        super::super::local_runtime().unwrap().block_on(async {
            let db = turso::Builder::new_local(":memory:").build().await.unwrap();
            let conn = db.connect().unwrap();
            conn.execute_batch("CREATE TABLE assessment_batches (id TEXT PRIMARY KEY)").await.unwrap();
            conn.execute_batch(CONTENT_SCHEMA).await.unwrap();
            conn.execute_batch("
                INSERT INTO assessment_batches VALUES ('selected'), ('other');
                INSERT INTO assessments VALUES
                    ('z','d1','first','s','b','r','issue','high','one'),
                    ('a','d2','second','s','b','r','issue','high','two'),
                    ('x','d3','outside','s','b','r','issue','high','three');
                INSERT INTO batch_assessments VALUES ('selected','a'), ('selected','z'), ('other','x'), ('other','z');
                INSERT INTO assessment_questions VALUES
                    ('z','check',2,'later'), ('x','check',0,'outside'), ('z','check',1,'earlier');
                INSERT INTO assessment_evidence VALUES
                    ('z','primary','b','b.rs',1,1,0,2,NULL), ('x','primary','x','x.rs',1,1,0,2,NULL),
                    ('z','primary','a','a.rs',1,1,0,2,'hash');
            ").await.unwrap();

            let batch = read_assessments(&conn, "selected").await.unwrap();
            let [first, second] = batch.as_slice() else {
                panic!("expected two batch members");
            };
            assert_eq!((first.review_id.as_str(), second.review_id.as_str()), ("first", "second"));
            let questions: Vec<_> = first.questions.iter().map(|q| q.text.as_str()).collect();
            assert_eq!(questions, ["earlier", "later"]);
            let evidence: Vec<_> = first.evidence.iter()
                .map(|e| (e.reference.as_str(), e.excerpt_sha256.as_deref()))
                .collect();
            assert_eq!(evidence, [("a", Some("hash")), ("b", None)]);
            assert!(second.questions.is_empty() && second.evidence.is_empty());

            let other = read_assessments(&conn, "other").await.unwrap();
            let reviews: Vec<_> = other.iter().map(|a| a.review_id.as_str()).collect();
            assert_eq!(reviews, ["first", "outside"]);
            assert_eq!(other[1].questions[0].text, "outside");
            assert_eq!(other[1].evidence[0].reference, "x");
        });
    }
}
