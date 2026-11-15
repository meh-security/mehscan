//! Read-only import of normalized v7 review history. These rows have no native
//! admission authority.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use turso::{Connection, Value, params::IntoParams, transaction::TransactionBehavior};

use super::{
    check_store_file, db_error, local_runtime, lock_store, open_local, prepare_legacy_schema,
    schema_version,
};

const VERSION: i64 = 7;

struct Table {
    name: &'static str,
    fields: &'static str,
    key: &'static str,
    references: &'static str,
}

impl Table {
    fn columns(&self) -> Vec<&str> {
        self.fields
            .split(',')
            .map(|field| field.split_whitespace().next().unwrap())
            .collect()
    }
}

macro_rules! table {
    ($name:literal, $fields:literal, $key:literal $(, $references:literal)?) => {
        Table { name: $name, fields: $fields, key: $key, references: concat!("" $(, $references)?) }
    };
}

// The selected relational data is sufficient to inspect saved decisions and
// their provenance. Object bodies and active dispatch state stay in the archive.
const TABLES: &[Table] = &[
    table!("repositories", "id TEXT NOT NULL", "id"),
    table!(
        "snapshots",
        "id TEXT NOT NULL, repository TEXT NOT NULL, policy TEXT NOT NULL, config TEXT NOT NULL, parent TEXT",
        "id",
        ", FOREIGN KEY (origin, repository) REFERENCES legacy_repositories(origin, id)"
    ),
    table!(
        "inputs",
        "snapshot TEXT NOT NULL, path TEXT NOT NULL, hash TEXT NOT NULL",
        "snapshot,path",
        ", FOREIGN KEY (origin, snapshot) REFERENCES legacy_snapshots(origin, id)"
    ),
    table!(
        "case_records",
        "id TEXT NOT NULL, digest TEXT NOT NULL, subject TEXT, owner_path TEXT, actor TEXT, conditions TEXT, remainder TEXT NOT NULL",
        "id"
    ),
    table!(
        "case_reviews",
        "id TEXT NOT NULL, snapshot TEXT NOT NULL, binding TEXT NOT NULL, artifact TEXT NOT NULL, closed INTEGER NOT NULL, created INTEGER NOT NULL",
        "id",
        ", FOREIGN KEY (origin, snapshot) REFERENCES legacy_snapshots(origin, id), FOREIGN KEY (origin, artifact) REFERENCES legacy_case_records(origin, id)"
    ),
    table!(
        "assessment_questions",
        "id TEXT NOT NULL, check_id TEXT NOT NULL, question TEXT NOT NULL, route TEXT, task_kind TEXT, scope TEXT, acceptance TEXT, remainder TEXT NOT NULL",
        "id"
    ),
    table!(
        "case_record_questions",
        "record TEXT NOT NULL, ordinal INTEGER NOT NULL, question TEXT NOT NULL",
        "record,ordinal",
        ", FOREIGN KEY (origin, record) REFERENCES legacy_case_records(origin, id), FOREIGN KEY (origin, question) REFERENCES legacy_assessment_questions(origin, id)"
    ),
    table!(
        "check_decisions",
        "record TEXT NOT NULL, ordinal INTEGER NOT NULL, check_id TEXT, status TEXT, summary TEXT, next_fact TEXT, fields INTEGER NOT NULL, remainder TEXT NOT NULL",
        "record,ordinal",
        ", FOREIGN KEY (origin, record) REFERENCES legacy_case_records(origin, id)"
    ),
    table!(
        "native_decisions",
        "record TEXT NOT NULL, ordinal INTEGER NOT NULL, review_id TEXT, decision TEXT, fields INTEGER NOT NULL, remainder TEXT NOT NULL",
        "record,ordinal",
        ", FOREIGN KEY (origin, record) REFERENCES legacy_case_records(origin, id)"
    ),
    table!(
        "finding_decisions",
        "record TEXT NOT NULL, ordinal INTEGER NOT NULL, finding_key TEXT, question TEXT, decision TEXT, assessment_fields INTEGER NOT NULL, assessment_remainder TEXT NOT NULL, fields INTEGER NOT NULL, remainder TEXT NOT NULL",
        "record,ordinal",
        ", FOREIGN KEY (origin, record) REFERENCES legacy_case_records(origin, id)"
    ),
    table!(
        "evidence_ranges",
        "id TEXT NOT NULL, path TEXT NOT NULL, start_line INTEGER NOT NULL, end_line INTEGER NOT NULL, text_field TEXT, text_artifact TEXT, source_hash TEXT, remainder TEXT NOT NULL",
        "id"
    ),
    table!(
        "case_evidence",
        "record TEXT NOT NULL, section TEXT NOT NULL, owner_ordinal INTEGER NOT NULL, ordinal INTEGER NOT NULL, evidence TEXT NOT NULL",
        "record,section,owner_ordinal,ordinal",
        ", FOREIGN KEY (origin, record) REFERENCES legacy_case_records(origin, id), FOREIGN KEY (origin, evidence) REFERENCES legacy_evidence_ranges(origin, id)"
    ),
    table!(
        "case_attachments",
        "record TEXT NOT NULL, kind TEXT NOT NULL, artifact TEXT NOT NULL",
        "record,kind",
        ", FOREIGN KEY (origin, record) REFERENCES legacy_case_records(origin, id)"
    ),
    table!(
        "case_origins",
        "review TEXT NOT NULL, repository TEXT NOT NULL, case_id TEXT NOT NULL, owner_path TEXT NOT NULL",
        "review",
        ", FOREIGN KEY (origin, review) REFERENCES legacy_case_reviews(origin, id)"
    ),
    table!(
        "case_candidates",
        "id TEXT NOT NULL, repository TEXT NOT NULL, case_id TEXT NOT NULL, owner_path TEXT NOT NULL, origin_review TEXT NOT NULL, proposal_key TEXT NOT NULL, status TEXT NOT NULL, current_review TEXT",
        "id",
        ", FOREIGN KEY (origin, origin_review) REFERENCES legacy_case_reviews(origin, id), FOREIGN KEY (origin, current_review) REFERENCES legacy_case_reviews(origin, id)"
    ),
    table!(
        "validity_subjects",
        "id TEXT NOT NULL, repository TEXT NOT NULL, kind TEXT NOT NULL, subject_key TEXT NOT NULL",
        "id"
    ),
    table!(
        "validity_facts",
        "id TEXT NOT NULL, subject TEXT NOT NULL, predicate TEXT NOT NULL, target TEXT NOT NULL, producer TEXT NOT NULL",
        "id"
    ),
    table!(
        "validity_values",
        "id TEXT NOT NULL, body TEXT NOT NULL",
        "id"
    ),
    table!(
        "validity_observations",
        "fact TEXT NOT NULL, snapshot TEXT NOT NULL, value_hash TEXT, value_id TEXT NOT NULL",
        "fact,snapshot",
        ", FOREIGN KEY (origin, fact) REFERENCES legacy_validity_facts(origin, id), FOREIGN KEY (origin, snapshot) REFERENCES legacy_snapshots(origin, id), FOREIGN KEY (origin, value_id) REFERENCES legacy_validity_values(origin, id)"
    ),
    table!(
        "validity_assessments",
        "review TEXT NOT NULL, subject TEXT NOT NULL, contract TEXT NOT NULL, complete INTEGER NOT NULL, scope TEXT NOT NULL",
        "review",
        ", FOREIGN KEY (origin, review) REFERENCES legacy_case_reviews(origin, id)"
    ),
    table!(
        "validity_inputs",
        "review TEXT NOT NULL, fact TEXT NOT NULL, role TEXT NOT NULL, value_hash TEXT, basis TEXT NOT NULL",
        "review,fact,role",
        ", FOREIGN KEY (origin, review) REFERENCES legacy_case_reviews(origin, id), FOREIGN KEY (origin, fact) REFERENCES legacy_validity_facts(origin, id), FOREIGN KEY (origin, basis) REFERENCES legacy_validity_values(origin, id)"
    ),
    table!(
        "questions",
        "id TEXT NOT NULL, repository TEXT, body TEXT NOT NULL",
        "id"
    ),
    table!(
        "question_details",
        "question TEXT NOT NULL, subject TEXT NOT NULL, kind TEXT NOT NULL, boundary TEXT NOT NULL, scope TEXT NOT NULL, schema_version TEXT NOT NULL, operands TEXT NOT NULL, conditions TEXT NOT NULL",
        "question",
        ", FOREIGN KEY (origin, question) REFERENCES legacy_questions(origin, id)"
    ),
    table!(
        "answers",
        "id TEXT NOT NULL, question TEXT NOT NULL, snapshot TEXT NOT NULL, body TEXT NOT NULL, created INTEGER NOT NULL",
        "id",
        ", FOREIGN KEY (origin, question) REFERENCES legacy_questions(origin, id), FOREIGN KEY (origin, snapshot) REFERENCES legacy_snapshots(origin, id)"
    ),
    table!(
        "answer_details",
        "answer TEXT NOT NULL, digest TEXT NOT NULL, outcome TEXT NOT NULL, summary TEXT NOT NULL, provenance TEXT NOT NULL, contract TEXT NOT NULL, conditions TEXT NOT NULL, gaps TEXT NOT NULL, notes TEXT",
        "answer",
        ", FOREIGN KEY (origin, answer) REFERENCES legacy_answers(origin, id)"
    ),
    table!(
        "answer_evidence",
        "answer TEXT NOT NULL, ordinal INTEGER NOT NULL, path TEXT NOT NULL, start_line INTEGER NOT NULL, end_line INTEGER NOT NULL, source_hash TEXT NOT NULL, remainder TEXT NOT NULL",
        "answer,ordinal",
        ", FOREIGN KEY (origin, answer) REFERENCES legacy_answers(origin, id)"
    ),
    table!(
        "dependencies",
        "answer TEXT NOT NULL, kind TEXT NOT NULL, target TEXT NOT NULL, fingerprint TEXT NOT NULL",
        "answer,kind,target",
        ", FOREIGN KEY (origin, answer) REFERENCES legacy_answers(origin, id)"
    ),
    table!(
        "disputes",
        "answer TEXT NOT NULL, reason TEXT NOT NULL",
        "answer",
        ", FOREIGN KEY (origin, answer) REFERENCES legacy_answers(origin, id)"
    ),
    table!(
        "case_checks",
        "snapshot TEXT NOT NULL, case_id TEXT NOT NULL, check_id TEXT NOT NULL, question TEXT NOT NULL, roles TEXT NOT NULL",
        "snapshot,case_id,check_id",
        ", FOREIGN KEY (origin, snapshot) REFERENCES legacy_snapshots(origin, id), FOREIGN KEY (origin, question) REFERENCES legacy_questions(origin, id)"
    ),
];

pub(super) async fn install(conn: &Connection) -> Result<(), String> {
    conn.execute("CREATE TABLE legacy_imports (origin TEXT NOT NULL PRIMARY KEY, source_version INTEGER NOT NULL, digest TEXT NOT NULL)", ())
        .await.map_err(db_error)?;
    for table in TABLES {
        let ddl = format!(
            "CREATE TABLE legacy_{} (origin TEXT NOT NULL REFERENCES legacy_imports(origin), {},
             PRIMARY KEY (origin, {}){})",
            table.name, table.fields, table.key, table.references,
        );
        conn.execute(ddl, ()).await.map_err(db_error)?;
    }
    Ok(())
}

pub(super) fn help() {
    println!(
        "  mehscan memory import-legacy --store FILE --legacy FILE --origin NAME\n  mehscan memory legacy-history --store FILE --origin NAME [--assessment ID]"
    );
}

pub(super) fn run(operation: &str, arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let mut args = super::super::ParsedArguments::parse(arguments)?;
    if args.help {
        help();
        return Ok(());
    }
    if args.root != Path::new(".") {
        return Err("legacy memory operations accept named options only".into());
    }
    let destination =
        std::path::absolute(args.required("--store")?).map_err(|error| error.to_string())?;
    let origin = args.required("--origin")?;
    if origin.trim().is_empty() || origin.len() > 256 || origin.chars().any(char::is_control) {
        return Err("legacy origin requires a nonempty identifier of at most 256 bytes".into());
    }
    check_store_file(&destination)?;
    let result = if operation == "import-legacy" {
        let source =
            fs::canonicalize(args.required("--legacy")?).map_err(|error| error.to_string())?;
        args.finish()?;
        if !source.is_file() || destination.canonicalize().is_ok_and(|path| path == source) {
            return Err(
                "legacy import requires distinct source and destination database files".into(),
            );
        }
        local_runtime()?.block_on(import(&source, &destination, &origin))?
    } else {
        let assessment = args.optional("--assessment");
        args.finish()?;
        if !destination.is_file() {
            return Err("legacy history requires an existing review memory database".into());
        }
        let _lock = lock_store(&destination)?;
        local_runtime()?.block_on(async {
            let (_database, conn) = open_local(&destination, true).await?;
            history(&conn, &origin, assessment.as_deref()).await
        })?
    };
    super::super::print_json(&result)
}

async fn import(source: &Path, destination: &Path, origin: &str) -> Result<Json, String> {
    let (_source_db, mut legacy) = open_local(source, true).await?;
    let read = legacy.transaction().await.map_err(db_error)?;
    let mut version = read
        .query("PRAGMA user_version", ())
        .await
        .map_err(db_error)?;
    let row = version
        .next()
        .await
        .map_err(db_error)?
        .ok_or("legacy schema version unavailable")?;
    if row.get::<i64>(0).map_err(db_error)? != VERSION {
        return Err("legacy import requires a normalized version 7 store".into());
    }
    drop(version);
    let mut roots = read
        .query("SELECT root FROM repositories", ())
        .await
        .map_err(db_error)?;
    while let Some(row) = roots.next().await.map_err(db_error)? {
        let root = PathBuf::from(row.get::<String>(0).map_err(db_error)?);
        if root.is_dir() {
            super::super::review_state::outside_source(destination, &root)?;
        }
    }
    drop(roots);

    let _lock = lock_store(destination)?;
    let (_target_db, mut target) = open_local(destination, false).await?;
    let write = target
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await
        .map_err(db_error)?;
    prepare_legacy_schema(&write).await?;
    let existing = imported_digest(&write, origin).await?;
    if existing.is_none() {
        write
            .execute(
                "INSERT INTO legacy_imports VALUES (?1, ?2, '')",
                (origin, VERSION),
            )
            .await
            .map_err(db_error)?;
    }
    let mut digest = Sha256::new();
    digest.update(b"mehscanLegacyMemory/v1\0");
    let mut counts = BTreeMap::new();
    for table in TABLES {
        let count = transfer_table(
            &read,
            &write,
            table,
            origin,
            existing.is_none(),
            &mut digest,
        )
        .await?;
        counts.insert(table.name, count);
    }
    let identity = format!("{:x}", digest.finalize());
    if let Some(previous) = &existing {
        if *previous != identity {
            return Err(
                "legacy origin already refers to different history; choose a distinct origin"
                    .into(),
            );
        }
    } else {
        write
            .execute(
                "UPDATE legacy_imports SET digest = ?1 WHERE origin = ?2",
                (identity.as_str(), origin),
            )
            .await
            .map_err(db_error)?;
    }
    write.commit().await.map_err(db_error)?;
    Ok(
        json!({"authority":"historical_context","origin":origin,"source_version":VERSION,
              "digest":identity,"reused":existing.is_some(),"counts":counts}),
    )
}

async fn transfer_table(
    read: &Connection,
    write: &Connection,
    table: &Table,
    origin: &str,
    insert: bool,
    digest: &mut Sha256,
) -> Result<usize, String> {
    let columns = table.columns();
    let mut rows = read
        .query(
            format!(
                "SELECT {} FROM {} ORDER BY {}",
                columns.join(","),
                table.name,
                table.key
            ),
            (),
        )
        .await
        .map_err(db_error)?;
    let mut target = if insert {
        let parameters = vec!["?"; columns.len() + 1].join(",");
        Some(
            write
                .prepare(format!(
                    "INSERT INTO legacy_{} VALUES ({parameters})",
                    table.name
                ))
                .await
                .map_err(db_error)?,
        )
    } else {
        None
    };
    digest_bytes(digest, table.name.as_bytes());
    let mut count = 0;
    while let Some(row) = rows.next().await.map_err(db_error)? {
        count += 1;
        let mut values = vec![Value::Text(origin.into())];
        for index in 0..columns.len() {
            let value = row.get_value(index).map_err(db_error)?;
            match &value {
                Value::Null => digest.update([0]),
                Value::Integer(n) => {
                    digest.update([1]);
                    digest.update(n.to_le_bytes());
                }
                Value::Real(n) => {
                    digest.update([2]);
                    digest.update(n.to_bits().to_le_bytes());
                }
                Value::Text(s) => {
                    digest.update([3]);
                    digest_bytes(digest, s.as_bytes());
                }
                Value::Blob(bytes) => {
                    digest.update([4]);
                    digest_bytes(digest, bytes);
                }
            }
            values.push(value);
        }
        if let Some(statement) = &mut target {
            statement
                .execute(values)
                .await
                .map_err(|error| format!("legacy {}: {error}", table.name))?;
        }
    }
    digest.update((count as u64).to_le_bytes());
    Ok(count)
}

fn digest_bytes(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

async fn imported_digest(conn: &Connection, origin: &str) -> Result<Option<String>, String> {
    let mut rows = conn
        .query(
            "SELECT digest FROM legacy_imports WHERE origin = ?1",
            (origin,),
        )
        .await
        .map_err(db_error)?;
    rows.next()
        .await
        .map_err(db_error)?
        .map(|row| row.get(0).map_err(db_error))
        .transpose()
}

async fn history(
    conn: &Connection,
    origin: &str,
    assessment: Option<&str>,
) -> Result<Json, String> {
    if schema_version(conn).await? < 3 {
        return Err("review memory has no legacy imports".into());
    }
    let digest = imported_digest(conn, origin)
        .await?
        .ok_or("unknown legacy origin")?;
    let mut result = json!({"authority":"historical_context","origin":origin,"digest":digest});
    const ASSESSMENTS: &str =
        "SELECT r.id, r.snapshot, r.artifact, r.binding, r.closed, r.created, c.digest, c.subject, c.owner_path
         FROM legacy_case_reviews r JOIN legacy_case_records c ON c.origin = r.origin AND c.id = r.artifact
         WHERE r.origin = ?1";
    if let Some(id) = assessment {
        let query = format!("{ASSESSMENTS} AND r.id = ?2");
        let row = rows_json(conn, &query, (origin, id))
            .await?
            .into_iter()
            .next()
            .ok_or("unknown legacy assessment")?;
        let record = row["artifact"]
            .as_str()
            .ok_or("missing legacy assessment artifact")?;
        result["checks"] = json!(rows_json(conn,
            "SELECT d.check_id, q.question, d.status, d.summary, d.next_fact
             FROM legacy_check_decisions d LEFT JOIN legacy_case_record_questions l
               ON l.origin = d.origin AND l.record = d.record AND d.check_id =
                 (SELECT check_id FROM legacy_assessment_questions WHERE origin = l.origin AND id = l.question)
             LEFT JOIN legacy_assessment_questions q ON q.origin = l.origin AND q.id = l.question
             WHERE d.origin = ?1 AND d.record = ?2 ORDER BY d.ordinal", (origin, record)).await?);
        for (name, sql) in [
            ("native_decisions", "SELECT review_id, decision FROM legacy_native_decisions WHERE origin = ?1 AND record = ?2 ORDER BY ordinal"),
            ("findings", "SELECT finding_key, question, decision FROM legacy_finding_decisions WHERE origin = ?1 AND record = ?2 ORDER BY ordinal"),
            ("evidence", "SELECT e.id, l.section, e.path, e.start_line, e.end_line, e.source_hash, e.text_artifact
                FROM legacy_case_evidence l JOIN legacy_evidence_ranges e ON e.origin = l.origin AND e.id = l.evidence
                WHERE l.origin = ?1 AND l.record = ?2 ORDER BY l.section,l.owner_ordinal,l.ordinal"),
        ] {
            result[name] = json!(rows_json(conn, sql, (origin, record)).await?);
        }
        result["dependencies"] = json!(rows_json(conn,
            "SELECT i.fact, f.predicate, f.target, f.producer, i.role, i.value_hash, i.basis
             FROM legacy_validity_inputs i JOIN legacy_validity_facts f ON f.origin = i.origin AND f.id = i.fact
             WHERE i.origin = ?1 AND i.review = ?2 ORDER BY i.fact,i.role", (origin, id)).await?);
        result["historical_candidates"] = json!(rows_json(conn,
            "SELECT id, case_id, owner_path, proposal_key, status, origin_review, current_review
             FROM legacy_case_candidates WHERE origin = ?1 AND (origin_review = ?2 OR current_review = ?2)
             ORDER BY id", (origin, id)).await?);
        result["assessment"] = row;
    } else {
        let query = format!("{ASSESSMENTS} ORDER BY r.created,r.id");
        result["assessments"] = json!(rows_json(conn, &query, (origin,)).await?);
    }
    Ok(result)
}

async fn rows_json(
    conn: &Connection,
    sql: &str,
    parameters: impl IntoParams,
) -> Result<Vec<Json>, String> {
    let mut rows = conn.query(sql, parameters).await.map_err(db_error)?;
    let columns = rows.column_names();
    let mut output = Vec::new();
    while let Some(row) = rows.next().await.map_err(db_error)? {
        let mut object = serde_json::Map::new();
        for (index, name) in columns.iter().enumerate() {
            let value = match row.get_value(index).map_err(db_error)? {
                Value::Null => Json::Null,
                Value::Integer(number) => json!(number),
                Value::Real(number) => json!(number),
                Value::Text(text) => json!(text),
                Value::Blob(_) => return Err("unexpected binary value in legacy history".into()),
            };
            object.insert(name.clone(), value);
        }
        output.push(Json::Object(object));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn normalized_legacy_import_is_read_only_idempotent_and_transactional() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "mehscan-legacy-import-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&base).unwrap();
        let source = base.join("legacy.sqlite");
        let target = base.join("memory.turso");
        local_runtime().unwrap().block_on(async {
            {
                let (_db, conn) = open_local(&source, false).await.unwrap();
                for table in TABLES {
                    let root = if table.name == "repositories" { ", root TEXT NOT NULL" } else { "" };
                    conn.execute(format!("CREATE TABLE {} ({}{}, PRIMARY KEY ({}))",
                        table.name, table.fields, root, table.key), ()).await.unwrap();
                }
                conn.execute_batch(
                    "PRAGMA user_version = 7;
                     INSERT INTO repositories VALUES ('repo', 'archived-checkout');
                     INSERT INTO snapshots VALUES ('snapshot','repo','policy','{}',NULL);
                     INSERT INTO inputs VALUES ('snapshot','app.js','old-hash');
                     INSERT INTO case_records VALUES ('artifact','digest','subject','app.js',NULL,NULL,'{}');
                     INSERT INTO case_reviews VALUES ('review','snapshot','binding','artifact',0,1);
                     INSERT INTO assessment_questions VALUES ('question','check','Is the input bounded?',NULL,NULL,NULL,NULL,'{}');
                     INSERT INTO case_record_questions VALUES ('artifact',0,'question');
                     INSERT INTO check_decisions VALUES ('artifact',0,'check','unresolved','Awaiting caller evidence','Caller binding',15,'{}');
                     INSERT INTO evidence_ranges VALUES ('range','app.js',2,3,'quote',NULL,'old-hash','{}');
                     INSERT INTO case_evidence VALUES ('artifact','proofs',0,0,'range');
                     INSERT INTO validity_facts VALUES ('fact','subject','file','app.js','producer');
                     INSERT INTO validity_values VALUES ('value','recorded input');
                     INSERT INTO validity_inputs VALUES ('review','fact','control','old-hash','value');
                     INSERT INTO case_candidates VALUES ('candidate','repo','case','app.js','review','proposal','needs_review',NULL);",
                ).await.unwrap();
            }
            {
                let (_db, conn) = open_local(&target, false).await.unwrap();
                super::super::prepare_schema(&conn).await.unwrap();
                assert_eq!(schema_version(&conn).await.unwrap(), 2);
            }
            let original = fs::read(&source).unwrap();
            let first = import(&source, &target, "fixture").await.unwrap();
            let repeated = import(&source, &target, "fixture").await.unwrap();
            assert_eq!(first["counts"]["case_reviews"], 1);
            assert_eq!(repeated["reused"], true);
            assert_eq!(repeated["digest"], first["digest"]);
            assert_eq!(fs::read(&source).unwrap(), original);
            {
                let (_db, conn) = open_local(&target, true).await.unwrap();
                let saved = history(&conn, "fixture", Some("review")).await.unwrap();
                assert_eq!(saved["authority"], "historical_context");
                assert_eq!(saved["checks"][0]["question"], "Is the input bounded?");
                assert_eq!(saved["checks"][0]["next_fact"], "Caller binding");
                assert_eq!(saved["evidence"][0]["start_line"], 2);
                assert_eq!(saved["dependencies"][0]["role"], "control");
                assert_eq!(saved["historical_candidates"][0]["status"], "needs_review");
            }
            {
                let (_db, conn) = open_local(&source, false).await.unwrap();
                conn.execute("UPDATE check_decisions SET summary = 'Changed old archive'", ()).await.unwrap();
                conn.execute("INSERT INTO case_evidence VALUES ('artifact','proofs',0,1,'missing')", ()).await.unwrap();
            }
            let error = import(&source, &target, "fixture").await.unwrap_err();
            assert!(error.contains("refers to different history"), "{error}");
            let error = import(&source, &target, "failed-import").await.unwrap_err();
            assert!(error.contains("case_evidence"), "{error}");
            let (_db, conn) = open_local(&target, true).await.unwrap();
            assert!(imported_digest(&conn, "failed-import").await.unwrap().is_none());
            let saved = history(&conn, "fixture", Some("review")).await.unwrap();
            assert_eq!(saved["checks"][0]["summary"], "Awaiting caller evidence");
        });
        assert!(
            base.canonicalize()
                .unwrap()
                .starts_with(std::env::temp_dir().canonicalize().unwrap())
        );
        fs::remove_dir_all(base).unwrap();
    }
}
