//! Decode whole and split case artifacts from pre-relational memory archives.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value as Json, json};
use sha2::{Digest, Sha256};
use turso::{Builder, Connection, Database};

use super::{TABLES, db_error, distinct_destination, open_local, table_exists};

const CASE_PARTS: &[&str] = &[
    "facts",
    "inspected",
    "proofs",
    "proposals",
    "prior_research",
    "prior_inspected",
];

fn generated_case_table(name: &str) -> bool {
    matches!(
        name,
        "case_records"
            | "assessment_questions"
            | "case_record_questions"
            | "check_decisions"
            | "native_decisions"
            | "finding_decisions"
            | "evidence_ranges"
            | "case_evidence"
            | "case_attachments"
    )
}

pub(super) async fn normalize(
    source: &Connection,
    database: &Path,
    destination: &Path,
    explicit_pack: Option<&Path>,
) -> Result<(Database, Connection), String> {
    let temporary = Builder::new_local(":memory:")
        .build()
        .await
        .map_err(db_error)?;
    let conn = temporary.connect().map_err(db_error)?;
    if !table_exists(source, "case_records").await? && table_exists(source, "case_reviews").await? {
        create_staging_tables(&conn, generated_case_table).await?;
        let mut cases = source
            .query(
                "SELECT DISTINCT artifact FROM case_reviews ORDER BY artifact",
                (),
            )
            .await
            .map_err(db_error)?;
        if let Some(first) = cases.next().await.map_err(db_error)? {
            let objects = Objects::open(source, database, destination, explicit_pack).await?;
            let mut row = Some(first);
            while let Some(case) = row {
                let id: String = case.get(0).map_err(db_error)?;
                let (payload, references) = objects.case(&id).await?;
                project(&conn, &id, &payload, &references).await?;
                row = cases.next().await.map_err(db_error)?;
            }
        }
    }
    if has_inline_observations(source).await? {
        normalize_validity(source, &conn).await?;
    }
    normalize_knowledge(source, &conn).await?;
    Ok((temporary, conn))
}

async fn create_staging_tables(
    conn: &Connection,
    selected: impl Fn(&str) -> bool,
) -> Result<(), String> {
    for table in TABLES.iter().filter(|table| selected(table.name)) {
        conn.execute(
            format!(
                "CREATE TABLE {} ({}, PRIMARY KEY ({}))",
                table.name, table.fields, table.key
            ),
            (),
        )
        .await
        .map_err(db_error)?;
    }
    Ok(())
}

async fn has_inline_observations(source: &Connection) -> Result<bool, String> {
    let mut columns = source
        .query("PRAGMA table_info(validity_observations)", ())
        .await
        .map_err(db_error)?;
    while let Some(row) = columns.next().await.map_err(db_error)? {
        if row.get::<String>(1).map_err(db_error)? == "body" {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn normalize_validity(source: &Connection, target: &Connection) -> Result<(), String> {
    create_staging_tables(target, |name| {
        matches!(
            name,
            "validity_values" | "validity_observations" | "validity_inputs"
        )
    })
    .await?;
    let mut observations = source.query("SELECT fact,snapshot,value_hash,body FROM validity_observations ORDER BY fact,snapshot", ())
        .await.map_err(db_error)?;
    while let Some(row) = observations.next().await.map_err(db_error)? {
        let body: String = row.get(3).map_err(db_error)?;
        let value = observation_value(target, &body).await?;
        target
            .execute(
                "INSERT INTO validity_observations VALUES (?,?,?,?)",
                (
                    row.get::<String>(0).map_err(db_error)?,
                    row.get::<String>(1).map_err(db_error)?,
                    row.get::<Option<String>>(2).map_err(db_error)?,
                    value,
                ),
            )
            .await
            .map_err(db_error)?;
    }
    let mut inputs = source.query("SELECT review,fact,role,value_hash,basis FROM validity_inputs ORDER BY review,fact,role", ())
        .await.map_err(db_error)?;
    while let Some(row) = inputs.next().await.map_err(db_error)? {
        let basis: String = row.get(4).map_err(db_error)?;
        let parsed: Json = serde_json::from_str(&basis).map_err(|error| error.to_string())?;
        let value = if let (Some(fact), Some(snapshot)) = (
            parsed["fact"].as_str(),
            parsed["observation_snapshot"].as_str(),
        ) && parsed.as_object().is_some_and(|fields| fields.len() == 2)
        {
            let mut rows = target
                .query(
                    "SELECT value_id FROM validity_observations WHERE fact = ?1 AND snapshot = ?2",
                    (fact, snapshot),
                )
                .await
                .map_err(db_error)?;
            rows.next()
                .await
                .map_err(db_error)?
                .ok_or("legacy dependency observation is missing")?
                .get::<String>(0)
                .map_err(db_error)?
        } else {
            observation_value(target, &basis).await?
        };
        target
            .execute(
                "INSERT INTO validity_inputs VALUES (?,?,?,?,?)",
                (
                    row.get::<String>(0).map_err(db_error)?,
                    row.get::<String>(1).map_err(db_error)?,
                    row.get::<String>(2).map_err(db_error)?,
                    row.get::<Option<String>>(3).map_err(db_error)?,
                    value,
                ),
            )
            .await
            .map_err(db_error)?;
    }
    Ok(())
}

async fn observation_value(conn: &Connection, body: &str) -> Result<String, String> {
    let identity = id(&json!(["observation-value/v1", body]));
    conn.execute(
        "INSERT INTO validity_values VALUES (?1, ?2) ON CONFLICT(id) DO NOTHING",
        (identity.as_str(), body),
    )
    .await
    .map_err(db_error)?;
    Ok(identity)
}

async fn normalize_knowledge(source: &Connection, target: &Connection) -> Result<(), String> {
    if table_exists(source, "questions").await? && !table_exists(source, "question_details").await?
    {
        create_staging_tables(target, |name| {
            matches!(name, "questions" | "question_details")
        })
        .await?;
        let mut questions = source
            .query("SELECT id,repository,body FROM questions ORDER BY id", ())
            .await
            .map_err(db_error)?;
        while let Some(row) = questions.next().await.map_err(db_error)? {
            let identity: String = row.get(0).map_err(db_error)?;
            let body: String = row.get(2).map_err(db_error)?;
            let spec: Json = serde_json::from_str(&body).map_err(|error| error.to_string())?;
            let details =
                ["subject", "kind", "boundary", "scope", "schema"].map(|key| spec[key].as_str());
            let mut remainder = body.as_str();
            if let [
                Some(subject),
                Some(kind),
                Some(boundary),
                Some(scope),
                Some(schema),
            ] = details
                && spec.get("operands").is_some()
                && spec.get("conditions").is_some()
            {
                target
                    .execute(
                        "INSERT INTO question_details VALUES (?,?,?,?,?,?,?,?)",
                        (
                            identity.as_str(),
                            subject,
                            kind,
                            boundary,
                            scope,
                            schema,
                            packed(&spec["operands"]),
                            packed(&spec["conditions"]),
                        ),
                    )
                    .await
                    .map_err(db_error)?;
                remainder = "{}";
            }
            target
                .execute(
                    "INSERT INTO questions VALUES (?,?,?)",
                    (
                        identity,
                        row.get::<Option<String>>(1).map_err(db_error)?,
                        remainder,
                    ),
                )
                .await
                .map_err(db_error)?;
        }
    }
    if table_exists(source, "answers").await? && !table_exists(source, "answer_details").await? {
        create_staging_tables(target, |name| {
            matches!(name, "answers" | "answer_details" | "answer_evidence")
        })
        .await?;
        let mut answers = source
            .query(
                "SELECT id,question,snapshot,body,created FROM answers ORDER BY id",
                (),
            )
            .await
            .map_err(db_error)?;
        while let Some(row) = answers.next().await.map_err(db_error)? {
            let identity: String = row.get(0).map_err(db_error)?;
            let body: String = row.get(3).map_err(db_error)?;
            let answer: Json = serde_json::from_str(&body).map_err(|error| error.to_string())?;
            let has_details = write_answer(target, &identity, &answer).await?;
            target
                .execute(
                    "INSERT INTO answers VALUES (?,?,?,?,?)",
                    (
                        identity,
                        row.get::<String>(1).map_err(db_error)?,
                        row.get::<String>(2).map_err(db_error)?,
                        if has_details { "{}" } else { body.as_str() },
                        row.get::<i64>(4).map_err(db_error)?,
                    ),
                )
                .await
                .map_err(db_error)?;
        }
    }
    Ok(())
}

async fn write_answer(conn: &Connection, identity: &str, answer: &Json) -> Result<bool, String> {
    let [Some(outcome), Some(summary), Some(provenance)] =
        ["outcome", "summary", "provenance"].map(|key| answer[key].as_str())
    else {
        return Ok(false);
    };
    let Some(evidence) = answer["evidence"].as_array() else {
        return Ok(false);
    };
    conn.execute(
        "INSERT INTO answer_details VALUES (?,?,?,?,?,?,?,?,?)",
        (
            identity,
            id(answer),
            outcome,
            summary,
            provenance,
            packed(&answer["contract"]),
            packed(&answer["conditions"]),
            packed(&answer["gaps"]),
            answer.get("notes").map(packed),
        ),
    )
    .await
    .map_err(db_error)?;
    for (ordinal, proof) in evidence.iter().enumerate() {
        let (Some(path), Some(start), Some(end), Some(artifact)) = (
            proof["path"].as_str(),
            proof["start_line"].as_i64(),
            proof["end_line"].as_i64(),
            proof["artifact"].as_str(),
        ) else {
            return Err("legacy answer has incomplete evidence coordinates".into());
        };
        let (_, _, remainder) = split(
            proof,
            &["path", "start_line", "end_line", "artifact", "quote"],
        )?;
        conn.execute(
            "INSERT INTO answer_evidence VALUES (?,?,?,?,?,?,?)",
            (
                identity,
                order(ordinal)?,
                path,
                start,
                end,
                artifact,
                packed(&Json::Object(remainder)),
            ),
        )
        .await
        .map_err(db_error)?;
    }
    Ok(true)
}

struct Objects {
    pack: Option<(Database, Connection)>,
    has_codec: bool,
    directories: Vec<PathBuf>,
}

impl Objects {
    async fn open(
        source: &Connection,
        database: &Path,
        destination: &Path,
        explicit: Option<&Path>,
    ) -> Result<Self, String> {
        let mut default_dir = database.as_os_str().to_owned();
        default_dir.push(".artifacts");
        let mut directories = vec![PathBuf::from(default_dir)];
        let parent = database
            .parent()
            .ok_or("legacy database has no containing directory")?;
        let mut pack_path = explicit.map(Path::to_path_buf);
        if table_exists(source, "artifact_storage").await? {
            let mut rows = source
                .query(
                    "SELECT kind, path FROM artifact_storage ORDER BY kind,path",
                    (),
                )
                .await
                .map_err(db_error)?;
            while let Some(row) = rows.next().await.map_err(db_error)? {
                let kind: String = row.get(0).map_err(db_error)?;
                let location = parent.join(row.get::<String>(1).map_err(db_error)?);
                match kind.as_str() {
                    "legacy" => directories.push(location),
                    "objects" if pack_path.is_none() => pack_path = Some(location),
                    _ => {}
                }
            }
        }
        let path = pack_path.unwrap_or_else(|| parent.join(".mehscan-objects.sqlite"));
        let mut has_codec = false;
        let pack = if path.is_file() {
            let location = path.canonicalize().map_err(|error| error.to_string())?;
            distinct_destination(&location, destination)?;
            let (db, conn) = open_local(&location, true).await?;
            let mut rows = conn
                .query("PRAGMA table_info(objects)", ())
                .await
                .map_err(db_error)?;
            while let Some(row) = rows.next().await.map_err(db_error)? {
                has_codec |= row.get::<String>(1).map_err(db_error)? == "codec";
            }
            drop(rows);
            Some((db, conn))
        } else if explicit.is_some() {
            return Err("specified legacy object pack is unavailable".into());
        } else {
            None
        };
        Ok(Self {
            pack,
            has_codec,
            directories,
        })
    }

    async fn read(&self, identity: &str) -> Result<Vec<u8>, String> {
        if identity.len() != 64
            || !identity
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err("invalid legacy artifact identity".into());
        }
        if let Some((_, pack)) = &self.pack {
            let sql = if self.has_codec {
                "SELECT body,codec FROM objects WHERE hash = ?1"
            } else {
                "SELECT body,'raw' FROM objects WHERE hash = ?1"
            };
            let mut rows = pack.query(sql, (identity,)).await.map_err(db_error)?;
            if let Some(row) = rows.next().await.map_err(db_error)? {
                let body: Vec<u8> = row.get(0).map_err(db_error)?;
                let codec: String = row.get(1).map_err(db_error)?;
                let bytes = match codec.as_str() {
                    "raw" => body,
                    "zlib" => miniz_oxide::inflate::decompress_to_vec_zlib(&body)
                        .map_err(|_| format!("invalid compressed legacy artifact {identity}"))?,
                    _ => return Err("unsupported legacy artifact codec".into()),
                };
                return verify(identity, bytes);
            }
        }
        for directory in &self.directories {
            let path = directory.join(identity);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_file() => {
                    let bytes = fs::read(&path).map_err(|error| error.to_string())?;
                    return verify(identity, bytes);
                }
                Ok(_) => return Err("legacy artifact must be a regular file".into()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        Err(format!("missing legacy artifact {identity}"))
    }

    async fn case(&self, id: &str) -> Result<(Json, BTreeReferences), String> {
        let mut payload: Json =
            serde_json::from_slice(&self.read(id).await?).map_err(|error| error.to_string())?;
        let mut references = BTreeReferences::new();
        if let Some(version) = payload.get("case_artifact_version") {
            match version.as_u64() {
                Some(1) => {}
                Some(2) => {
                    let parts = payload["case_parts"]
                        .as_object()
                        .ok_or("invalid split legacy case artifact")?
                        .clone();
                    let result = payload["result"]
                        .as_object_mut()
                        .ok_or("legacy case has no result")?;
                    for (field, reference) in parts {
                        if !CASE_PARTS.contains(&field.as_str()) || result.contains_key(&field) {
                            return Err("invalid legacy case part membership".into());
                        }
                        let reference = reference
                            .as_str()
                            .ok_or("invalid legacy case part reference")?;
                        let part = serde_json::from_slice(&self.read(reference).await?)
                            .map_err(|error| error.to_string())?;
                        result.insert(field.clone(), part);
                        references.insert(field, reference.into());
                    }
                    if let Some(reference) = payload.get("question_artifact") {
                        if payload.get("questions").is_some() {
                            return Err("ambiguous legacy question reference".into());
                        }
                        let reference = reference
                            .as_str()
                            .ok_or("invalid legacy question reference")?
                            .to_owned();
                        payload["questions"] =
                            serde_json::from_slice(&self.read(&reference).await?)
                                .map_err(|error| error.to_string())?;
                        references.insert("questions".into(), reference);
                    }
                }
                _ => return Err("unsupported legacy case artifact format".into()),
            }
        }
        Ok((payload, references))
    }
}

type BTreeReferences = std::collections::BTreeMap<String, String>;

fn verify(identity: &str, bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    if format!("{:x}", Sha256::digest(&bytes)) != identity {
        return Err(format!("legacy artifact checksum differs: {identity}"));
    }
    Ok(bytes)
}

fn items(value: &Json) -> &[Json] {
    value.as_array().map(Vec::as_slice).unwrap_or_default()
}

fn split(row: &Json, names: &[&str]) -> Result<(Vec<Json>, i64, Map<String, Json>), String> {
    let mut remaining = row.as_object().ok_or("expected a legacy record")?.clone();
    let mut flags = 0;
    let values = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            remaining.remove(*name).map_or(Json::Null, |value| {
                flags |= 1 << index;
                value
            })
        })
        .collect();
    Ok((values, flags, remaining))
}

fn packed(value: &Json) -> String {
    value.to_string()
}

fn id(value: &Json) -> String {
    format!("{:x}", Sha256::digest(packed(value).as_bytes()))
}

fn order(value: usize) -> Result<i64, String> {
    i64::try_from(value).map_err(|_| "legacy ordinal exceeds storage range".into())
}

async fn project(
    conn: &Connection,
    record: &str,
    payload: &Json,
    references: &BTreeReferences,
) -> Result<(), String> {
    let result = payload["result"]
        .as_object()
        .ok_or("legacy case has no result")?;
    let case = &payload["case"];
    let original_case = case["id"]
        .as_str()
        .or_else(|| payload["result"]["case_id"].as_str());
    let residual = json!({"case_artifact_version":payload["case_artifact_version"],
                          "status":result.get("status"),"archive_record":record});
    conn.execute(
        "INSERT INTO case_records VALUES (?,?,?,?,?,?,?)",
        (
            record,
            id(payload),
            original_case,
            case["owner_path"].as_str(),
            packed(&case["actor"]),
            packed(&case["conditions"]),
            packed(&residual),
        ),
    )
    .await
    .map_err(db_error)?;
    for (field, reference) in references {
        conn.execute(
            "INSERT INTO case_attachments VALUES (?,?,?)",
            (record, field.as_str(), reference.as_str()),
        )
        .await
        .map_err(db_error)?;
    }
    for (index, question) in items(&payload["questions"]).iter().enumerate() {
        let (Some(check), Some(text)) = (question["id"].as_str(), question["question"].as_str())
        else {
            continue;
        };
        let identity = id(question);
        conn.execute(
            "INSERT INTO assessment_questions VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING",
            (
                identity.as_str(),
                check,
                text,
                question["route"].as_str(),
                question["task_kind"].as_str(),
                question["scope"].as_str(),
                question["acceptance"].as_str(),
                "{}",
            ),
        )
        .await
        .map_err(db_error)?;
        conn.execute(
            "INSERT INTO case_record_questions VALUES (?,?,?)",
            (record, order(index)?, identity.as_str()),
        )
        .await
        .map_err(db_error)?;
    }
    for section in ["proofs", "inspected", "prior_inspected"] {
        write_ranges(
            conn,
            record,
            section,
            -1,
            items(&payload["result"][section]),
        )
        .await?;
    }
    let draft = &payload["result"]["draft"];
    for (index, check) in items(&draft["work_checks"]).iter().enumerate() {
        let ordinal = order(index)?;
        let (values, flags, mut remaining) = split(
            check,
            &["check_id", "status", "summary", "next_deciding_fact"],
        )?;
        write_ranges(
            conn,
            record,
            "check-evidence",
            ordinal,
            items(&check["evidence"]),
        )
        .await?;
        remaining.remove("evidence");
        conn.execute(
            "INSERT INTO check_decisions VALUES (?,?,?,?,?,?,?,?)",
            (
                record,
                ordinal,
                values[0].as_str(),
                values[1].as_str(),
                values[2].as_str(),
                values[3].as_str(),
                flags,
                packed(&Json::Object(remaining)),
            ),
        )
        .await
        .map_err(db_error)?;
    }
    for (index, response) in items(&draft["results"]).iter().enumerate() {
        let ordinal = order(index)?;
        let (values, flags, mut remaining) = split(response, &["review_id", "decision"])?;
        write_ranges(
            conn,
            record,
            "native-evidence",
            ordinal,
            items(&response["evidence"]),
        )
        .await?;
        remaining.remove("evidence");
        conn.execute(
            "INSERT INTO native_decisions VALUES (?,?,?,?,?,?)",
            (
                record,
                ordinal,
                values[0].as_str(),
                values[1].as_str(),
                flags,
                packed(&Json::Object(remaining)),
            ),
        )
        .await
        .map_err(db_error)?;
    }
    // Some archived assignments stored proposal envelopes on the result.
    let proposals = draft
        .get("proposals")
        .unwrap_or(&payload["result"]["proposals"]);
    for (index, proposal) in items(proposals).iter().enumerate() {
        let ordinal = order(index)?;
        let (values, flags, mut remaining) = split(proposal, &["key", "question"])?;
        let (decision, assessment_flags, assessment) = match remaining.remove("assessment") {
            Some(value) => {
                let (fields, flags, remaining) = split(&value, &["decision"])?;
                (fields[0].clone(), flags | 2, remaining)
            }
            None => (Json::Null, 0, Map::new()),
        };
        write_ranges(
            conn,
            record,
            "finding-anchor",
            ordinal,
            std::slice::from_ref(&proposal["anchor"]),
        )
        .await?;
        write_ranges(
            conn,
            record,
            "finding-evidence",
            ordinal,
            items(&proposal["evidence"]),
        )
        .await?;
        remaining.remove("anchor");
        remaining.remove("evidence");
        conn.execute(
            "INSERT INTO finding_decisions VALUES (?,?,?,?,?,?,?,?,?)",
            (
                record,
                ordinal,
                values[0].as_str(),
                values[1].as_str(),
                decision.as_str(),
                assessment_flags,
                packed(&Json::Object(assessment)),
                flags,
                packed(&Json::Object(remaining)),
            ),
        )
        .await
        .map_err(db_error)?;
    }
    Ok(())
}

async fn write_ranges(
    conn: &Connection,
    record: &str,
    section: &str,
    owner: i64,
    ranges: &[Json],
) -> Result<(), String> {
    for (index, row) in ranges.iter().enumerate() {
        let (Some(path), Some(start), Some(end)) = (
            row["path"].as_str(),
            row["start_line"].as_i64(),
            row["end_line"].as_i64(),
        ) else {
            continue;
        };
        let identity = id(row);
        let (_, _, mut remaining) = split(row, &["path", "start_line", "end_line"])?;
        // Case bytes remain in the original archive. Retain the excerpt digest
        // without duplicating the inspected source text for each result.
        for key in ["quote", "text"] {
            if let Some(text) = remaining
                .remove(key)
                .and_then(|value| value.as_str().map(str::to_owned))
            {
                remaining.insert(
                    format!("{key}_sha256"),
                    json!(format!("{:x}", Sha256::digest(text.as_bytes()))),
                );
            }
        }
        conn.execute(
            "INSERT INTO evidence_ranges VALUES (?,?,?,?,NULL,NULL,?,?) ON CONFLICT(id) DO NOTHING",
            (
                identity.as_str(),
                path,
                start,
                end,
                row["source_sha256"].as_str(),
                packed(&Json::Object(remaining)),
            ),
        )
        .await
        .map_err(db_error)?;
        conn.execute(
            "INSERT INTO case_evidence VALUES (?,?,?,?,?)",
            (record, section, owner, order(index)?, identity.as_str()),
        )
        .await
        .map_err(db_error)?;
    }
    Ok(())
}
