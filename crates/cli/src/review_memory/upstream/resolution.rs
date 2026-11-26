use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use turso::Connection;

use super::{Publication, PublishedReview, Snapshot, assessments::Assessment, db_error};

pub(super) const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS review_resolutions (
        publication_id TEXT PRIMARY KEY NOT NULL REFERENCES assessment_batches(id),
        body TEXT NOT NULL
    );
";

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ReviewerKind {
    Engineer,
    Ai,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    decision_id: String,
    parents: BTreeSet<String>,
    reviewer_kind: ReviewerKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reviewer_contract: Option<String>,
    rationale: String,
}

const MAX_RECORD_BYTES: u64 = 256 * 1024;
pub(super) const ID_PREFIX: &str = "resolution:";

fn digest(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn native_decision_id(id: &str) -> bool {
    id.strip_prefix("mehscanDecision/v1:").is_some_and(digest)
}

impl Record {
    pub(super) fn load(path: &Path, root: &Path) -> Result<Self, String> {
        let path = fs::canonicalize(path).map_err(|error| error.to_string())?;
        crate::review_state::outside_source(&path, root)
            .map_err(|_| "resolution file must be outside the source directory")?;
        if !path.is_file() {
            return Err("resolution must be a regular file".into());
        }
        let mut bytes = Vec::new();
        fs::File::open(path)
            .and_then(|file| file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes))
            .map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err("resolution file exceeds 256 KiB".into());
        }
        let record: Self = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid resolution file: {error}"))?;
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), String> {
        if !native_decision_id(&self.decision_id)
            || self.parents.is_empty()
            || self.parents.len() > 2048
            || !self.parents.iter().all(|parent| {
                native_decision_id(parent) || parent.strip_prefix(ID_PREFIX).is_some_and(digest)
            })
        {
            return Err(
                "resolution requires a native decision ID and 1–2048 current head IDs".into(),
            );
        }
        if self.rationale.trim().is_empty() || self.rationale.len() > 8192 {
            return Err("resolution rationale must be nonempty and at most 8 KiB".into());
        }
        match self.reviewer_contract.as_deref() {
            Some(value)
                if value.trim().is_empty()
                    || value.len() > 256
                    || value.chars().any(char::is_control) =>
            {
                return Err("invalid reviewer contract".into());
            }
            None if self.reviewer_kind == ReviewerKind::Ai => {
                return Err(
                    "AI resolution requires a configured reviewer contract identifier".into(),
                );
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn select_assessment(
        &self,
        content: &mut Publication,
        snapshot: &Snapshot,
    ) -> Result<(), String> {
        content
            .assessments
            .retain(|item| item.decision_id == self.decision_id);
        content
            .dependencies
            .retain(|item| item.decision_id == self.decision_id);
        let [assessment] = content.assessments.as_slice() else {
            return Err("resolution decision is absent from the retained batch".into());
        };
        if !assessment.has_source_evidence(|path| {
            content.dependencies.iter().any(|input| {
                input.path == path
                    && input
                        .sha256
                        .as_ref()
                        .is_some_and(|hash| snapshot.files.get(path) == Some(hash))
            })
        }) {
            return Err("resolution requires retained evidence bound to the current source".into());
        }
        Ok(())
    }

    pub(super) fn validate_parents(
        &self,
        assessment: &Assessment,
        result: &Projection<'_>,
    ) -> Result<(), String> {
        let current = result
            .findings
            .get(assessment.subject_key.as_str())
            .ok_or("resolution subject has no published decisions")?;
        if current
            .current
            .iter()
            .any(|head| head.assessment.review_id != assessment.review_id)
            || current
                .current
                .iter()
                .map(|head| head.id)
                .ne(self.parents.iter().map(String::as_str))
        {
            return Err(
                "shared resolution parents changed; pull and review the current heads".into(),
            );
        }
        Ok(())
    }
}

pub(super) async fn available(conn: &Connection) -> Result<bool, String> {
    let mut rows = conn
        .query(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'review_resolutions'",
            (),
        )
        .await
        .map_err(db_error)?;
    Ok(rows.next().await.map_err(db_error)?.is_some())
}

pub(super) async fn body(conn: &Connection, id: &str) -> Result<Option<String>, String> {
    let mut rows = conn
        .query(
            "SELECT body FROM review_resolutions WHERE publication_id = ?1",
            (id,),
        )
        .await
        .map_err(db_error)?;
    rows.next()
        .await
        .map_err(db_error)?
        .map(|row| row.get(0).map_err(db_error))
        .transpose()
}

#[derive(Clone, Copy, Serialize)]
struct Head<'a> {
    id: &'a str,
    publication: &'a str,
    assessment: &'a Assessment,
}

#[derive(Serialize)]
struct Finding<'a> {
    status: &'static str,
    verdict: Option<&'a str>,
    current: Vec<Head<'a>>,
}

#[derive(Serialize, Default)]
pub(super) struct Projection<'a> {
    findings: BTreeMap<&'a str, Finding<'a>>,
    unapplied_resolutions: BTreeSet<&'a str>,
}

impl Projection<'_> {
    pub(super) fn is_applied(&self, publication: &str) -> bool {
        !self.unapplied_resolutions.contains(publication)
    }
}

struct Candidate<'a> {
    head: Head<'a>,
    record: Record,
    missing: usize,
}

fn same_subject(left: Head<'_>, right: Head<'_>) -> bool {
    left.assessment.subject_key == right.assessment.subject_key
        && left.assessment.review_id == right.assessment.review_id
}

pub(super) fn project(publications: &[PublishedReview]) -> Projection<'_> {
    let mut result = Projection::default();
    let mut known = BTreeMap::new();
    let mut candidates = BTreeMap::new();
    for publication in publications {
        let id = publication.id.as_str();
        if !id.starts_with(ID_PREFIX) && publication.resolution.is_none() {
            for assessment in &publication.assessments {
                let decision = assessment.decision_id.as_str();
                known.entry(decision).or_insert(Head {
                    id: decision,
                    publication: id,
                    assessment,
                });
            }
            continue;
        }
        result.unapplied_resolutions.insert(id);
        let Some(body) = &publication.resolution else {
            continue;
        };
        let Ok(record) = serde_json::from_value::<Record>(body.clone()) else {
            continue;
        };
        let [assessment] = publication.assessments.as_slice() else {
            continue;
        };
        if record.validate().is_ok()
            && assessment.decision_id == record.decision_id
            && assessment.has_source_evidence(|path| {
                publication.file_dependencies.iter().any(|dependency| {
                    dependency.path == path
                        && dependency.decision_id == record.decision_id
                        && dependency.sha256.as_deref().is_some_and(digest)
                })
            })
        {
            candidates.insert(
                id,
                Candidate {
                    head: Head {
                        id,
                        publication: id,
                        assessment,
                    },
                    record,
                    missing: 0,
                },
            );
        }
    }

    // Only resolutions with a complete, same-subject ancestry can hide earlier heads.
    let mut waiting = BTreeMap::<String, Vec<&str>>::new();
    let mut ready = VecDeque::new();
    for (&id, candidate) in &mut candidates {
        for parent in &candidate.record.parents {
            if !known.contains_key(parent.as_str()) {
                waiting.entry(parent.clone()).or_default().push(id);
                candidate.missing += 1;
            }
        }
        if candidate.missing == 0 {
            ready.push_back(id);
        }
    }
    let mut superseded = BTreeSet::new();
    let mut resolved_decisions = BTreeSet::new();
    while let Some(id) = ready.pop_front() {
        let Some(candidate) = candidates.remove(id) else {
            continue;
        };
        if known.contains_key(id)
            || !candidate
                .record
                .parents
                .iter()
                .all(|parent| same_subject(candidate.head, known[parent.as_str()]))
        {
            continue;
        }
        known.insert(id, candidate.head);
        resolved_decisions.insert(candidate.head.assessment.decision_id.as_str());
        superseded.extend(candidate.record.parents);
        result.unapplied_resolutions.remove(id);
        for dependent in waiting.remove(id).into_iter().flatten() {
            let candidate = candidates.get_mut(dependent).expect("unapplied dependent");
            candidate.missing -= 1;
            if candidate.missing == 0 {
                ready.push_back(dependent);
            }
        }
    }

    let mut by_subject = BTreeMap::<&str, Vec<_>>::new();
    for (id, head) in known {
        if !superseded.contains(id) && !resolved_decisions.contains(id) {
            by_subject
                .entry(&head.assessment.subject_key)
                .or_default()
                .push(head);
        }
    }
    for (subject, current) in by_subject {
        let verdicts: BTreeSet<_> = current
            .iter()
            .filter(|head| !head.assessment.has_open_checks())
            .map(|head| head.assessment.verdict.as_str())
            .collect();
        let (status, verdict) = if verdicts.contains("issue") && verdicts.contains("not_issue") {
            ("disputed", None)
        } else if current.iter().any(|head| head.assessment.has_open_checks()) {
            ("needs_review", None)
        } else {
            ("settled", verdicts.first().copied())
        };
        result.findings.insert(
            subject,
            Finding {
                status,
                verdict,
                current,
            },
        );
    }
    result
}
