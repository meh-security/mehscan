//! One locked append-only transaction journal; derived views are never authority.
use mehscan_core::{
    ReviewAttemptStatus, ReviewDecisionRecord, ReviewStateBinding, ReviewStateSupersession,
    ReviewSubjectState,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAX_JOURNAL_BYTES: u64 = 512 * 1024 * 1024;

fn hash<T: Serialize>(kind: &str, value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(kind, value)).map_err(|error| error.to_string())?;
    Ok(format!("{kind}:{:x}", Sha256::digest(bytes)))
}

fn label(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err("state identifiers must be nonempty, bounded text without control characters".into())
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Claim {
        repository_key: String,
        stream: String,
        binding: ReviewStateBinding,
        attempt_id: String,
        expected_generation: u64,
        retry: bool,
    },
    Record {
        key: String,
        generation: u64,
        owner: String,
        records: Vec<ReviewDecisionRecord>,
        supersessions: Vec<ReviewStateSupersession>,
        provenance: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        work_package: Option<mehscan_core::ReviewWorkPackage>,
    },
    End {
        key: String,
        generation: u64,
        owner: String,
        status: ReviewAttemptStatus,
    },
    Plan {
        key: String,
        generation: u64,
        owner: String,
        expected_plan_id: Option<String>,
        plan: mehscan_core::ReviewCompletionPlan,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        work_package: Option<mehscan_core::ReviewWorkPackage>,
    },
    Pending {
        key: String,
        generation: u64,
        owner: String,
        inventory_input_fingerprint: String,
        draft: mehscan_core::ReviewPendingDraft,
    },
    Fact {
        key: String,
        generation: u64,
        owner: String,
        inventory_input_fingerprint: String,
        question_id: String,
        answer: String,
        evidence: Vec<mehscan_core::ReviewChangeEvidence>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transaction {
    schema_version: String,
    sequence: u64,
    previous_hash: String,
    operation_key: String,
    command: Command,
    result: Value,
    hash: String,
}

#[derive(Clone, Serialize)]
struct Attempt {
    generation: u64,
    attempt_id: String,
    snapshot_id: String,
    binding: ReviewStateBinding,
    status: ReviewAttemptStatus,
    #[serde(skip_serializing)]
    owner: String,
    admissions: BTreeSet<String>,
}

#[derive(Default)]
struct Stream {
    repository_key: String,
    name: String,
    attempts: Vec<Attempt>,
    decisions: BTreeMap<String, ReviewDecisionRecord>,
    heads: BTreeMap<String, BTreeSet<String>>,
    lineage: BTreeMap<String, ReviewStateSupersession>,
    admissions: BTreeMap<u64, BTreeSet<String>>,
    provenance: BTreeMap<u64, Vec<Value>>,
    completion_plans: BTreeMap<u64, Vec<mehscan_core::ReviewCompletionPlanRecord>>,
    pending: BTreeMap<String, mehscan_core::ReviewPendingRecord>,
    facts: BTreeMap<String, mehscan_core::ReviewFactRecord>,
    fact_reviews: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Default)]
struct State {
    streams: BTreeMap<String, Stream>,
    receipts: BTreeMap<String, (String, u64, Value)>,
    sequence: u64,
    last_hash: String,
}

fn stream_key(repository_key: &str, stream: &str) -> Result<String, String> {
    label(repository_key)?;
    label(stream)?;
    hash("mehscanStateStream/v1", &(repository_key, stream))
}

fn subject_key(record: &ReviewDecisionRecord) -> Result<String, String> {
    hash(
        "mehscanStateSubject/v1",
        &(&record.identity.subject_key, &record.assessment_context),
    )
}

impl State {
    fn currently_owned(&self, command: &Command) -> bool {
        let (key, generation, owner, attempt_id) = match command {
            Command::Claim {
                repository_key,
                stream,
                attempt_id,
                ..
            } => {
                let Ok(key) = stream_key(repository_key, stream) else {
                    return false;
                };
                (key, None, None, Some(attempt_id))
            }
            Command::Record {
                key,
                generation,
                owner,
                ..
            }
            | Command::End {
                key,
                generation,
                owner,
                ..
            }
            | Command::Plan {
                key,
                generation,
                owner,
                ..
            }
            | Command::Pending {
                key,
                generation,
                owner,
                ..
            }
            | Command::Fact {
                key,
                generation,
                owner,
                ..
            } => (key.clone(), Some(*generation), Some(owner), None),
        };
        self.streams
            .get(&key)
            .and_then(|stream| stream.attempts.last())
            .is_some_and(|attempt| {
                attempt.status == ReviewAttemptStatus::Running
                    && generation.is_none_or(|generation| generation == attempt.generation)
                    && owner.is_none_or(|owner| owner == &attempt.owner)
                    && attempt_id.is_none_or(|id| id == &attempt.attempt_id)
            })
    }
    fn owned_stream(
        &mut self,
        key: &str,
        generation: u64,
        owner: &str,
    ) -> Result<&mut Stream, String> {
        let stream = self.streams.get_mut(key).ok_or("unknown state stream")?;
        let attempt = stream
            .attempts
            .last()
            .ok_or("state stream has no attempt")?;
        if attempt.generation != generation
            || attempt.owner != owner
            || attempt.status != ReviewAttemptStatus::Running
        {
            return Err(
                "stale generation, wrong owner or terminal attempt cannot update state".into(),
            );
        }
        Ok(stream)
    }

    fn apply(&mut self, command: &Command) -> Result<Value, String> {
        match command {
            Command::Claim {
                repository_key,
                stream,
                binding,
                attempt_id,
                expected_generation,
                retry,
            } => {
                label(attempt_id)?;
                if let Some(key) = &binding.coordination_key {
                    label(key)?;
                }
                if binding.repository.repository_key.as_deref() != Some(repository_key)
                    || binding.assessment_context.kind != "source_only"
                {
                    return Err(
                        "state claims require a namespaced native source-only binding".into(),
                    );
                }
                let key = stream_key(repository_key, stream)?;
                let snapshot_id = hash("mehscanStateSnapshot/v1", binding)?;
                let item = self.streams.entry(key.clone()).or_default();
                let generation = item.attempts.last().map_or(0, |attempt| attempt.generation);
                if generation != *expected_generation {
                    return Err(format!(
                        "generation changed: expected {expected_generation}, current {generation}"
                    ));
                }
                if let Some(current) = item.attempts.last() {
                    if current.snapshot_id == snapshot_id
                        && !retry
                        && matches!(
                            current.status,
                            ReviewAttemptStatus::Running | ReviewAttemptStatus::Finished
                        )
                    {
                        return Ok(
                            json!({"status":"coalesced","stream_key":key,"generation":generation,"snapshot_id":snapshot_id}),
                        );
                    }
                }
                if item
                    .attempts
                    .iter()
                    .any(|attempt| &attempt.attempt_id == attempt_id)
                {
                    return Err(
                        "attempt ID is immutable and cannot be reused for a new generation".into(),
                    );
                }
                let generation = generation
                    .checked_add(1)
                    .ok_or("state generation exhausted")?;
                let owner = hash(
                    "mehscanStateOwner/v1",
                    &(
                        &key,
                        generation,
                        attempt_id,
                        &snapshot_id,
                        self.sequence + 1,
                    ),
                )?;
                item.repository_key = repository_key.clone();
                item.name = stream.clone();
                item.attempts.push(Attempt {
                    generation,
                    attempt_id: attempt_id.clone(),
                    snapshot_id: snapshot_id.clone(),
                    binding: binding.clone(),
                    status: ReviewAttemptStatus::Running,
                    owner: owner.clone(),
                    admissions: BTreeSet::new(),
                });
                Ok(
                    json!({"status":"claimed","stream_key":key,"generation":generation,"snapshot_id":snapshot_id,"owner":owner}),
                )
            }
            Command::Record {
                key,
                generation,
                owner,
                records,
                supersessions,
                provenance,
                work_package,
            } => {
                let stream = self.owned_stream(key, *generation, owner)?;
                let binding = stream.attempts.last().unwrap().binding.clone();
                if stream
                    .completion_plans
                    .get(generation)
                    .and_then(|plans| plans.last())
                    .is_some_and(|saved| saved.plan.runtime.is_some())
                    && work_package.is_none()
                {
                    return Err("runtime-bound review requires its exact work package".into());
                }
                if let Some(package) = work_package {
                    validate_work_package(
                        stream,
                        stream.attempts.last().unwrap(),
                        package,
                        records,
                    )?;
                }
                let mut incoming = BTreeMap::new();
                for record in records {
                    if record.repository != binding.repository
                        || record.assessment_context != binding.assessment_context
                        || record.source_fingerprint != binding.source_fingerprint
                        || record.inventory_input_fingerprint.as_deref()
                            != Some(binding.inventory_input_fingerprint.as_str())
                        || binding.subjects.get(&record.response.review_id)
                            != Some(&record.identity)
                    {
                        return Err(
                            "decision does not match current inventory/source/context binding"
                                .into(),
                        );
                    }
                    if incoming
                        .insert(record.decision_id.clone(), record)
                        .is_some()
                    {
                        return Err("decision transaction contains duplicate decision IDs".into());
                    }
                    if stream
                        .decisions
                        .get(&record.decision_id)
                        .is_some_and(|saved| saved != record)
                    {
                        return Err("immutable decision ID has different contents".into());
                    }
                }
                let mut links = BTreeMap::new();
                for link in supersessions {
                    let child = incoming
                        .get(&link.decision_id)
                        .ok_or("superseding decision is not in the validated incoming run")?;
                    let subject = subject_key(child)?;
                    let parents = link.parents.iter().cloned().collect::<BTreeSet<_>>();
                    if link.reason.trim().is_empty()
                        || link.reason.len() > 4096
                        || parents.is_empty()
                        || parents.len() != link.parents.len()
                        || parents.contains(&link.decision_id)
                    {
                        return Err("supersession requires distinct parents, a new child and revalidation reason".into());
                    }
                    if stream.heads.get(&subject) != Some(&parents) {
                        return Err(
                            "supersession parents changed or do not cover all unresolved heads"
                                .into(),
                        );
                    }
                    if stream.lineage.contains_key(&link.decision_id)
                        || stream.decisions.contains_key(&link.decision_id)
                    {
                        return Err("supersession child already exists; immutable lineage cannot be rewritten".into());
                    }
                    if links.insert(subject, link).is_some() {
                        return Err(
                            "one transaction cannot supersede a subject more than once".into()
                        );
                    }
                }
                // All preconditions above are checked before changing derived state.
                for (subject, link) in &links {
                    stream.heads.remove(subject);
                    stream
                        .lineage
                        .insert(link.decision_id.clone(), (*link).clone());
                }
                for record in records {
                    let subject = subject_key(record)?;
                    // Re-admitting an immutable historical response cannot undo its
                    // explicit supersession. A new assessment needs a new record.
                    let superseded = stream
                        .lineage
                        .values()
                        .any(|link| link.parents.contains(&record.decision_id));
                    if !superseded {
                        stream
                            .heads
                            .entry(subject)
                            .or_default()
                            .insert(record.decision_id.clone());
                    }
                    stream
                        .decisions
                        .entry(record.decision_id.clone())
                        .or_insert_with(|| record.clone());
                    stream
                        .admissions
                        .entry(*generation)
                        .or_default()
                        .insert(record.decision_id.clone());
                    stream
                        .attempts
                        .last_mut()
                        .unwrap()
                        .admissions
                        .insert(record.decision_id.clone());
                }
                if let Some(package) = work_package {
                    for fact in &package.payload.evidence_updates {
                        let question = &stream.pending[&fact.question_id];
                        if let mehscan_core::ReviewPendingOrigin::Decision { decision_id } =
                            &question.origin
                        {
                            let review_id = &stream.decisions[decision_id].response.review_id;
                            for record in records
                                .iter()
                                .filter(|record| &record.response.review_id == review_id)
                            {
                                stream
                                    .fact_reviews
                                    .entry(fact.fact_id.clone())
                                    .or_default()
                                    .insert(record.decision_id.clone());
                            }
                        }
                    }
                }
                stream
                    .provenance
                    .entry(*generation)
                    .or_default()
                    .push(provenance.clone());
                Ok(
                    json!({"status":"recorded","generation":generation,"decision_ids":incoming.keys().collect::<Vec<_>>()}),
                )
            }
            Command::End {
                key,
                generation,
                owner,
                status,
            } => {
                if *status == ReviewAttemptStatus::Running {
                    return Err("end status must be finished, cancelled or incomplete".into());
                }
                let stream = self.owned_stream(key, *generation, owner)?;
                stream.attempts.last_mut().unwrap().status = *status;
                Ok(json!({"status":status,"generation":generation}))
            }
            Command::Plan {
                key,
                generation,
                owner,
                expected_plan_id,
                plan,
                work_package,
            } => {
                let stream = self.owned_stream(key, *generation, owner)?;
                if let Some(package) = work_package {
                    validate_work_package(stream, stream.attempts.last().unwrap(), package, &[])?;
                }
                let binding = &stream.attempts.last().unwrap().binding;
                super::review_completion::validate(binding, plan)?;
                let plans = stream.completion_plans.entry(*generation).or_default();
                if plans.last().map(|record| &record.plan_id) != expected_plan_id.as_ref() {
                    return Err("completion plan changed; expected current parent plan ID".into());
                }
                let plan_id = hash(
                    "mehscanCompletionPlan/v1",
                    &(key, generation, expected_plan_id, plan),
                )?;
                plans.push(mehscan_core::ReviewCompletionPlanRecord {
                    plan_id: plan_id.clone(),
                    parent_plan_id: expected_plan_id.clone(),
                    generation: *generation,
                    plan: plan.clone(),
                    work_package_id: work_package
                        .as_ref()
                        .map(|package| package.package_id.clone()),
                });
                Ok(json!({"status":"planned","generation":generation,"plan_id":plan_id}))
            }
            Command::Pending {
                key,
                generation,
                owner,
                inventory_input_fingerprint,
                draft,
            } => {
                let stream = self.owned_stream(key, *generation, owner)?;
                let attempt = stream.attempts.last().unwrap();
                if draft.schema_version != "1"
                    || inventory_input_fingerprint != &attempt.binding.inventory_input_fingerprint
                {
                    return Err("pending question does not match current inventory/schema".into());
                }
                super::review_completion::explanation(&draft.question)?;
                let subject_key = match &draft.origin {
                    mehscan_core::ReviewPendingOrigin::Decision { decision_id } => {
                        let record = stream
                            .decisions
                            .get(decision_id)
                            .ok_or("pending origin decision is unknown")?;
                        let supported = record
                            .response
                            .checks
                            .iter()
                            .chain(
                                record
                                    .response
                                    .investigation
                                    .iter()
                                    .flat_map(|trace| &trace.blockers),
                            )
                            .any(|question| question == &draft.question);
                        if record.response.decision != mehscan_core::ReviewDecision::NeedsReview
                            || !supported
                        {
                            return Err("pending question must be an explicit check/blocker in a current needs_review response".into());
                        }
                        Some(record.identity.subject_key.clone())
                    }
                    mehscan_core::ReviewPendingOrigin::ChangePass { plan_id, path } => {
                        let plan = stream
                            .completion_plans
                            .get(generation)
                            .and_then(|plans| plans.last())
                            .ok_or("pending origin plan is absent")?;
                        if &plan.plan_id != plan_id
                            || !plan.plan.change_pass.iter().any(|entry| {
                                &entry.path == path
                                    && entry.status
                                        == mehscan_core::ReviewChangePassStatus::NeedsReview
                                    && entry.questions.contains(&draft.question)
                            })
                        {
                            return Err(
                                "pending question must belong to the current change-pass plan"
                                    .into(),
                            );
                        }
                        None
                    }
                };
                let question_id = hash(
                    "mehscanPendingQuestion/v1",
                    &(key, generation, &draft.origin, draft.kind, &draft.question),
                )?;
                let record = mehscan_core::ReviewPendingRecord {
                    question_id: question_id.clone(),
                    generation: *generation,
                    assessment_context: attempt.binding.assessment_context.clone(),
                    subject_key,
                    origin: draft.origin.clone(),
                    kind: draft.kind,
                    question: draft.question.clone(),
                };
                if !pending_current(stream, attempt, &record)? {
                    return Err(
                        "pending origin has been superseded or is not admitted in this generation"
                            .into(),
                    );
                }
                stream.pending.entry(question_id.clone()).or_insert(record);
                Ok(json!({"status":"pending","generation":generation,"question_id":question_id}))
            }
            Command::Fact {
                key,
                generation,
                owner,
                inventory_input_fingerprint,
                question_id,
                answer,
                evidence,
            } => {
                let stream = self.owned_stream(key, *generation, owner)?;
                let attempt = stream.attempts.last().unwrap();
                let question = stream
                    .pending
                    .get(question_id)
                    .ok_or("fact targets an unknown pending question")?;
                if inventory_input_fingerprint != &attempt.binding.inventory_input_fingerprint
                    || !pending_current(stream, attempt, question)?
                {
                    return Err(
                        "fact targets a superseded or foreign pending question/binding".into(),
                    );
                }
                super::review_completion::explanation(answer)?;
                if evidence.is_empty()
                    || evidence.iter().any(|artifact| {
                        artifact.source.side != mehscan_core::ReviewChangeEvidenceSide::Current
                    })
                {
                    return Err("fact updates require current authorized source evidence; external claims are unsupported".into());
                }
                let fact_id = hash(
                    "mehscanPendingFact/v1",
                    &(
                        key,
                        generation,
                        inventory_input_fingerprint,
                        question_id,
                        answer,
                        evidence,
                    ),
                )?;
                stream.facts.entry(fact_id.clone()).or_insert_with(|| {
                    mehscan_core::ReviewFactRecord {
                        fact_id: fact_id.clone(),
                        question_id: question_id.clone(),
                        generation: *generation,
                        inventory_input_fingerprint: inventory_input_fingerprint.clone(),
                        answer: answer.clone(),
                        evidence: evidence.clone(),
                    }
                });
                Ok(
                    json!({"status":"evidence_available","generation":generation,"question_id":question_id,"fact_id":fact_id,
                    "revalidation_required":true}),
                )
            }
        }
    }

    fn view(&self, key: &str, history: bool) -> Result<Value, String> {
        let stream = self.streams.get(key).ok_or("unknown state stream")?;
        let current = stream
            .attempts
            .last()
            .ok_or("state stream has no attempt")?;
        let admissions = stream
            .admissions
            .get(&current.generation)
            .cloned()
            .unwrap_or_default();
        let mut subjects = BTreeMap::new();
        for identity in current.binding.subjects.values() {
            let key = hash(
                "mehscanStateSubject/v1",
                &(&identity.subject_key, &current.binding.assessment_context),
            )?;
            let heads = stream.heads.get(&key).cloned().unwrap_or_default();
            let current_ids = heads.intersection(&admissions).cloned().collect::<Vec<_>>();
            let historical_ids = heads.difference(&admissions).cloned().collect::<Vec<_>>();
            let state = if current_ids.is_empty() {
                ReviewSubjectState::Unassessed
            } else if !historical_ids.is_empty() {
                ReviewSubjectState::AwaitingSupersession
            } else if current_ids.len() > 1 {
                ReviewSubjectState::Conflict
            } else {
                ReviewSubjectState::Recorded
            };
            let decision = (state == ReviewSubjectState::Recorded)
                .then(|| stream.decisions[&current_ids[0]].response.decision);
            subjects.insert(key, json!({"subject_key":identity.subject_key,"occurrence_key":identity.occurrence_key,"state":state,"decision":decision,
                "current_decision_ids":current_ids,"historical_decision_ids":historical_ids}));
        }
        let historical_only = stream
            .heads
            .iter()
            .filter(|(key, _)| !subjects.contains_key(*key))
            .map(|(key, heads)| json!({"state_subject_key":key,"decision_ids":heads}))
            .collect::<Vec<_>>();
        let mut result = json!({"schema_version":"1","sequence":self.sequence,"repository_key":stream.repository_key,"stream":stream.name,
            "generation":current.generation,"snapshot_id":current.snapshot_id,"attempt_id":current.attempt_id,"attempt_status":current.status,
            "subjects":subjects.into_values().collect::<Vec<_>>(),"historical_only_subjects":historical_only,"alert_disposition":"not_established"});
        if history {
            result["attempts"] = json!(stream.attempts);
            result["decisions"] = json!(stream.decisions);
            result["supersessions"] = json!(stream.lineage);
            result["admission_provenance"] = json!(stream.provenance);
            result["completion_plans"] = json!(stream.completion_plans);
        }
        result["completion"] = completion_view(stream, current, &result["subjects"])?;
        result["pending_questions"] = pending_view(stream, current)?;
        if history {
            result["pending_history"] = json!(stream.pending);
            result["fact_history"] = json!(stream.facts);
            result["fact_review_admissions"] = json!(stream.fact_reviews);
        }
        Ok(result)
    }
}

fn pending_current(
    stream: &Stream,
    attempt: &Attempt,
    question: &mehscan_core::ReviewPendingRecord,
) -> Result<bool, String> {
    if question.generation != attempt.generation
        || question.assessment_context != attempt.binding.assessment_context
    {
        return Ok(false);
    }
    match &question.origin {
        mehscan_core::ReviewPendingOrigin::Decision { decision_id } => {
            let record = stream
                .decisions
                .get(decision_id)
                .ok_or("pending decision disappeared from immutable history")?;
            Ok(attempt.admissions.contains(decision_id)
                && stream
                    .heads
                    .get(&subject_key(record)?)
                    .is_some_and(|heads| heads.contains(decision_id)))
        }
        mehscan_core::ReviewPendingOrigin::ChangePass { plan_id, .. } => Ok(stream
            .completion_plans
            .get(&attempt.generation)
            .and_then(|plans| plans.last())
            .is_some_and(|plan| &plan.plan_id == plan_id)),
    }
}

fn pending_view(stream: &Stream, attempt: &Attempt) -> Result<Value, String> {
    let mut questions = Vec::new();
    for question in stream.pending.values() {
        if !pending_current(stream, attempt, question)? {
            continue;
        }
        let fact_ids = stream
            .facts
            .values()
            .filter(|fact| {
                fact.question_id == question.question_id && fact.generation == attempt.generation
            })
            .map(|fact| &fact.fact_id)
            .collect::<Vec<_>>();
        let answers = stream
            .facts
            .values()
            .filter(|fact| {
                fact.question_id == question.question_id && fact.generation == attempt.generation
            })
            .map(|fact| &fact.answer)
            .collect::<BTreeSet<_>>();
        let review_ids = match &question.origin {
            mehscan_core::ReviewPendingOrigin::Decision { decision_id } => {
                vec![stream.decisions[decision_id].response.review_id.clone()]
            }
            mehscan_core::ReviewPendingOrigin::ChangePass { .. } => Vec::new(),
        };
        let fresh = fact_ids
            .iter()
            .any(|id| !stream.fact_reviews.contains_key(*id));
        questions.push(json!({"question_id":question.question_id,"kind":question.kind,"question":question.question,"origin":question.origin,
            "state":if fact_ids.is_empty() { "awaiting_evidence" } else if fresh { "evidence_available" } else { "pending_after_revalidation" },"fact_ids":fact_ids,
            "resume_review_ids":review_ids,"revalidation_required":fresh,"needs_adjudication":answers.len() > 1}));
    }
    Ok(json!(questions))
}

fn work_package(
    stream: &Stream,
    attempt: &Attempt,
    requested: Option<&[String]>,
    resume_only: bool,
) -> Result<mehscan_core::ReviewWorkPackage, String> {
    let saved = stream
        .completion_plans
        .get(&attempt.generation)
        .and_then(|plans| plans.last())
        .ok_or("work handoff requires a current completion plan")?;
    let selected = saved
        .plan
        .selected_review_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let ids = requested.map_or_else(|| selected.clone(), |ids| ids.iter().cloned().collect());
    if requested.is_some_and(|values| values.len() != ids.len()) || !ids.is_subset(&selected) {
        return Err("work handoff IDs must be distinct and selected in the current plan".into());
    }
    let mut questions = Vec::new();
    let mut facts = Vec::new();
    let mut resumable = BTreeSet::new();
    for question in stream.pending.values() {
        if !pending_current(stream, attempt, question)? {
            continue;
        }
        let relevant = match &question.origin {
            mehscan_core::ReviewPendingOrigin::Decision { decision_id } => {
                ids.contains(&stream.decisions[decision_id].response.review_id)
            }
            mehscan_core::ReviewPendingOrigin::ChangePass { .. } => true,
        };
        if !relevant {
            continue;
        }
        let updates = stream
            .facts
            .values()
            .filter(|fact| {
                fact.question_id == question.question_id && fact.generation == attempt.generation
            })
            .cloned()
            .collect::<Vec<_>>();
        if updates
            .iter()
            .any(|fact| !stream.fact_reviews.contains_key(&fact.fact_id))
        {
            if let mehscan_core::ReviewPendingOrigin::Decision { decision_id } = &question.origin {
                resumable.insert(stream.decisions[decision_id].response.review_id.clone());
            }
        }
        questions.push(question.clone());
        facts.extend(updates);
    }
    let ids = if resume_only {
        ids.intersection(&resumable)
            .cloned()
            .collect::<BTreeSet<_>>()
    } else {
        ids
    };
    if resume_only {
        questions.retain(|question| match &question.origin {
            mehscan_core::ReviewPendingOrigin::Decision { decision_id } => {
                ids.contains(&stream.decisions[decision_id].response.review_id)
            }
            mehscan_core::ReviewPendingOrigin::ChangePass { .. } => true,
        });
        facts.retain(|fact| {
            questions
                .iter()
                .any(|question| question.question_id == fact.question_id)
        });
    }
    let mut expected_parents = BTreeMap::new();
    let mut parents = BTreeSet::new();
    for id in &ids {
        let identity = &attempt.binding.subjects[id];
        let key = hash(
            "mehscanStateSubject/v1",
            &(&identity.subject_key, &attempt.binding.assessment_context),
        )?;
        let heads = stream.heads.get(&key).cloned().unwrap_or_default();
        parents.extend(heads.iter().cloned());
        expected_parents.insert(id.clone(), heads.into_iter().collect());
    }
    let payload = mehscan_core::ReviewWorkPayload {
        schema_version: "1".into(),
        generation: attempt.generation,
        snapshot_id: attempt.snapshot_id.clone(),
        plan_id: saved.plan_id.clone(),
        inventory_input_fingerprint: attempt.binding.inventory_input_fingerprint.clone(),
        repository: attempt.binding.repository.clone(),
        assessment_context: attempt.binding.assessment_context.clone(),
        impact_scope: attempt.binding.impact_scope.clone(),
        review_ids: ids.into_iter().collect(),
        policy: saved.plan.policy,
        runtime: saved.plan.runtime.clone(),
        planned_review_ids: saved.plan.selected_review_ids.clone(),
        deferred_review_ids: saved.plan.deferred_review_ids.clone(),
        expected_parents,
        parent_decisions: parents
            .into_iter()
            .map(|id| stream.decisions[&id].clone())
            .collect(),
        pending_questions: questions,
        evidence_updates: facts,
        change_pass: saved.plan.change_pass.clone(),
    };
    Ok(mehscan_core::ReviewWorkPackage {
        package_id: hash("mehscanReviewWork/v1", &payload)?,
        payload,
    })
}

fn validate_work_package(
    stream: &Stream,
    attempt: &Attempt,
    package: &mehscan_core::ReviewWorkPackage,
    records: &[ReviewDecisionRecord],
) -> Result<(), String> {
    if package.package_id != hash("mehscanReviewWork/v1", &package.payload)? {
        return Err("work package integrity check failed".into());
    }
    // Regenerate the exact handoff view; new facts, changed plans or parent heads
    // fence a late response even on the same source revision.
    let current = work_package(stream, attempt, Some(&package.payload.review_ids), false)?;
    if &current != package {
        return Err(
            "work package plan/parents/facts/generation changed; request fresh work".into(),
        );
    }
    if records.iter().any(|record| {
        !package
            .payload
            .review_ids
            .contains(&record.response.review_id)
    }) {
        return Err("response contains work outside its selected handoff IDs".into());
    }
    Ok(())
}

fn completion_view(stream: &Stream, attempt: &Attempt, subjects: &Value) -> Result<Value, String> {
    let Some(saved) = stream
        .completion_plans
        .get(&attempt.generation)
        .and_then(|plans| plans.last())
    else {
        return Ok(
            json!({"status":"not_planned","review_work_complete":false,"accounting_complete":false,
            "security_resolution":"not_established"}),
        );
    };
    let plan = &saved.plan;
    let mut missing = Vec::new();
    let mut pending = Vec::new();
    let mut issues = Vec::new();
    for id in &plan.selected_review_ids {
        let identity = &attempt.binding.subjects[id];
        let state = subjects
            .as_array()
            .unwrap()
            .iter()
            .find(|state| state["subject_key"] == identity.subject_key)
            .ok_or("completion subject is absent from current state")?;
        if state["state"] != "recorded" {
            missing.push(id);
        } else if state["decision"] == "needs_review" {
            pending.push(id);
        } else if state["decision"] == "issue" {
            issues.push(id);
        }
    }
    let unassessed = plan
        .change_pass
        .iter()
        .filter(|entry| entry.status == mehscan_core::ReviewChangePassStatus::Unassessed)
        .map(|entry| &entry.path)
        .collect::<Vec<_>>();
    let limited = plan
        .change_pass
        .iter()
        .filter(|entry| {
            matches!(
                entry.status,
                mehscan_core::ReviewChangePassStatus::Deferred
                    | mehscan_core::ReviewChangePassStatus::CoverageGap
            )
        })
        .map(|entry| &entry.path)
        .collect::<Vec<_>>();
    let change_pending = plan.change_pass.iter().filter(|entry| entry.status == mehscan_core::ReviewChangePassStatus::NeedsReview)
        .map(|entry| json!({"path":entry.path,"questions":entry.questions,"native_review_ids":entry.native_review_ids})).collect::<Vec<_>>();
    let work_complete = missing.is_empty() && unassessed.is_empty() && limited.is_empty();
    let has_limits = !limited.is_empty()
        || !plan.native_coverage_limits.is_empty()
        || !plan.deferred_review_ids.is_empty();
    Ok(json!({"plan_id":saved.plan_id,"policy":plan.policy,
        "status":if !work_complete { "incomplete" } else if has_limits { "complete_with_limits" } else { "complete" },
        "accounting_complete":unassessed.is_empty(),"review_work_complete":work_complete,
        "selected_review_count":plan.selected_review_ids.len(),"deferred_review_ids":plan.deferred_review_ids,
        "missing_or_conflicting_review_ids":missing,"pending_review_ids":pending,"issue_review_ids":issues,
        "unassessed_changed_paths":unassessed,"limited_changed_paths":limited,"pending_changed_effects":change_pending,
        "native_coverage_limits":plan.native_coverage_limits,"security_resolution":"not_established"}))
}

fn read_state(file: &mut File) -> Result<State, String> {
    if file.metadata().map_err(|error| error.to_string())?.len() > MAX_JOURNAL_BYTES {
        return Err("state journal exceeds local store size limit".into());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
        return Err("state journal has a torn tail; explicit recovery is required".into());
    }
    let mut state = State::default();
    for raw in bytes.split_inclusive(|byte| *byte == b'\n') {
        let line = &raw[..raw.len() - 1];
        if line.is_empty() {
            return Err("state journal contains an empty transaction".into());
        }
        let tx: Transaction = serde_json::from_slice(line)
            .map_err(|error| format!("invalid state transaction: {error}"))?;
        let expected = hash(
            "mehscanStateTransaction/v1",
            &(
                &tx.schema_version,
                tx.sequence,
                &tx.previous_hash,
                &tx.operation_key,
                &tx.command,
                &tx.result,
            ),
        )?;
        if tx.schema_version != "1"
            || tx.sequence != state.sequence + 1
            || tx.previous_hash != state.last_hash
            || tx.hash != expected
            || state.receipts.contains_key(&tx.operation_key)
        {
            return Err("state journal integrity/order check failed; no mutation permitted".into());
        }
        let result = state.apply(&tx.command)?;
        if result != tx.result {
            return Err("state journal replay differs from recorded receipt".into());
        }
        state.receipts.insert(
            tx.operation_key,
            (
                hash("mehscanStateCommand/v1", &tx.command)?,
                tx.sequence,
                tx.result,
            ),
        );
        state.sequence = tx.sequence;
        state.last_hash = tx.hash;
    }
    Ok(state)
}

fn transact(store: &Path, operation: &str, command: Command) -> Result<Value, String> {
    label(operation)?;
    let create = matches!(&command, Command::Claim { .. });
    if create {
        fs::create_dir_all(store).map_err(|error| error.to_string())?;
    }
    let path = store.join("transactions.jsonl");
    if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err("state journal must not be a symlink".into());
    }
    let mut file = OpenOptions::new()
        .create(create)
        .read(true)
        .append(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    fs2::FileExt::lock_exclusive(&file).map_err(|error| error.to_string())?;
    let mut state = read_state(&mut file)?;
    let command_hash = hash("mehscanStateCommand/v1", &command)?;
    if let Some((saved_hash, sequence, result)) = state.receipts.get(operation) {
        if saved_hash != &command_hash {
            return Err("operation key already belongs to a different command".into());
        }
        // A prior append can be visible even when its durability acknowledgement
        // failed. Retrying the operation must retry synchronization as well.
        sync_journal(&file, store)?;
        return Ok(
            json!({"sequence":sequence,"replayed":true,"currently_owned":state.currently_owned(&command) && (!matches!(&command, Command::Claim { .. }) || result.get("owner").is_some()),"result":result}),
        );
    }
    let result = state.apply(&command)?;
    let currently_owned = state.currently_owned(&command)
        && (!matches!(&command, Command::Claim { .. }) || result.get("owner").is_some());
    let sequence = state
        .sequence
        .checked_add(1)
        .ok_or("state sequence exhausted")?;
    let tx_hash = hash(
        "mehscanStateTransaction/v1",
        &(
            "1",
            sequence,
            &state.last_hash,
            operation,
            &command,
            &result,
        ),
    )?;
    let tx = Transaction {
        schema_version: "1".into(),
        sequence,
        previous_hash: state.last_hash,
        operation_key: operation.into(),
        command,
        result: result.clone(),
        hash: tx_hash,
    };
    let mut bytes = serde_json::to_vec(&tx).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    if file.metadata().map_err(|error| error.to_string())?.len() + bytes.len() as u64
        > MAX_JOURNAL_BYTES
    {
        return Err("state journal exceeds local store size limit".into());
    }
    file.write_all(&bytes)
        .map_err(|error| format!("state append failed; inspect journal before retry: {error}"))?;
    sync_journal(&file, store)?;
    Ok(
        json!({"sequence":sequence,"replayed":false,"currently_owned":currently_owned,"result":result}),
    )
}

fn sync_journal(file: &File, _store: &Path) -> Result<(), String> {
    file.sync_all().map_err(|error| {
        format!(
            "state durability acknowledgement failed; retry with the same operation key: {error}"
        )
    })?;
    #[cfg(unix)]
    File::open(_store)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            format!("state directory sync failed; retry with the same operation key: {error}")
        })?;
    Ok(())
}

fn outside_source(store: &Path, root: &Path) -> Result<(), String> {
    let source = fs::canonicalize(root).map_err(|error| error.to_string())?;
    let mut ancestor = std::path::absolute(store).map_err(|error| error.to_string())?;
    let mut missing = Vec::new();
    while !ancestor.exists() {
        missing.push(ancestor.file_name().ok_or("invalid store path")?.to_owned());
        ancestor.pop();
    }
    let mut resolved = fs::canonicalize(ancestor).map_err(|error| error.to_string())?;
    for part in missing.into_iter().rev() {
        resolved.push(part);
    }
    if resolved.starts_with(source) {
        Err("durable state must stay outside the authorized source root".into())
    } else {
        Ok(())
    }
}

fn inventory(
    path: &Path,
    root: &Path,
) -> Result<
    (
        mehscan_engine::investigation::ReviewInventory,
        ReviewStateBinding,
    ),
    String,
> {
    let cache: mehscan_engine::investigation::ReviewInventory = serde_json::from_slice(
        &fs::read(path.join("scan-cache.json")).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    super::engine(mehscan_engine::investigation::validate_review_inventory(
        root, &cache,
    ))?;
    let fingerprint = super::engine(cache.input_fingerprint())?;
    let summary: Value = serde_json::from_slice(
        &fs::read(path.join("inventory.json")).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if summary["input_fingerprint"].as_str() != Some(&fingerprint) {
        return Err("inventory summary does not match cache".into());
    }
    let catalog = cache
        .identity_catalog
        .as_ref()
        .ok_or("state requires native identity; regenerate inventory")?;
    if catalog.repository.repository_key.is_none() {
        return Err("state requires --repository-key at inventory creation".into());
    }
    let binding = ReviewStateBinding {
        repository: catalog.repository.clone(),
        assessment_context: catalog.assessment_context.clone(),
        source_fingerprint: catalog.source_fingerprint.clone(),
        inventory_input_fingerprint: fingerprint,
        impact_scope: cache.scan.impact_scope.clone(),
        coordination_key: None,
        subjects: catalog.subjects.clone(),
    };
    Ok((cache, binding))
}

fn validate_runtime_engine(runtime: &mehscan_core::ReviewRuntimeContract) -> Result<(), String> {
    runtime.validate(runtime.policy)?;
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let bytes = fs::read(executable).map_err(|error| error.to_string())?;
    if runtime.engine_version != env!("CARGO_PKG_VERSION")
        || runtime.engine_sha256 != format!("{:x}", Sha256::digest(bytes))
    {
        return Err("review runtime engine changed; prepare a new contract and plan".into());
    }
    Ok(())
}

fn validate_runtime_skill(
    runtime: &mehscan_core::ReviewRuntimeContract,
    skill: Option<&str>,
    provider: Option<&str>,
    root: &Path,
) -> Result<(), String> {
    validate_runtime_engine(runtime)?;
    let skill = Path::new(skill.ok_or("runtime-bound review requires --skill-root")?);
    outside_source(skill, root)?;
    if super::engine(mehscan_engine::review_runtime::skill_bundle_id(skill))?
        != runtime.skill_bundle_id
    {
        return Err("review runtime skill changed; prepare a new contract and plan".into());
    }
    if let Some(expected) = &runtime.provider {
        let path = Path::new(provider.ok_or("provider-bound review requires --provider-contract")?);
        outside_source(path, root)?;
        let actual: mehscan_core::ReviewProviderContract =
            serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        actual.validate()?;
        if &actual != expected {
            return Err("review provider changed; prepare a new contract and plan".into());
        }
    } else if provider.is_some() {
        return Err("provider contract supplied for an unbound provider".into());
    }
    Ok(())
}

fn runtime_template(
    args: &mut super::ParsedArguments,
    policy: mehscan_core::ReviewCompletionPolicy,
    root: Option<&Path>,
) -> Result<mehscan_core::ReviewRuntimeContract, String> {
    let skill = PathBuf::from(args.required("--skill-root")?);
    if let Some(root) = root {
        outside_source(&skill, root)?;
    }
    let mut limits = mehscan_core::ReviewResearchLimits::for_policy(policy);
    if let Some(value) = args.optional_usize("--research-rounds")? {
        limits.rounds = value;
    }
    if let Some(value) = args.optional_usize("--research-queries")? {
        limits.queries = value;
    }
    if let Some(value) = args.optional_usize("--research-bytes")? {
        limits.bytes = value;
    }
    if let Some(value) = args.optional_usize("--timeout")? {
        limits.timeout_seconds = value;
    }
    limits.validate()?;
    let provider = args
        .optional("--provider-contract")
        .map(|path| {
            if let Some(root) = root {
                outside_source(Path::new(&path), root)?;
            }
            let contract: mehscan_core::ReviewProviderContract =
                serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
                    .map_err(|error| error.to_string())?;
            contract.validate()?;
            Ok::<_, String>(contract)
        })
        .transpose()?;
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    Ok(mehscan_core::ReviewRuntimeContract {
        schema_version: "1".into(),
        policy,
        worker_protocol: mehscan_core::REVIEW_WORKER_PROTOCOL,
        engine_version: env!("CARGO_PKG_VERSION").into(),
        engine_sha256: format!(
            "{:x}",
            Sha256::digest(fs::read(executable).map_err(|error| error.to_string())?)
        ),
        skill_bundle_id: super::engine(mehscan_engine::review_runtime::skill_bundle_id(&skill))?,
        limits,
        provider,
    })
}

pub(super) fn run(mut arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let operation = arguments
        .next()
        .ok_or("state requires claim, runtime-template, plan-template, plan, pending, fact, work, record, end, status or history")?;
    if matches!(operation.as_str(), "--help" | "help" | "-h") {
        help();
        return Ok(());
    }
    let mut args = super::ParsedArguments::parse(arguments)?;
    if args.help {
        help();
        return Ok(());
    }
    if operation == "runtime-template" {
        let policy = match args.optional("--policy").as_deref().unwrap_or("value") {
            "value" => mehscan_core::ReviewCompletionPolicy::Value,
            "comprehensive" => mehscan_core::ReviewCompletionPolicy::Comprehensive,
            _ => return Err("completion policy must be value or comprehensive".into()),
        };
        let runtime = runtime_template(&mut args, policy, None)?;
        args.finish()?;
        return super::print_json(&runtime);
    }
    if operation == "plan-template" {
        let inventory_path = PathBuf::from(args.required("--inventory")?);
        let root = PathBuf::from(args.required("--source-root")?);
        let policy = match args.optional("--policy").as_deref().unwrap_or("value") {
            "value" => mehscan_core::ReviewCompletionPolicy::Value,
            "comprehensive" => mehscan_core::ReviewCompletionPolicy::Comprehensive,
            _ => return Err("completion policy must be value or comprehensive".into()),
        };
        let runtime = if args.options.contains_key("--skill-root") {
            Some(runtime_template(&mut args, policy, Some(&root))?)
        } else {
            None
        };
        args.finish()?;
        let (_, binding) = inventory(&inventory_path, &root)?;
        let mut draft = super::review_completion::template(&binding, policy);
        draft.runtime = runtime;
        return super::print_json(&draft);
    }
    let store = PathBuf::from(args.required("--store")?);
    let stream = args.required("--stream")?;
    if operation == "work" {
        let inventory_path = PathBuf::from(args.required("--inventory")?);
        let root = PathBuf::from(args.required("--source-root")?);
        outside_source(&store, &root)?;
        let generation = args.required_usize("--generation")? as u64;
        let owner = args.required("--owner")?;
        let requested = args.optional("--review-ids").map(|ids| {
            if ids.is_empty() {
                Vec::new()
            } else {
                ids.split(',').map(str::to_owned).collect::<Vec<_>>()
            }
        });
        let resume_only = args.optional_bool("--resume-only")?.unwrap_or(false);
        let skill = args.optional("--skill-root");
        let provider = args.optional("--provider-contract");
        args.finish()?;
        let (_, binding) = inventory(&inventory_path, &root)?;
        let journal_path = store.join("transactions.jsonl");
        if fs::symlink_metadata(&journal_path)
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err("state journal must not be a symlink".into());
        }
        let mut file = OpenOptions::new()
            .read(true)
            .open(journal_path)
            .map_err(|error| error.to_string())?;
        fs2::FileExt::lock_shared(&file).map_err(|error| error.to_string())?;
        let mut state = read_state(&mut file)?;
        let stream = state.owned_stream(
            &stream_key(
                binding.repository.repository_key.as_deref().unwrap(),
                &stream,
            )?,
            generation,
            &owner,
        )?;
        if stream
            .attempts
            .last()
            .unwrap()
            .binding
            .inventory_input_fingerprint
            != binding.inventory_input_fingerprint
        {
            return Err("work inventory differs from active generation".into());
        }
        let package = work_package(
            stream,
            stream.attempts.last().unwrap(),
            requested.as_deref(),
            resume_only,
        )?;
        if let Some(runtime) = &package.payload.runtime {
            validate_runtime_skill(runtime, skill.as_deref(), provider.as_deref(), &root)?;
        }
        return super::print_json(&package);
    }
    if matches!(operation.as_str(), "status" | "history") {
        let repository_key = args.required("--repository-key")?;
        args.finish()?;
        let path = store.join("transactions.jsonl");
        if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err("state journal must not be a symlink".into());
        }
        let mut file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|error| error.to_string())?;
        fs2::FileExt::lock_shared(&file).map_err(|error| error.to_string())?;
        let state = read_state(&mut file)?;
        return super::print_json(&state.view(
            &stream_key(&repository_key, &stream)?,
            operation == "history",
        )?);
    }
    let operation_key = args.required("--operation-key")?;
    let command = match operation.as_str() {
        "pending" | "fact" => {
            let inventory_path = PathBuf::from(args.required("--inventory")?);
            let root = PathBuf::from(args.required("--source-root")?);
            outside_source(&store, &root)?;
            let generation = args.required_usize("--generation")? as u64;
            let owner = args.required("--owner")?;
            let input = args.required("--input")?;
            args.finish()?;
            let (cache, binding) = inventory(&inventory_path, &root)?;
            let key = stream_key(
                binding.repository.repository_key.as_deref().unwrap(),
                &stream,
            )?;
            let bytes = fs::read(input).map_err(|error| error.to_string())?;
            if operation == "pending" {
                let draft = serde_json::from_slice::<mehscan_core::ReviewPendingDraft>(&bytes)
                    .map_err(|error| error.to_string())?;
                Command::Pending {
                    key,
                    generation,
                    owner,
                    inventory_input_fingerprint: binding.inventory_input_fingerprint,
                    draft,
                }
            } else {
                let draft = serde_json::from_slice::<mehscan_core::ReviewFactDraft>(&bytes)
                    .map_err(|error| error.to_string())?;
                if draft.schema_version != "1" {
                    return Err("unsupported fact schema".into());
                }
                let mut evidence = Vec::new();
                for reference in &draft.evidence {
                    evidence.push(super::review_completion::evidence(
                        &root, &binding, reference,
                    )?);
                }
                super::engine(mehscan_engine::investigation::validate_review_inventory(
                    &root, &cache,
                ))?;
                Command::Fact {
                    key,
                    generation,
                    owner,
                    inventory_input_fingerprint: binding.inventory_input_fingerprint,
                    question_id: draft.question_id,
                    answer: draft.answer,
                    evidence,
                }
            }
        }
        "plan" => {
            let inventory_path = PathBuf::from(args.required("--inventory")?);
            let root = PathBuf::from(args.required("--source-root")?);
            outside_source(&store, &root)?;
            let generation = args.required_usize("--generation")? as u64;
            let owner = args.required("--owner")?;
            let input = args.required("--input")?;
            let expected_plan_id = args.optional("--expected-plan-id");
            let work_package = read_work_package(args.optional("--work-package"))?;
            let skill = args.optional("--skill-root");
            let provider = args.optional("--provider-contract");
            args.finish()?;
            let (cache, binding) = inventory(&inventory_path, &root)?;
            let draft = serde_json::from_slice::<mehscan_core::ReviewCompletionDraft>(
                &fs::read(input).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let plan = super::review_completion::materialize(&root, &binding, &cache, draft)?;
            super::review_completion::validate(&binding, &plan)?;
            if let Some(runtime) = &plan.runtime {
                validate_runtime_skill(runtime, skill.as_deref(), provider.as_deref(), &root)?;
            }
            // Source reads and pinned blobs cannot silently race a changed inventory.
            super::engine(mehscan_engine::investigation::validate_review_inventory(
                &root, &cache,
            ))?;
            Command::Plan {
                key: stream_key(
                    binding.repository.repository_key.as_deref().unwrap(),
                    &stream,
                )?,
                generation,
                owner,
                expected_plan_id,
                plan,
                work_package,
            }
        }
        "claim" => {
            let inventory_path = PathBuf::from(args.required("--inventory")?);
            let root = PathBuf::from(args.required("--source-root")?);
            outside_source(&store, &root)?;
            let attempt_id = args.required("--attempt-id")?;
            let expected_generation = args.required_usize("--expected-generation")? as u64;
            let retry = args.optional_bool("--retry")?.unwrap_or(false);
            let coordination_key = args.optional("--coordination-key");
            if let Some(key) = &coordination_key {
                label(key)?;
            }
            args.finish()?;
            let (_, mut binding) = inventory(&inventory_path, &root)?;
            binding.coordination_key = coordination_key;
            Command::Claim {
                repository_key: binding.repository.repository_key.clone().unwrap(),
                stream,
                binding,
                attempt_id,
                expected_generation,
                retry,
            }
        }
        "record" => {
            let inventory_path = PathBuf::from(args.required("--inventory")?);
            let root = PathBuf::from(args.required("--source-root")?);
            outside_source(&store, &root)?;
            let run = PathBuf::from(args.required("--run")?);
            let generation = args.required_usize("--generation")? as u64;
            let owner = args.required("--owner")?;
            let supersessions = args
                .optional("--supersessions")
                .map(|path| {
                    fs::read(path)
                        .map_err(|error| error.to_string())
                        .and_then(|bytes| {
                            serde_json::from_slice::<Vec<ReviewStateSupersession>>(&bytes)
                                .map_err(|error| error.to_string())
                        })
                })
                .transpose()?
                .unwrap_or_default();
            let allow_partial = args.optional_bool("--allow-partial")?.unwrap_or(false);
            let work_package = read_work_package(args.optional("--work-package"))?;
            let skill = args.optional("--skill-root");
            let provider = args.optional("--provider-contract");
            if let Some(runtime) = work_package
                .as_ref()
                .and_then(|package| package.payload.runtime.as_ref())
            {
                validate_runtime_skill(runtime, skill.as_deref(), provider.as_deref(), &root)?;
            }
            let reviewer = args.optional("--reviewer");
            if let Some(label_value) = &reviewer {
                label(label_value)?;
            }
            args.finish()?;
            let (cache, binding) = inventory(&inventory_path, &root)?;
            let (manifest, pairs, work) =
                super::read_complete_bundle_responses(&run, None, allow_partial, Some(&root))?;
            let validator = super::engine(
                mehscan_engine::investigation::ReviewHistoryValidator::new(&root, &cache),
            )?;
            for (bundle, _) in &pairs {
                super::engine(validator.validate_bundle(bundle))?;
            }
            let report = super::engine(
                mehscan_engine::investigation::build_finding_report_from_manifest_with_work(
                    &manifest,
                    env!("CARGO_PKG_VERSION"),
                    reviewer,
                    &pairs,
                    false,
                    work,
                ),
            )?;
            if report.decision_records.len() != report.summary.reviewed {
                return Err("state cannot admit legacy decisions without native records".into());
            }
            let key = stream_key(
                binding.repository.repository_key.as_deref().unwrap(),
                &stream,
            )?;
            let mut provenance = json!({"tool":report.tool,"triage":report.triage,"impact_scope":report.scan.impact_scope});
            if let Some(package) = &work_package {
                provenance["work_package_id"] = json!(package.package_id);
                if let Some(runtime) = &package.payload.runtime {
                    provenance["runtime"] = json!(runtime);
                }
                provenance["evidence_update_ids"] = json!(
                    package
                        .payload
                        .evidence_updates
                        .iter()
                        .map(|fact| &fact.fact_id)
                        .collect::<Vec<_>>()
                );
            }
            Command::Record {
                key,
                generation,
                owner,
                records: report.decision_records,
                supersessions,
                provenance,
                work_package,
            }
        }
        "end" => {
            let repository_key = args.required("--repository-key")?;
            let generation = args.required_usize("--generation")? as u64;
            let owner = args.required("--owner")?;
            let status = match args.required("--status")?.as_str() {
                "finished" => ReviewAttemptStatus::Finished,
                "cancelled" => ReviewAttemptStatus::Cancelled,
                "incomplete" => ReviewAttemptStatus::Incomplete,
                _ => return Err("end status must be finished, cancelled or incomplete".into()),
            };
            args.finish()?;
            Command::End {
                key: stream_key(&repository_key, &stream)?,
                generation,
                owner,
                status,
            }
        }
        _ => return Err("unknown state operation".into()),
    };
    super::print_json(&transact(&store, &operation_key, command)?)
}

fn read_work_package(
    path: Option<String>,
) -> Result<Option<mehscan_core::ReviewWorkPackage>, String> {
    path.map(|path| {
        fs::read(path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|error| error.to_string()))
    })
    .transpose()
}

fn help() {
    println!(
        "Pending facts and handoff:\n  mehscan state pending|fact --store DIR --stream KEY --inventory DIR --source-root ROOT --generation N --owner TOKEN --input FILE --operation-key ID\n  mehscan state work --store DIR --stream KEY --inventory DIR --source-root ROOT --generation N --owner TOKEN [--review-ids ID,ID] [--resume-only true|false]\nPending questions attach to exact current needs_review checks or a current change-pass question. Source-bound evidence updates request revalidation; they never change verdicts. Work exports a provider-neutral package without ownership credentials. Pass --work-package FILE to plan/record to reject changed parents, facts, plans or generations. Record accepts --reviewer LABEL as unauthenticated provenance. External/deployment fact authority remains unsupported.\n"
    );
    println!(
        "USAGE:\n  mehscan state claim --store DIR --stream KEY --inventory DIR --source-root ROOT --attempt-id ID --expected-generation N --operation-key ID [--retry true|false]\n  mehscan state record --store DIR --stream KEY --inventory DIR --source-root ROOT --run DIR --generation N --owner TOKEN --operation-key ID [--supersessions FILE] [--allow-partial true|false]\n  mehscan state end --store DIR --stream KEY --repository-key KEY --generation N --owner TOKEN --status finished|cancelled|incomplete --operation-key ID\n  mehscan state status|history --store DIR --stream KEY --repository-key KEY\n\nLocal trusted-worker state, not an authorization or merge gate. Store outside source. Claim uses compare-and-swap generation; duplicate snapshots coalesce without granting ownership. Retry receipts retain original generation and may be stale. Record validates current inventory, native bundle evidence and all three verdicts. Supersessions is an array of {{decision_id, parents, reason}}; exact unresolved parents and same subject/context are required. History never clears newly discovered or missing work. Finished is execution state, not complete security coverage. Hash-chained durable journal rejects corrupt/torn data instead of guessing recovery. Hosted generation coordination, authenticated provenance and cross-revision verdict reuse remain unsupported."
    );
    println!(
        "\nOptional claim: --coordination-key KEY binds a trusted coordinator's opaque lifecycle/tool contract into the snapshot. It does not authenticate that assertion."
    );
    println!(
        "\nCompletion accounting:\n  mehscan state runtime-template --skill-root DIR [--policy value|comprehensive] [--research-rounds N --research-queries N --research-bytes N --timeout SECONDS]\n  mehscan state plan-template --inventory DIR --source-root ROOT [--policy value|comprehensive] [--skill-root DIR --provider-contract FILE]\n  mehscan state plan --store DIR --stream KEY --inventory DIR --source-root ROOT --generation N --owner TOKEN --input FILE --operation-key ID [--expected-plan-id ID]\nRuntime-bound plan, work and record require --skill-root DIR and verify actual trusted package bytes outside source. Provider-bound runtime/plan templates accept --provider-contract FILE; bound plan/work/record require the same descriptor. Templates select all native IDs and leave changed paths unassessed. Value may defer IDs with explicit reasons; Comprehensive must select every admitted ID. Every changed path requires an entry, including deletions and unsupported paths. Assessed modifications/deletions/renames require pinned base evidence; primary current evidence is required for existing files. Native response completion, pending effects, coverage limits and execution status remain distinct. Plan updates require the exact current parent. Evidence is materialized from authorized source, not caller-supplied text."
    );
}
