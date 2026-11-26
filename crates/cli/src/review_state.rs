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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        assignment: Option<String>,
    },
    Allocate {
        key: String,
        generation: u64,
        owner: String,
        assignment: String,
        worker: String,
        reserve_calls: Option<usize>,
        work_package: mehscan_core::ReviewWorkPackage,
    },
    Release {
        key: String,
        generation: u64,
        owner: String,
        assignment: String,
    },
    Reuse {
        key: String,
        generation: u64,
        owner: String,
        batch: String,
        previous_generation: u64,
        previous_attempt: String,
        decision_ids: Vec<String>,
        work_package: mehscan_core::ReviewWorkPackage,
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
    PendingBatch {
        key: String,
        generation: u64,
        owner: String,
        inventory_input_fingerprint: String,
        drafts: Vec<mehscan_core::ReviewPendingDraft>,
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

#[derive(Clone, Default)]
struct Stream {
    repository_key: String,
    name: String,
    attempts: Vec<Attempt>,
    decisions: BTreeMap<String, ReviewDecisionRecord>,
    heads: BTreeMap<String, BTreeSet<String>>,
    lineage: BTreeMap<String, ReviewStateSupersession>,
    admissions: BTreeMap<u64, BTreeSet<String>>,
    reusable_admissions: BTreeMap<u64, BTreeMap<String, String>>,
    knowledge_admissions: BTreeMap<u64, BTreeMap<String, Vec<String>>>,
    sharing: Option<mehscan_core::ReviewSharingBinding>,
    provenance: BTreeMap<u64, Vec<Value>>,
    completion_plans: BTreeMap<u64, Vec<mehscan_core::ReviewCompletionPlanRecord>>,
    pending: BTreeMap<String, mehscan_core::ReviewPendingRecord>,
    facts: BTreeMap<String, mehscan_core::ReviewFactRecord>,
    fact_reviews: BTreeMap<String, BTreeSet<String>>,
    assignments: BTreeMap<String, allocations::Assignment>,
}

mod allocations;
use super::review_memory::knowledge::{
    Reader as KnowledgeReader, Selection as KnowledgeSelection, premise_revisions,
};

fn memory_options(args: &mut super::ParsedArguments) -> Result<(Option<PathBuf>, bool), String> {
    let store = args.optional("--memory-store").map(PathBuf::from);
    let temporary = super::review_memory::temporary_mode(
        args.optional("--memory-mode").as_deref(),
        store.is_some(),
    )?;
    Ok((store, temporary))
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
            | Command::Reuse {
                key,
                generation,
                owner,
                ..
            }
            | Command::Allocate {
                key,
                generation,
                owner,
                ..
            }
            | Command::Release {
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
            | Command::PendingBatch {
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
                    && match command {
                        Command::Allocate { assignment, .. } => self.streams[&key]
                            .assignments
                            .get(assignment)
                            .is_some_and(|item| item.is_active(attempt.generation)),
                        _ => true,
                    }
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
            Command::Allocate {
                key,
                generation,
                owner,
                assignment,
                worker,
                reserve_calls,
                work_package,
            } => self.owned_stream(key, *generation, owner)?.allocate(
                assignment,
                worker,
                work_package,
                *reserve_calls,
            ),
            Command::Release {
                key,
                generation,
                owner,
                assignment,
            } => self
                .owned_stream(key, *generation, owner)?
                .release(*generation, assignment),
            Command::Record {
                key,
                generation,
                owner,
                records,
                supersessions,
                provenance,
                work_package,
                assignment,
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
                } else {
                    stream.check_sharing(None)?;
                }
                stream.validate_allocation(
                    *generation,
                    assignment.as_deref(),
                    work_package.as_ref(),
                    records,
                )?;
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
                    let bindings = stream.knowledge_admissions.entry(*generation).or_default();
                    for record in records {
                        bindings.insert(
                            record.decision_id.clone(),
                            premise_revisions(
                                &package.payload.knowledge,
                                &record.response.review_id,
                            ),
                        );
                    }
                    if reusable_work(package)
                        && package.payload.pending_questions.is_empty()
                        && package.payload.evidence_updates.is_empty()
                    {
                        let candidates = stream.reusable_admissions.entry(*generation).or_default();
                        for record in records.iter().filter(|record| settled(record)) {
                            candidates.insert(
                                record.decision_id.clone(),
                                package.payload.plan_id.clone(),
                            );
                        }
                    }
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
                let mut provenance = provenance.clone();
                if let Some(package) = work_package {
                    if let Some(sharing) = &package.payload.knowledge.sharing {
                        stream.sharing = Some(sharing.clone());
                        provenance["sharing"] = json!(sharing);
                    }
                    let revisions = records
                        .iter()
                        .filter_map(|record| {
                            let id = &record.response.review_id;
                            let revisions = package.payload.knowledge.revisions(id);
                            (!revisions.is_empty()).then_some((id, revisions))
                        })
                        .collect::<BTreeMap<_, _>>();
                    if !revisions.is_empty() {
                        provenance["knowledge_revisions"] = json!(revisions);
                    }
                }
                if let Some(id) = assignment {
                    provenance["assignment"] = stream.finish_allocation(id);
                }
                stream
                    .provenance
                    .entry(*generation)
                    .or_default()
                    .push(provenance);
                Ok(
                    json!({"status":"recorded","generation":generation,"decision_ids":incoming.keys().collect::<Vec<_>>()}),
                )
            }
            Command::Reuse {
                key,
                generation,
                owner,
                batch,
                previous_generation,
                previous_attempt,
                decision_ids,
                work_package,
            } => {
                let stream = self.owned_stream(key, *generation, owner)?;
                let current = stream.attempts.last().unwrap();
                validate_work_package(stream, current, work_package, &[])?;
                if !reusable_work(work_package) {
                    return Err("memory reuse requires a bound full-source work package without a change pass".into());
                }
                let previous = stream
                    .attempts
                    .iter()
                    .find(|attempt| {
                        attempt.generation == *previous_generation
                            && attempt.attempt_id == *previous_attempt
                    })
                    .ok_or("retained memory generation does not exist in this native stream")?;
                if previous.generation >= current.generation
                    || previous.status != ReviewAttemptStatus::Finished
                    || previous.binding != current.binding
                {
                    return Err("memory reuse requires matching native bindings from an earlier finished generation".into());
                }
                let previous_plan = stream
                    .completion_plans
                    .get(previous_generation)
                    .and_then(|plans| plans.last())
                    .ok_or("earlier generation lacks a native completion plan")?;
                let current_plan = stream.completion_plans[generation].last().unwrap();
                if previous_plan.plan != current_plan.plan {
                    return Err(
                        "memory reuse requires the same native plan and review runtime".into(),
                    );
                }
                let mut records = Vec::new();
                let mut review_ids = BTreeSet::new();
                let blocked = pending_memory_reviews(stream, work_package);
                let reserved = stream.reserved_reviews(*generation);
                for id in decision_ids {
                    let Some(record) = stream.decisions.get(id) else {
                        return Err("retained decision is missing from native state".into());
                    };
                    let review = &record.response.review_id;
                    let parents = work_package.payload.expected_parents.get(review);
                    if previous.admissions.contains(id)
                        && stream
                            .reusable_admissions
                            .get(previous_generation)
                            .and_then(|eligible| eligible.get(id))
                            == Some(&previous_plan.plan_id)
                        && settled(record)
                        && stream.knowledge_revisions(*previous_generation, id)
                            == premise_revisions(&work_package.payload.knowledge, review)
                        && !blocked.contains(review)
                        && !reserved.contains(review.as_str())
                        && parents.is_some_and(|parents| parents.as_slice() == [id.as_str()])
                        && !current.admissions.contains(id)
                        && review_ids.insert(review.clone())
                    {
                        records.push(record.clone());
                    }
                }
                let remaining = work_package
                    .payload
                    .review_ids
                    .iter()
                    .filter(|id| {
                        let parents = &work_package.payload.expected_parents[*id];
                        !review_ids.contains(*id)
                            && (blocked.contains(*id) || !matches!(parents.as_slice(), [parent]
                                if current.admissions.contains(parent) && settled(&stream.decisions[parent])
                                    && stream.knowledge_revisions(*generation, parent)
                                        == premise_revisions(&work_package.payload.knowledge, id))
                            )
                    })
                    .collect::<Vec<_>>();
                let reused: Vec<_> = records
                    .iter()
                    .map(|record| record.decision_id.clone())
                    .collect();
                if !records.is_empty() {
                    self.apply(&Command::Record {
                        key: key.clone(), generation: *generation, owner: owner.clone(),
                        records, supersessions: Vec::new(),
                        provenance: json!({"kind":"exact_memory_reuse","batch":batch,"previous_generation":previous_generation,
                                           "work_package_id":work_package.package_id,"decision_ids":reused}),
                        work_package: Some(work_package.clone()),
                        assignment: None,
                    })?;
                    if !blocked.is_empty() {
                        // Preserve eligibility for partial reuse while keeping
                        // ordinary Record replay identical for older journals.
                        let stream = self.owned_stream(key, *generation, owner)?;
                        let eligible = stream.reusable_admissions.entry(*generation).or_default();
                        for id in &reused {
                            eligible.insert(id.clone(), work_package.payload.plan_id.clone());
                        }
                    }
                }
                Ok(
                    json!({"status":"memory_reuse","generation":generation,"decision_ids":reused,
                    "reused_review_ids":review_ids,"remaining_review_ids":remaining,"model_calls":0}),
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
                if !stream.reserved_reviews(*generation).is_empty() {
                    return Err("release active assignments before replacing the plan".into());
                }
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
                if let Some(sharing) = work_package
                    .as_ref()
                    .and_then(|package| package.payload.knowledge.sharing.as_ref())
                {
                    stream.sharing = Some(sharing.clone());
                }
                Ok(json!({"status":"planned","generation":generation,"plan_id":plan_id}))
            }
            Command::PendingBatch {
                key,
                generation,
                owner,
                inventory_input_fingerprint,
                drafts,
            } => {
                if drafts.is_empty() || drafts.len() > 256 {
                    return Err("pending batch must contain 1 to 256 questions".into());
                }
                // Validate the whole batch in an isolated derived state before
                // mutating this state or appending its single transaction.
                let mut trial = State::default();
                trial.streams.insert(
                    key.clone(),
                    self.streams.get(key).ok_or("unknown state stream")?.clone(),
                );
                let results = drafts
                    .iter()
                    .map(|draft| {
                        trial.apply(&Command::Pending {
                            key: key.clone(),
                            generation: *generation,
                            owner: owner.clone(),
                            inventory_input_fingerprint: inventory_input_fingerprint.clone(),
                            draft: draft.clone(),
                        })
                    })
                    .collect::<Result<Vec<_>, _>>();
                let results = results?;
                self.streams
                    .insert(key.clone(), trial.streams.remove(key).unwrap());
                Ok(json!({"status":"pending","generation":generation,
                    "question_ids":results.iter().map(|r| r["question_id"].clone()).collect::<Vec<_>>()}))
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
        if !stream.assignments.is_empty() {
            result["assignments"] = stream.assignment_view(current, history);
        }
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
        excluded_review_ids: saved.plan.excluded_review_ids.clone(),
        expected_parents,
        parent_decisions: parents
            .into_iter()
            .map(|id| stream.decisions[&id].clone())
            .collect(),
        pending_questions: questions,
        evidence_updates: facts,
        change_pass: saved.plan.change_pass.clone(),
        knowledge: Default::default(),
    };
    Ok(mehscan_core::ReviewWorkPackage {
        package_id: hash("mehscanReviewWork/v1", &payload)?,
        payload,
    })
}

fn bind_knowledge(
    package: &mut mehscan_core::ReviewWorkPackage,
    binding: &ReviewStateBinding,
    selection: &KnowledgeSelection,
) -> Result<(), String> {
    package.payload.knowledge = selection.context(&package.payload, binding)?;
    package.package_id = hash("mehscanReviewWork/v1", &package.payload)?;
    Ok(())
}

impl Stream {
    fn check_sharing(
        &self,
        sharing: Option<&mehscan_core::ReviewSharingBinding>,
    ) -> Result<(), String> {
        if self.sharing.as_ref() != sharing
            && (self.sharing.is_some() || !self.decisions.is_empty())
        {
            return Err("review journal belongs to a different sharing audience; use its dedicated state home".into());
        }
        Ok(())
    }

    fn knowledge_revisions(&self, generation: u64, decision: &str) -> &[String] {
        self.knowledge_admissions
            .get(&generation)
            .and_then(|items| items.get(decision))
            .map_or(&[], Vec::as_slice)
    }
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
    stream.check_sharing(package.payload.knowledge.sharing.as_ref())?;
    // Regenerate the exact handoff view; new facts, changed plans or parent heads
    // fence a late response even on the same source revision.
    let current = work_package(stream, attempt, Some(&package.payload.review_ids), false)?;
    let mut supplied = package.payload.clone();
    // Live knowledge is checked under the memory lock before append. Replay
    // uses the revisions saved with the journal transaction.
    supplied.knowledge = Default::default();
    if current.payload != supplied {
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

fn reusable_work(package: &mehscan_core::ReviewWorkPackage) -> bool {
    let payload = &package.payload;
    payload
        .runtime
        .as_ref()
        .is_some_and(|runtime| runtime.orchestration.is_none())
        && payload.impact_scope.is_none()
        && payload.change_pass.is_empty()
        && payload.pending_questions.iter().all(|question| {
            matches!(
                question.origin,
                mehscan_core::ReviewPendingOrigin::Decision { .. }
            )
        })
}

fn pending_memory_reviews(
    stream: &Stream,
    package: &mehscan_core::ReviewWorkPackage,
) -> BTreeSet<String> {
    package
        .payload
        .pending_questions
        .iter()
        .filter_map(|question| {
            let mehscan_core::ReviewPendingOrigin::Decision { decision_id } = &question.origin
            else {
                return None;
            };
            Some(stream.decisions[decision_id].response.review_id.clone())
        })
        .collect()
}

fn settled(record: &ReviewDecisionRecord) -> bool {
    record.response.decision != mehscan_core::ReviewDecision::NeedsReview
        && record.response.checks.is_empty()
        && record
            .response
            .investigation
            .as_ref()
            .is_none_or(|trace| trace.blockers.is_empty())
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
    let changed_paths = plan
        .change_pass
        .iter()
        .map(|entry| {
            json!({"path":entry.path,"status":entry.status,"summary":entry.summary,
                "questions":entry.questions,"native_review_ids":entry.native_review_ids,
                "evidence":entry.evidence.iter().map(|evidence| json!({
                    "artifact_id":evidence.artifact_id,"source":evidence.source,"revision":evidence.revision
                })).collect::<Vec<_>>()})
        })
        .collect::<Vec<_>>();
    let work_complete = missing.is_empty() && unassessed.is_empty() && limited.is_empty();
    let has_limits = !limited.is_empty()
        || !plan.native_coverage_limits.is_empty()
        || !plan.deferred_review_ids.is_empty();
    Ok(json!({"plan_id":saved.plan_id,"policy":plan.policy,
        "status":if !work_complete { "incomplete" } else if has_limits { "complete_with_limits" } else { "complete" },
        "accounting_complete":unassessed.is_empty(),"review_work_complete":work_complete,
        "selected_review_count":plan.selected_review_ids.len(),"deferred_review_ids":plan.deferred_review_ids,
        "excluded_review_ids":plan.excluded_review_ids,
        "missing_or_conflicting_review_ids":missing,"pending_review_ids":pending,"issue_review_ids":issues,
        "unassessed_changed_paths":unassessed,"limited_changed_paths":limited,"pending_changed_effects":change_pending,
        "changed_paths":changed_paths,
        "native_coverage_limits":plan.native_coverage_limits,"security_resolution":"not_established"}))
}

fn read_state(file: &mut File, through: Option<u64>) -> Result<State, String> {
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
        if through == Some(state.sequence) {
            return Ok(state);
        }
    }
    if through.is_some() {
        return Err("native completion receipt sequence is missing from state journal".into());
    }
    Ok(state)
}

fn transact(store: &Path, operation: &str, command: Command) -> Result<Value, String> {
    transact_checked(store, operation, command, |_, _| Ok(()))
}

fn transact_checked(
    store: &Path,
    operation: &str,
    command: Command,
    check: impl FnOnce(&State, &Command) -> Result<(), String>,
) -> Result<Value, String> {
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
    let mut state = read_state(&mut file, None)?;
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
    check(&state, &command)?;
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

fn read_store(store: &Path, through: Option<u64>) -> Result<State, String> {
    let path = store.join("transactions.jsonl");
    if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err("state journal must not be a symlink".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    fs2::FileExt::lock_shared(&file).map_err(|error| error.to_string())?;
    read_state(&mut file, through)
}

#[derive(Serialize)]
pub(super) struct MemoryAdmission {
    pub generation: u64,
    pub attempt: String,
    pub status: ReviewAttemptStatus,
    pub records: Vec<ReviewDecisionRecord>,
    pub sharing: Option<mehscan_core::ReviewSharingBinding>,
}

pub(super) struct RetainedBatch {
    pub id: String,
    pub generation: u64,
    pub attempt: String,
    pub decisions: Vec<String>,
}

pub(super) struct MemoryPreparation<'a> {
    pub store: &'a Path,
    pub stream: &'a str,
    pub repository_key: &'a str,
    pub inventory: &'a str,
    pub generation: u64,
    pub owner: &'a str,
    pub requested: Option<&'a [String]>,
}

#[derive(Serialize)]
pub(super) struct PreparedMemory {
    pub memory: Value,
    pub work_package: mehscan_core::ReviewWorkPackage,
}

impl MemoryPreparation<'_> {
    fn native_work(
        &self,
        state: &mut State,
        key: &str,
        selection: &KnowledgeSelection,
    ) -> Result<mehscan_core::ReviewWorkPackage, String> {
        let stream = state.owned_stream(key, self.generation, self.owner)?;
        let attempt = stream.attempts.last().unwrap();
        if attempt.binding.inventory_input_fingerprint != self.inventory {
            return Err("work inventory differs from active generation".into());
        }
        let selected = stream.available_reviews(attempt, self.requested)?;
        stream.check_sharing(selection.sharing.as_ref())?;
        let mut package = work_package(stream, attempt, selected.as_deref(), false)?;
        bind_knowledge(&mut package, &attempt.binding, selection)?;
        Ok(package)
    }

    fn remaining_work(
        &self,
        state: &mut State,
        key: &str,
        full: mehscan_core::ReviewWorkPackage,
        selection: &KnowledgeSelection,
    ) -> Result<mehscan_core::ReviewWorkPackage, String> {
        if !reusable_work(&full) {
            return Ok(full);
        }
        let stream = state.owned_stream(key, self.generation, self.owner)?;
        let attempt = stream.attempts.last().unwrap();
        let blocked = pending_memory_reviews(stream, &full);
        let remaining = full.payload.review_ids.iter().filter(|id| {
            let parents = &full.payload.expected_parents[*id];
            blocked.contains(*id) || !matches!(parents.as_slice(), [parent]
                if attempt.admissions.contains(parent)
                && stream.knowledge_revisions(self.generation, parent) == premise_revisions(&full.payload.knowledge, id)
                && stream.reusable_admissions.get(&self.generation).and_then(|admitted| admitted.get(parent)) == Some(&full.payload.plan_id)
                && settled(&stream.decisions[parent]))
        }).cloned().collect::<Vec<_>>();
        if remaining.len() == full.payload.review_ids.len() {
            return Ok(full);
        }
        let mut package = work_package(stream, attempt, Some(&remaining), false)?;
        bind_knowledge(&mut package, &attempt.binding, selection)?;
        Ok(package)
    }

    pub(super) fn prepare(
        &self,
        source: &Path,
        skill: &str,
        provider: Option<&str>,
        retained: Option<Result<Option<RetainedBatch>, String>>,
        selection: &KnowledgeSelection,
    ) -> Result<PreparedMemory, String> {
        let key = stream_key(self.repository_key, self.stream)?;
        let mut state = read_store(self.store, None)?;
        let mut full = self.native_work(&mut state, &key, selection)?;
        if let Some(runtime) = &full.payload.runtime {
            validate_runtime_skill(runtime, Some(skill), provider, source)?;
        }
        let (mut memory, reuse) = match retained {
            Some(Ok(Some(batch))) => {
                let operation = hash(
                    "mehscanMemoryPrepare/v1",
                    &(&key, self.generation, &full.package_id, &batch.id),
                )?;
                let command = reuse_command(key.clone(), self.owner.into(), full.clone(), batch);
                let command_hash = hash("mehscanStateCommand/v1", &command)?;
                if let Some((saved_hash, _, _)) = state.receipts.get(&operation) {
                    if &command_hash != saved_hash {
                        return Err(
                            "memory preparation operation conflicts with its journal receipt"
                                .into(),
                        );
                    }
                    (json!({"status":"matched"}), Some((operation, command)))
                } else {
                    // Preview against the same native validation used by the
                    // explicit command. A compatibility miss leaves normal work.
                    match state.apply(&command) {
                        Ok(result)
                            if result["reused_review_ids"]
                                .as_array()
                                .is_some_and(|ids| !ids.is_empty()) =>
                        {
                            (json!({"status":"matched"}), Some((operation, command)))
                        }
                        Ok(_) => (json!({"status":"no_eligible_decisions"}), None),
                        Err(reason) => (json!({"status":"incompatible","reason":reason}), None),
                    }
                }
            }
            Some(Ok(None)) => (json!({"status":"no_batch"}), None),
            Some(Err(reason)) => (json!({"status":"unavailable","reason":reason}), None),
            None => (json!({"status":"skipped","reason":"temporary_mode"}), None),
        };
        if let Some((operation, command)) = reuse {
            // Once the controller attempts the append, report write or race
            // failures explicitly. A retry can recover the exact receipt.
            let receipt = transact(self.store, &operation, command)?;
            memory = receipt["result"].clone();
            memory["replayed"] = receipt["replayed"].clone();
            state = read_store(self.store, None)?;
            let current = self.native_work(&mut state, &key, selection)?;
            if current.payload.runtime != full.payload.runtime {
                return Err(
                    "native runtime changed during memory preparation; request fresh work".into(),
                );
            }
            full = current;
        }
        let work = self.remaining_work(&mut state, &key, full, selection)?;
        memory["remaining_review_ids"] = json!(work.payload.review_ids);
        Ok(PreparedMemory {
            memory,
            work_package: work,
        })
    }
}

pub(super) fn reuse_memory(
    store: &Path,
    stream: &str,
    owner: String,
    operation_key: &str,
    work: mehscan_core::ReviewWorkPackage,
    batch: RetainedBatch,
    selection: &KnowledgeSelection,
) -> Result<Value, String> {
    let key = stream_key(
        work.payload
            .repository
            .repository_key
            .as_deref()
            .ok_or("missing repository key")?,
        stream,
    )?;
    transact_checked(
        store,
        operation_key,
        reuse_command(key.clone(), owner, work, batch),
        |state, command| {
            let Command::Reuse { work_package, .. } = command else {
                unreachable!()
            };
            let attempt = state
                .streams
                .get(&key)
                .and_then(|stream| stream.attempts.last())
                .ok_or("state stream has no attempt")?;
            if selection.context(&work_package.payload, &attempt.binding)?
                != work_package.payload.knowledge
            {
                return Err("applicable knowledge changed; request fresh work".into());
            }
            Ok(())
        },
    )
}

fn reuse_command(
    key: String,
    owner: String,
    work: mehscan_core::ReviewWorkPackage,
    batch: RetainedBatch,
) -> Command {
    Command::Reuse {
        key,
        generation: work.payload.generation,
        owner,
        work_package: work,
        batch: batch.id,
        previous_generation: batch.generation,
        previous_attempt: batch.attempt,
        decision_ids: batch.decisions,
    }
}

pub(super) fn memory_admission(
    store: &Path,
    stream: &str,
    generation: u64,
    repository: &mehscan_core::ReviewRepositoryIdentity,
    source: &str,
    inventory: &str,
    through: Option<u64>,
) -> Result<MemoryAdmission, String> {
    let state = read_store(store, through)?;
    let key = stream_key(
        repository
            .repository_key
            .as_deref()
            .ok_or("missing repository key")?,
        stream,
    )?;
    let stream = state.streams.get(&key).ok_or("unknown state stream")?;
    let attempt = stream
        .attempts
        .last()
        .ok_or("state stream has no attempt")?;
    if attempt.generation != generation
        || &attempt.binding.repository != repository
        || attempt.binding.source_fingerprint != source
        || attempt.binding.inventory_input_fingerprint != inventory
    {
        return Err(
            "memory admission does not match the current state generation and inventory".into(),
        );
    }
    if !matches!(
        attempt.status,
        ReviewAttemptStatus::Finished | ReviewAttemptStatus::Incomplete
    ) {
        return Err("memory retention requires a finished or incomplete native attempt".into());
    }
    let mut records = Vec::new();
    for heads in stream.heads.values().filter(|heads| heads.len() == 1) {
        if let Some(id) = heads.first()
            && attempt.admissions.contains(id)
        {
            records.push(stream.decisions[id].clone());
        }
    }
    Ok(MemoryAdmission {
        generation,
        attempt: attempt.attempt_id.clone(),
        status: attempt.status,
        records,
        sharing: stream.sharing.clone(),
    })
}

pub(super) fn outside_source(store: &Path, root: &Path) -> Result<(), String> {
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

pub(super) fn load_inventory(
    path: &Path,
) -> Result<(mehscan_engine::investigation::ReviewInventory, String), String> {
    let cache: mehscan_engine::investigation::ReviewInventory = serde_json::from_slice(
        &fs::read(path.join("scan-cache.json")).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let fingerprint = super::engine(cache.input_fingerprint())?;
    let summary: Value = serde_json::from_slice(
        &fs::read(path.join("inventory.json")).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if summary["input_fingerprint"].as_str() != Some(&fingerprint) {
        return Err("inventory summary does not match cache".into());
    }
    Ok((cache, fingerprint))
}

fn inventory_repository_key(path: &Path) -> Result<String, String> {
    let (cache, _) = load_inventory(path)?;
    cache
        .identity_catalog
        .and_then(|catalog| catalog.repository.repository_key)
        .ok_or_else(|| "state requires a repository identity; regenerate a standalone inventory or supply --repository-key".into())
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
    let (cache, fingerprint) = load_inventory(path)?;
    super::engine(mehscan_engine::investigation::validate_review_inventory(
        root, &cache,
    ))?;
    let catalog = cache
        .identity_catalog
        .as_ref()
        .ok_or("state requires native identity; regenerate inventory")?;
    let key = catalog.repository.repository_key.as_deref().ok_or(
        "state requires a repository identity; regenerate a standalone inventory or supply --repository-key",
    )?;
    super::review_memory::validate_repository_root(root, key)?;
    let binding = ReviewStateBinding {
        repository: catalog.repository.clone(),
        assessment_context: catalog.assessment_context.clone(),
        source_fingerprint: catalog.source_fingerprint.clone(),
        inventory_input_fingerprint: fingerprint,
        impact_scope: cache.scan.impact_scope.clone(),
        coordination_key: None,
        subjects: catalog.subjects.clone(),
        comprehensive_exclusions: cache.entries.iter().filter_map(|entry| {
            entry.comprehensive_exclusion.as_ref().map(|hint|
                (entry.review_id.clone(), format!("Conservative Comprehensive scope ({}): {} Unreviewed; not a safety verdict.", hint.reason, hint.assumption)))
        }).collect(),
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

pub(super) fn validate_runtime_skill(
    runtime: &mehscan_core::ReviewRuntimeContract,
    skill: Option<&str>,
    provider: Option<&str>,
    root: &Path,
) -> Result<(), String> {
    validate_runtime_engine(runtime)?;
    let skill = Path::new(skill.ok_or("runtime-bound review requires --skill-root")?);
    outside_source(skill, root)?;
    if !super::engine(mehscan_engine::review_runtime::matches_skill_bundle(
        skill,
        &runtime.skill_bundle_id,
    ))? {
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
    let orchestration = args
        .optional("--review-orchestration")
        .map(|path| {
            if let Some(root) = root {
                outside_source(Path::new(&path), root)?;
            }
            let contract: mehscan_core::ReviewOrchestrationContract =
                serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
                    .map_err(|error| error.to_string())?;
            contract.validate(provider.as_ref())?;
            Ok::<_, String>(contract)
        })
        .transpose()?;
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
        orchestration,
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
    if let Some(path) = args.optional("--project-run") {
        let project = super::review_memory::PreparedProject::read(Path::new(&path))?;
        let mut supply = |name: &str, value: String| -> Result<(), String> {
            if args.options.insert(name.into(), value).is_some() {
                return Err(format!("--project-run already supplies {name}"));
            }
            Ok(())
        };
        let temporary = project.temporary();
        if operation != "plan-template" {
            supply("--store", project.state_store.display().to_string())?;
            supply("--stream", project.stream)?;
        }
        if operation == "release" {
            supply("--repository-key", project.repository_key)?;
        } else {
            supply("--inventory", project.inventory.display().to_string())?;
            if !matches!(operation.as_str(), "status" | "history") {
                supply("--source-root", project.source_root.display().to_string())?;
            }
        }
        if matches!(
            operation.as_str(),
            "work" | "allocate" | "plan" | "record" | "end"
        ) {
            if temporary {
                supply("--memory-mode", "temporary".into())?;
            } else {
                supply("--memory-store", project.memory_store.display().to_string())?;
            }
        }
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
        // Keep historical/manual templates compatible; automated handoffs opt
        // into the native initial priority hints instead of silently selecting all.
        let selection = args.optional("--selection").unwrap_or_else(|| "all".into());
        if !matches!(selection.as_str(), "all" | "policy") {
            return Err("plan-template selection must be all or policy".into());
        }
        let runtime = if args.options.contains_key("--skill-root") {
            Some(runtime_template(&mut args, policy, Some(&root))?)
        } else {
            None
        };
        args.finish()?;
        let (cache, binding) = inventory(&inventory_path, &root)?;
        let mut draft = super::review_completion::template(&binding, policy);
        if selection == "policy" {
            super::review_completion::select_policy(&mut draft, &cache);
        }
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
        let assignment = args.optional("--assignment");
        let read_completed = args
            .optional_bool("--read-completed-assignment")?
            .unwrap_or(false);
        if read_completed && assignment.is_none() {
            return Err("reading a completed assignment requires --assignment".into());
        }
        let skill = args.optional("--skill-root");
        let provider = args.optional("--provider-contract");
        let (memory_store, temporary) = memory_options(&mut args)?;
        args.finish()?;
        let (_, binding) = inventory(&inventory_path, &root)?;
        let reader = KnowledgeReader::lock(
            &root,
            &binding.repository,
            memory_store.as_deref(),
            temporary,
        )?;
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
        let mut state = read_state(&mut file, None)?;
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
        let attempt = stream.attempts.last().unwrap();
        let selected = if let Some(id) = assignment {
            Some(
                stream
                    .assigned_reviews(generation, &id, requested.as_deref(), read_completed)?
                    .to_vec(),
            )
        } else {
            stream.available_reviews(attempt, requested.as_deref())?
        };
        let mut package = work_package(stream, attempt, selected.as_deref(), resume_only)?;
        bind_knowledge(
            &mut package,
            &binding,
            &reader.load(&root, &inventory_path)?,
        )?;
        stream.check_sharing(package.payload.knowledge.sharing.as_ref())?;
        if let Some(runtime) = &package.payload.runtime {
            validate_runtime_skill(runtime, skill.as_deref(), provider.as_deref(), &root)?;
        }
        return super::print_json(&package);
    }
    if matches!(operation.as_str(), "status" | "history") {
        let repository_key = match (
            args.optional("--repository-key"),
            args.optional("--inventory"),
        ) {
            (Some(key), None) => key,
            (None, Some(path)) => inventory_repository_key(Path::new(&path))?,
            _ => {
                return Err(
                    "state status or history requires one of --repository-key or --inventory"
                        .into(),
                );
            }
        };
        args.finish()?;
        let state = read_store(&store, None)?;
        return super::print_json(&state.view(
            &stream_key(&repository_key, &stream)?,
            operation == "history",
        )?);
    }
    let operation_key = args.required("--operation-key")?;
    let command = match operation.as_str() {
        "allocate" => {
            let root = PathBuf::from(args.required("--source-root")?);
            let inventory_path = PathBuf::from(args.required("--inventory")?);
            let generation = args.required_usize("--generation")? as u64;
            let owner = args.required("--owner")?;
            let worker = args.required("--worker")?;
            let reserve_calls = args.optional_usize("--reserve-calls")?;
            label(&worker)?;
            let work = args.required("--work-package")?;
            outside_source(&store, &root)?;
            outside_source(Path::new(&work), &root)?;
            let package =
                read_work_package(Some(work))?.ok_or("allocation requires a work package")?;
            let (_, binding) = inventory(&inventory_path, &root)?;
            if package.payload.inventory_input_fingerprint != binding.inventory_input_fingerprint {
                return Err("allocation work belongs to a different inventory".into());
            }
            let skill = args.optional("--skill-root");
            let provider = args.optional("--provider-contract");
            let (memory_store, temporary) = memory_options(&mut args)?;
            if let Some(runtime) = &package.payload.runtime {
                validate_runtime_skill(runtime, skill.as_deref(), provider.as_deref(), &root)?;
            }
            let key = stream_key(
                binding.repository.repository_key.as_deref().unwrap(),
                &stream,
            )?;
            let assignment = hash("mehscanAssignment/v1", &(&key, generation, &operation_key))?;
            args.finish()?;
            let reader = KnowledgeReader::lock(
                &root,
                &binding.repository,
                memory_store.as_deref(),
                temporary,
            )?;
            let command = Command::Allocate {
                key,
                generation,
                owner,
                assignment,
                worker,
                reserve_calls,
                work_package: package,
            };
            return super::print_json(&transact_checked(
                &store,
                &operation_key,
                command,
                |_, command| {
                    let Command::Allocate { work_package, .. } = command else {
                        unreachable!()
                    };
                    reader
                        .load(&root, &inventory_path)?
                        .validate(&work_package.payload, &binding)
                },
            )?);
        }
        "release" => Command::Release {
            key: stream_key(&args.required("--repository-key")?, &stream)?,
            generation: args.required_usize("--generation")? as u64,
            owner: args.required("--owner")?,
            assignment: args.required("--assignment")?,
        },
        "pending" | "pending-batch" | "fact" => {
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
            if operation == "pending-batch" {
                let drafts =
                    serde_json::from_slice::<Vec<mehscan_core::ReviewPendingDraft>>(&bytes)
                        .map_err(|error| error.to_string())?;
                if drafts.is_empty() || drafts.len() > 256 {
                    return Err("pending batch must contain 1 to 256 questions".into());
                }
                Command::PendingBatch {
                    key,
                    generation,
                    owner,
                    inventory_input_fingerprint: binding.inventory_input_fingerprint,
                    drafts,
                }
            } else if operation == "pending" {
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
            let (memory_store, temporary) = memory_options(&mut args)?;
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
            let command = Command::Plan {
                key: stream_key(
                    binding.repository.repository_key.as_deref().unwrap(),
                    &stream,
                )?,
                generation,
                owner,
                expected_plan_id,
                plan,
                work_package,
            };
            let Command::Plan { work_package, .. } = &command else {
                unreachable!()
            };
            if work_package.is_some() {
                let reader = KnowledgeReader::lock(
                    &root,
                    &binding.repository,
                    memory_store.as_deref(),
                    temporary,
                )?;
                return super::print_json(&transact_checked(
                    &store,
                    &operation_key,
                    command,
                    |_, command| {
                        let Command::Plan {
                            work_package: Some(package),
                            ..
                        } = command
                        else {
                            unreachable!()
                        };
                        reader
                            .load(&root, &inventory_path)?
                            .validate(&package.payload, &binding)
                    },
                )?);
            }
            command
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
            let assignment = args.optional("--assignment");
            let skill = args.optional("--skill-root");
            let provider = args.optional("--provider-contract");
            if let Some(runtime) = work_package
                .as_ref()
                .and_then(|package| package.payload.runtime.as_ref())
            {
                validate_runtime_skill(runtime, skill.as_deref(), provider.as_deref(), &root)?;
            }
            let reviewer = args.optional("--reviewer");
            let execution = args.optional("--review-execution");
            let (memory_store, temporary) = memory_options(&mut args)?;
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
                    if runtime.orchestration.is_some() {
                        let path = Path::new(
                            execution
                                .as_deref()
                                .ok_or("tiered review requires --review-execution")?,
                        );
                        outside_source(path, &root)?;
                        let receipt: mehscan_core::ReviewExecutionReceipt = serde_json::from_slice(
                            &fs::read(path).map_err(|error| error.to_string())?,
                        )
                        .map_err(|error| error.to_string())?;
                        validate_execution(
                            &receipt,
                            package,
                            &report.decision_records,
                            &pairs,
                            path.parent().unwrap(),
                            &root,
                        )?;
                        provenance["review_execution"] = json!(receipt);
                    } else if execution.is_some() {
                        return Err("execution receipt requires a tiered runtime".into());
                    }
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
            if execution.is_some() && provenance.get("review_execution").is_none() {
                return Err(
                    "execution receipt requires a tiered runtime-bound work package".into(),
                );
            }
            let reader = KnowledgeReader::lock(
                &root,
                &binding.repository,
                memory_store.as_deref(),
                temporary,
            )?;
            let command = Command::Record {
                key,
                generation,
                owner,
                records: report.decision_records,
                supersessions,
                provenance,
                work_package,
                assignment,
            };
            let receipt = transact_checked(&store, &operation_key, command, |_, command| {
                let Command::Record {
                    work_package,
                    records,
                    ..
                } = command
                else {
                    unreachable!()
                };
                let selection = reader.load(&root, &inventory_path)?;
                if let Some(package) = work_package {
                    selection.validate(&package.payload, &binding)?;
                } else if selection.sharing.is_some()
                    || records
                        .iter()
                        .any(|record| !selection.revisions_for(&record.identity).is_empty())
                {
                    return Err(
                        "review with applicable knowledge requires its exact work package".into(),
                    );
                }
                Ok(())
            })?;
            return super::print_json(&receipt);
        }
        "end" => {
            let repository_key = args.optional("--repository-key");
            let generation = args.required_usize("--generation")? as u64;
            let owner = args.required("--owner")?;
            let status = match args.required("--status")?.as_str() {
                "finished" => ReviewAttemptStatus::Finished,
                "cancelled" => ReviewAttemptStatus::Cancelled,
                "incomplete" => ReviewAttemptStatus::Incomplete,
                _ => return Err("end status must be finished, cancelled or incomplete".into()),
            };
            let memory_store = args.optional("--memory-store").map(PathBuf::from);
            let mode = args.optional("--memory-mode");
            let temporary =
                super::review_memory::temporary_mode(mode.as_deref(), memory_store.is_some())?;
            let source_root = args.optional("--source-root").map(PathBuf::from);
            let inventory = args.optional("--inventory").map(PathBuf::from);
            let repository_key = if let Some(key) = repository_key {
                key
            } else {
                let path = inventory
                    .as_deref()
                    .ok_or("state end requires --repository-key or --inventory")?;
                let key = inventory_repository_key(path)?;
                if let Some(root) = source_root.as_deref() {
                    super::review_memory::validate_repository_root(root, &key)?;
                }
                key
            };
            let memory = match (source_root, inventory) {
                (Some(source_root), Some(inventory)) if !temporary => {
                    Some(super::review_memory::EndRetention {
                        store: memory_store,
                        source_root,
                        inventory,
                    })
                }
                (Some(_), Some(_)) => None,
                (None, None) if temporary || (mode.is_none() && memory_store.is_none()) => None,
                _ => return Err("memory retention requires --source-root and --inventory".into()),
            };
            args.finish()?;
            let key = stream_key(&repository_key, &stream)?;
            let reader = memory
                .as_ref()
                .filter(|_| status == ReviewAttemptStatus::Finished)
                .map(|memory| {
                    let (cache, _) = load_inventory(&memory.inventory)?;
                    let repository = &cache
                        .identity_catalog
                        .as_ref()
                        .ok_or("missing inventory identity")?
                        .repository;
                    KnowledgeReader::lock(
                        &memory.source_root,
                        repository,
                        memory.store.as_deref(),
                        false,
                    )
                })
                .transpose();
            let mut receipt = transact_checked(
                &store,
                &operation_key,
                Command::End {
                    key: key.clone(),
                    generation,
                    owner,
                    status,
                },
                |state, _| {
                    if status != ReviewAttemptStatus::Finished {
                        return Ok(());
                    }
                    let stream = state.streams.get(&key).ok_or("unknown state stream")?;
                    let attempt = stream
                        .attempts
                        .last()
                        .ok_or("state stream has no attempt")?;
                    if attempt.generation != generation {
                        return Err("review completion belongs to a different generation".into());
                    }
                    let has_bindings = stream.sharing.is_some()
                        || attempt
                            .admissions
                            .iter()
                            .any(|id| !stream.knowledge_revisions(generation, id).is_empty());
                    let selection = match (&reader, &memory) {
                        (Ok(Some(reader)), Some(memory)) => reader.load(&memory.source_root, &memory.inventory),
                        (Err(reason), _) => Err(reason.clone()),
                        _ => Err("finishing a knowledge-bound review requires its memory store and inventory".into()),
                    };
                    let selection = match selection {
                        Ok(selection) => selection,
                        Err(reason) if has_bindings => return Err(reason),
                        Err(_) => return Ok(()),
                    };
                    stream.check_sharing(selection.sharing.as_ref())?;
                    for id in &attempt.admissions {
                        let record = &stream.decisions[id];
                        if stream
                            .heads
                            .get(&subject_key(record)?)
                            .is_some_and(|heads| heads.contains(id))
                            && selection.revisions_for(&record.identity)
                                != stream.knowledge_revisions(generation, id)
                        {
                            return Err("applicable knowledge changed after admission; refresh affected work before finishing".into());
                        }
                    }
                    Ok(())
                },
            )?;
            drop(reader);
            if temporary {
                receipt["memory"] = json!({"status":"skipped","reason":"temporary_mode"});
            } else if let Some(memory) = memory {
                if status == ReviewAttemptStatus::Cancelled {
                    receipt["memory"] = json!({"status":"skipped","reason":"attempt_cancelled"});
                } else {
                    let sequence = receipt["sequence"]
                        .as_u64()
                        .ok_or("missing native completion sequence")?;
                    // The native close is already durable. Replay this exact terminal
                    // journal prefix on retry, even if another generation has started.
                    receipt["memory"] =
                        match memory.retain(&store, &stream, &repository_key, generation, sequence)
                        {
                            Ok(mut retained) => {
                                retained["status"] = json!("retained");
                                retained
                            }
                            Err(reason) => json!({"status":"pending","reason":reason}),
                        };
                }
            }
            return super::print_json(&receipt);
        }
        _ => return Err("unknown state operation".into()),
    };
    super::print_json(&transact(&store, &operation_key, command)?)
}

fn validate_execution(
    receipt: &mehscan_core::ReviewExecutionReceipt,
    package: &mehscan_core::ReviewWorkPackage,
    records: &[mehscan_core::ReviewDecisionRecord],
    pairs: &[(
        mehscan_core::PathReviewBundle,
        mehscan_core::PathReviewBundleResponseSet,
    )],
    execution_root: &Path,
    root: &Path,
) -> Result<(), String> {
    use mehscan_core::ReviewDecision::{Issue, NeedsReview, NotIssue};
    let runtime = package
        .payload
        .runtime
        .as_ref()
        .ok_or("execution requires runtime")?;
    let policy = runtime
        .orchestration
        .as_ref()
        .ok_or("execution requires orchestration")?;
    let primary = runtime
        .provider
        .as_ref()
        .ok_or("execution requires primary provider")?;
    let digest = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut sources = std::collections::BTreeMap::<
        String,
        (String, mehscan_core::PathReviewBundleResponseSet),
    >::new();
    if receipt.schema_version != "1"
        || receipt.package_id != package.package_id
        || receipt.cases.len() != records.len()
    {
        return Err("execution receipt differs from native work/decision coverage".into());
    }
    for case in &receipt.cases {
        let record = records
            .iter()
            .find(|r| r.response.review_id == case.review_id)
            .ok_or("execution receipt names an unrelated review")?;
        if !seen.insert(&case.review_id) || !(1..=3).contains(&case.assessments.len()) {
            return Err("execution receipt contains duplicate or missing assessments".into());
        }
        let mut profiles = std::collections::BTreeSet::new();
        let mut jobs = std::collections::BTreeSet::new();
        if let Some(revalidation) = &case.revalidation {
            if revalidation.assessments.len() != 2
                || revalidation.assessments[0].profile == revalidation.assessments[1].profile
            {
                return Err("revalidation requires a fresh distinct-profile pair".into());
            }
        }
        let prior = case.assessments.iter().enumerate().map(|(index, a)| {
            (
                a,
                ["investigator", "verification", "adjudication"][index],
                index == 2,
            )
        });
        let qa = case.quality_review.iter().map(|a| (a, "final_qa", true));
        let fresh = case
            .revalidation
            .iter()
            .flat_map(|r| r.assessments.iter())
            .map(|a| (a, "verification", false));
        let fresh_qa = case
            .revalidation
            .iter()
            .flat_map(|r| r.quality_review.iter())
            .map(|a| (a, "final_qa", true));
        for (index, (assessment, expected_role, expert_only)) in
            prior.chain(qa).chain(fresh).chain(fresh_qa).enumerate()
        {
            let expected = match assessment.profile.as_str() {
                "routine" => primary,
                "expert" => &policy.expert,
                _ => return Err("unknown execution provider profile".into()),
            };
            if &assessment.provider != expected
                || assessment.role != expected_role
                || (index < case.assessments.len()
                    && index < 2
                    && !profiles.insert(&assessment.profile))
                || (expert_only && assessment.profile != "expert")
                || !digest(&assessment.job_id)
                || !digest(&assessment.response_sha256)
                || !jobs.insert(&assessment.job_id)
            {
                return Err("execution assessment differs from bound provider policy".into());
            }
            let bundle = &pairs
                .iter()
                .find(|(bundle, _)| bundle.review_ids.contains(&case.review_id))
                .ok_or("execution assessment has no matching native bundle")?
                .0;
            if !sources.contains_key(&assessment.job_id) {
                let path = execution_root
                    .join("assessments")
                    .join(format!("{}.json", assessment.job_id));
                outside_source(&path, root)?;
                if fs::metadata(&path).map_err(|e| e.to_string())?.len() > 8 * 1024 * 1024 {
                    return Err("assessment artifact exceeds bounded intake".into());
                }
                let bytes = fs::read(&path).map_err(|e| e.to_string())?;
                let response: mehscan_core::PathReviewBundleResponseSet =
                    serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                super::engine(
                    mehscan_engine::investigation::validate_path_review_bundle_response(
                        bundle, &response,
                    ),
                )?;
                super::validate_review_artifact_source_text(root, &response)?;
                sources.insert(
                    assessment.job_id.clone(),
                    (format!("{:x}", Sha256::digest(bytes)), response),
                );
            }
            let (digest, response) = &sources[&assessment.job_id];
            if digest != &assessment.response_sha256
                || response.bundle_fingerprint != bundle.bundle_fingerprint
                || !response
                    .results
                    .iter()
                    .any(|r| r.review_id == case.review_id && r.decision == assessment.decision)
            {
                return Err("assessment receipt differs from its validated source artifact".into());
            }
        }
        let final_decision = record.response.decision;
        let first = case.assessments[0].decision;
        let quality = policy.quality.as_ref();
        let adjudicated = case.assessments.len() == 3;
        let mut basis = if adjudicated {
            if !quality.is_some_and(|q| q.adjudicate_disagreements) {
                return Err("adjudication is not enabled by the native policy".into());
            }
            let resolution = case
                .resolution
                .as_ref()
                .ok_or("adjudication requires an explicit source resolution")?;
            if resolution.disputed_claim.trim().is_empty()
                || resolution.disputed_claim.chars().count() > 300
                || resolution.reason.trim().is_empty()
                || resolution.reason.chars().count() > 500
            {
                return Err(
                    "adjudication resolution must name a bounded disputed claim and reason".into(),
                );
            }
            let assessment = &case.assessments[2];
            let resolved = sources[&assessment.job_id]
                .1
                .results
                .iter()
                .find(|r| r.review_id == case.review_id)
                .unwrap();
            let reason = resolution
                .reason
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            if !resolved.investigation.as_ref().is_some_and(|trace| {
                !trace.decisive_artifacts.is_empty()
                    && trace.reviewer_inferences.iter().any(|i| i.claim == reason)
            }) {
                return Err("adjudication resolution is not bound to its source assessment".into());
            }
            let decision = assessment.decision;
            if decision != NeedsReview
                && !case.assessments[..2].iter().any(|a| a.decision == decision)
            {
                // A newly proposed verdict needs another independent assessment.
                NeedsReview
            } else {
                decision
            }
        } else {
            if case.resolution.is_some() {
                return Err("resolution requires an adjudication assessment".into());
            }
            if case.assessments.len() == 2
                && !matches!(
                    (first, case.assessments[1].decision),
                    (Issue, NotIssue) | (NotIssue, Issue)
                )
            {
                // Resolving a pending question is progress, not conflicting
                // affirmative evidence. The expert owns this terminal decision.
                case.assessments
                    .iter()
                    .find(|a| a.profile == "expert")
                    .map_or(NeedsReview, |a| a.decision)
            } else if case.assessments.iter().any(|a| a.decision != first) {
                NeedsReview
            } else {
                first
            }
        };
        if let Some(blocker) = &case.blocker {
            if !matches!(
                blocker.as_str(),
                "external_required" | "human_required" | "budget_exhausted"
            ) || final_decision != NeedsReview
            {
                return Err("unavailable facts must remain pending".into());
            }
        }
        let prior_basis = basis;
        let check_qa = |qa: Option<&mehscan_core::ReviewAssessmentReceipt>,
                        basis|
         -> Result<(), String> {
            if quality.is_some_and(|q| q.final_qa) {
                if basis != NeedsReview && qa.is_none() {
                    return Err("native quality policy requires a final QA assessment".into());
                }
                if let Some(qa) = qa {
                    if qa.decision != NeedsReview && qa.decision != basis {
                        return Err("final QA cannot change a verdict except to reopen it".into());
                    }
                }
            } else if qa.is_some() {
                return Err("final QA is not enabled by the native policy".into());
            }
            Ok(())
        };
        check_qa(case.quality_review.as_ref(), basis)?;
        let mut final_qa = case.quality_review.as_ref();
        if let Some(revalidation) = &case.revalidation {
            let new_proposal = adjudicated
                && prior_basis == NeedsReview
                && case.assessments[2].decision != NeedsReview;
            let reopened = prior_basis != NeedsReview
                && case
                    .quality_review
                    .as_ref()
                    .is_some_and(|qa| qa.decision == NeedsReview);
            if case.blocker.is_some()
                || !quality.is_some_and(|q| q.adjudicate_disagreements)
                || !match revalidation.reason.as_str() {
                    "new_source_verdict" => new_proposal,
                    "quality_reopening" => reopened,
                    _ => false,
                }
            {
                return Err(
                    "revalidation requires an available new proposal or QA reopening".into(),
                );
            }
            basis = if revalidation.assessments[0].decision == revalidation.assessments[1].decision
                && revalidation.assessments[0].decision
                    == if new_proposal {
                        case.assessments[2].decision
                    } else {
                        prior_basis
                    } {
                revalidation.assessments[0].decision
            } else {
                NeedsReview
            };
            check_qa(revalidation.quality_review.as_ref(), basis)?;
            final_qa = revalidation.quality_review.as_ref();
        }
        if final_decision == Issue && (case.assessments.len() < 2 || basis != Issue) {
            return Err(
                "reported issue requires two independent bound assessments and resolved evidence"
                    .into(),
            );
        }
        if final_decision != NeedsReview && final_decision != basis {
            return Err("conflicting assessments require explicit pending adjudication".into());
        }
        let sample = Sha256::digest(format!("{}:{}", policy.audit_seed, case.review_id).as_bytes());
        let sampled =
            u32::from_be_bytes(sample[..4].try_into().unwrap()) % 100 < policy.audit_percent as u32;
        if final_decision == NotIssue && sampled && case.assessments.len() < 2 {
            return Err("sampled closure requires an independent assessment".into());
        }
        if let Some(qa) = final_qa {
            if final_decision != NeedsReview && qa.decision != final_decision {
                return Err("final QA reopening must remain pending".into());
            }
        }
    }
    Ok(())
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
        "Local assignments:\n  mehscan state allocate --store DIR --stream KEY --inventory DIR --source-root ROOT --generation N --owner TOKEN --work-package FILE --worker LABEL --operation-key ID\n  mehscan state release --store DIR --stream KEY --repository-key KEY --generation N --owner TOKEN --assignment ID --operation-key KEY\n  Submit assigned work with state record --assignment ID and the original --work-package."
    );
    println!(
        "Pending facts and handoff:\n  mehscan state pending|pending-batch|fact --store DIR --stream KEY --inventory DIR --source-root ROOT --generation N --owner TOKEN --input FILE --operation-key ID\n  mehscan state work --store DIR --stream KEY --inventory DIR --source-root ROOT --generation N --owner TOKEN [--review-ids ID,ID] [--resume-only true|false]\nPending questions attach to exact current needs_review checks or a current change-pass question. Source-bound evidence updates request revalidation; they never change verdicts. Work exports a provider-neutral package without ownership credentials. Pass --work-package FILE to plan/record to reject changed parents, facts, plans or generations. Record accepts --reviewer LABEL as unauthenticated provenance. External/deployment fact authority remains unsupported.\n"
    );
    println!(
        "USAGE:\n  mehscan state claim --store DIR --stream KEY --inventory DIR --source-root ROOT --attempt-id ID --expected-generation N --operation-key ID [--retry true|false]\n  mehscan state record --store DIR --stream KEY --inventory DIR --source-root ROOT --run DIR --generation N --owner TOKEN --operation-key ID [--supersessions FILE] [--allow-partial true|false]\n  mehscan state end --store DIR --stream KEY --generation N --owner TOKEN --status finished|cancelled|incomplete --operation-key ID (--repository-key KEY | --inventory DIR --source-root ROOT)\n  mehscan state status|history --store DIR --stream KEY (--repository-key KEY | --inventory DIR)\n\nLocal trusted-worker state, not an authorization or merge gate. Store outside source. Claim uses compare-and-swap generation; duplicate snapshots coalesce without granting ownership. Retry receipts retain original generation and may be stale. Record validates current inventory, native bundle evidence and all three verdicts. Supersessions is an array of {{decision_id, parents, reason}}; exact unresolved parents and same subject/context are required. History never clears newly discovered or missing work. Finished is execution state, not complete security coverage. Hash-chained durable journal rejects corrupt/torn data instead of guessing recovery. Hosted generation coordination, authenticated provenance and cross-revision verdict reuse remain unsupported."
    );
    println!(
        "\nOptional claim: --coordination-key KEY binds a trusted coordinator's opaque lifecycle/tool contract into the snapshot. It does not authenticate that assertion."
    );
    println!(
        "\nEnd with --inventory DIR --source-root ROOT to retain finished or incomplete work in local review memory. Use --memory-store FILE to override its location, or --memory-mode temporary to skip retention. If memory.status=pending, retry with the same operation key after correcting its reason."
    );
    println!(
        "\nA prepared project.json can supply shared paths and stream to state commands with --project-run FILE.\nCompletion accounting:\n  mehscan state runtime-template --skill-root DIR [--policy value|comprehensive] [--research-rounds N --research-queries N --research-bytes N --timeout SECONDS]\n  mehscan state plan-template --inventory DIR --source-root ROOT [--policy value|comprehensive] [--selection all|policy] [--skill-root DIR --provider-contract FILE]\n  mehscan state plan --store DIR --stream KEY --inventory DIR --source-root ROOT --generation N --owner TOKEN --input FILE --operation-key ID [--expected-plan-id ID]\nRuntime-bound plan, work and record require --skill-root DIR and verify actual trusted package bytes outside source. Provider-bound runtime/plan templates accept --provider-contract FILE; bound plan/work/record require the same descriptor. Templates default to all native IDs; --selection policy applies initial Value priority hints as explicit unreviewed deferrals, while Comprehensive selects all. Changed paths remain unassessed. Value may defer IDs with explicit reasons; Comprehensive must select every admitted ID. Every changed path requires an entry, including deletions and unsupported paths. Assessed modifications/deletions/renames require pinned base evidence; primary current evidence is required for existing files. Native response completion, pending effects, coverage limits and execution status remain distinct. Plan updates require the exact current parent. Evidence is materialized from authorized source, not caller-supplied text."
    );
    println!(
        "\nTiered local review: runtime-template and plan-template accept --review-orchestration FILE with a bound expert provider, shared case/run limits and seeded closure audits. Tiered state record also requires --review-execution FILE and its assessments/ artifacts; native admission validates their source, provider policy and issue verification coverage."
    );
}
