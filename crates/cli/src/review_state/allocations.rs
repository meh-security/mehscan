use std::collections::BTreeSet;

use mehscan_core::{ReviewAttemptStatus, ReviewDecisionRecord, ReviewWorkPackage};
use serde::Serialize;
use serde_json::{Value, json};

use super::{Attempt, Stream, premise_revisions, settled, validate_work_package};

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Active,
    Completed,
    Released,
}

#[derive(Clone, Serialize)]
pub(super) struct Assignment {
    generation: u64,
    package: String,
    worker: String,
    review_ids: Vec<String>,
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    reserved_model_calls: Option<usize>,
}

impl Assignment {
    pub(super) fn is_active(&self, generation: u64) -> bool {
        self.generation == generation && self.status == Status::Active
    }
}

impl Stream {
    pub(super) fn assigned_reviews(
        &self,
        generation: u64,
        id: &str,
        requested: Option<&[String]>,
        read_completed: bool,
    ) -> Result<&[String], String> {
        let assignment = self
            .assignments
            .get(id)
            .filter(|item| {
                item.generation == generation
                    && (item.status == Status::Active
                        || read_completed && item.status == Status::Completed)
            })
            .ok_or("assignment is unavailable for the active generation")?;
        if let Some(requested) = requested {
            let mut requested = requested.to_vec();
            requested.sort();
            if requested != assignment.review_ids {
                return Err("requested reviews differ from the assignment".into());
            }
        }
        Ok(&assignment.review_ids)
    }

    pub(super) fn reserved_reviews(&self, generation: u64) -> BTreeSet<&str> {
        self.assignments
            .values()
            .filter(|assignment| assignment.is_active(generation))
            .flat_map(|assignment| assignment.review_ids.iter().map(String::as_str))
            .collect()
    }

    pub(super) fn available_reviews(
        &self,
        attempt: &Attempt,
        requested: Option<&[String]>,
    ) -> Result<Option<Vec<String>>, String> {
        let reserved = self.reserved_reviews(attempt.generation);
        if let Some(requested) = requested {
            if requested.iter().any(|id| reserved.contains(id.as_str())) {
                return Err("requested review already belongs to an active assignment".into());
            }
            return Ok(Some(requested.to_vec()));
        }
        if reserved.is_empty() {
            return Ok(None);
        }
        let plan = self
            .completion_plans
            .get(&attempt.generation)
            .and_then(|plans| plans.last())
            .ok_or("work handoff requires a current completion plan")?;
        Ok(Some(
            plan.plan
                .selected_review_ids
                .iter()
                .filter(|id| !reserved.contains(id.as_str()))
                .cloned()
                .collect(),
        ))
    }

    pub(super) fn allocate(
        &mut self,
        id: &str,
        worker: &str,
        package: &ReviewWorkPackage,
        reserve_calls: Option<usize>,
    ) -> Result<Value, String> {
        let attempt = self.attempts.last().unwrap();
        validate_work_package(self, attempt, package, &[])?;
        if self.assignments.contains_key(id) || package.payload.review_ids.is_empty() {
            return Err("assignment requires a fresh ID and at least one review".into());
        }
        self.available_reviews(attempt, Some(&package.payload.review_ids))?;
        if package
            .payload
            .expected_parents
            .iter()
            .any(|(review_id, parents)| {
                matches!(parents.as_slice(), [parent]
                if attempt.admissions.contains(parent) && settled(&self.decisions[parent])
                    && self.knowledge_revisions(attempt.generation, parent)
                        == premise_revisions(&package.payload.knowledge, review_id))
            })
        {
            return Err(
                "assignment includes a settled review already admitted to this generation".into(),
            );
        }
        let assignment = Assignment {
            generation: attempt.generation,
            package: package.package_id.clone(),
            worker: worker.into(),
            review_ids: package.payload.review_ids.clone(),
            status: Status::Active,
            reserved_model_calls: self.reserve_model_calls(package, reserve_calls)?,
        };
        let result = json!({"status":"allocated","assignment_id":id,"assignment":assignment});
        self.assignments.insert(id.into(), assignment);
        Ok(result)
    }

    fn reserve_model_calls(
        &self,
        package: &ReviewWorkPackage,
        requested: Option<usize>,
    ) -> Result<Option<usize>, String> {
        let policy = package
            .payload
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.orchestration.as_ref());
        let Some(policy) = policy else {
            return if requested.is_some() {
                Err("--reserve-calls requires a tiered plan with a shared call limit".into())
            } else {
                Ok(None)
            };
        };
        let consumed = self
            .assignments
            .values()
            .filter(|item| item.generation == package.payload.generation)
            .filter_map(|item| item.reserved_model_calls)
            .fold(0usize, usize::saturating_add);
        let remaining = policy.run_limits.model_calls.saturating_sub(consumed);
        let case_capacity = policy
            .case_limits
            .model_calls
            .saturating_mul(package.payload.review_ids.len());
        let calls = requested.unwrap_or(case_capacity.min(policy.run_limits.model_calls));
        if calls == 0 || calls > remaining || calls > case_capacity {
            return Err(format!(
                "worker call reservation exceeds the available allowance ({remaining} remaining)"
            ));
        }
        Ok(Some(calls))
    }

    pub(super) fn validate_allocation(
        &self,
        generation: u64,
        id: Option<&str>,
        package: Option<&ReviewWorkPackage>,
        records: &[ReviewDecisionRecord],
    ) -> Result<(), String> {
        let assigned = self.reserved_reviews(generation);
        let submitted = records
            .iter()
            .map(|record| record.response.review_id.as_str())
            .collect::<BTreeSet<_>>();
        if let Some(id) = id {
            let assignment = self
                .assignments
                .get(id)
                .filter(|assignment| assignment.is_active(generation))
                .ok_or("assignment is unavailable for the active generation")?;
            if package.is_none_or(|package| package.package_id != assignment.package)
                || !submitted
                    .iter()
                    .copied()
                    .eq(assignment.review_ids.iter().map(String::as_str))
                || records.len() != submitted.len()
            {
                return Err(
                    "assigned response must complete exactly its assigned work package".into(),
                );
            }
        } else if !assigned.is_disjoint(&submitted) {
            return Err("responses for assigned reviews require their assignment ID".into());
        }
        Ok(())
    }

    pub(super) fn finish_allocation(&mut self, id: &str) -> Value {
        let assignment = self.assignments.get_mut(id).expect("validated assignment");
        assignment.status = Status::Completed;
        json!({"assignment_id":id,"worker":assignment.worker})
    }

    pub(super) fn release(&mut self, generation: u64, id: &str) -> Result<Value, String> {
        let assignment = self
            .assignments
            .get_mut(id)
            .filter(|assignment| assignment.is_active(generation))
            .ok_or("assignment is unavailable for the active generation")?;
        assignment.status = Status::Released;
        Ok(json!({"status":"released","assignment_id":id,"generation":generation}))
    }

    pub(super) fn assignment_view(&self, current: &Attempt, history: bool) -> Value {
        json!(
            self.assignments
                .iter()
                .filter(|(_, item)| history || item.generation == current.generation)
                .map(|(id, item)| {
                    let mut value = json!(item);
                    value["assignment_id"] = json!(id);
                    if item.status == Status::Active
                        && (item.generation != current.generation
                            || current.status != ReviewAttemptStatus::Running)
                    {
                        value["status"] = json!("expired");
                    }
                    value
                })
                .collect::<Vec<_>>()
        )
    }
}
