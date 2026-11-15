use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture {
    base: PathBuf,
    source: PathBuf,
    inventory: PathBuf,
    run: PathBuf,
    store: PathBuf,
}

fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args(args)
        .output()
        .unwrap()
}
fn ok(args: &[&str]) -> Value {
    let output = invoke(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn reject(args: &[&str], message: &str) {
    let output = invoke(args);
    assert!(!output.status.success(), "unexpected success for {args:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(message),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn read(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn turso_retains_native_pending_decisions_only_for_exact_current_inputs() {
    let mut fixture = Fixture::new("memory-admission");
    let db = fixture.base.join("memory.turso");
    let memory = |fixture: &Fixture, operation, generation| {
        let mut args = vec![
            "memory",
            operation,
            "--store",
            db.to_str().unwrap(),
            "--source-root",
            fixture.source.to_str().unwrap(),
            "--inventory",
            fixture.inventory.to_str().unwrap(),
            "--stream",
            "pr:24",
        ];
        if operation == "retain" {
            args.extend([
                "--state-store",
                fixture.store.to_str().unwrap(),
                "--generation",
                generation,
            ]);
        }
        invoke(&args)
    };
    let check = |output: Output| {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };

    let empty = check(memory(&fixture, "assessments", ""));
    assert_eq!(empty["batches"], json!([]));
    assert!(!db.exists());
    let claim = fixture.claim("before", "0", "memory-claim", false);
    let owner = claim["result"]["owner"].as_str().unwrap();
    let decisions = fixture.answers("needs_review", "The exact caller still needs confirmation.");
    ok(&fixture.record_args("1", owner, "memory-record"));
    let premature = memory(&fixture, "retain", "1");
    assert!(!premature.status.success());
    assert!(String::from_utf8_lossy(&premature.stderr).contains("finished or incomplete"));
    assert!(!db.exists());
    ok(&[
        "state",
        "end",
        "--store",
        fixture.store.to_str().unwrap(),
        "--stream",
        "pr:24",
        "--repository-key",
        "repo:123",
        "--generation",
        "1",
        "--owner",
        owner,
        "--status",
        "incomplete",
        "--operation-key",
        "memory-end",
    ]);
    let retained = check(memory(&fixture, "retain", "1"));
    assert_eq!(retained["assessments"], decisions.len());
    let repeated = check(memory(&fixture, "retain", "1"));
    assert_eq!(repeated["batch"], retained["batch"]);
    assert_eq!(repeated["reused"], true);
    let saved = check(memory(&fixture, "assessments", ""));
    assert_eq!(saved["authority"], "retained_context");
    assert_eq!(saved["batches"].as_array().unwrap().len(), 1);
    let batch = &saved["batches"][0];
    assert_eq!(batch["attempt_status"], "incomplete");
    for decision in decisions {
        let row = batch["assessments"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["decision_id"] == decision["decision_id"])
            .unwrap();
        assert_eq!(row["verdict"], "needs_review");
        assert_eq!(
            row["response_fingerprint"],
            decision["response_fingerprint"]
        );
        assert_eq!(
            row["questions"][0]["text"],
            decision["response"]["checks"][0]
        );
        assert_eq!(row["evidence"][0]["path"], "app.js");
    }
    let wrong_generation = memory(&fixture, "retain", "2");
    assert!(!wrong_generation.status.success());
    assert!(String::from_utf8_lossy(&wrong_generation.stderr).contains("current state generation"));

    let retry = fixture.claim("recheck", "1", "memory-claim-recheck", true);
    let retry_owner = retry["result"]["owner"].as_str().unwrap();
    fixture.answers("not_issue", "Conflicting verdict without supersession.");
    ok(&fixture.record_args("2", retry_owner, "memory-record-conflict"));
    ok(&[
        "state",
        "end",
        "--store",
        fixture.store.to_str().unwrap(),
        "--stream",
        "pr:24",
        "--repository-key",
        "repo:123",
        "--generation",
        "2",
        "--owner",
        retry_owner,
        "--status",
        "incomplete",
        "--operation-key",
        "memory-end-conflict",
    ]);
    assert_eq!(check(memory(&fixture, "retain", "2"))["assessments"], 0);
    let latest = check(memory(&fixture, "assessments", ""));
    assert_eq!(latest["batches"].as_array().unwrap().len(), 1);
    assert_eq!(latest["batches"][0]["generation"], 2);
    assert_eq!(latest["batches"][0]["assessments"], json!([]));

    let path = fixture.source.join("app.js");
    let original = fs::read_to_string(&path).unwrap();
    fs::write(path, original + "\n// Change the source snapshot.\n").unwrap();
    assert!(!memory(&fixture, "assessments", "").status.success());
    fixture.prepare("changed-memory");
    assert_eq!(
        check(memory(&fixture, "assessments", ""))["batches"],
        json!([])
    );
    assert!(
        fixture
            .base
            .canonicalize()
            .unwrap()
            .starts_with(std::env::temp_dir().canonicalize().unwrap())
    );
    fs::remove_dir_all(&fixture.base).unwrap();
}

#[test]
fn exact_turso_reuse_readmits_settled_native_decisions_under_matching_work() {
    let fixture = Fixture::new("memory-replay");
    let skill = fixture.base.join("skill");
    fs::create_dir(&skill).unwrap();
    fs::write(skill.join("SKILL.md"), "Trusted local review policy.").unwrap();
    let skill = skill.to_str().unwrap();
    let mut plan = fixture.plan_template("value");
    plan["runtime"] = ok(&["state", "runtime-template", "--skill-root", skill]);
    let plan_file = fixture.base.join("plan.json");
    let work_file = fixture.base.join("work.json");
    let work = work_file.to_str().unwrap();
    let end = |generation: &str, owner: &str, status: &str, key: &str| {
        ok(&[
            "state",
            "end",
            "--store",
            fixture.store.to_str().unwrap(),
            "--stream",
            "pr:24",
            "--repository-key",
            "repo:123",
            "--generation",
            generation,
            "--owner",
            owner,
            "--status",
            status,
            "--operation-key",
            key,
        ]);
    };
    let prepare = |generation: &str, owner: &str, draft: &Value, key: &str| {
        fs::write(&plan_file, draft.to_string()).unwrap();
        let mut plan_args = fixture.plan_args(owner, &plan_file, key);
        let index = plan_args
            .iter()
            .position(|value| *value == "--generation")
            .unwrap();
        plan_args[index + 1] = generation;
        plan_args.extend(["--skill-root", skill]);
        ok(&plan_args);
        let mut work_args = fixture.work_args(owner, false);
        let index = work_args
            .iter()
            .position(|value| *value == "--generation")
            .unwrap();
        work_args[index + 1] = generation;
        work_args.extend(["--skill-root", skill]);
        let package = ok(&work_args);
        fs::write(&work_file, package.to_string()).unwrap();
        package
    };

    let first = fixture.claim("initial", "0", "reuse-claim-1", false);
    let owner = first["result"]["owner"].as_str().unwrap();
    prepare("1", owner, &plan, "reuse-plan-1");
    let decisions = fixture.answers("not_issue", "Synthetic source assessment.");
    assert!(!decisions.is_empty());
    let mut record = fixture.record_args("1", owner, "original-record");
    record.extend(["--skill-root", skill, "--work-package", work]);
    ok(&record);
    end("1", owner, "finished", "reuse-end-1");
    let db = fixture.base.join("review-memory.turso");
    let common = [
        "--store",
        db.to_str().unwrap(),
        "--state-store",
        fixture.store.to_str().unwrap(),
        "--stream",
        "pr:24",
        "--inventory",
        fixture.inventory.to_str().unwrap(),
        "--source-root",
        fixture.source.to_str().unwrap(),
    ];
    let mut retain = vec!["memory", "retain", "--generation", "1"];
    retain.extend(common);
    let saved = ok(&retain);
    assert_eq!(saved["assessments"], decisions.len());
    let batch = saved["batch"].as_str().unwrap();
    let reuse = |owner, operation| {
        let mut args = vec![
            "memory",
            "reuse",
            "--batch",
            batch,
            "--owner",
            owner,
            "--work-package",
            work,
            "--skill-root",
            skill,
            "--operation-key",
            operation,
        ];
        args.extend(common);
        args
    };

    let second = fixture.claim("different-runtime", "1", "reuse-claim-2", true);
    let owner = second["result"]["owner"].as_str().unwrap();
    let mut different = plan.clone();
    different["runtime"]["limits"]["queries"] = json!(7);
    prepare("2", owner, &different, "reuse-plan-2");
    reject(
        &reuse(owner, "reuse-admission"),
        "same native plan and review runtime",
    );
    assert!(
        !fixture.view(false)["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["state"] == "recorded")
    );
    end("2", owner, "incomplete", "reuse-end-2");

    let third = fixture.claim("matching-runtime", "2", "reuse-claim-3", true);
    let owner = third["result"]["owner"].as_str().unwrap();
    let package = prepare("3", owner, &plan, "reuse-plan-3");
    let args = reuse(owner, "reuse-admission");
    let receipt = ok(&args);
    assert_eq!(receipt["result"]["model_calls"], 0);
    assert_eq!(
        receipt["result"]["reused_review_ids"],
        package["payload"]["review_ids"]
    );
    assert_eq!(receipt["result"]["remaining_review_ids"], json!([]));
    assert_eq!(ok(&args)["replayed"], true);
    let history = fixture.view(true);
    assert_eq!(
        history["decisions"].as_object().unwrap().len(),
        decisions.len()
    );
    assert_eq!(
        history["admission_provenance"]["3"][0]["kind"],
        "exact_memory_reuse"
    );
    assert_eq!(
        history["admission_provenance"]["3"][0]["previous_generation"],
        1
    );
    assert!(
        history["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["state"] == "recorded")
    );

    let pending = fixture.answers("needs_review", "The caller still needs a deciding fact.");
    let links = fixture.supersessions(&pending, &history, "reuse-supersessions.json");
    let mut record = fixture.record_args("3", owner, "reopen-after-reuse");
    record.extend([
        "--skill-root",
        skill,
        "--work-package",
        work,
        "--supersessions",
        links.to_str().unwrap(),
    ]);
    ok(&record);
    end("3", owner, "finished", "reuse-end-3");

    let fourth = fixture.claim("pending-parent", "3", "reuse-claim-4", true);
    let owner = fourth["result"]["owner"].as_str().unwrap();
    let package = prepare("4", owner, &plan, "reuse-plan-4");
    let skipped = ok(&reuse(owner, "reuse-after-supersession"));
    assert_eq!(skipped["result"]["reused_review_ids"], json!([]));
    assert_eq!(
        skipped["result"]["remaining_review_ids"],
        package["payload"]["review_ids"]
    );
    assert!(
        fixture
            .base
            .canonicalize()
            .unwrap()
            .starts_with(std::env::temp_dir().canonicalize().unwrap())
    );
    fs::remove_dir_all(&fixture.base).unwrap();
}

#[test]
fn native_end_retries_memory_retention_at_the_original_terminal_receipt() {
    let fixture = Fixture::new("memory-end");
    let first = fixture.claim("original", "0", "end-memory-claim", false);
    let owner = first["result"]["owner"].as_str().unwrap();
    let decisions = fixture.answers("needs_review", "Keep the original outstanding check.");
    ok(&fixture.record_args("1", owner, "end-memory-record"));
    let db = fixture.base.join("memory.turso");
    // A temporarily invalid backing path fails retention after the native end.
    fs::create_dir(&db).unwrap();
    let end = [
        "state",
        "end",
        "--store",
        fixture.store.to_str().unwrap(),
        "--stream",
        "pr:24",
        "--repository-key",
        "repo:123",
        "--generation",
        "1",
        "--owner",
        owner,
        "--status",
        "finished",
        "--operation-key",
        "end-with-memory",
        "--memory-store",
        db.to_str().unwrap(),
        "--inventory",
        fixture.inventory.to_str().unwrap(),
        "--source-root",
        fixture.source.to_str().unwrap(),
    ];
    let failed = ok(&end);
    assert_eq!(failed["result"]["status"], "finished");
    assert_eq!(failed["memory"]["status"], "pending");
    assert_eq!(fixture.view(false)["attempt_status"], "finished");

    let later = fixture.claim("later", "1", "later-claim", true);
    let later_owner = later["result"]["owner"].as_str().unwrap();
    fixture.answers(
        "not_issue",
        "A separate evaluation has a different outcome.",
    );
    ok(&fixture.record_args("2", later_owner, "later-record"));
    fs::remove_dir(&db).unwrap();

    let source = fixture.source.join("app.js");
    let unchanged = fs::read(&source).unwrap();
    let mut edited = unchanged.clone();
    edited.extend(b"\n// Different checkout contents.\n");
    fs::write(&source, edited).unwrap();
    let stale = ok(&end);
    assert_eq!(stale["memory"]["status"], "pending");
    assert!(
        stale["memory"]["reason"]
            .as_str()
            .unwrap()
            .contains("source files changed")
    );
    assert!(!db.exists());
    fs::write(&source, unchanged).unwrap();

    let retained = ok(&end);
    assert_eq!(retained["sequence"], failed["sequence"]);
    assert_eq!(retained["replayed"], true);
    assert_eq!(retained["memory"]["status"], "retained");
    assert_eq!(retained["memory"]["assessments"], decisions.len());
    assert_eq!(retained["memory"]["reused"], false);
    let repeated = ok(&end);
    assert_eq!(repeated["memory"]["batch"], retained["memory"]["batch"]);
    assert_eq!(repeated["memory"]["reused"], true);

    let lookup = ok(&[
        "memory",
        "assessments",
        "--store",
        db.to_str().unwrap(),
        "--stream",
        "pr:24",
        "--inventory",
        fixture.inventory.to_str().unwrap(),
        "--source-root",
        fixture.source.to_str().unwrap(),
    ]);
    let batch = &lookup["batches"][0];
    assert_eq!(batch["generation"], 1);
    assert!(
        batch["assessments"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["verdict"] == "needs_review")
    );
    let current = fixture.view(false);
    assert_eq!(current["generation"], 2);
    assert_eq!(current["attempt_status"], "running");
    let cancelled = ok(&[
        "state",
        "end",
        "--store",
        fixture.store.to_str().unwrap(),
        "--stream",
        "pr:24",
        "--repository-key",
        "repo:123",
        "--generation",
        "2",
        "--owner",
        later_owner,
        "--status",
        "cancelled",
        "--operation-key",
        "cancel-with-memory",
        "--memory-store",
        fixture.base.join("unused.turso").to_str().unwrap(),
        "--inventory",
        fixture.inventory.to_str().unwrap(),
        "--source-root",
        fixture.base.join("missing-source").to_str().unwrap(),
    ]);
    assert_eq!(cancelled["memory"]["status"], "skipped");
    assert!(!fixture.base.join("unused.turso").exists());
    assert!(
        fixture
            .base
            .canonicalize()
            .unwrap()
            .starts_with(std::env::temp_dir().canonicalize().unwrap())
    );
    fs::remove_dir_all(&fixture.base).unwrap();
}

impl Fixture {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "mehscan-state-{label}-{}-{nonce}",
            std::process::id()
        ));
        let source = base.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(
            source.join("app.js"),
            "function handle(request) { eval(request.query.code); }\n",
        )
        .unwrap();
        let mut fixture = Self {
            inventory: base.join("inventory-1"),
            run: base.join("run-1"),
            store: base.join("state"),
            base,
            source,
        };
        fixture.prepare("1");
        fixture
    }
    fn prepare(&mut self, suffix: &str) {
        self.inventory = self.base.join(format!("inventory-{suffix}"));
        self.run = self.base.join(format!("run-{suffix}"));
        ok(&[
            "investigate",
            "review-inventory",
            self.source.to_str().unwrap(),
            "--repository-key",
            "repo:123",
            "--output",
            self.inventory.to_str().unwrap(),
        ]);
        let inventory = read(&self.inventory.join("inventory.json"));
        let ids = inventory["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["review_id"].as_str().unwrap())
            .collect::<Vec<_>>()
            .join(",");
        assert!(!ids.is_empty());
        ok(&[
            "investigate",
            "review-bundles",
            self.source.to_str().unwrap(),
            "--inventory",
            self.inventory.to_str().unwrap(),
            "--review-ids",
            &ids,
            "--output",
            self.run.to_str().unwrap(),
            "--max-reviews",
            "1",
        ]);
    }
    fn answers(&self, decision: &str, summary: &str) -> Vec<Value> {
        let manifest = read(&self.run.join("manifest.json"));
        for entry in manifest["bundles"].as_array().unwrap() {
            let filename = entry["filename"].as_str().unwrap();
            let request: mehscan_core::PathReviewBundle = serde_json::from_slice(
                &fs::read(self.run.join("requests").join(filename)).unwrap(),
            )
            .unwrap();
            let results = request.review_ids.iter().map(|id| {
                let anchor = mehscan_engine::investigation::bundle_selected_anchor_id(&request, id).unwrap();
                json!({"review_id":id,"selected_anchor_id":anchor,"decision":decision,"confidence":"medium","summary":summary,
                    "checks":if decision == "needs_review" { vec!["Confirm the exact input authority.", "Confirm whether a sanitizer covers this code operand."] } else { Vec::new() },
                    "investigation":{"decisive_artifacts":[],"journal_summary":null,"citations":[{"artifact_id":anchor,"claim":"Selected native operation."}],
                        "reviewer_inferences":[],"reviewer_origin_leads":[],"blockers":[]}})
            }).collect::<Vec<_>>();
            fs::write(self.run.join("responses").join(filename), json!({"schema_version":"1.3","bundle_fingerprint":request.bundle_fingerprint,"results":results}).to_string()).unwrap();
        }
        ok(&[
            "report",
            "--run",
            self.run.to_str().unwrap(),
            "--source-root",
            self.source.to_str().unwrap(),
        ])["decision_records"]
            .as_array()
            .unwrap()
            .clone()
    }
    fn claim(&self, attempt: &str, expected: &str, operation: &str, retry: bool) -> Value {
        ok(&[
            "state",
            "claim",
            "--store",
            self.store.to_str().unwrap(),
            "--stream",
            "pr:24",
            "--inventory",
            self.inventory.to_str().unwrap(),
            "--source-root",
            self.source.to_str().unwrap(),
            "--attempt-id",
            attempt,
            "--expected-generation",
            expected,
            "--operation-key",
            operation,
            "--retry",
            if retry { "true" } else { "false" },
        ])
    }
    fn record_args<'a>(
        &'a self,
        generation: &'a str,
        owner: &'a str,
        operation: &'a str,
    ) -> Vec<&'a str> {
        vec![
            "state",
            "record",
            "--store",
            self.store.to_str().unwrap(),
            "--stream",
            "pr:24",
            "--inventory",
            self.inventory.to_str().unwrap(),
            "--source-root",
            self.source.to_str().unwrap(),
            "--run",
            self.run.to_str().unwrap(),
            "--generation",
            generation,
            "--owner",
            owner,
            "--operation-key",
            operation,
        ]
    }
    fn view(&self, history: bool) -> Value {
        ok(&[
            "state",
            if history { "history" } else { "status" },
            "--store",
            self.store.to_str().unwrap(),
            "--stream",
            "pr:24",
            "--repository-key",
            "repo:123",
        ])
    }
    fn supersessions(&self, incoming: &[Value], view: &Value, name: &str) -> PathBuf {
        let links = incoming.iter().map(|record| {
            let subject = view["subjects"].as_array().unwrap().iter().find(|subject| subject["subject_key"] == record["identity"]["subject_key"]).unwrap();
            let mut parents = subject["current_decision_ids"].as_array().unwrap().clone();
            parents.extend(subject["historical_decision_ids"].as_array().unwrap().iter().cloned());
            json!({"decision_id":record["decision_id"],"parents":parents,"reason":"Synthetic current-source re-evaluation of this exact subject."})
        }).collect::<Vec<_>>();
        let file = self.base.join(name);
        fs::write(&file, serde_json::to_vec(&links).unwrap()).unwrap();
        file
    }
    fn plan_template(&self, policy: &str) -> Value {
        ok(&[
            "state",
            "plan-template",
            "--inventory",
            self.inventory.to_str().unwrap(),
            "--source-root",
            self.source.to_str().unwrap(),
            "--policy",
            policy,
        ])
    }
    fn plan_args<'a>(
        &'a self,
        owner: &'a str,
        input: &'a Path,
        operation: &'a str,
    ) -> Vec<&'a str> {
        vec![
            "state",
            "plan",
            "--store",
            self.store.to_str().unwrap(),
            "--stream",
            "pr:24",
            "--inventory",
            self.inventory.to_str().unwrap(),
            "--source-root",
            self.source.to_str().unwrap(),
            "--generation",
            "1",
            "--owner",
            owner,
            "--input",
            input.to_str().unwrap(),
            "--operation-key",
            operation,
        ]
    }
    fn typed_args<'a>(
        &'a self,
        operation: &'a str,
        owner: &'a str,
        input: &'a Path,
        key: &'a str,
    ) -> Vec<&'a str> {
        vec![
            "state",
            operation,
            "--store",
            self.store.to_str().unwrap(),
            "--stream",
            "pr:24",
            "--inventory",
            self.inventory.to_str().unwrap(),
            "--source-root",
            self.source.to_str().unwrap(),
            "--generation",
            "1",
            "--owner",
            owner,
            "--input",
            input.to_str().unwrap(),
            "--operation-key",
            key,
        ]
    }
    fn work_args<'a>(&'a self, owner: &'a str, resume_only: bool) -> Vec<&'a str> {
        vec![
            "state",
            "work",
            "--store",
            self.store.to_str().unwrap(),
            "--stream",
            "pr:24",
            "--inventory",
            self.inventory.to_str().unwrap(),
            "--source-root",
            self.source.to_str().unwrap(),
            "--generation",
            "1",
            "--owner",
            owner,
            "--resume-only",
            if resume_only { "true" } else { "false" },
        ]
    }
    fn work(&self, owner: &str, resume_only: bool) -> Value {
        ok(&self.work_args(owner, resume_only))
    }
}

#[test]
fn evidence_updates_resume_exact_questions_without_changing_the_native_verdict() {
    let fixture = Fixture::new("pending-resumption");
    let claim = fixture.claim("attempt", "0", "claim", false);
    let owner = claim["result"]["owner"].as_str().unwrap();
    let plan = fixture.base.join("plan.json");
    fs::write(&plan, fixture.plan_template("comprehensive").to_string()).unwrap();
    ok(&fixture.plan_args(owner, &plan, "plan"));
    let records = fixture.answers(
        "needs_review",
        "Synthetic pending review with two independent missing facts.",
    );
    ok(&fixture.record_args("1", owner, "pending-response"));
    let input = fixture.base.join("question.json");
    let mut question_ids = Vec::new();
    for (index, question) in records[0]["response"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        fs::write(&input, json!({"schema_version":"1","origin":{"kind":"decision","decision_id":records[0]["decision_id"]},
            "kind":if index == 0 {"source_authority"} else {"control_coverage"},"question":question}).to_string()).unwrap();
        let key = format!("question-{index}");
        let saved = ok(&fixture.typed_args("pending", owner, &input, &key));
        assert_eq!(
            ok(&fixture.typed_args("pending", owner, &input, &key))["replayed"],
            true
        );
        question_ids.push(saved["result"]["question_id"].clone());
    }
    let batch = fixture.base.join("pending-batch.json");
    let drafts = records[0]["response"]["checks"].as_array().unwrap().iter().enumerate().map(|(index,question)|
        json!({"schema_version":"1","origin":{"kind":"decision","decision_id":records[0]["decision_id"]},
            "kind":if index == 0 {"source_authority"} else {"control_coverage"},"question":question})).collect::<Vec<_>>();
    let journal_before = fs::read(fixture.store.join("transactions.jsonl")).unwrap();
    let mut invalid = drafts.clone();
    invalid[1]["question"] = json!("A question absent from the admitted response.");
    fs::write(&batch, serde_json::to_vec(&invalid).unwrap()).unwrap();
    reject(
        &fixture.typed_args("pending-batch", owner, &batch, "invalid-batch"),
        "explicit check/blocker",
    );
    assert_eq!(
        fs::read(fixture.store.join("transactions.jsonl")).unwrap(),
        journal_before
    );
    fs::write(&batch, serde_json::to_vec(&drafts).unwrap()).unwrap();
    let saved = ok(&fixture.typed_args("pending-batch", owner, &batch, "valid-batch"));
    assert_eq!(
        saved["result"]["question_ids"].as_array().unwrap().len(),
        drafts.len()
    );
    assert_eq!(
        ok(&fixture.typed_args("pending-batch", owner, &batch, "valid-batch"))["replayed"],
        true
    );
    assert!(
        fixture.work(owner, true)["payload"]["review_ids"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let stale_work = fixture.base.join("before-evidence.json");
    fs::write(&stale_work, fixture.work(owner, false).to_string()).unwrap();
    let fact = fixture.base.join("fact.json");
    fs::write(
        &fact,
        json!({"schema_version":"1","question_id":question_ids[0],
        "answer":"The selected operation consumes request.query.code in current source.",
        "evidence":[{"side":"current","path":"app.js","start_line":1,"end_line":1}]})
        .to_string(),
    )
    .unwrap();
    let update = ok(&fixture.typed_args("fact", owner, &fact, "fact"));
    assert_eq!(update["result"]["revalidation_required"], true);
    let view = fixture.view(false);
    assert!(
        view["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .all(|subject| subject["decision"] == "needs_review")
    );
    let questions = view["pending_questions"].as_array().unwrap();
    assert_eq!(
        questions
            .iter()
            .filter(|question| question["state"] == "evidence_available")
            .count(),
        1
    );
    assert_eq!(
        questions
            .iter()
            .filter(|question| question["state"] == "awaiting_evidence")
            .count(),
        1
    );
    let mut args = fixture.record_args("1", owner, "stale-package");
    args.extend(["--work-package", stale_work.to_str().unwrap()]);
    reject(&args, "plan/parents/facts/generation changed");
    let fresh_work = fixture.work(owner, true);
    assert_eq!(
        fresh_work["payload"]["review_ids"],
        json!([records[0]["response"]["review_id"]])
    );
    assert_eq!(
        fresh_work["payload"]["pending_questions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(!fresh_work.to_string().contains("\"owner\""));
    assert_eq!(
        fresh_work["payload"]["evidence_updates"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let package = fixture.base.join("resume-work.json");
    fs::write(&package, fresh_work.to_string()).unwrap();
    // An accepted unchanged pending response records the evidence admission;
    // the same unavailable question does not repeatedly reschedule itself.
    let mut args = fixture.record_args("1", owner, "still-pending-after-review");
    args.extend(["--work-package", package.to_str().unwrap()]);
    ok(&args);
    assert!(
        fixture.work(owner, true)["payload"]["review_ids"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let after = fixture.view(false);
    assert!(
        after["pending_questions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|question| question["state"] == "pending_after_revalidation"
                && question["revalidation_required"] == false)
    );
    let issue = fixture.answers(
        "issue",
        "Synthetic fresh adjudication of the supplied exact subject facts.",
    );
    assert_eq!(issue.len(), 1);
    let links = fixture.supersessions(&issue, &fixture.view(false), "parents.json");
    let mut args = fixture.record_args("1", owner, "adjudicate");
    args.extend([
        "--work-package",
        package.to_str().unwrap(),
        "--supersessions",
        links.to_str().unwrap(),
        "--reviewer",
        "synthetic/medium",
    ]);
    ok(&args);
    let history = fixture.view(true);
    assert!(history["pending_questions"].as_array().unwrap().is_empty());
    assert_eq!(history["pending_history"].as_object().unwrap().len(), 2);
    assert_eq!(history["fact_history"].as_object().unwrap().len(), 1);
    assert_eq!(
        history["decisions"][records[0]["decision_id"].as_str().unwrap()],
        records[0]
    );
    reject(
        &fixture.typed_args("fact", owner, &fact, "late-fact"),
        "superseded or foreign",
    );
}

#[test]
fn work_packages_reject_tampering_changed_plans_and_outside_selection() {
    let fixture = Fixture::new("work-packets");
    let claim = fixture.claim("attempt", "0", "claim", false);
    let owner = claim["result"]["owner"].as_str().unwrap();
    let plan = fixture.base.join("plan.json");
    let draft = fixture.plan_template("comprehensive");
    fs::write(&plan, draft.to_string()).unwrap();
    let saved = ok(&fixture.plan_args(owner, &plan, "plan"));
    let original = fixture.work(owner, false);
    let mut changed = original.clone();
    changed["payload"]["generation"] = json!(999);
    let packet = fixture.base.join("work.json");
    fs::write(&packet, changed.to_string()).unwrap();
    fixture.answers("not_issue", "Synthetic exact operation safe decision.");
    let mut args = fixture.record_args("1", owner, "tampered");
    args.extend(["--work-package", packet.to_str().unwrap()]);
    reject(&args, "integrity check failed");
    fs::write(&packet, original.to_string()).unwrap();
    let mut args = fixture.plan_args(owner, &plan, "new-plan");
    args.extend([
        "--expected-plan-id",
        saved["result"]["plan_id"].as_str().unwrap(),
    ]);
    ok(&args);
    let mut args = fixture.record_args("1", owner, "old-plan");
    args.extend(["--work-package", packet.to_str().unwrap()]);
    reject(&args, "plan/parents/facts/generation changed");
}

#[test]
fn completion_partition_and_exact_parent_updates_do_not_infer_safety() {
    let fixture = Fixture::new("completion-partition");
    let claim = fixture.claim("attempt", "0", "claim", false);
    let owner = claim["result"]["owner"].as_str().unwrap();
    assert_eq!(fixture.view(false)["completion"]["status"], "not_planned");
    let mut draft = fixture.plan_template("comprehensive");
    let input = fixture.base.join("plan.json");
    let ids = draft["selected_review_ids"].as_array().unwrap().clone();
    let id = ids[0].as_str().unwrap();
    draft["selected_review_ids"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    fs::write(&input, draft.to_string()).unwrap();
    reject(
        &fixture.plan_args(owner, &input, "plan"),
        "partition every native ID",
    );
    draft["deferred_review_ids"][id] = json!("Explicit Value deferral.");
    fs::write(&input, draft.to_string()).unwrap();
    reject(
        &fixture.plan_args(owner, &input, "plan"),
        "Comprehensive cannot defer",
    );
    draft["policy"] = json!("value");
    fs::write(&input, draft.to_string()).unwrap();
    let saved = ok(&fixture.plan_args(owner, &input, "plan"));
    assert_eq!(
        ok(&fixture.plan_args(owner, &input, "plan"))["replayed"],
        true
    );
    assert_eq!(
        fixture.view(false)["completion"]["selected_review_count"],
        ids.len() - 1
    );
    fixture.answers("needs_review", "Synthetic exact pending answer.");
    ok(&fixture.record_args("1", owner, "pending"));
    let status = fixture.view(false);
    assert_eq!(status["completion"]["review_work_complete"], true);
    assert_eq!(status["completion"]["status"], "complete_with_limits");
    assert_eq!(
        status["completion"]["security_resolution"],
        "not_established"
    );
    draft["selected_review_ids"] = json!(ids);
    draft["deferred_review_ids"] = json!({});
    draft["policy"] = json!("comprehensive");
    fs::write(&input, draft.to_string()).unwrap();
    reject(
        &fixture.plan_args(owner, &input, "revision"),
        "expected current parent",
    );
    let mut args = fixture.plan_args(owner, &input, "revision");
    args.extend([
        "--expected-plan-id",
        saved["result"]["plan_id"].as_str().unwrap(),
    ]);
    ok(&args);
    assert_eq!(
        fixture.view(true)["completion_plans"]["1"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn changed_completion_accounts_for_zero_candidates_old_source_and_coverage_gaps() {
    let mut fixture = Fixture::new("changed-completion");
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .arg("-C")
            .arg(&fixture.source)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    git(&["init", "--quiet"]);
    git(&["config", "user.name", "Mehscan fixture"]);
    git(&["config", "user.email", "fixture@example.invalid"]);
    fs::write(
        fixture.source.join("guard.js"),
        "function allowed(user) { return user.admin; }\n",
    )
    .unwrap();
    fs::write(fixture.source.join("empty.js"), "").unwrap();
    git(&["add", "."]);
    git(&["commit", "--quiet", "-m", "base"]);
    let base = git(&["rev-parse", "HEAD"]);
    fs::remove_file(fixture.source.join("guard.js")).unwrap();
    fs::remove_file(fixture.source.join("empty.js")).unwrap();
    fs::write(
        fixture.source.join("unknown.xyz"),
        "changed unsupported contract\n",
    )
    .unwrap();
    fixture.inventory = fixture.base.join("changed-inventory");
    ok(&[
        "investigate",
        "review-inventory",
        fixture.source.to_str().unwrap(),
        "--changed-from",
        &base,
        "--diff-mode",
        "files",
        "--repository-key",
        "repo:123",
        "--output",
        fixture.inventory.to_str().unwrap(),
    ]);
    let claim = fixture.claim("attempt", "0", "claim", false);
    let owner = claim["result"]["owner"].as_str().unwrap();
    let mut draft = fixture.plan_template("comprehensive");
    assert!(draft["selected_review_ids"].as_array().unwrap().is_empty());
    let input = fixture.base.join("change-plan.json");
    let original = draft.clone();
    draft["change_pass"].as_array_mut().unwrap().pop();
    fs::write(&input, draft.to_string()).unwrap();
    reject(
        &fixture.plan_args(owner, &input, "plan"),
        "every changed path",
    );
    draft = original;
    for entry in draft["change_pass"].as_array_mut().unwrap() {
        if entry["path"] == "guard.js" {
            entry["status"] = json!("needs_review");
            entry["summary"] =
                json!("Removed the old authorization helper; unchanged callers need review.");
            entry["questions"] =
                json!(["Does an unchanged caller still enforce the admin boundary?"]);
            entry["evidence"] =
                json!([{ "side":"base", "path":"guard.js", "start_line":1, "end_line":1 }]);
        } else if entry["path"] == "empty.js" {
            entry["status"] = json!("reviewed");
            entry["summary"] = json!("Inspected the pinned empty file removed by this change.");
            entry["evidence"] =
                json!([{ "side":"base", "path":"empty.js", "start_line":1, "end_line":1 }]);
        } else {
            entry["status"] = json!("coverage_gap");
            entry["summary"] = json!("Native analyzer does not cover this contract.");
        }
    }
    fs::write(&input, draft.to_string()).unwrap();
    let saved = ok(&fixture.plan_args(owner, &input, "plan"));
    let history = fixture.view(true);
    assert_eq!(history["completion"]["accounting_complete"], true);
    assert_eq!(history["completion"]["review_work_complete"], false);
    assert_eq!(
        history["completion"]["pending_changed_effects"][0]["path"],
        "guard.js"
    );
    assert!(
        !history["completion"]["native_coverage_limits"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let plans = history["completion_plans"]["1"].as_array().unwrap();
    let guard = plans[0]["plan"]["change_pass"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["path"] == "guard.js")
        .unwrap();
    assert!(
        guard["evidence"][0]["text"]
            .as_str()
            .unwrap()
            .contains("user.admin")
    );
    assert_eq!(guard["evidence"][0]["revision"], base);
    let mut bad = draft.clone();
    for entry in bad["change_pass"].as_array_mut().unwrap() {
        if entry["path"] == "guard.js" {
            entry["evidence"][0]["path"] = json!("../outside.js");
        }
    }
    fs::write(&input, bad.to_string()).unwrap();
    let mut args = fixture.plan_args(owner, &input, "bad-revision");
    args.extend([
        "--expected-plan-id",
        saved["result"]["plan_id"].as_str().unwrap(),
    ]);
    reject(&args, "inside the authorized root");
    assert_eq!(
        fixture.view(false)["completion"]["plan_id"],
        saved["result"]["plan_id"]
    );
}

#[test]
fn ownership_compare_and_swap_retries_and_terminal_attempts_survive_processes() {
    let fixture = Fixture::new("ownership");
    let first = fixture.claim("attempt-a", "0", "claim-a", false);
    let owner = first["result"]["owner"].as_str().unwrap();
    assert_eq!(first["currently_owned"], true);
    assert_eq!(
        fixture.claim("attempt-a", "0", "claim-a", false)["replayed"],
        true
    );
    let duplicate = fixture.claim("delivery-b", "1", "delivery-b", false);
    assert_eq!(duplicate["result"]["status"], "coalesced");
    assert!(duplicate["result"]["owner"].is_null());
    assert_eq!(duplicate["currently_owned"], false);
    fixture.answers("issue", "Synthetic current operation decision.");
    let retry = fixture.claim("attempt-c", "1", "claim-c", true);
    assert_eq!(retry["result"]["generation"], 2);
    assert_eq!(
        fixture.claim("attempt-a", "0", "claim-a", false)["currently_owned"],
        false
    );
    reject(
        &fixture.record_args("1", owner, "stale-record"),
        "stale generation",
    );
    let owner = retry["result"]["owner"].as_str().unwrap();
    ok(&fixture.record_args("2", owner, "record-c"));
    let ended = ok(&[
        "state",
        "end",
        "--store",
        fixture.store.to_str().unwrap(),
        "--stream",
        "pr:24",
        "--repository-key",
        "repo:123",
        "--generation",
        "2",
        "--owner",
        owner,
        "--status",
        "finished",
        "--operation-key",
        "end-c",
    ]);
    assert_eq!(ended["currently_owned"], false);
    reject(
        &fixture.record_args("2", owner, "after-end"),
        "terminal attempt",
    );
    assert_eq!(fixture.view(true)["attempts"].as_array().unwrap().len(), 2);
    assert_eq!(fixture.view(false)["alert_disposition"], "not_established");
}

#[test]
fn all_verdicts_conflict_until_exact_validated_supersession_preserves_old_proof() {
    let fixture = Fixture::new("lineage");
    let claimed = fixture.claim("attempt-1", "0", "claim-1", false);
    let owner = claimed["result"]["owner"].as_str().unwrap();
    let issues = fixture.answers(
        "issue",
        "Synthetic issue for the selected native operation.",
    );
    let first = ok(&fixture.record_args("1", owner, "issues"));
    assert_eq!(
        ok(&fixture.record_args("1", owner, "issues"))["replayed"],
        true
    );
    assert_eq!(
        first["result"]["decision_ids"].as_array().unwrap().len(),
        issues.len()
    );
    let negatives = fixture.answers(
        "not_issue",
        "Synthetic negative on the exact same selected native operation.",
    );
    ok(&fixture.record_args("1", owner, "negatives"));
    let conflict = fixture.view(false);
    assert!(
        conflict["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .all(|subject| subject["state"] == "conflict")
    );
    let pending = fixture.answers(
        "needs_review",
        "Synthetic adjudication needs input-authority facts.",
    );
    let links = fixture.supersessions(&pending, &conflict, "parents.json");
    let mut incomplete = read(&links);
    incomplete[0]["parents"].as_array_mut().unwrap().pop();
    let bad = fixture.base.join("bad-parents.json");
    fs::write(&bad, incomplete.to_string()).unwrap();
    let length = fs::metadata(fixture.store.join("transactions.jsonl"))
        .unwrap()
        .len();
    let mut args = fixture.record_args("1", owner, "adjudicate");
    args.extend(["--supersessions", bad.to_str().unwrap()]);
    reject(&args, "parents changed");
    assert_eq!(
        fs::metadata(fixture.store.join("transactions.jsonl"))
            .unwrap()
            .len(),
        length
    );
    let mut args = fixture.record_args("1", owner, "adjudicate");
    args.extend(["--supersessions", links.to_str().unwrap()]);
    ok(&args);
    let history = fixture.view(true);
    assert!(
        history["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .all(|subject| subject["state"] == "recorded" && subject["decision"] == "needs_review")
    );
    let saved = history["decisions"].as_object().unwrap();
    for original in issues.iter().chain(&negatives).chain(&pending) {
        assert_eq!(&saved[original["decision_id"].as_str().unwrap()], original);
    }
    assert!(!history["admission_provenance"].is_null());
    // A different operation key must not resurrect a superseded parent.
    assert_eq!(
        fixture.answers(
            "issue",
            "Synthetic issue for the selected native operation."
        ),
        issues
    );
    ok(&fixture.record_args("1", owner, "duplicate-historical-issue"));
    assert_eq!(fixture.view(false)["subjects"], history["subjects"]);
}

#[test]
fn changed_source_does_not_inherit_negative_and_new_subjects_remain_unassessed() {
    let mut fixture = Fixture::new("source-change");
    let claimed = fixture.claim("attempt-1", "0", "claim-1", false);
    let old_owner = claimed["result"]["owner"].as_str().unwrap();
    let old = fixture.answers("not_issue", "Synthetic old source decision.");
    ok(&fixture.record_args("1", old_owner, "old-negative"));
    let old_inventory = fixture.inventory.clone();
    fs::write(
        fixture.source.join("app.js"),
        "// inserted source comment\nfunction handle(request) { eval(request.query.code); }\n",
    )
    .unwrap();
    fixture.prepare("2");
    let fresh = fixture.answers("issue", "Synthetic fresh source re-evaluation.");
    assert_eq!(
        old.iter()
            .map(|record| record["identity"]["subject_key"].as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>(),
        fresh
            .iter()
            .map(|record| record["identity"]["subject_key"].as_str().unwrap())
            .collect()
    );
    let claimed = fixture.claim("attempt-2", "1", "claim-2", false);
    let owner = claimed["result"]["owner"].as_str().unwrap();
    assert!(
        fixture.view(false)["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .all(|subject| subject["state"] == "unassessed" && subject["decision"].is_null())
    );
    reject(
        &[
            "state",
            "claim",
            "--store",
            fixture.store.to_str().unwrap(),
            "--stream",
            "pr:24",
            "--inventory",
            old_inventory.to_str().unwrap(),
            "--source-root",
            fixture.source.to_str().unwrap(),
            "--attempt-id",
            "old-again",
            "--expected-generation",
            "2",
            "--operation-key",
            "old-again",
        ],
        "stale",
    );
    ok(&fixture.record_args("2", owner, "fresh-without-parent"));
    let pending = fixture.view(false);
    assert!(
        pending["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .all(|subject| subject["state"] == "awaiting_supersession")
    );
    let adjudicated = fixture.answers("issue", "Synthetic explicit current-source adjudication.");
    let links = fixture.supersessions(&adjudicated, &pending, "fresh-parents.json");
    let mut args = fixture.record_args("2", owner, "fresh-adjudicated");
    args.extend(["--supersessions", links.to_str().unwrap()]);
    ok(&args);
    assert!(
        fixture.view(false)["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .all(|subject| subject["decision"] == "issue")
    );
    fs::write(
        fixture.source.join("new.js"),
        "function newer(request) { eval(request.query.other); }\n",
    )
    .unwrap();
    fixture.prepare("3");
    fixture.claim("attempt-3", "2", "claim-3", false);
    assert!(
        fixture.view(false)["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .all(|subject| subject["state"] == "unassessed")
    );
}

#[test]
fn concurrent_claims_have_one_owner_and_corrupt_or_torn_journals_refuse_updates() {
    let fixture = Fixture::new("concurrency");
    let args = [
        "state",
        "claim",
        "--store",
        fixture.store.to_str().unwrap(),
        "--stream",
        "pr:24",
        "--inventory",
        fixture.inventory.to_str().unwrap(),
        "--source-root",
        fixture.source.to_str().unwrap(),
        "--expected-generation",
        "0",
    ];
    let a = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args(args)
        .args(["--attempt-id", "a", "--operation-key", "a"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let b = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args(args)
        .args(["--attempt-id", "b", "--operation-key", "b"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let a = a.wait_with_output().unwrap();
    let b = b.wait_with_output().unwrap();
    assert_ne!(a.status.success(), b.status.success());
    assert_eq!(fixture.view(false)["generation"], 1);
    let journal = fixture.store.join("transactions.jsonl");
    let original = fs::read(&journal).unwrap();
    fs::write(&journal, &original[..original.len() - 1]).unwrap();
    let mut torn_claim = args.to_vec();
    let expected = torn_claim
        .iter()
        .position(|arg| *arg == "--expected-generation")
        .unwrap()
        + 1;
    torn_claim[expected] = "1";
    torn_claim.extend([
        "--attempt-id",
        "after-torn-tail",
        "--operation-key",
        "after-torn-tail",
        "--retry",
        "true",
    ]);
    reject(&torn_claim, "torn tail");
    assert_eq!(fs::read(&journal).unwrap(), original[..original.len() - 1]);
    reject(
        &[
            "state",
            "status",
            "--store",
            fixture.store.to_str().unwrap(),
            "--stream",
            "pr:24",
            "--repository-key",
            "repo:123",
        ],
        "torn tail",
    );
    let mut altered: Value = serde_json::from_slice(&original).unwrap();
    altered["command"]["attempt_id"] = json!("forged");
    fs::write(&journal, format!("{altered}\n")).unwrap();
    reject(
        &[
            "state",
            "status",
            "--store",
            fixture.store.to_str().unwrap(),
            "--stream",
            "pr:24",
            "--repository-key",
            "repo:123",
        ],
        "integrity",
    );
    fs::write(&journal, original).unwrap();
    let owner_receipt: Value = serde_json::from_slice(if a.status.success() {
        &a.stdout
    } else {
        &b.stdout
    })
    .unwrap();
    let owner = owner_receipt["result"]["owner"].as_str().unwrap();
    fixture.answers("issue", "Synthetic source-bound answer.");
    reject(
        &fixture.record_args("1", owner, if a.status.success() { "a" } else { "b" }),
        "different command",
    );
}

#[test]
fn concurrent_supersession_requires_the_exact_remaining_parents() {
    let mut fixture = Fixture::new("adjudication-race");
    fs::write(
        fixture.source.join("other.js"),
        "function other(request) { eval(request.query.other); }\n",
    )
    .unwrap();
    fixture.prepare("independent-subjects");
    let claimed = fixture.claim("attempt", "0", "claim", false);
    let owner = claimed["result"]["owner"].as_str().unwrap();
    fixture.answers("issue", "Synthetic original assessment.");
    ok(&fixture.record_args("1", owner, "initial"));
    let before = fixture.view(false);
    let fresh = fixture.answers(
        "needs_review",
        "Synthetic revalidation needs authority facts.",
    );
    let links = fixture.supersessions(&fresh, &before, "race-parents.json");
    let mut foreign = read(&links);
    assert!(foreign.as_array().unwrap().len() > 1);
    let parents = foreign[1]["parents"].clone();
    foreign[0]["parents"] = parents;
    let foreign_file = fixture.base.join("foreign-subject-parents.json");
    fs::write(&foreign_file, foreign.to_string()).unwrap();
    let mut foreign_args = fixture.record_args("1", owner, "foreign-subject-parents");
    foreign_args.extend(["--supersessions", foreign_file.to_str().unwrap()]);
    reject(&foreign_args, "parents changed");
    assert_eq!(fixture.view(false)["subjects"], before["subjects"]);
    let mut a_args = fixture.record_args("1", owner, "adjudication-a");
    a_args.extend(["--supersessions", links.to_str().unwrap()]);
    let mut b_args = fixture.record_args("1", owner, "adjudication-b");
    b_args.extend(["--supersessions", links.to_str().unwrap()]);
    let a = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args(a_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let b = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args(b_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let a = a.wait_with_output().unwrap();
    let b = b.wait_with_output().unwrap();
    assert_ne!(a.status.success(), b.status.success());
    let loser = if a.status.success() { &b } else { &a };
    assert!(String::from_utf8_lossy(&loser.stderr).contains("parents changed"));
    let history = fixture.view(true);
    assert_eq!(
        history["supersessions"].as_object().unwrap().len(),
        fresh.len()
    );
    assert!(
        history["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .all(|subject| subject["state"] == "recorded" && subject["decision"] == "needs_review")
    );
}

#[test]
fn partial_run_keeps_missing_subjects_unassessed_even_after_execution_finishes() {
    let mut fixture = Fixture::new("partial");
    fs::write(
        fixture.source.join("other.js"),
        "function other(request) { eval(request.query.other); }\n",
    )
    .unwrap();
    fixture.prepare("two-subjects");
    let claimed = fixture.claim("attempt", "0", "claim", false);
    let owner = claimed["result"]["owner"].as_str().unwrap();
    fixture.answers("not_issue", "Synthetic exact subject dismissal.");
    let manifest = read(&fixture.run.join("manifest.json"));
    let bundles = manifest["bundles"].as_array().unwrap();
    assert!(bundles.len() > 1);
    fs::remove_file(
        fixture
            .run
            .join("responses")
            .join(bundles[0]["filename"].as_str().unwrap()),
    )
    .unwrap();
    reject(
        &fixture.record_args("1", owner, "missing"),
        "could not read complete path-review bundle response",
    );
    let mut args = fixture.record_args("1", owner, "partial");
    args.extend(["--allow-partial", "true"]);
    ok(&args);
    let before = fixture.view(false);
    let subjects = before["subjects"].as_array().unwrap();
    assert!(
        subjects
            .iter()
            .any(|subject| subject["state"] == "unassessed" && subject["decision"].is_null())
    );
    assert!(
        subjects
            .iter()
            .any(|subject| subject["state"] == "recorded" && subject["decision"] == "not_issue")
    );
    ok(&[
        "state",
        "end",
        "--store",
        fixture.store.to_str().unwrap(),
        "--stream",
        "pr:24",
        "--repository-key",
        "repo:123",
        "--generation",
        "1",
        "--owner",
        owner,
        "--status",
        "finished",
        "--operation-key",
        "end",
    ]);
    let after = fixture.view(true);
    assert_eq!(after["subjects"], before["subjects"]);
    assert_eq!(after["attempt_status"], "finished");
    assert_eq!(after["alert_disposition"], "not_established");
}

#[test]
fn state_inside_source_and_legacy_or_foreign_inventory_cannot_be_admitted() {
    let fixture = Fixture::new("boundaries");
    let inside = fixture.source.join("state");
    reject(
        &[
            "state",
            "claim",
            "--store",
            inside.to_str().unwrap(),
            "--stream",
            "pr:24",
            "--inventory",
            fixture.inventory.to_str().unwrap(),
            "--source-root",
            fixture.source.to_str().unwrap(),
            "--attempt-id",
            "a",
            "--expected-generation",
            "0",
            "--operation-key",
            "a",
        ],
        "outside",
    );
    assert!(!inside.exists());
    let unscoped = fixture.base.join("unscoped");
    ok(&[
        "investigate",
        "review-inventory",
        fixture.source.to_str().unwrap(),
        "--output",
        unscoped.to_str().unwrap(),
    ]);
    reject(
        &[
            "state",
            "claim",
            "--store",
            fixture.store.to_str().unwrap(),
            "--stream",
            "pr:24",
            "--inventory",
            unscoped.to_str().unwrap(),
            "--source-root",
            fixture.source.to_str().unwrap(),
            "--attempt-id",
            "a",
            "--expected-generation",
            "0",
            "--operation-key",
            "a",
        ],
        "repository-key",
    );
    let first = fixture.claim("a", "0", "a", false);
    let foreign = fixture.base.join("foreign");
    ok(&[
        "investigate",
        "review-inventory",
        fixture.source.to_str().unwrap(),
        "--repository-key",
        "repo:other",
        "--output",
        foreign.to_str().unwrap(),
    ]);
    fixture.answers("issue", "Synthetic source-bound answer.");
    let mut args = fixture.record_args("1", first["result"]["owner"].as_str().unwrap(), "foreign");
    let inventory_index = args.iter().position(|arg| *arg == "--inventory").unwrap() + 1;
    args[inventory_index] = foreign.to_str().unwrap();
    reject(&args, "native identity");
}

#[test]
fn native_runtime_profiles_bind_work_and_fence_old_handoffs() {
    let fixture = Fixture::new("runtime-profile");
    let skill = fixture.base.join("skill");
    fs::create_dir_all(skill.join("references")).unwrap();
    fs::write(skill.join("SKILL.md"), "trusted router").unwrap();
    fs::write(skill.join("references/contract.md"), "bound policy").unwrap();
    let value = ok(&[
        "state",
        "runtime-template",
        "--skill-root",
        skill.to_str().unwrap(),
    ]);
    assert_eq!(value["policy"], "value");
    assert_eq!(value["limits"]["rounds"], 5);
    assert_eq!(value["limits"]["queries"], 24);
    assert_eq!(value["limits"]["bytes"], 524288);
    assert_eq!(value["limits"]["timeout_seconds"], 900);
    let comprehensive = ok(&[
        "state",
        "runtime-template",
        "--skill-root",
        skill.to_str().unwrap(),
        "--policy",
        "comprehensive",
    ]);
    assert_eq!(comprehensive["limits"], value["limits"]);
    assert_eq!(value["engine_sha256"], comprehensive["engine_sha256"]);
    let claim = fixture.claim("runtime", "0", "claim-runtime", false);
    let owner = claim["result"]["owner"].as_str().unwrap();
    let mut draft = fixture.plan_template("value");
    draft["runtime"] = value.clone();
    let file = fixture.base.join("plan.json");
    fs::write(&file, draft.to_string()).unwrap();
    let mut args = fixture.plan_args(owner, &file, "plan-runtime");
    args.extend(["--skill-root", skill.to_str().unwrap()]);
    let saved = ok(&args);
    let mut work_args = fixture.work_args(owner, false);
    reject(&work_args, "requires --skill-root");
    work_args.extend(["--skill-root", skill.to_str().unwrap()]);
    let original = ok(&work_args);
    assert_eq!(original["payload"]["runtime"], value);
    assert!(!original.to_string().contains(owner));
    let packet = fixture.base.join("work.json");
    fs::write(&packet, original.to_string()).unwrap();
    fixture.answers("not_issue", "Synthetic exact operation safe decision.");
    reject(
        &fixture.record_args("1", owner, "no-package"),
        "exact work package",
    );
    draft["runtime"]["limits"]["queries"] = json!(7);
    fs::write(&file, draft.to_string()).unwrap();
    let mut args = fixture.plan_args(owner, &file, "new-runtime");
    args.extend([
        "--skill-root",
        skill.to_str().unwrap(),
        "--expected-plan-id",
        saved["result"]["plan_id"].as_str().unwrap(),
        "--work-package",
        packet.to_str().unwrap(),
    ]);
    ok(&args);
    let current = ok(&work_args);
    assert_ne!(current["package_id"], original["package_id"]);
    let mut args = fixture.record_args("1", owner, "stale-runtime");
    args.extend([
        "--work-package",
        packet.to_str().unwrap(),
        "--skill-root",
        skill.to_str().unwrap(),
    ]);
    reject(&args, "plan/parents/facts/generation changed");
    fs::write(&packet, current.to_string()).unwrap();
    let mut args = fixture.record_args("1", owner, "current-runtime");
    args.extend([
        "--work-package",
        packet.to_str().unwrap(),
        "--skill-root",
        skill.to_str().unwrap(),
    ]);
    ok(&args);
    fs::write(skill.join("references/contract.md"), "changed policy").unwrap();
    let changed = ok(&[
        "state",
        "runtime-template",
        "--skill-root",
        skill.to_str().unwrap(),
    ]);
    assert_ne!(changed["skill_bundle_id"], value["skill_bundle_id"]);
    reject(&work_args, "skill changed");
    reject(&args, "skill changed");
    assert!(
        !fixture.view(true)["decisions"]
            .as_object()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn native_runtime_rejects_incompatible_engine_protocol_policy_and_limits() {
    let fixture = Fixture::new("runtime-invalid");
    let skill = fixture.base.join("skill");
    fs::create_dir_all(&skill).unwrap();
    fs::write(skill.join("SKILL.md"), "trusted").unwrap();
    reject(
        &[
            "state",
            "runtime-template",
            "--skill-root",
            skill.to_str().unwrap(),
            "--research-rounds",
            "11",
        ],
        "supported bounds",
    );
    reject(
        &[
            "state",
            "plan-template",
            "--inventory",
            fixture.inventory.to_str().unwrap(),
            "--source-root",
            fixture.source.to_str().unwrap(),
            "--skill-root",
            fixture.source.to_str().unwrap(),
        ],
        "outside the authorized source",
    );
    let contract = ok(&[
        "state",
        "runtime-template",
        "--skill-root",
        skill.to_str().unwrap(),
    ]);
    let claim = fixture.claim("runtime", "0", "claim", false);
    let owner = claim["result"]["owner"].as_str().unwrap();
    let file = fixture.base.join("bad-plan.json");
    for (index, (key, value, message)) in [
        ("worker_protocol", json!(99), "runtime contract"),
        ("policy", json!("comprehensive"), "runtime contract"),
        ("engine_sha256", json!("0".repeat(64)), "engine changed"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut draft = fixture.plan_template("value");
        draft["runtime"] = contract.clone();
        draft["runtime"][key] = value;
        fs::write(&file, draft.to_string()).unwrap();
        let operation = format!("bad-runtime-{index}");
        let mut args = fixture.plan_args(owner, &file, &operation);
        args.extend(["--skill-root", skill.to_str().unwrap()]);
        reject(&args, message);
    }
    assert_eq!(fixture.view(true)["decisions"], json!({}));
}

#[test]
fn provider_contract_changes_fence_native_work_and_admission() {
    let fixture = Fixture::new("provider-contract");
    let skill = fixture.base.join("skill");
    fs::create_dir_all(&skill).unwrap();
    fs::write(skill.join("SKILL.md"), "trusted").unwrap();
    let provider_path = fixture.base.join("provider.json");
    let provider = json!({"schema_version":"1","provider":"codex-cli",
        "executable_version":"0.162.0-alpha.17.2",
        "model":"gpt-6-luna","reasoning_effort":"medium"});
    fs::write(&provider_path, provider.to_string()).unwrap();
    let runtime = ok(&[
        "state",
        "runtime-template",
        "--skill-root",
        skill.to_str().unwrap(),
        "--provider-contract",
        provider_path.to_str().unwrap(),
    ]);
    assert_eq!(runtime["provider"], provider);
    let claim = fixture.claim("provider", "0", "claim", false);
    let owner = claim["result"]["owner"].as_str().unwrap();
    let mut draft = fixture.plan_template("value");
    draft["runtime"] = runtime;
    let plan = fixture.base.join("plan.json");
    fs::write(&plan, draft.to_string()).unwrap();
    let mut plan_args = fixture.plan_args(owner, &plan, "plan");
    plan_args.extend([
        "--skill-root",
        skill.to_str().unwrap(),
        "--provider-contract",
        provider_path.to_str().unwrap(),
    ]);
    let saved = ok(&plan_args);
    let mut args = fixture.work_args(owner, false);
    args.extend(["--skill-root", skill.to_str().unwrap()]);
    reject(&args, "requires --provider-contract");
    args.extend(["--provider-contract", provider_path.to_str().unwrap()]);
    let original = ok(&args);
    assert_eq!(original["payload"]["runtime"]["provider"], provider);
    let packet = fixture.base.join("work.json");
    fs::write(&packet, original.to_string()).unwrap();
    let old_provider = fixture.base.join("old-provider.json");
    fs::write(&old_provider, provider.to_string()).unwrap();
    let mut changed = provider.clone();
    changed["model"] = json!("another-model");
    fs::write(&provider_path, changed.to_string()).unwrap();
    reject(&args, "provider changed");
    draft["runtime"]["provider"] = changed;
    fs::write(&plan, draft.to_string()).unwrap();
    let mut plan_args = fixture.plan_args(owner, &plan, "new-provider");
    plan_args.extend([
        "--skill-root",
        skill.to_str().unwrap(),
        "--provider-contract",
        provider_path.to_str().unwrap(),
        "--expected-plan-id",
        saved["result"]["plan_id"].as_str().unwrap(),
    ]);
    ok(&plan_args);
    assert_ne!(original["package_id"], ok(&args)["package_id"]);
    fixture.answers(
        "not_issue",
        "Synthetic operation safe decision for admission tests.",
    );
    let mut record = fixture.record_args("1", owner, "old-provider-result");
    record.extend([
        "--skill-root",
        skill.to_str().unwrap(),
        "--provider-contract",
        old_provider.to_str().unwrap(),
        "--work-package",
        packet.to_str().unwrap(),
    ]);
    reject(&record, "plan/parents/facts/generation changed");
    assert_eq!(fixture.view(true)["decisions"], json!({}));
}
