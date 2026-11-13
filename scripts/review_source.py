"""Default AI source assignments: discover, assess and native-finalize in shared context."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import copy
import json
from pathlib import Path
import re
import shutil
import time

import review_context as context
import review_budget
import review_scheduler
import review_domains
import review_work
import review_questions
import review_source_recovery as source_recovery
from review_case_state import CaseState
import review_orchestration


def source_recovery_binding(args, package, plan, commands, scanner_sha, worker):
    """Resume only the same source, target, policy and trusted controller."""
    modules = ("review_source.py", "review_source_recovery.py", "review_worker.py", "review_work.py",
        "review_questions.py", "review_case_state.py", "review_evidence.py", "review_budget.py",
        "review_orchestration.py", "review_context.py", "review_domains.py", "review_scheduler.py")
    return {"package_id":package["package_id"], "plan_id":plan["plan_id"],
        "store":str(Path(args.store).resolve()), "stream":args.stream,
        "manifest_sha256":worker.digest_file(args.work_plan), "commands":commands, "scanner_sha256":scanner_sha,
        "controller":{name:worker.digest_file(Path(__file__).with_name(name)) for name in modules},
        "options":{name:getattr(args, name, None) for name in (
            "review_goal", "coverage_target", "max_calls", "input_token_budget", "admission_seconds", "cost_budget",
            "include_supporting_source", "domain_session_mode", "question_routing")},
        "rates_sha256":worker.digest_file(args.cost_rates) if getattr(args, "cost_rates", None) else None}


def selection_options(plan):
    """Compact source metadata for host selection; never repeat source bodies."""
    return {"source_plan_id": plan["plan_id"], "source_fingerprint": plan["source_fingerprint"],
            "assignments": [{"assignment_id": a["id"], "review_ids": a["review_ids"],
                             "windows": [{k: w[k] for k in ("path", "start_line", "end_line", "source_sha256")}
                                         for w in a["windows"]]} for a in plan["assignments"]],
            "next_step": "Inspect the application and native queue, then supply a source-bound --work-plan FILE with --review-goal budget or coverage in a new output attempt. Keep every native lead accounted for; rank concrete failure/control checks and preserve unknown scope. For an explicitly requested origin mix, --source-selection FILE retains the existing zero-to-six additional AI operations and complete native queue; --native-share sets that allocation (default 80). Both plan forms bind source_plan_id and source_fingerprint."}


def validate_selection(selection, plan):
    if not isinstance(selection, dict) or any(selection.get(k) != plan[v] for k, v in
            (("source_plan_id", "plan_id"), ("source_fingerprint", "source_fingerprint"))):
        raise ValueError("source selection differs from the current native plan or source fingerprint")
    selected = selection.get("assignment_ids")
    if (not isinstance(selected, list) or not 0 <= len(selected) <= 6 or
            any(not isinstance(i, str) for i in selected) or len(set(selected)) != len(selected)):
        raise ValueError("source selection requires zero to six distinct ranked AI assignments")
    rows = selection.get("assignments")
    if not isinstance(rows, list) or len(rows) != len(selected):
        raise ValueError("source selection requires one named operation per assignment")
    by_id = {a["id"]: a for a in plan["assignments"]}
    focus = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("assignment_id") not in selected or row["assignment_id"] in focus:
            raise ValueError("source operation membership differs from ranked selection")
        if any(not isinstance(row.get(k), str) or not row[k].strip() or len(row[k]) > 4000
               for k in ("owner_path", "question", "protected_effect", "area", "reason", "next_deciding_fact")):
            raise ValueError("source operation requires bounded question, effect, area, reason and owner path")
        if (type(row.get("start_line")) is not int or type(row.get("end_line")) is not int
                or not 1 <= row["start_line"] <= row["end_line"]):
            raise ValueError("source operation requires an ordered original-source owner range")
        assignment = by_id.get(row["assignment_id"])
        if assignment is None or not any(w["path"] == row["owner_path"] and
                w["start_line"] <= row["start_line"] <= row["end_line"] <= w["end_line"] for w in assignment["windows"]):
            raise ValueError("source operation range is outside its selected native assignment")
        signal = row.get("signal")
        if (not isinstance(signal, dict) or signal.get("kind") not in ("native_candidate", "source_relationship")
                or not isinstance(signal.get("evidence"), list) or not 1 <= len(signal["evidence"]) <= 12):
            raise ValueError("source operation requires a concrete source-backed signal")
        evidence = []
        for cite in signal["evidence"]:
            if (not isinstance(cite, dict) or not isinstance(cite.get("path"), str) or
                    type(cite.get("start_line")) is not int or type(cite.get("end_line")) is not int or
                    not 1 <= cite["start_line"] <= cite["end_line"] or cite["end_line"] - cite["start_line"] >= 400):
                raise ValueError("source signal requires bounded original-source evidence ranges")
            window = next((w for a in plan["assignments"] for w in a["windows"] if
                           w["path"] == cite["path"] and w["start_line"] <= cite["start_line"] <= cite["end_line"] <= w["end_line"]), None)
            if window is None:
                raise ValueError("source signal evidence is outside native source windows")
            evidence.append({k: cite[k] for k in ("path", "start_line", "end_line")} | {
                "quote": "\n".join(window["text"].split("\n")[cite["start_line"] - window["start_line"]:cite["end_line"] - window["start_line"] + 1])})
        focus[row["assignment_id"]] = {k: row[k] for k in
            ("owner_path", "start_line", "end_line", "question", "protected_effect", "area", "reason", "next_deciding_fact")}
        focus[row["assignment_id"]]["signal"] = {"kind": signal["kind"], "evidence": evidence}
    if set(focus) != set(selected):
        raise ValueError("source operation membership differs from ranked selection")
    return selected, focus


def investigation_queues(plan, native_ids, ai_ids, selection, native_share):
    """Rank investigations without changing native admission or sharing verdicts."""
    native_ids = set(native_ids)
    native = [a["id"] for a in plan["assignments"] if native_ids.intersection(a["review_ids"])]
    ranked = selection.get("native_assignment_ids", native)
    if (not isinstance(ranked, list) or any(not isinstance(i, str) for i in ranked)
            or len(ranked) != len(set(ranked)) or set(ranked) != set(native)):
        raise ValueError("native ranking must preserve every admitted native investigation")
    # An AI focus on a native investigation is resolved there, without a second job.
    ai = [i for i in ai_ids if i not in native] if native_share else list(ai_ids)
    return {"native": ranked if native_share else [], "ai": ai if native_share < 100 else []}


def scoped_native_ids(ids, entries, focus):
    scoped = {e["review_id"] for e in entries for row in focus.values()
              if e["path"] == row["owner_path"] and row["start_line"] <= e["line"] <= row["end_line"]}
    return [rid for rid in ids if rid in scoped]


def reconcile_completion_plan(draft, current_ids):
    """Source proposals can supersede generic markers and refill native pages.

    Keep old assessments as historical source work, never transfer them to a
    newly exposed question. The completion plan must partition the derived IDs.
    """
    current_ids = set(current_ids)
    groups = [set(draft.get(key, {})) for key in
              ("selected_review_ids", "deferred_review_ids", "excluded_review_ids")]
    if any(a & b for index, a in enumerate(groups) for b in groups[index + 1:]):
        raise ValueError("source completion plan has overlapping dispositions")
    previous_ids = set().union(*groups)
    displaced = sorted(previous_ids - current_ids)
    exposed = sorted(current_ids - previous_ids)
    draft["selected_review_ids"] = sorted(groups[0] & current_ids)
    for key in ("deferred_review_ids", "excluded_review_ids"):
        draft[key] = {rid: reason for rid, reason in draft.get(key, {}).items() if rid in current_ids}
    for rid in exposed:
        draft["deferred_review_ids"][rid] = "Native question exposed after source admission; not reviewed and no prior verdict transferred."
    return {"displaced_review_ids": displaced, "new_unreviewed_ids": exposed}


def excluded_native_questions(plan):
    """Keep lookup-only source claims out of the default native fallback queue."""
    return {
        rid: source["reason"]
        for source in plan.get("excluded_sources", [])
        for rid in source.get("review_ids", [])
    }


def load_native_cards(native, root, inventory, stage, ids, assignment_id):
    """Materialize native facts only for an investigation that actually starts."""
    if not ids:
        return {}
    original = Path(stage) / "native-inputs" / assignment_id
    native(["investigate", "review-bundles", root, "--inventory", inventory,
            "--review-ids", ",".join(ids), "--output", original])
    manifest = json.loads((original / "manifest.json").read_text(encoding="utf8"))
    cards = {}
    for bundle in manifest["bundles"]:
        sweep = native(["investigate", "review-sweep", "--bundle",
                        original / "requests" / bundle["filename"]])
        for card in sweep["reviews"]:
            if card["review_id"] in cards:
                raise ValueError("native source cards contain duplicate review membership")
            index = int(card["question_id"].split("-")[-1]) - 1
            cards[card["review_id"]] = {
                "question": sweep["questions"][index],
                "facts": {k: card[k] for k in (
                    "anchor", "operand_facts", "decision_facts", "path_steps",
                    "source_configuration", "truncation", "suggested_lookups") if k in card},
            }
    if set(cards) != set(ids):
        raise ValueError("native source cards differ from the investigation's exact review membership")
    return cards


def validate_assignment_scope(plan):
    """Queryable-only registry entries must never become ambient source windows."""
    lookup_only = {source["path"] for source in plan.get("excluded_sources", [])}
    metadata_keys = {"path", "reason", "review_ids", "source_sha256", "line_count"}
    if any(set(source) - metadata_keys for source in plan.get("excluded_sources", [])):
        raise ValueError("queryable-only plan records must contain metadata, not source text")
    if any(w["path"] in lookup_only for a in plan["assignments"] for w in a["windows"]):
        raise ValueError("queryable-only source cannot enter default assignment windows")


def validate_reuse_alias(previous, assignment, original):
    if (original is None or original[0] != assignment or
        Path(previous["reuse"]["prior_result"]).resolve() != original[2].resolve() or
        previous["reuse"]["prior_plan_id"] != original[3] or
        any(previous.get(key) != original[1].get(key) for key in
            ("assignment_id", "draft", "proofs", "proposals", "inspected", "facts", "followups", "claim_contexts", "claim_context_errors", "proposal_followups", "proposal_contexts"))):
        raise ValueError("prior reused source result differs from its supplied original")


def reused_source_result(assignment, previous, plan):
    """Reconstruct and validate the completed result's source-backed envelope."""
    if previous.get("status") != "complete" or previous.get("unknown_provider_calls") != 0:
        raise ValueError("only completed source assignments with known usage are reusable")
    if previous.get("assignment_id") != assignment["id"]:
        raise ValueError("reused source assignment identity changed")
    draft = previous["draft"]
    expected = {(w["path"], w["start_line"], w["end_line"]) for w in assignment["windows"]}
    coverage = [(w["path"], w["start_line"], w["end_line"]) for w in draft["coverage"]]
    ids = [row["review_id"] for row in draft["results"]]
    if len(coverage) != len(set(coverage)) or set(coverage) != expected or len(ids) != len(set(ids)) or set(ids) != set(assignment["review_ids"]):
        raise ValueError("reused source coverage or assessment membership changed")
    visible = [*assignment["windows"], *previous["inspected"]]
    def citations(assessment):
        result = []
        for cite in assessment.get("evidence", []):
            lines = {w["start_line"] + i: line for w in visible if w["path"] == cite["path"]
                     for i, line in enumerate(w["text"].split("\n"))}
            first, last = cite["start_line"], cite["end_line"]
            if not 1 <= first <= last or last - first >= 400 or any(n not in lines for n in range(first, last + 1)):
                raise ValueError("reused assessment cites unseen source")
            result.append({**{k: cite[k] for k in ("path", "start_line", "end_line")},
                           "quote": "\n".join(lines[n] for n in range(first, last + 1))})
        return result
    proofs = [c for row in draft["results"] for c in citations(row)]
    proposals = []
    for proposal in draft["proposals"]:
        proofs.extend(citations(proposal["assessment"]))
        proposals.append({k: v for k, v in proposal.items() if k != "assessment"} | {
            "assignment_id": assignment["id"],
            "anchor": citations({"evidence": [proposal["anchor"]]})[0],
            "evidence": citations({"evidence": proposal["evidence"]}),
        })
    if proofs != previous["proofs"] or proposals != previous["proposals"]:
        raise ValueError("reused source proof or proposal differs from completed draft")
    return {"plan": plan, "inspected": previous["inspected"], "proposals": proposals,
            "assessment_evidence": proofs}


def retain_training_turns(summary, output):
    """Copy observed source turns without rewriting inputs or replaying models."""
    stage = Path(summary).parent
    for path in (stage / "jobs").glob("*/*-input.json"):
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError("source training inputs require regular files")
        frame = json.loads(path.read_text(encoding="utf8"))
        conversation = frame.get("conversation_id", "")
        if frame.get("kind") != "source_review" or not re.fullmatch(
            r"[0-9a-f]{64}", conversation
        ):
            raise ValueError("invalid source training conversation")
        turn = path.name.removesuffix("-input.json")
        if not turn.isdigit():
            raise ValueError("invalid source training turn")
        destination = Path(output) / "training-turns" / conversation
        destination.mkdir(parents=True, exist_ok=True)
        files = [
            path,
            path.with_name(turn + "-facts.json"),
            path.with_name("context.json"),
        ]
        response = path.with_name(turn + "-response.json")
        if response.exists():
            files.append(response)
        for source in files:
            if source.is_symlink() or not source.is_file():
                raise ValueError("source trajectory lacks captured reviewer inputs")
            target = destination / source.name
            if target.exists():
                if target.is_symlink() or target.read_bytes() != source.read_bytes():
                    raise ValueError(
                        "recovered source trajectory differs from captured inputs"
                    )
            else:
                shutil.copyfile(source, target)


def run(args, legacy, worker):
    root = Path(args.source_root).resolve(strict=True)
    output = worker.outside(args.output, root, False)
    domain_path = getattr(args, "domain_plan", None)
    if domain_path and (args.phase != "all" or getattr(args, "source_selection", None)
            or getattr(args, "reuse_source_results", None) or getattr(args, "resume_from", None)
            or getattr(args, "first_pass", None) or getattr(args, "second_pass", "off") != "off"
            or getattr(args, "native_share", 80) != 80):
        raise ValueError("domain review requires a fresh all-phase plan without source selection, reuse, follow-up or native-share overrides")
    if getattr(args, "reuse_source_results", None) and (getattr(args, "first_pass", None) or args.phase != "all" or getattr(args, "resume_from", None)):
        raise ValueError("source-result reuse requires a fresh all-phase source attempt")
    if getattr(args, "first_pass", None) or args.phase != "all":
        return legacy(args)
    if getattr(args, "validate_only", False) or getattr(args, "source_profile", None):
        raise ValueError(
            "exact-bundle validation and bound source profiles require --phase native"
        )
    if not 1 <= args.workers <= 16:
        raise ValueError("review workers must be 1 to 16")
    source_resume = None
    lineage_output = output
    if getattr(args, "resume_from", None):
        previous = Path(args.resume_from) / "source-review/summary.json"
        if not previous.is_file():
            if (Path(args.resume_from) / "source-review").is_dir():
                if not getattr(args, "work_plan", None) or not (previous.parent / "source-recovery.json").is_file():
                    raise ValueError("source recovery requires the original work plan and a bound checkpoint")
                source_resume = Path(args.resume_from)
                args.resume_from = None
            else:
                return legacy(args)
    if getattr(args, "resume_from", None):
        data = worker.read(previous)
        if data.get("work_review"):
            handoff, data, inherited_budget = review_work.read_handoff(Path(args.resume_from), root, worker)
            if getattr(args, "work_plan", None) and worker.digest_file(args.work_plan) != handoff["manifest_sha256"]:
                raise ValueError("work-plan continuation requires the original unchanged manifest")
            args._review_budget = inherited_budget
        if (worker.read(data["effective_args"]["work_package"])["payload"]["policy"] == "value"
                and not data.get("budget_path")):
            raise ValueError("Value source continuation requires its original bounded selection and budget ledger")
        for name, value in data["effective_args"].items():
            setattr(args, name, value)
        args._source_prepared = str(previous)
        result = legacy(args)
        if data.get("work_review") and (Path(args.resume_from) / "source-review/work-ledger.json").is_file():
            prior = worker.read(Path(args.resume_from) / "source-review/work-ledger.json")
            if prior:
                result["work_goal"] = {"goal":prior["goal"], "status":prior["target_status"],
                    "target_complete":prior["target_complete"], "completed_items":prior["summary"]["closed"],
                    "remaining_items":prior["summary"]["remaining"], "ledger":str(Path(args.resume_from) / "source-review/work-ledger.json"),
                    "authority":"Historical first-pass checks retained during native handoff continuation."}
                result["work_goal"]["continuation_of"] = str(Path(args.resume_from).resolve())
                if prior.get("goal") == "coverage" and not prior.get("target_complete"):
                    result["status"] = "incomplete"
                worker.write(output / "worker.json", result)
        return result
    started_run = time.monotonic()
    started_epoch = time.time()
    output.mkdir(parents=True, exist_ok=False)
    stage = output / "source-review"
    stage.mkdir()
    args._source_attempt_created = True
    env = {
        k: v
        for k, v in worker.os.environ.items()
        if k not in ("GH_TOKEN", "GITHUB_TOKEN")
        and not k.endswith("_API_KEY")
        and not k.startswith("GIT_CONFIG_")
    }
    env.update(GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")
    scanner = worker.outside(args.scanner, root)
    scanner_sha = worker.digest_file(scanner)
    skill = worker.outside(args.skill_root, root)
    inventory = worker.outside(args.inventory, root)
    command = worker.read(worker.outside(args.reviewer_command, root))
    if (
        not isinstance(command, list)
        or not command
        or not all(isinstance(s, str) for s in command)
    ):
        raise ValueError("invalid reviewer command")
    if not Path(command[0]).is_absolute():
        raise ValueError("reviewer must be a trusted absolute executable")
    for arg in command:
        if Path(arg).is_file():
            worker.outside(arg, root)
    claim = worker.read(args.claim)["result"]
    args._source_generation = claim["generation"]
    common = [
        "--store",
        str(args.store),
        "--stream",
        args.stream,
        "--inventory",
        str(inventory),
        "--source-root",
        str(root),
        "--generation",
        str(claim["generation"]),
        "--owner",
        claim["owner"],
    ]

    def native(arguments, timeout=900):
        if worker.digest_file(scanner) != scanner_sha:
            raise ValueError("trusted scanner changed during source review")
        try:
            return worker.execute(
                [str(scanner), *map(str, arguments)], stage, env, timeout,
                output_limit=worker.NATIVE_OUTPUT_LIMIT,
            )
        except worker.CommandFailure as error:
            error.step = "native/" + "/".join(map(str, arguments[:2]))
            raise

    runtime_options = ["--skill-root", str(skill)] + (
        ["--provider-contract", str(args.provider_contract)]
        if args.provider_contract
        else []
    )
    package = native(["state", "work", *common, *runtime_options])
    if package != worker.read(args.work_package):
        raise ValueError("source assignment requires current unaltered native work")
    payload = package["payload"]
    work_path = getattr(args, "work_plan", None)
    if domain_path and payload["policy"] != "value":
        raise ValueError("opt-in domain review currently requires Value policy")
    runtime = payload.get("runtime")
    if not runtime or runtime["worker_protocol"] != 2:
        raise ValueError(
            "AI source review requires a native runtime-bound plan; use plan-template --skill-root"
        )
    if (
        runtime["skill_bundle_id"] != context.skill_bundle_id(skill)
        or runtime["engine_sha256"] != scanner_sha
    ):
        raise ValueError("source review runtime changed")
    question_routing = bool(getattr(args, "question_routing", False))
    if question_routing and (not work_path or not runtime.get("orchestration") or not args.expert_command):
        raise ValueError("question routing requires a work plan, native bound routine/expert profiles and --expert-command")
    if question_routing and any((runtime["orchestration"].get("quality") or {}).values()):
        raise ValueError("question routing uses an expert owner; native paired-verdict QA requires the separate native workflow")
    if question_routing and (getattr(args, "expert_workers", 1) != 1 or getattr(args, "expert_review_ids", None)
            or getattr(args, "source_collector_profile", None)):
        raise ValueError("question routing uses --workers for case capacity; native profile routing overrides are separate")
    if runtime.get("orchestration") and not question_routing:
        raise ValueError(
            "repository source review currently uses one configured model; use native phase for explicit experimental tiered bundles"
        )
    artifact_root = (
        worker.outside(args.artifact_root, root) if args.artifact_root else output
    )
    if not output.is_relative_to(artifact_root):
        raise ValueError("worker output must stay inside its declared artifact root")
    provider_config = worker.validate_provider_command(
        command, runtime.get("provider"), skill, root, artifact_root
    )
    source_commands = {"routine": command}
    if question_routing:
        expert = worker.read(worker.outside(args.expert_command, root))
        if not isinstance(expert, list) or not expert or any(not isinstance(v, str) for v in expert):
            raise ValueError("invalid expert command")
        if not Path(expert[0]).is_absolute():
            raise ValueError("expert reviewer must use a trusted absolute executable")
        for argument in expert:
            if Path(argument).is_file():
                worker.outside(argument, root)
        owner_config = worker.validate_provider_command(expert, runtime["orchestration"]["expert"], skill, root, artifact_root)
        if any(config.get("schema_mode", "stable") != "stable" for config in (provider_config, owner_config)):
            raise ValueError("question routing requires stable provider schemas")
        source_commands["expert"] = expert
    command_bindings = {profile:context.digest([argv, [worker.digest_file(v) for v in argv if Path(v).is_file()]])
                        for profile, argv in source_commands.items()}
    if domain_path and provider_config is not None and provider_config.get("schema_mode", "stable") != "stable":
        raise ValueError("domain review requires the stable provider schema before call admission")
    limits = runtime["limits"]
    for key, name in [
        ("rounds", "research_rounds"),
        ("queries", "research_queries"),
        ("bytes", "research_bytes"),
        ("timeout_seconds", "timeout"),
    ]:
        value = getattr(args, name, None)
        if value is not None and value != limits[key]:
            raise ValueError("source review override differs from the native allowance")
    ids = payload["review_ids"]
    def source_plan(selected_ids):
        return native([
            "investigate",
            "source-review-plan",
            root,
            "--inventory",
            inventory,
            "--review-ids",
            ",".join(selected_ids),
            *(["--include-supporting-source", "true"] if getattr(args, "include_supporting_source", False) else []),
        ])
    plan = source_plan(ids)
    validate_assignment_scope(plan)
    worker.write(stage / "plan.json", plan)
    options = selection_options(plan)
    worker.write(stage / "selection-options.json", options)
    selection_path = getattr(args, "source_selection", None)
    if payload["policy"] == "value" and not selection_path and not domain_path and not work_path:
        checkpoint = {"status": "selection_required", "generation": claim["generation"],
                      "calls": 0, "unknown_provider_calls": 0, "stage": "source_selection",
                      "source_plan_id": plan["plan_id"], "source_fingerprint": plan["source_fingerprint"],
                      "selection_options": str(stage / "selection-options.json"), "next_step": options["next_step"]}
        worker.write(stage / "checkpoint.json", checkpoint)
        worker.write(output / "worker.json", checkpoint)
        return checkpoint
    selected = [a["id"] for a in plan["assignments"]]
    focus = {}
    budget_path = None
    queues = None
    domain_registry = None
    work_registry = None
    case_by_assignment = {}
    domain_states = {}
    native_share = getattr(args, "native_share", 80)
    if domain_path or work_path:
        manifest = worker.read(worker.outside(work_path or domain_path, root))
        original_ids = [rid for rid in ids if rid not in excluded_native_questions(plan)]
        if work_path:
            targets = getattr(args, "coverage_target", None)
            targets = [value.strip() for value in targets.split(",")] if targets is not None else None
            work_registry = review_work.validate(manifest, plan, original_ids, validate_selection=validate_selection,
                goal=getattr(args, "review_goal", None) or "budget", targets=targets)
            if question_routing and any(len(case["verify_review_ids"]) > runtime["orchestration"]["max_reviews_per_job"] for case in work_registry["cases"]):
                raise ValueError("question routing verification membership exceeds the bound case size")
            domain_registry = work_registry
            worker.write(stage / "work-plan.json", work_registry)
        else:
            domain_registry = review_domains.validate(manifest, plan, original_ids, validate_selection=validate_selection)
        worker.write(stage / "domain-plan.json", domain_registry)
        worker.write(stage / "selection-plan.json", plan)
        worker.write(stage / "lead-accounting.json", domain_registry["lead_accounting"])
        selected = list(dict.fromkeys(case["assignment_id"] for case in domain_registry["cases"]))
        focus = {case["assignment_id"]: case["focus"] for case in domain_registry["cases"]}
        case_by_assignment = {(case["id"] if work_registry else case["assignment_id"]): case for case in domain_registry["cases"]}
        ids = [rid for case in domain_registry["cases"] for rid in case["verify_review_ids"]]
        plan = source_plan(ids)
        validate_assignment_scope(plan)
        # Native assignments keep their source identity while only Verify IDs
        # enter native verdict membership. Other roles retain separate accounting.
        for case in domain_registry["cases"]:
            row = case["focus"] | {"assignment_id": case["assignment_id"]}
            validate_selection({"source_plan_id": plan["plan_id"], "source_fingerprint": plan["source_fingerprint"],
                "assignment_ids": [case["assignment_id"]], "assignments": [row]}, plan)
            canonical_ids = next(a["review_ids"] for a in plan["assignments"] if a["id"] == case["assignment_id"])
            if work_registry:
                canonical_ids = [rid for rid in canonical_ids if rid in case["verify_review_ids"]]
            if set(canonical_ids) != set(case["verify_review_ids"]):
                raise ValueError("domain verification membership changed during native preparation")
            case["verify_review_ids"] = list(canonical_ids)
            case["review_roles"]["verify"] = list(canonical_ids)
        worker.write(stage / "domain-plan.json", domain_registry)
        worker.write(stage / "plan.json", plan)
        budget_path = stage / "budget.json"
        cost = None
        if getattr(args, "cost_budget", None) is not None or getattr(args, "cost_rates", None):
            if not work_registry or not getattr(args, "cost_rates", None):
                raise ValueError("cost accounting requires a work plan and model rate file")
            rates = worker.read(worker.outside(args.cost_rates, root))
            model = (runtime.get("provider") or {}).get("model")
            if question_routing:
                models = {model, runtime["orchestration"]["expert"]["model"]}
                if rates.get("currency") != "USD" or not models <= set(rates.get("models", {})):
                    raise ValueError("question routing cost rates require USD models entries for both bound providers")
                cost = review_budget.provider_cost_policy(getattr(args, "cost_budget", None),
                    {m:rates["models"][m] for m in models})
            else:
                if not model or rates.get("model") != model or rates.get("currency") != "USD":
                    raise ValueError("cost rate model/currency differs from the provider binding")
                cost = review_budget.cost_policy(getattr(args, "cost_budget", None), rates.get("rates"))
        managed_calls = getattr(args, "max_calls", 40)
        if question_routing:
            managed_calls = min(managed_calls, runtime["orchestration"]["run_limits"]["model_calls"])
        if source_resume:
            recovery_binding = source_recovery_binding(args, package, plan, command_bindings, scanner_sha, worker)
            recovered = source_recovery.restore(source_resume, stage, recovery_binding, root, worker)
            budget_path = Path(recovered["budget_path"])
            lineage_output = Path(recovered["lineage_output"])
            source_recovery.settle_interrupted(stage, budget_path, worker)
        else:
            review_budget.initialize(budget_path, max_calls=managed_calls,
                input_limit=getattr(args, "input_token_budget", 1_500_000),
                admission_seconds=getattr(args, "admission_seconds", 1200), cost=cost,
                started_at=started_epoch if work_registry else None)
        args._review_budget = str(budget_path)
        if work_registry:
            source_recovery.seal(stage,
                source_recovery_binding(args, package, plan, command_bindings, scanner_sha, worker),
                budget_path, lineage_output, worker)
            report = review_work.ledger(work_registry, budget=review_budget.snapshot(budget_path))
            worker.write(stage / "work-ledger.json", report)
            worker.write_text(stage / "remaining-work.md", review_work.markdown(report))
            if not domain_registry["cases"]:
                result = {"status": "incomplete", "generation": claim["generation"], "calls": 0,
                          "reason": "NoReadyWork", "work_goal": report["target_status"]}
                worker.write(output / "worker.json", result)
                return result
    elif selection_path:
        selection = worker.read(worker.outside(selection_path, root))
        selected, focus = validate_selection(selection, plan)
        worker.write(stage / "selection.json", selection)
        worker.write(stage / "selection-plan.json", plan)
        admitted = [rid for rid in ids if rid not in excluded_native_questions(plan)]
        queues = investigation_queues(plan, admitted, selected, selection, native_share)
        if native_share == 0:
            # Explicit AI-only review does not turn nearby native candidates into tasks.
            ids = []
            plan = source_plan(ids)
            validate_assignment_scope(plan)
            validate_selection({**selection, "source_plan_id": plan["plan_id"]}, plan)
            worker.write(stage / "plan.json", plan)
        selected = queues["native"] + queues["ai"]
        budget_path = stage / "budget.json"
        review_budget.initialize(budget_path, max_calls=getattr(args, "max_calls", 40),
            input_limit=getattr(args, "input_token_budget", 1_500_000),
            admission_seconds=getattr(args, "admission_seconds", 1200), native_percent=native_share)
        args._review_budget = str(budget_path)
    selected_set = set(selected)
    by_id = {a["id"]: a for a in plan["assignments"]}
    excluded_ids = excluded_native_questions(plan)
    # Native admission is independent of the additional AI discovery selection.
    ids = [rid for rid in ids if rid not in excluded_ids]
    selected_native_ids = set(ids)
    lane_by_id = {identity: lane for lane, members in (queues or {}).items() for identity in members}
    if queues is not None:
        worker.write(stage / "schedule.json", {
            "native_share": native_share, "native_candidate_ids": ids,
            "native_candidate_count": len(ids), "native_investigations": queues["native"],
            "ai_investigations": queues["ai"], "coverage_plan": selection.get("coverage_plan"),
            "authority": "Prioritization and shared context only; every native candidate retains its own decision. Unfinished work remains unreviewed."})
    entries = {
        e["review_id"]: e for e in worker.read(inventory / "inventory.json")["entries"]
    }
    contract = (skill / "references/source-review.md").read_text(encoding="utf8")
    contract += (
        "\n"
        + context.sections(skill / "references/final-proof-check.md", ["final_proof"])[
            "text"
        ]
    )
    contract += (
        "\n"
        + context.sections(skill / "references/runtime-review.md", ["api_semantics", "control_consumers", "claim_context", "followup_selection"])[
            "text"
        ]
    )
    # Source review has its own native-bound assignment, not an invented vulnerability.
    api = context.research_api(skill)
    guidance = context.guidance_catalog(skill)
    if domain_registry:
        for domain in domain_registry["domains"]:
            session_id = context.digest([package["package_id"], "domain", domain["id"], str(lineage_output)])
            members = [{"id": case["id"], "assignment_id": case["assignment_id"],
                "conversation_id": context.digest([package["package_id"], "source_review", case["id"] if work_registry else case["assignment_id"], str(lineage_output)]),
                "review_ids": case["verify_review_ids"]} for case in domain["cases"]]
            paths = [w["path"] for case in domain["cases"] for a in plan["assignments"]
                     if a["id"] == case["assignment_id"] for w in a["windows"]]
            domain_states[domain["id"]] = {"id": session_id,
                "binding": context.digest([package["package_id"], domain, members]), "cases": members,
                "contract": contract + "".join("\n" + g["text"] for g in context.language_contracts(skill, paths)),
                "shared_facts": domain["shared_facts"], "facts": [], "inspected": [], "citation_windows": {}}
        worker.write(stage / "schedule.json", {"mode": "domain", "domains": [{"id": d["id"],
            "cases": [c["id"] for c in d["cases"]]} for d in domain_registry["domains"]],
            "verification_ids": ids, "lead_count": len(domain_registry["lead_accounting"]),
            "authority": "Cases share source facts and a provider thread; verdicts remain case-specific. Cover/Context roles have no native verdict obligation."})
    source_metrics = source_recovery.receipts(stage, worker) if source_resume else []
    inherited_source_calls = len(source_metrics)
    reuse_jobs = {}
    partial_windows = []
    reuse_paths = getattr(args, "reuse_source_results", None) or []
    if isinstance(reuse_paths, str):
        reuse_paths = [reuse_paths]
    for reuse_path in reuse_paths:
        prior = worker.outside(reuse_path, root)
        if prior.resolve() == output.resolve():
            raise ValueError("source reuse requires a separate prior attempt")
        prior_stage = prior / "source-review"
        prior_plan = worker.read(prior_stage / "plan.json")
        for key in ("source_fingerprint", "inventory_fingerprint"):
            if prior_plan[key] != plan[key]:
                raise ValueError("prior source plan binding differs from current plan")
        prior_assignments = {a["id"]: a for a in prior_plan["assignments"]}
        for directory in (prior_stage / "jobs").iterdir():
            if not directory.is_dir():
                continue
            old = prior_assignments.get(directory.name)
            if old is None:
                raise ValueError("prior source job is absent from its plan")
            result_path = directory / "result.json"
            previous = worker.read(result_path) if result_path.is_file() else None
            if previous is None or previous.get("status") != "complete" or previous.get("unknown_provider_calls") != 0:
                partial_windows.extend(old["windows"])
                continue
            if previous.get("reuse"):
                original = reuse_jobs.get(directory.name)
                validate_reuse_alias(previous, old, original)
                continue
            frame = worker.read(directory / "0-input.json")
            prior_work = worker.read(Path(frame["work_package"]))["payload"]
            prior_runtime = prior_work["runtime"]
            prior_context = worker.read(directory / "context.json")
            prior_windows = [{key: window[key] for key in ("path", "start_line", "end_line", "source_sha256", "text")}
                             for window in prior_context["primary"]["windows"]]
            if (prior_work["policy"] != payload["policy"] or
                any(prior_runtime.get(key) != runtime.get(key) for key in ("provider", "policy", "worker_protocol", "limits")) or
                frame.get("review_ids") != old["review_ids"] or prior_context["work"]["policy"] != prior_work["policy"] or
                prior_context["work"]["runtime"] != prior_runtime or prior_context["work"]["review_ids"] != old["review_ids"] or
                prior_context.get("source_assignment_id") != old["id"] or prior_windows != old["windows"]):
                raise ValueError("prior source reviewer policy, provider or membership differs")
            if directory.name in reuse_jobs:
                raise ValueError("duplicate independent completed source assignment")
            reuse_jobs[directory.name] = (old, previous, result_path, prior_plan["plan_id"])

    def overlaps_partial(assignment):
        return any(w["path"] == p["path"] and w["start_line"] <= p["end_line"] and p["start_line"] <= w["end_line"]
                   for w in assignment["windows"] for p in partial_windows)

    preparation_broker = worker.EvidenceBroker()
    question_budget = (review_orchestration.SharedReviewBudget(stage / "question-budget.json",
        runtime["orchestration"], worker.write,
        previous=stage / "question-budget.json" if source_resume else None) if question_routing else None)
    case_binding = {
        "source_plan_id":work_registry["source_plan_id"],
        "source_fingerprint":work_registry["source_fingerprint"],
        "work_package_id":package["package_id"], "work_plan_digest":context.digest(work_registry["items"])} if work_registry else None
    case_store = ((CaseState(stage / "case-state.sqlite", case_binding) if source_resume else
        CaseState.create(stage / "case-state.sqlite", root, case_binding, work_registry)) if work_registry else None)
    recovery_cases = {identity for identity, case in case_store.snapshot()["cases"].items()
                      if case["execution"] != "unstarted"} if source_resume else set()
    recovery_jobs = {path.parent.name for pattern in ("*/recovery.json", "*/result.json")
                     for path in (stage / "jobs").glob(pattern)} if source_resume else set()
    if source_resume:
        source_recovery.claim_successor(source_resume, stage, worker)

    def completion_remaining(case_id):
        return review_budget.snapshot(budget_path).get("completion_holds", {}).get(case_id, {}).get("remaining", 0)

    def prepare_definition(case_id, spec, usage):
        """One explicit declaration file, no inferred dispatch or caller expansion."""
        source_file = context.source_file(root, spec["path"])
        if not source_file.is_file():
            return {"status":"not_ready", "reason":"Named declaration file unavailable.", "request":spec}, None
        query = {"tool":"definition", "review_id":None, "arguments":spec,
                 "purpose":"Prepare the explicitly named implementation for a factual check."}
        arguments = worker.research_arguments(query, root, [], stage, api=api, guidance=guidance)
        units = worker.research_cost([query], api=api)
        key = context.digest([plan["source_fingerprint"], query])
        timeout = max(0, question_budget.remaining(case_id, "timeout_seconds"))
        if timeout <= 0:
            return {"status":"not_ready", "reason":"Preparation deadline exhausted.", "request":spec}, None
        def remaining_preparation():
            left = question_budget.remaining(case_id, "timeout_seconds")
            if left <= 0:
                raise TimeoutError("Preparation deadline exhausted.")
            return left
        def load():
            result = worker.definition_result(native(arguments, timeout),
                lambda values: native(["investigate", "source", root, "--path", values["path"],
                    "--start-line", values["start_line"], "--end-line", values["end_line"]],
                    remaining_preparation()))
            return result
        try:
            # Cached lookups also consume the recipient's bounded research units.
            question_budget.reserve(case_id, "queries", units)
            usage["queries"] += units
            preparation_usage_path = stage / "preparation" / (context.digest([case_id, "usage"]) + ".json")
            preparation_usage_path.parent.mkdir(exist_ok=True)
            worker.write(preparation_usage_path, usage)
            result, reused = preparation_broker.get(key, load, timeout)
            size = len(json.dumps(result, ensure_ascii=False).encode("utf8"))
            usage["bytes"] += size
            worker.write(preparation_usage_path, usage)
            question_budget.reserve(case_id, "bytes", size)
        except (review_orchestration.BudgetExhausted, worker.CommandFailure, TimeoutError) as error:
            return {"status":"not_ready", "reason":str(error), "request":spec}, None
        receipt = {"request":query, "result":result, "reused":reused, "query_units":units}
        receipt_path = stage / "preparation" / (context.digest([case_id, key]) + ".json")
        receipt_path.parent.mkdir(exist_ok=True)
        worker.write(receipt_path, receipt)
        note = {"request":spec, "reused":reused, "query_units":units,
                "receipt":str(receipt_path.relative_to(stage))}
        if not result.get("source_complete"):
            return {**note, "status":"not_ready", "reason":result.get("limit") or "Implementation incomplete."}, None
        window = context.delivered_source_window(root, result)
        extent = context.source_result_window(result)
        if window is None or window["end_line"] != extent["end_line"]:
            return {**note, "status":"not_ready", "reason":"Implementation source is byte-clipped."}, None
        return {**note, "status":"ready", "reason":"One complete declaration supplied; dispatch remains unproven."}, {
            **{key:window[key] for key in ("path", "start_line", "end_line", "source_sha256")},
            "quote":window["text"]}

    def assignment_job(assignment, question=None, question_results=(), prepaid=None, supporting_cards=None, owner_required=True,
                       prepared_question=()):
        profile = "routine" if question is not None or not question_routing else "expert"
        available_assertions = [dep for _, answer in question_results for dep in answer.get("assertions", [])]
        command = source_commands[profile]
        command_binding = command_bindings[profile]
        provider = runtime.get("provider") if profile == "routine" else runtime["orchestration"]["expert"]
        job_id = assignment.get("_job_id", assignment["id"])
        if question is not None:
            job_id = context.digest([job_id, "question", question["id"]])
            assignment = {**assignment, "review_ids": []}
        directory = stage / "jobs" / job_id
        directory.mkdir(parents=True, exist_ok=bool(source_resume))
        offline = bool(source_resume and job_id in recovery_jobs)
        if offline and (directory / "result.json").is_file():
            return worker.read(directory / "result.json")
        prior_job = reuse_jobs.get(assignment["id"])
        if prior_job and prior_job[0] != assignment:
            result = {"assignment_id": assignment["id"], "status": "incomplete", "review_ids": assignment["review_ids"],
                      "error": "PriorMembershipChanged", "detail": "Prior completed assignment has different native membership; preserve its exact proof without replay.",
                      "queries": 0, "bytes": 0, "calls": 0, "unknown_provider_calls": 0, "seconds": 0}
            worker.write(directory / "result.json", result)
            return result
        if prior_job and prior_job[0] == assignment:
            _, previous, prior_result, prior_plan_id = prior_job
            try:
                admission = reused_source_result(assignment, previous, plan)
                worker.write(directory / "admission.json", admission)
                native(["investigate", "source-review-check", root, "--inventory", inventory,
                        "--input", directory / "admission.json"])
                result = {**previous, "calls": 0, "queries": 0, "bytes": 0, "seconds": 0,
                          "unknown_provider_calls": 0,
                          "reuse": {"prior_result": str(prior_result), "prior_plan_id": prior_plan_id, "prior_calls": previous["calls"],
                                    "note": "Previously completed assessment; not a new review under current guidance. Prior usage remains in the original attempt."}}
            except Exception as error:
                result = {"assignment_id": assignment["id"], "status": "incomplete", "review_ids": assignment["review_ids"],
                          "error": type(error).__name__, "detail": str(error), "queries": 0, "bytes": 0,
                          "calls": 0, "unknown_provider_calls": 0, "seconds": 0,
                          "prior_source_attempt": str(prior_result.parent.parent.parent.parent)}
            worker.write(directory / "result.json", result)
            return result
        if overlaps_partial(assignment):
            result = {"assignment_id": assignment["id"], "status": "incomplete", "review_ids": assignment["review_ids"],
                      "error": "PriorPartialSource", "detail": "Prior incomplete source work overlaps; no automatic replacement call.",
                      "queries": 0, "bytes": 0, "calls": 0, "unknown_provider_calls": 0, "seconds": 0,
                      "prior_source_attempts": [str(path) for path in reuse_paths]}
            worker.write(directory / "result.json", result)
            return result
        domain_case = case_by_assignment.get(assignment.get("_work_item_id", job_id))
        if question is not None:
            domain_case = {**domain_case, "checks": [question]}
        domain_state = domain_states[domain_case["domain_id"]] if domain_case else None
        if question is not None:
            signals = [review_domains._shared_fact(cite, plan) for cite in domain_case["focus"]["signal"]["evidence"]]
            domain_state = {**domain_state, "shared_facts":[*domain_state["shared_facts"], *signals]}
        case_index = next(i for i, c in enumerate(domain_state["cases"]) if c["id"] == domain_case["id"]) if domain_case else 0
        source_offset = case_index * 1000
        # Keep the native exporter and sweep, including their SQL/control facts,
        # while avoiding bundle preparation for deferred or already settled jobs.
        try:
            card_ids = ([rid for role in review_domains.ROLES for rid in domain_case["review_roles"][role]]
                        if domain_case else assignment["review_ids"])
            native_cards = supporting_cards if supporting_cards is not None else load_native_cards(native, root, inventory, stage, card_ids, job_id)
        except Exception as error:
            result = {"assignment_id": assignment["id"], "status": "incomplete",
                      "review_ids": assignment["review_ids"], "error": type(error).__name__,
                      "detail": getattr(error, "stderr", str(error)), "queries": 0, "bytes": 0,
                      "calls": 0, "unknown_provider_calls": 0, "seconds": 0}
            worker.write(directory / "result.json", result)
            return result
        known = [
            {**entries[i], **native_cards.get(i, {})} for i in assignment["review_ids"]
        ]
        windows = [
            {
                **w,
                "side": "current",
                "artifact_id": context.digest([plan["plan_id"], w]),
                "complete_file": False,
            }
            for w in (review_questions.owner_windows(assignment, domain_case["focus"]) if question is not None else assignment["windows"])
        ]
        packet = {
            "schema_version": "1",
            "source_binding": {
                "snapshot_id": payload["snapshot_id"],
                "inventory_input_fingerprint": payload["inventory_input_fingerprint"],
            },
            "contract": contract + "".join(
                "\n" + guide["text"] for guide in context.language_contracts(
                    skill, [w["path"] for w in assignment["windows"]]
                )
            ),
            "work": context.compact_work(payload, assignment["review_ids"]),
            "native_questions": known,
            "primary": {"windows": windows, "limits": plan["limitations"]},
            "source_assignment_id": assignment["id"],
        }
        packet["known_native_questions"] = [
            {
                k: e.get(k)
                for k in (
                    "review_id",
                    "path",
                    "line",
                    "rule_id",
                    "capability",
                    "cwe_candidates",
                    "operand_facts",
                )
            }
            for e in entries.values()
            if e["review_id"] in selected_native_ids and any(
                w["path"] == e["path"] and w["start_line"] <= e["line"] <= w["end_line"]
                for w in assignment["windows"]
            )
        ]
        if assignment["id"] in focus:
            packet["review_focus"] = domain_case["focus"] if work_registry else focus[assignment["id"]]
            if not domain_case:
                packet["contract"] += ("\nInvestigate the named operation and question in review_focus. Assigned windows provide context; "
                "coverage applies only to that question, and unrelated functions were not audited. Treat the focus as a question, "
                "not evidence or an expected answer. Inspect deciding relationships within the existing allowance.")
        if domain_case:
            packet["contract"] = domain_state["contract"]
            # Shared source text is delivered once as inspected f-evidence below;
            # the stable prefix needs its bindings, not a second copy of code.
            packet["domain_shared_facts"] = [{k: v for k, v in cite.items() if k != "quote"}
                                             for cite in domain_state["shared_facts"]]
            packet["domain_case"] = {"id": domain_case["id"], "domain_id": domain_case["domain_id"],
                "review_roles": domain_case["review_roles"],
                "coverage_markers": [{**entries[rid], **native_cards[rid]} for rid in domain_case["review_roles"]["cover"]],
                "context_facts": [{"review_id": rid, "facts": native_cards[rid]["facts"]}
                                  for rid in domain_case["review_roles"]["context"]]}
        elif assignment["review_ids"]:
            packet["contract"] += ("\nAssess every assigned native question independently, preserving its actor, operands, guards and effect. "
                "Any additional review_focus supplements these questions and cannot remove them. Shared source is not a shared verdict. "
                "Do not audit unrelated functions merely because they occur in the supplied context windows.")
        if work_registry:
            packet["work_item"] = {"id": domain_case["id"], "actor": domain_case["actor"],
                "conditions": domain_case["conditions"], "checks": domain_case["checks"]}
            packet["contract"] += ("\nReview the named work item's required checks and assigned Verify IDs. "
                "Its actor and conditions describe the planning scope, not established source facts. "
                "Bind actual applicability and protected effects with cited evidence. Do not expand into a general lifecycle audit. "
                "Finalize once each required check has an evidenced answer or a concrete unresolved deciding fact.")
        if question_routing:
            packet["job_binding"] = {"profile":profile, "role":"question_answerer" if question is not None else "investigator", "provider":provider}
        if question is not None:
            packet["contract"] = review_questions.FACT_CONTRACT
            packet["native_questions"] = []
            packet["known_native_questions"] = []
            packet["supporting_native_facts"] = [{"review_id":rid, "facts":card["facts"]}
                for rid, card in native_cards.items()]
            packet["review_focus"] = {"question":question["question"], "scope":question["scope"], "acceptance":question["acceptance"]}
        elif question_results:
            packet["question_answers"] = [review_questions.answer_note(check, result) for check, result in question_results]
            packet["contract"] += ("\nQuestion answers are attributed model interpretations, not security verdicts. "
                "Reuse the delivered original source; inspect the deciding relationship and remaining applicability/impact. "
                "Do not repeat source searches simply to recreate the question worker's evidence. Conflicting or incomplete answers remain unresolved.")
        worker.write(directory / "context.json", packet)
        conversation = context.digest(
            [package["package_id"], "source_review", assignment.get("_work_item_id", job_id), str(lineage_output),
             *([["question", question["id"]]] if question is not None else [])]
        )
        facts = copy.deepcopy(domain_state["facts"]) if domain_state else []
        inspected = copy.deepcopy(domain_state["inspected"]) if domain_state else []
        citation_windows = {
            "s" + str(source_offset + i): {
                **{k: w[k] for k in ("path", "start_line", "end_line")},
                "anchor": True,
            }
            for i, w in enumerate(windows)
        }
        if domain_state:
            citation_windows.update(copy.deepcopy(domain_state["citation_windows"]))
        queries = 0
        received = 0
        calls = 0
        unknown_calls = 0
        started = time.monotonic()
        last = None
        local_rounds = min(limits["rounds"], 1) if question is not None else limits["rounds"]
        local_seconds = limits["timeout_seconds"]
        if question is not None and owner_required:
            local_seconds = min(local_seconds, max(0, question_budget.remaining(domain_case["id"], "timeout_seconds")) / 2)
        working_chain = ""
        feedback = None

        def remaining():
            left = local_seconds - (time.monotonic() - started)
            if question_budget:
                left = min(left, question_budget.remaining(domain_case["id"], "timeout_seconds"))
            if left <= 0:
                raise TimeoutError("source assignment deadline exhausted")
            return left

        def offer_source(result, handle):
            candidate = context.delivered_source_window(root, result)
            if candidate is not None:
                inspected.append(candidate)
                citation_windows[handle] = {
                    **{k: candidate[k] for k in ("path", "start_line", "end_line")},
                    "anchor": False,
                }

        if domain_state and not facts:
            for cite in domain_state["shared_facts"]:
                if work_registry:
                    hydrated = review_domains._shared_fact({key: cite[key] for key in ("path", "start_line", "end_line")}, plan)
                    if hydrated["source_sha256"] != cite["source_sha256"]:
                        raise ValueError("work evidence source binding changed")
                    cite = hydrated
                prepared = {"operation": "prepared_source", "results": {
                    **{k: cite[k] for k in ("path", "start_line", "end_line")}, "text": cite["quote"]}}
                fact = {"result_id": context.digest([domain_state["id"], cite]),
                        "query": {"tool": "source", "review_id": None, "purpose": "Controller-supplied shared domain source",
                                  "arguments": {k: cite[k] for k in ("path", "start_line", "end_line")}},
                        "result": prepared}
                facts.append(fact)
                offer_source(prepared, "f" + str(len(facts) - 1))

        for _, answer in question_results:
            for fact in answer.get("facts", []):
                if any(f["result_id"] == fact["result_id"] for f in facts):
                    continue
                facts.append(copy.deepcopy(fact))
                offer_source(fact["result"], "f" + str(len(facts) - 1))

        for cite in prepared_question:
            prepared = {"operation":"prepared_source", "results":{
                **{key:cite[key] for key in ("path", "start_line", "end_line")}, "text":cite["quote"]}}
            window = context.delivered_source_window(root, prepared)
            if window is None or window["source_sha256"] != cite["source_sha256"]:
                raise ValueError("Prepared implementation source binding changed")
            fact = {"result_id":context.digest(["question-preparation", cite]),
                "query":{"tool":"source", "review_id":None, "purpose":"Controller-prepared deciding source",
                    "arguments":{key:cite[key] for key in ("path", "start_line", "end_line")}},
                "result":prepared}
            if not any(previous["result_id"] == fact["result_id"] for previous in facts):
                facts.append(fact)
                offer_source(prepared, "f" + str(len(facts) - 1))

        checkpoint_binding = context.digest([packet, command_binding, provider, conversation])

        def save_checkpoint(phase, turn, lease=None):
            if work_registry:
                source_recovery.save(directory / "recovery.json", checkpoint_binding, phase,
                    {"turn":turn, "provider":provider, "lease":lease, "last":last,
                     "facts":facts, "inspected":inspected, "citation_windows":citation_windows,
                     "queries":queries, "bytes":received, "calls":calls, "unknown_provider_calls":unknown_calls,
                     "seconds":time.monotonic() - started}, budget_path, worker)

        try:
            if offline:
                saved = source_recovery.checkpoint(directory / "recovery.json", checkpoint_binding, worker)
                if saved:
                    facts, inspected, citation_windows = saved["facts"], saved["inspected"], saved["citation_windows"]
                    queries, received, calls, unknown_calls = (saved[k] for k in ("queries", "bytes", "calls", "unknown_provider_calls"))
                    started -= saved["seconds"]
                    last = saved["last"]
                    # A crash after the raw response write can precede the draft checkpoint.
                    response_path = directory / (str(saved["turn"]) + "-response.json")
                    if saved["phase"] == "inflight":
                        receipt = worker.observed_turn(directory, {"conversation_id":conversation, "round":saved["turn"]},
                            provider, require_complete_usage=False)
                        if receipt or not runtime.get("provider") and response_path.is_file():
                            unknown_calls = max(0, unknown_calls - 1)
                            if response_path.is_file():
                                last = worker.read(response_path).get("draft")
                if last is None:
                    raise ValueError("Interrupted source research retained; no automatic replacement model call")
            else:
                save_checkpoint("ready", 0)
            for turn in (() if offline else range(local_rounds + 1)):
                if native(["state", "work", *common, *runtime_options]) != package:
                    raise ValueError("source work was superseded")
                if context.skill_bundle_id(skill) != runtime["skill_bundle_id"]:
                    raise ValueError("source skill changed")
                if (
                    context.digest(
                        [
                            command,
                            [
                                worker.digest_file(value)
                                for value in command
                                if Path(value).is_file()
                            ],
                        ]
                    )
                    != command_binding
                ):
                    raise ValueError("source reviewer configuration changed")
                aliases = {
                    "s" + str(source_offset + i): w["artifact_id"] for i, w in enumerate(windows)
                }
                aliases.update(
                    {"f" + str(i): f["result_id"] for i, f in enumerate(facts)}
                )
                source_ids = {
                    f["result_id"]
                    for f in facts
                    if f["result"].get("operation")
                    in ("get_source", "get_definition", "prepared_source")
                }
                source_handles = [
                    h
                    for h, value in aliases.items()
                    if value in source_ids
                    or value in {w["artifact_id"] for w in windows}
                ]
                worker.write(directory / "facts.json", {"facts": facts})
                frame = {
                    "schema_version": "1",
                    "kind": "source_review",
                    "source_root": str(root),
                    "conversation_id": conversation,
                    "scanner": str(scanner),
                    "inventory": str(inventory),
                    "work_package": str(args.work_package),
                    "review_ids": assignment["review_ids"],
                    "review_role": "question_answerer" if question is not None else "investigator",
                    "followup_selection": True,
                    "evidence_packet": str(directory / "context.json"),
                    "shared_facts": str(directory / "facts.json"),
                    "provider_metrics": str(
                        directory / ("provider-metrics-" + conversation + ".jsonl")
                    ),
                    "artifact_root": str(
                        Path(args.artifact_root).resolve()
                        if args.artifact_root
                        else output
                    ),
                    "research": {
                        "round": turn,
                        "rounds_remaining": local_rounds - turn,
                        "queries_remaining": (
                            limits["queries"] - queries
                            if turn < local_rounds
                            else 0
                        ),
                        "bytes_remaining": limits["bytes"] - received,
                        "seconds_remaining": remaining(),
                        "artifact_handles": aliases,
                        "source_artifact_handles": source_handles,
                        "coverage_windows": {
                            "s" + str(source_offset + i): {k: w[k] for k in ("path", "start_line", "end_line")}
                            for i, w in enumerate(windows)
                        },
                        "citation_windows": dict(citation_windows),
                        "results": [],
                        "working_chain": working_chain,
                        "progress": [],
                        "feedback": feedback,
                    },
                }
                if question_routing:
                    frame["profile"] = profile
                    frame["research"]["rounds_remaining"] = min(frame["research"]["rounds_remaining"],
                        max(0, question_budget.remaining(domain_case["id"], "model_calls") -
                            (completion_remaining(domain_case["id"]) + 1 if question is not None and owner_required else 1)))
                    frame["research"]["queries_remaining"] = min(frame["research"]["queries_remaining"],
                        max(0, question_budget.remaining(domain_case["id"], "queries")))
                if question is not None:
                    frame["research"]["question_only"] = True
                if domain_case and question is None:
                    frame["domain_session"] = {"id": domain_state["id"], "binding": domain_state["binding"],
                        "case_id": domain_case["id"], "case_index": case_index, "cases": domain_state["cases"]}
                    if getattr(args, "domain_session_mode", "shared") == "isolated":
                        frame["domain_session"] = {"id": context.digest([domain_state["id"], domain_case["id"]]),
                            "binding": context.digest([domain_state["binding"], domain_case["id"]]),
                            "case_id": domain_case["id"], "case_index": 0, "cases": [domain_state["cases"][case_index]]}
                if work_registry:
                    frame["research"]["required_checks"] = domain_case["checks"]
                    if available_assertions:
                        frame["research"]["available_assertions"] = available_assertions
                worker.write(directory / (str(turn) + "-input.json"), frame)
                worker.write(directory / (str(turn) + "-facts.json"), {"facts": facts})
                if question_budget:
                    if question is not None and question_budget.remaining(domain_case["id"], "model_calls") <= (completion_remaining(domain_case["id"]) if owner_required else 0):
                        raise review_orchestration.BudgetExhausted("Reserved final owner call; question work stopped")
                if prepaid is not None and budget_path and review_budget.snapshot(budget_path).get("fenced"):
                    raise review_budget.BudgetExhausted("Observed usage fenced further calls")
                lease = (prepaid if turn == 0 and prepaid is not None else
                    review_budget.reserve(budget_path, frame["kind"], lane=lane_by_id.get(assignment["id"]),
                        completion_owner=domain_case["id"] if work_registry and question is None else None) if budget_path else None)
                if question_budget:
                    try:
                        question_budget.reserve(domain_case["id"], "model_calls", 1)
                    except review_orchestration.BudgetExhausted:
                        if lease is not None:
                            review_budget.abandon(budget_path, lease)
                        raise
                if budget_path:
                    budget_state = review_budget.snapshot(budget_path)
                    remaining_calls = budget_state["max_calls"] - budget_state["reserved_calls"] - review_budget.held_calls(
                        budget_state, domain_case["id"] if work_registry and question is None else None)
                    lane_state = budget_state.get("lanes", {}).get(lane_by_id.get(assignment["id"]))
                    if lane_state:
                        remaining_calls = min(remaining_calls, lane_state["allocation"] - lane_state["reserved_calls"])
                    frame["research"]["rounds_remaining"] = min(frame["research"]["rounds_remaining"], remaining_calls)
                    if remaining_calls == 0:
                        frame["research"]["queries_remaining"] = 0
                    worker.write(directory / (str(turn) + "-input.json"), frame)
                calls += 1
                unknown_calls += 1
                save_checkpoint("inflight", turn, lease)
                response = worker.execute_provider(command, directory, env, remaining(), frame,
                                                   provider, budget_path, lease=lease)
                worker.write(directory / (str(turn) + "-response.json"), response)
                receipt = worker.observed_turn(
                    directory,
                    frame["research"] | {"conversation_id": conversation},
                    provider,
                    require_complete_usage=False,
                )
                if runtime.get("provider") and receipt is None:
                    raise ValueError(
                        "source provider usage is unknown; no automatic retry"
                    )
                if receipt:
                    if work_registry:
                        receipt["work_item_id"] = domain_case["id"]
                    source_metrics.append(receipt)
                    unknown_calls -= 1
                elif not runtime.get("provider"):
                    unknown_calls -= 1
                if "draft" in response:
                    last = response["draft"]
                    save_checkpoint("draft", turn, lease)
                    break
                save_checkpoint("research", turn, lease)
                if turn == local_rounds:
                    raise ValueError(
                        "source reviewer requested evidence after final consuming call"
                    )
                requests = response.get("research", [])
                if not requests:
                    raise ValueError(
                        "source reviewer returned neither a draft nor a deciding lookup"
                    )
                working_chain = response.get("working_chain", "")
                try:
                    requests, prepared, feedback = worker.research_batch_plan(
                        requests,
                        root,
                        [],
                        directory,
                        limits["queries"] - queries,
                        api=api,
                        guidance=guidance,
                    )
                except worker.ResearchBatchError as error:
                    feedback = {"reason":"invalid_research_arguments", "errors":error.errors,
                        "instruction":"No query executed. Repair only the reported arguments within the remaining allowance, or preserve the missing fact."}
                    worker.write(directory / (str(turn) + "-lookup-feedback.json"), feedback)
                    continue
                if question_budget:
                    question_budget.reserve(domain_case["id"], "queries", worker.research_cost(requests, api=api))
                queries += worker.research_cost(requests, api=api)
                batch = []
                for query, arguments in zip(requests, prepared):
                    try:
                        if query["tool"] == "guidance":
                            result = context.load_guidance(
                                skill, query["arguments"]["name"]
                            )
                        elif query["tool"] == "base_source":
                            result = context.read_base_source(
                                root,
                                (payload["impact_scope"] or {}).get("comparison"),
                                query["arguments"],
                                env,
                                remaining,
                            )
                        else:
                            result = native(arguments, remaining())
                        if query["tool"] == "definition":

                            def read_definition(values):
                                return native(
                                    [
                                        "investigate",
                                        "source",
                                        root,
                                        "--path",
                                        values["path"],
                                        "--start-line",
                                        values["start_line"],
                                        "--end-line",
                                        values["end_line"],
                                    ],
                                    remaining(),
                                )

                            def find_definition_text():
                                values = query["arguments"]
                                fallback = {
                                    "tool": "references",
                                    "review_id": None,
                                    "arguments": {
                                        "symbol": values["name"],
                                        **{
                                            k: values[k]
                                            for k in ("path", "path_prefix", "limit")
                                            if k in values
                                        },
                                    },
                                }
                                return native(
                                    worker.research_arguments(
                                        fallback,
                                        root,
                                        [],
                                        directory,
                                        api=api,
                                        guidance=guidance,
                                    ),
                                    remaining(),
                                )

                            result = worker.definition_result(
                                result, read_definition, find_definition_text
                            )
                    except worker.CommandFailure as error:
                        result = worker.missing_source_result(query, error)
                        if result is None:
                            raise
                    size = len(json.dumps(result, ensure_ascii=False).encode())
                    if question_budget:
                        question_budget.reserve(domain_case["id"], "bytes", size)
                    if received + size > limits["bytes"]:
                        raise ValueError(
                            "source result exceeds received-byte allowance"
                        )
                    received += size
                    item = {
                        "result_id": context.digest(
                            [conversation, turn, len(facts), result]
                        ),
                        "query": query,
                        "result": result,
                    }
                    if getattr(arguments, "filter_normalization", None):
                        item["filter_normalization"] = arguments.filter_normalization
                    facts.append(item)
                    batch.append(item)
                    worker.write(directory / (str(turn) + "-lookups.json"), batch)
                    offer_source(result, "f" + str(len(facts) - 1))
                    save_checkpoint("research", turn, lease)
                worker.write(directory / (str(turn) + "-lookups.json"), batch)
                save_checkpoint("ready", turn + 1)
            if last is None:
                raise ValueError("source review did not finalize its assignment")
            if question is not None:
                review_questions.check_draft(last)
            if work_registry:
                # Different work items may inspect the same physical assignment.
                # Namespace proposal keys without changing their evidence/verdicts.
                for proposal in last["proposals"]:
                    proposal["key"] = "work-" + context.digest([domain_case["id"], proposal["key"]])
            expected = {
                (w["path"], w["start_line"], w["end_line"])
                for w in windows
            }
            actual = [
                (w["path"], w["start_line"], w["end_line"]) for w in last["coverage"]
            ]
            if len(actual) != len(set(actual)) or set(actual) != expected:
                raise ValueError(
                    "source coverage must describe assigned ranges exactly once"
                )
            returned = [r["review_id"] for r in last["results"]]
            if len(returned) != len(set(returned)) or set(returned) != set(
                assignment["review_ids"]
            ):
                raise ValueError("source assessments changed native membership")
            visible = [*assignment["windows"], *inspected]

            followups = worker.second_pass.take_followups(last)
            context_errors = []
            claim_contexts = worker.second_pass.take_claim_contexts(last, errors=context_errors)
            proposal_followups = {}
            proposal_contexts = {}
            for proposal in last["proposals"]:
                assessed = proposal["assessment"]
                wrapped = {"results":[{**assessed, "review_id":proposal["key"]}]}
                notes = worker.second_pass.take_followups(wrapped)
                contexts = worker.second_pass.take_claim_contexts(wrapped, errors=context_errors)
                assessed.pop("followup", None)
                assessed.pop("claim_context", None)
                if notes:
                    proposal_followups[proposal["key"]] = notes[0]
                if contexts:
                    proposal_contexts[proposal["key"]] = contexts[0]

            def citations(assessment):
                result = []
                for cite in assessment.get("evidence", []):
                    lines = {
                        w["start_line"] + i: line
                        for w in visible
                        if w["path"] == cite["path"]
                        for i, line in enumerate(w["text"].split("\n"))
                    }
                    first, last = cite["start_line"], cite["end_line"]
                    if (
                        not 1 <= first <= last
                        or last - first >= 400
                        or any(n not in lines for n in range(first, last + 1))
                    ):
                        raise ValueError("assessment cites unseen source")
                    quote = "\n".join(lines[n] for n in range(first, last + 1))
                    result.append(
                        {
                            **{k: cite[k] for k in ("path", "start_line", "end_line")},
                            "quote": quote,
                        }
                    )
                return result

            proofs = []
            if work_registry:
                review_work.check_results(domain_case["checks"], last.get("work_checks"),
                    available_assertions if available_assertions else None)
                for check in last["work_checks"]:
                    proofs.extend(citations(check))
            for assessment in last["results"]:
                proofs.extend(citations(assessment))
            proposals = []
            for proposal in last["proposals"]:
                proofs.extend(citations(proposal["assessment"]))
                proposals.append(
                    {k: v for k, v in proposal.items() if k != "assessment"}
                    | {
                        "assignment_id": assignment["id"],
                        "anchor": citations({"evidence": [proposal["anchor"]]})[0],
                        "evidence": citations({"evidence": proposal["evidence"]}),
                    }
                )
            admission = {
                "plan": plan,
                "inspected": inspected,
                "proposals": proposals,
                "assessment_evidence": proofs,
            }
            worker.write(directory / "admission.json", admission)
            native(
                [
                    "investigate",
                    "source-review-check",
                    root,
                    "--inventory",
                    inventory,
                    "--input",
                    directory / "admission.json",
                ]
            )
            result = {
                "assignment_id": assignment["id"],
                "status": "complete",
                "draft": last,
                "inspected": inspected,
                "proofs": proofs,
                "proposals": proposals,
                "facts": facts,
                "followups": followups,
                "claim_contexts": claim_contexts,
                "claim_context_errors": context_errors,
                "proposal_followups": proposal_followups,
                "proposal_contexts": proposal_contexts,
                "queries": queries,
                "bytes": received,
                "calls": calls,
                "unknown_provider_calls": unknown_calls,
                "seconds": time.monotonic() - started,
            }
            if domain_state and question is None:
                domain_state["facts"] = copy.deepcopy(facts)
                domain_state["inspected"] = copy.deepcopy(inspected)
                domain_state["citation_windows"] = {k: copy.deepcopy(v) for k, v in citation_windows.items() if k.startswith("f")}
        except Exception as error:
            if unknown_calls and "frame" in locals():
                receipt = worker.observed_turn(
                    directory,
                    frame["research"] | {"conversation_id": conversation},
                    provider,
                    require_complete_usage=False,
                )
                if receipt:
                    source_metrics.append(receipt)
                    unknown_calls -= 1
            result = {
                "assignment_id": assignment["id"],
                "status": "incomplete",
                "error": type(error).__name__,
                "detail": getattr(error, "stderr", str(error)),
                "review_ids": assignment["review_ids"],
                "queries": queries,
                "bytes": received,
                "calls": calls,
                "unknown_provider_calls": unknown_calls,
                "seconds": time.monotonic() - started,
                "facts": facts,
                "inspected": inspected,
            }
        if question is not None:
            result.update(question_provider=provider, question_conversation_id=conversation)
        worker.write(directory / "result.json", result)
        return result

    results = [{"assignment_id": a["id"], "status": "deferred", "review_ids": a["review_ids"],
                "error": "SourceNotSelected", "detail": "Outside selected operations; not reviewed.",
                "queries": 0, "bytes": 0, "calls": 0, "unknown_provider_calls": 0, "seconds": 0}
               for a in plan["assignments"] if a["id"] not in selected_set]
    worker.write(stage / "progress.json", results)
    if domain_registry:
        domain_progress = {}
        domain_timings = {}
        domain_lock = worker.threading.Lock()

        def domain_job(domain):
            domain_started = time.monotonic()
            completed = []
            stopped = None
            for case in domain["cases"]:
                assignment = by_id[case["assignment_id"]]
                reason = stopped or review_budget.capacity(budget_path)
                if reason:
                    result = review_scheduler.deferred(assignment, reason)
                else:
                    with domain_lock:
                        domain_progress[case["id"]] = {"assignment_id": assignment["id"], "domain_id": domain["id"],
                            "case_id": case["id"], "status": "running", "calls": 0}
                        worker.write(stage / "domain-progress.json", list(domain_progress.values()))
                    result = assignment_job(assignment)
                result.update(domain_id=domain["id"], case_id=case["id"])
                if (stage / "jobs" / assignment["id"]).is_dir():
                    worker.write(stage / "jobs" / assignment["id"] / "result.json", result)
                completed.append(result)
                if result["status"] != "complete":
                    # A failed case may leave an unsealed/unknown provider turn.
                    # Do not skip to a later case or silently restart its thread.
                    stopped = "Earlier domain case did not complete; no automatic conversation replay."
                with domain_lock:
                    domain_progress[case["id"]] = {k: result[k] for k in ("assignment_id", "domain_id", "case_id", "status", "calls")}
                    worker.write(stage / "domain-progress.json", list(domain_progress.values()))
            domain_timings[domain["id"]] = time.monotonic() - domain_started
            return completed

        if work_registry:
            work_lock = worker.threading.Lock()

            def save_work():
                report = review_work.ledger(work_registry, case_store.results(),
                    budget=review_budget.snapshot(budget_path), metrics=list(source_metrics))
                worker.write(stage / "work-ledger.json", report)
                worker.write_text(stage / "remaining-work.md", review_work.markdown(report))

            jobs = [{"id": case["id"], "case": case, "review_ids": case["verify_review_ids"]}
                    for case in work_registry["cases"]]

            def admit_work(job):
                case = job["case"]
                if question_budget and review_questions.fact_only(case):
                    job["completion"] = {"requested":0, "granted":0, "remaining":0}
                    return
                desired = max(1, min(case["estimate"].get("owner_calls", [1, 2])[1], limits["rounds"] + 1, 6))
                if question_budget:
                    desired = min(desired, runtime["orchestration"]["case_limits"]["model_calls"])
                job["completion"] = review_budget.hold_completion(budget_path, case["id"], desired)

            def execute_work(job):
                case = job["case"]
                case_started = time.monotonic()
                with work_lock:
                    case_store.submit("start:" + case["id"], {"kind":"start", "case_id":case["id"]})
                    save_work()
                job_directory = context.digest(["work-item", case["id"]])
                assignment = {**by_id[case["assignment_id"]], "_job_id": job_directory, "_work_item_id": case["id"],
                              "review_ids": case["verify_review_ids"]}
                answers = []
                preparation = {}
                routing = {check["id"]:review_questions.route_check(check) for check in case["checks"]}
                if not question_budget:
                    for decision in routing.values():
                        decision.update(effective_route="owner", reason="Optional factual assistance is disabled.")
                saved_preparation_path = stage / "preparation" / (context.digest([case["id"], "case"]) + ".json")
                saved_preparation = (worker.read(saved_preparation_path) if case["id"] in recovery_cases
                    and saved_preparation_path.is_file() else {})
                preparation.update(saved_preparation.get("readiness", {}))
                preparation_usage_path = stage / "preparation" / (context.digest([case["id"], "usage"]) + ".json")
                preparation_usage = (worker.read(preparation_usage_path) if case["id"] in recovery_cases
                    and preparation_usage_path.is_file() else {"queries":0, "bytes":0})
                owner_prepared = saved_preparation.get("source", [])
                skipped_reason = "Question preparation did not start; owner reservation or source collection did not complete."
                prepaid = None
                fact_only = bool(question_budget and review_questions.fact_only(case))
                if question_budget:
                    question_budget.begin_case(case["id"])
                try:
                    if question_budget:
                        cards = load_native_cards(native, root, inventory, stage,
                            [rid for role in review_domains.ROLES for rid in case["review_roles"][role]], job_directory)
                        for check in case["checks"]:
                            decision = routing[check["id"]]
                            if decision["effective_route"] != "prepare":
                                continue
                            if case["id"] in recovery_cases:
                                # Offline finalization consumes original facts/answers only.
                                if context.digest([job_directory, "question", check["id"]]) not in recovery_jobs:
                                    decision.update(effective_route="blocked" if fact_only else "owner",
                                        reason="Unstarted optional work skipped during recovery; owner retains the check.")
                                    continue
                                answer = assignment_job(assignment, question=check, supporting_cards=cards,
                                    owner_required=not fact_only)
                                answer["assertions"] = case_store.record_question(case["id"], check,
                                    stage / "jobs" / context.digest([job_directory, "question", check["id"]]) / "result.json")
                                answers.append((check, answer))
                                decision.update(effective_route="fact_worker", reason="Saved source question; no replacement inference.")
                                continue
                            if (question_budget.remaining(case["id"], "model_calls") <= completion_remaining(case["id"])
                                    or review_budget.capacity(budget_path)):
                                skipped_reason = "Shared allowance preserves the owner turn or prevents further question calls."
                                decision.update(effective_route="blocked" if fact_only else "owner", reason=skipped_reason)
                                continue
                            readiness, prepared = review_questions.prepare_check(check,
                                lambda cite: review_domains._shared_fact(cite, plan),
                                lambda spec: prepare_definition(case["id"], spec, preparation_usage))
                            owner_prepared.extend(prepared)
                            preparation[check["id"]] = readiness
                            saved_preparation_path.parent.mkdir(exist_ok=True)
                            worker.write(saved_preparation_path, {"readiness":preparation, "source":owner_prepared})
                            if readiness["status"] != "ready":
                                decision.update(effective_route="blocked" if fact_only else "owner", reason=readiness["reason"])
                                continue
                            if (question_budget.remaining(case["id"], "model_calls") <= completion_remaining(case["id"])
                                    or review_budget.capacity(budget_path)):
                                skipped_reason = "Shared allowance preserves the owner turn or prevents further question calls."
                                decision.update(effective_route="blocked" if fact_only else "owner", reason=skipped_reason)
                                continue
                            decision.update(effective_route="fact_worker", reason=readiness["reason"])
                            answer = assignment_job(assignment, question=check, supporting_cards=cards,
                                owner_required=not fact_only, prepared_question=prepared)
                            answer["assertions"] = case_store.record_question(case["id"], check,
                                stage / "jobs" / context.digest([job_directory, "question", check["id"]]) / "result.json")
                            answers.append((check, answer))
                            with work_lock:
                                save_work()
                    result = (review_questions.fact_only_result(assignment, case["checks"], answers) if fact_only else
                        assignment_job(assignment, question_results=answers, prepaid=prepaid,
                            supporting_cards=cards if question_budget else None, prepared_question=owner_prepared))
                except (review_budget.BudgetExhausted, review_orchestration.BudgetExhausted) as error:
                    result = {**review_scheduler.deferred(job, str(error)), "assignment_id":assignment["id"]}
                except Exception as error:
                    result = {"assignment_id":assignment["id"], "review_ids":assignment["review_ids"],
                        "status":"incomplete", "error":type(error).__name__, "detail":getattr(error, "stderr", str(error)),
                        "calls":0, "queries":0, "bytes":0, "unknown_provider_calls":0, "seconds":0}
                finally:
                    if prepaid is not None:
                        review_budget.abandon(budget_path, prepaid)
                    if not fact_only:
                        review_budget.release_completion(budget_path, case["id"])
                    if question_budget:
                        question_budget.end_case(case["id"])
                if question_budget:
                    result["question_work"] = review_questions.execution_notes(case["checks"], answers,
                        runtime["provider"], lambda check_id:"source-review/jobs/" + context.digest(
                            [job_directory, "question", check_id]), skipped_reason, preparation, routing)
                    for key in ("calls", "queries", "bytes", "unknown_provider_calls"):
                        result[key] += sum(answer[key] for _, answer in answers)
                    for key in ("queries", "bytes"):
                        result[key] += preparation_usage[key]
                    result["seconds"] = time.monotonic() - case_started
                result.update(case_id=case["id"], domain_id=case["domain_id"], job_directory="source-review/jobs/" + job_directory)
                for decision in routing.values():
                    decision["provider"] = (runtime["provider"] if decision["effective_route"] == "fact_worker" else
                        runtime["orchestration"]["expert"] if question_budget and decision["effective_route"] == "owner" else
                        runtime.get("provider") if decision["effective_route"] == "owner" else None)
                result["routing"] = list(routing.values())
                result["completion_reservation"] = review_budget.snapshot(budget_path).get("completion_holds", {}).get(
                    case["id"], copy.deepcopy(job["completion"]))
                (stage / "jobs" / job_directory).mkdir(parents=True, exist_ok=True)
                worker.write(stage / "jobs" / job_directory / "result.json", result)
                return result

            def recover_then_schedule():
                pending = []
                saved_cases = case_store.snapshot()["cases"]
                projected = {result["case_id"]:result for result in case_store.results()}
                for job in jobs:
                    case_id = job["id"]
                    if source_resume and saved_cases[case_id]["result"]:
                        # Keep the original immutable result reference and receipts.
                        results.append(projected[case_id])
                        review_budget.release_completion(budget_path, case_id)
                    elif case_id in recovery_cases:
                        job["completion"] = review_budget.snapshot(budget_path).get("completion_holds", {}).get(
                            case_id, {"requested":0, "granted":0, "remaining":0})
                        path = stage / "jobs" / context.digest(["work-item", case_id]) / "result.json"
                        saved = worker.read(path) if path.is_file() else None
                        if saved and saved.get("case_id") == case_id:
                            review_budget.release_completion(budget_path, case_id)
                            yield job, saved
                        else:
                            yield job, execute_work(job)
                    else:
                        # A hold may have been booked immediately before the start checkpoint.
                        if source_resume and case_id in review_budget.snapshot(budget_path).get("completion_holds", {}):
                            recovery_cases.add(case_id)
                            job["completion"] = review_budget.snapshot(budget_path)["completion_holds"][case_id]
                            yield job, execute_work(job)
                        else:
                            pending.append(job)
                yield from review_scheduler.run({"ai":pending}, execute_work, workers=args.workers,
                    budget_path=budget_path, admit=admit_work)

            for job, result in recover_then_schedule():
                result.update(case_id=job["id"], domain_id=job["id"])
                with work_lock:
                    result_path = stage / "case-results" / (context.digest(job["id"]) + ".json")
                    result_path.parent.mkdir(exist_ok=True)
                    worker.write(result_path, result)
                    case_store.record_result(job["id"], result_path)
                    save_work()
                results.append(result)
                worker.write(stage / "progress.json", results)
        else:
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                futures = [pool.submit(domain_job, domain) for domain in domain_registry["domains"]]
                for future in as_completed(futures):
                    results.extend(future.result())
                    worker.write(stage / "progress.json", results)
        by_case = {result["case_id"]: result for result in results if "case_id" in result}
        for item in domain_registry["lead_accounting"].values():
            case_result = by_case.get(item["case_id"])
            if case_result is None:
                continue
            if case_result["status"] != "complete":
                item.update(status="deferred", case_status=case_result["status"])
            elif item["role"] == "verify":
                item.update(status="assessed", reviewed=True, case_status="complete")
            elif item["role"] == "cover":
                item.update(status="incorporated", case_status="complete")
            else:
                item.update(status="available", case_status="complete")
        worker.write(stage / "lead-accounting.json", domain_registry["lead_accounting"])
        metrics = []
        for path in (stage / "jobs").glob("*/provider-metrics-*.jsonl"):
            metrics.extend(json.loads(line) for line in path.read_text(encoding="utf8").splitlines() if line.strip())
        domain_usage = []
        for domain in domain_registry["domains"]:
            conversations = {case["conversation_id"] for case in domain_states[domain["id"]]["cases"]}
            if question_routing:
                conversations.update(note["conversation_id"] for case in domain["cases"]
                    for note in by_case.get(case["id"], {}).get("question_work", []) if note.get("conversation_id"))
            rows = [row for row in metrics if row.get("conversation_id") in conversations]
            domain_usage.append({"id": domain["id"], "wall_seconds": domain_timings.get(domain["id"], by_case.get(domain["id"], {}).get("seconds", 0)),
                "calls": len(rows), "cold_turns": sum(not row.get("resumed", False) for row in rows),
                "warm_case_starts": sum(bool(row.get("resumed") and row.get("domain_case_start")) for row in rows),
                "input_tokens": sum(row.get("usage", {}).get("input_tokens", 0) or 0 for row in rows),
                "cached_input_tokens": sum(row.get("usage", {}).get("cached_input_tokens", 0) or 0 for row in rows),
                "output_tokens": sum(row.get("usage", {}).get("output_tokens", 0) or 0 for row in rows),
                "max_turn_input_tokens": max((row.get("usage", {}).get("input_tokens", 0) or 0 for row in rows), default=0),
                "provider_elapsed_ms": sum(row.get("elapsed_ms", 0) or 0 for row in rows)})
        worker.write(stage / "domain-metrics.json", {
            "session_mode": getattr(args, "domain_session_mode", "shared"),
            "domains": len(domain_registry["domains"]), "cases": len(domain_registry["cases"]),
            "completed_cases": sum(result["status"] == "complete" for result in by_case.values()),
            "provider_calls": sum(result["calls"] for result in by_case.values()),
            "unknown_provider_calls": sum(result["unknown_provider_calls"] for result in by_case.values()),
            "usage_complete": (len(metrics) == sum(result["calls"] for result in by_case.values())
                and not any(result["unknown_provider_calls"] for result in by_case.values())
                and all(not set(row.get("unknown_delta_counters", [])).intersection(("input_tokens", "cached_input_tokens", "output_tokens"))
                        and all(type(row.get("usage", {}).get(key)) is int for key in ("input_tokens", "cached_input_tokens", "output_tokens"))
                        for row in metrics)),
            "cold_turns": sum(not row.get("resumed", False) for row in metrics),
            "warm_turns": sum(row.get("resumed", False) for row in metrics),
            "input_tokens": sum(row.get("usage", {}).get("input_tokens", 0) or 0 for row in metrics),
            "cached_input_tokens": sum(row.get("usage", {}).get("cached_input_tokens", 0) or 0 for row in metrics),
            "cache_write_tokens": (sum(row["usage"]["cache_write_tokens"] for row in metrics)
                if metrics and all(type(row.get("usage", {}).get("cache_write_tokens")) is int for row in metrics) else None),
            "output_tokens": sum(row.get("usage", {}).get("output_tokens", 0) or 0 for row in metrics),
            "per_domain": domain_usage,
            "note": "Observed provider usage; shared context is not a shared verdict, and missing cache-write usage is unknown."})
    elif queues is not None:
        jobs = {lane: [by_id[identity] for identity in members] for lane, members in queues.items()}
        for assignment, result in review_scheduler.run(jobs, assignment_job, workers=args.workers, budget_path=budget_path):
            results.append(result)
            worker.write(stage / "progress.json", results)
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(assignment_job, by_id[identity]) for identity in selected]
            for future in as_completed(futures):
                results.append(future.result())
                worker.write(stage / "progress.json", results)
    if native(["state", "work", *common, *runtime_options]) != package:
        raise ValueError("source work changed before native handoff")
    if question_budget:
        question_budget.close()
    if case_store:
        results = [r for r in results if "case_id" not in r] + case_store.results()
    successful = [r for r in results if r["status"] == "complete" and not r.get("reconsideration")]
    admission = {
        "plan": plan,
        "inspected": [w for r in successful for w in r["inspected"]],
        "proposals": [p for r in successful for p in r["proposals"]],
        "assessment_evidence": [c for r in successful for c in r["proofs"]],
    }
    worker.write(stage / "admission.json", admission)
    augmented = stage / "inventory"
    admitted = native(
        [
            "investigate",
            "source-review-admit",
            root,
            "--inventory",
            inventory,
            "--input",
            stage / "admission.json",
            "--output",
            augmented,
        ]
    )
    worker.write(stage / "admission-result.json", admitted)
    assessments = {
        row["review_id"]: row for r in successful for row in r["draft"]["results"]
    }
    question_assignments = {
        row["review_id"]: [r["assignment_id"]]
        for r in successful
        for row in r["draft"]["results"]
    }
    question_cases = {row["review_id"]:[r["case_id"]] for r in successful if "case_id" in r
        for row in r["draft"]["results"]}
    priorities = {}
    followups = [note for r in successful for note in r.get("followups", [])]
    claim_contexts = [value for r in successful for value in r.get("claim_contexts", [])]
    context_errors = [value for r in successful for value in r.get("claim_context_errors", []) if value["review_id"] in assessments]
    for result in successful:
        for proposal in result["draft"]["proposals"]:
            identity = admitted["mapping"][
                result["assignment_id"] + ":" + proposal["key"]
            ]
            row = {**proposal["assessment"], "review_id": identity}
            if identity in assessments and assessments[identity] != row:
                raise ValueError("duplicate questions have conflicting assessments")
            assessments[identity] = row
            if "case_id" in result:
                question_cases.setdefault(identity, []).append(result["case_id"])
            priorities[identity] = proposal["priority"]
            if proposal["key"] in result.get("proposal_followups", {}):
                followups.append({**result["proposal_followups"][proposal["key"]], "review_id":identity})
            if proposal["key"] in result.get("proposal_contexts", {}):
                claim_contexts.append({**result["proposal_contexts"][proposal["key"]], "review_id":identity})
            context_errors.extend({**error,"review_id":identity} for error in result.get("claim_context_errors", [])
                                  if error["review_id"] == proposal["key"])
            question_assignments.setdefault(identity, []).append(
                result["assignment_id"]
            )
    private = Path(args.store) / ("source-control-" + context.digest(str(output)))
    private.mkdir(parents=True)
    next_claim = native(
        [
            "state",
            "claim",
            "--store",
            args.store,
            "--stream",
            args.stream,
            "--inventory",
            augmented,
            "--source-root",
            root,
            "--expected-generation",
            claim["generation"],
            "--attempt-id",
            "source-" + context.digest(str(output))[:24],
            "--operation-key",
            "source-claim:" + context.digest(str(output)),
        ]
    )
    worker.write(private / "claim.json", next_claim)
    # Publish only a private-receipt pointer, so the host can end our derived
    # generation if subsequent plan/publication fails. Never export the owner.
    worker.write(
        stage / "handoff.json",
        {
            "parent_work_package_id": package["package_id"],
            "effective_args": {
                "inventory": str(augmented),
                "claim": str(private / "claim.json"),
            },
        },
    )
    effective = [
        "--store",
        args.store,
        "--stream",
        args.stream,
        "--inventory",
        augmented,
        "--source-root",
        root,
        "--generation",
        next_claim["result"]["generation"],
        "--owner",
        next_claim["result"]["owner"],
    ]
    final_runtime = runtime
    if question_routing:
        # Only the expert's security decisions enter native finalization. The
        # routine stage remains attributed evidence, not a native assessment.
        final_runtime = {k:v for k,v in runtime.items() if k != "orchestration"}
        final_runtime["provider"] = runtime["orchestration"]["expert"]
        worker.write(private / "provider.json", final_runtime["provider"])
        runtime_options = ["--skill-root", str(skill), "--provider-contract", str(private / "provider.json")]
        args.provider_contract = str(private / "provider.json")
        args.reviewer_command = args.expert_command
        args.expert_command = None
    draft = native(
        [
            "state",
            "plan-template",
            "--inventory",
            augmented,
            "--source-root",
            root,
            "--policy",
            payload["policy"],
            "--selection",
            "policy",
            *runtime_options,
        ]
    )
    # Preserve the exact runtime allowance/provider; no implicit reset of model budgets.
    draft["runtime"] = final_runtime
    draft.setdefault("deferred_review_ids", {})
    draft.setdefault("excluded_review_ids", {})
    failed_ids = {
        rid
        for result in results
        if result["status"] != "complete"
        for rid in result["review_ids"]
    }
    eligible = (set(ids) - failed_ids) | {
        rid
        for rid, p in priorities.items()
        if p == "value" or payload["policy"] == "comprehensive"
    }
    draft["selected_review_ids"] = sorted(eligible)
    for rid in eligible:
        draft["deferred_review_ids"].pop(rid, None)
        draft["excluded_review_ids"].pop(rid, None)
    for rid in entries:
        if rid not in eligible and rid not in draft["excluded_review_ids"]:
            draft["deferred_review_ids"].setdefault(
                rid,
                payload.get("deferred_review_ids", {}).get(
                    rid,
                    "Outside the requested native selection; source coverage is recorded separately.",
                ),
            )
    for rid, reason in excluded_ids.items():
        draft["excluded_review_ids"].pop(rid, None)
        draft["deferred_review_ids"][rid] = reason
    for rid in priorities:
        if rid not in eligible:
            draft["deferred_review_ids"][
                rid
            ] = "Source-discovered question retained for Comprehensive review."
    for rid in failed_ids:
        draft["deferred_review_ids"][
            rid
        ] = "Source assignment did not complete; no automatic replacement model call."
    membership_changes = reconcile_completion_plan(draft,
        [entry["review_id"] for entry in worker.read(augmented / "inventory.json")["entries"]])
    if payload["policy"] == "comprehensive":
        # Keep all admitted obligations, including unanswered/refilled IDs.
        draft["selected_review_ids"] = sorted(set(draft["selected_review_ids"]) | set(draft["deferred_review_ids"]))
        draft["deferred_review_ids"] = {}
    worker.write(stage / "membership-changes.json", membership_changes)
    worker.write(private / "plan.json", draft)
    native(
        [
            "state",
            "plan",
            *effective,
            "--input",
            private / "plan.json",
            "--operation-key",
            "source-plan:" + context.digest(str(output)),
            *runtime_options,
        ]
    )
    work = native(["state", "work", *effective, *runtime_options])
    worker.write(stage / "work.json", work)
    bundles = stage / "bundles"
    native(
        [
            "investigate",
            "review-bundles",
            root,
            "--inventory",
            augmented,
            "--review-ids",
            ",".join(work["payload"]["review_ids"]),
            *(["--max-reviews", "1"] if set(work["payload"]["review_ids"]) - set(assessments) else []),
            "--output",
            bundles,
        ]
    )
    manifest = worker.read(bundles / "manifest.json")
    coverage = [w for r in successful for w in r["draft"]["coverage"]]
    coverage.extend({**{k: w[k] for k in ("path", "start_line", "end_line")},
                     "status": "deferred", "summary": "Outside selected operations; not reviewed."}
                    for a in plan["assignments"] if a["id"] not in selected_set for w in a["windows"])
    counts = {
        status: sum(w["status"] == status for w in coverage)
        for status in ("examined", "needs_review", "deferred")
    }
    manifest.setdefault("scope", []).append(
        (f"Work review: {len(successful)}/{len(work_registry['cases'])} funded items completed; " if work_registry else
         f"AI source review: {len(successful)}/{len(results)} assignments completed; ") +
        f"{counts['examined']} examined ranges, {counts['needs_review']} ranges needing context, "
        f"{counts['deferred']} deferred ranges. Source coverage is distinct from vulnerability verdicts; "
        "no findings does not establish source safety. See source-review.json for range records."
    )
    reused_count = sum("reuse" in result for result in successful)
    if reused_count:
        manifest["scope"].append(
            f"{reused_count} completed source assignments reuse prior assessments; "
            "these are not new reviews under current guidance. Prior usage remains in the original attempt."
        )
    if focus:
        manifest["scope"].append("Bounded source coverage applies to the selected operations and questions only; unrelated functions were not audited.")
    if domain_registry:
        role_counts = {role: sum(item["role"] == role for item in domain_registry["lead_accounting"].values())
                       for role in (*review_domains.ROLES, "unclassified")}
        manifest["scope"].append(f"Domain review: {len(successful)}/{len(domain_registry['cases'])} cases completed; "
            f"{role_counts['verify']} verification targets, {role_counts['cover']} coverage markers, "
            f"{role_counts['context']} context leads and {role_counts['unclassified']} unclassified/deferred leads. "
            "Cover/Context roles are not negative verdicts. See source-review/lead-accounting.json.")
    if work_registry:
        current_work = review_work.ledger(work_registry, results, budget=review_budget.snapshot(budget_path), metrics=source_metrics)
        manifest["scope"].append("Work goal: " + current_work["goal"] + "; target status: " + current_work["target_status"]
            + ". Remaining planned items by potential impact: " + json.dumps(current_work["summary"]["remaining_by_potential_impact"])
            + ". Unclassified native items: " + str(len(current_work["summary"]["unclassified_native_ids"]))
            + "; importance unknown. Coverage is limited to named checks. See source-review/work-ledger.json and remaining-work.md.")
    worker.write(bundles / "manifest.json", manifest)
    summary = {
        "schema_version": "1",
        "origin": "hybrid" if domain_registry and any(item["role"] != "unclassified" for item in domain_registry["lead_accounting"].values()) else "ai_source_only" if not ids else "hybrid",
        "native_selected_claims": len(ids),
        "excluded_sources": plan.get("excluded_sources", []),
        "plan_id": plan["plan_id"],
        "source_fingerprint": plan["source_fingerprint"],
        "parent_work_package_id": package["package_id"],
        "elapsed_ms": round((time.monotonic() - started_run) * 1000),
        "assignments": len(plan["assignments"]),
        "completed_assignments": len({result["assignment_id"] for result in successful}) if work_registry else len(successful),
        "reused_assignments": reused_count,
        "selected_assignment_ids": selected,
        "selected_assignments": len(selected),
        "schedule": "schedule.json" if queues is not None or domain_registry else None,
        "domain_review": {"domains": len(domain_registry["domains"]), "cases": len(domain_registry["cases"]),
            "session_mode": getattr(args, "domain_session_mode", "shared"),
            "completed_cases": len(successful), "role_counts": role_counts,
            "lead_accounting": "lead-accounting.json", "metrics": "domain-metrics.json"} if domain_registry else None,
        "native_admitted_ids": ids,
        "native_unreviewed_ids": sorted(set(ids) - set(assessments)),
        "native_membership_changes": membership_changes,
        "budget_path": str(budget_path) if budget_path else None,
        "limitations": plan["limitations"],
        "coverage": coverage,
        "results": results,
        "assessments": assessments,
        "followups": followups,
        "claim_contexts": claim_contexts,
        "claim_context_errors": context_errors,
        "question_assignments": question_assignments,
        "question_cases": question_cases,
        "source_questions": len(priorities),
        "calls": sum(r["calls"] for r in results),
        "unknown_provider_calls": sum(r["unknown_provider_calls"] for r in results),
        "effective_args": {
            "inventory": str(augmented),
            "claim": str(private / "claim.json"),
            "work_package": str(stage / "work.json"),
            "run": str(bundles),
        },
    }
    if work_registry:
        summary["work_review"] = {"goal": work_registry["goal"], "funded_items": len(work_registry["cases"]),
            "completed_items": len(successful), "ledger": str(stage / "work-ledger.json")}
        summary["effective_args"].update(reviewer_command=args.reviewer_command, provider_contract=args.provider_contract)
    if source_resume:
        summary["recovery"] = {"parent":str(source_resume.resolve()), "lineage_origin":str(lineage_output),
            "inherited_receipted_calls":inherited_source_calls,
            "new_receipted_calls":len(source_metrics) - inherited_source_calls,
            "elapsed_ms_scope":"Current recovery attempt; provider receipts retain prior turn durations."}
    if question_routing:
        summary["question_routing"] = {"routine":runtime["provider"], "owner":final_runtime["provider"],
            "budget":"question-budget.json", "authority":"Question answers are supporting evidence; expert owns security conclusions."}
    worker.write(stage / "summary.json", summary)
    with (stage / "provider-metrics.jsonl").open("w", encoding="utf8") as handle:
        for metric in source_metrics:
            handle.write(json.dumps(metric) + "\n")
    if work_registry:
        review_work.freeze_handoff(stage, worker.digest_file(work_path), case_store.binding, worker)
    for name, value in summary["effective_args"].items():
        setattr(args, name, value)
    args._source_prepared = str(stage / "summary.json")
    result = legacy(args)
    if work_registry:
        if (output / "second-pass.json").is_file():
            audit = worker.read(output / "second-pass.json")
            for gap in review_work.audit_case_gaps(work_registry, audit["results"]):
                case_store.submit(context.digest(["native-audit", gap]),
                    {"kind":"native_audit", "case_id":gap["case_id"], "review_ids":[gap["review_id"]],
                     "reason":"A second-pass native proof changed; reconcile the original case checks with its new evidence."})
            results = [r for r in results if "case_id" not in r] + case_store.results()
            review_work.freeze_handoff(stage, worker.digest_file(work_path), case_store.binding, worker)
        report = review_work.ledger(work_registry, results, budget=review_budget.snapshot(budget_path), metrics=source_metrics)
        report["native_admission_status"] = result["status"]
        failures = [row for row in results if row["status"] == "incomplete" and row.get("error") != "BudgetExhausted"]
        report["stop_reason"] = ("investigation_failure" if failures else "allowance_reached" if any(
            row["status"] in ("deferred", "incomplete") and row.get("error") == "BudgetExhausted" for row in results
            if "case_id" in row) else "ready_work_finished")
        result["work_goal"] = {"goal": report["goal"], "status": report["target_status"],
            "target_complete": report["target_complete"], "stop_reason": report["stop_reason"],
            "completed_items": report["summary"]["closed"], "remaining_items": report["summary"]["remaining"],
            "ledger": str(stage / "work-ledger.json")}
        if report["goal"] == "coverage" and not report["target_complete"]:
            result["status"] = "incomplete"
        report["execution_status"] = result["status"]
        worker.write(stage / "work-ledger.json", report)
        worker.write_text(stage / "remaining-work.md", review_work.markdown(report))
        worker.write(output / "worker.json", result)
    return result
