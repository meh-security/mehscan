"""Default AI source assignments: discover, assess and native-finalize in shared context."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import re
import shutil
import time

import review_context as context


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
    if getattr(args, "first_pass", None) or args.phase != "all":
        return legacy(args)
    if getattr(args, "validate_only", False) or getattr(args, "source_profile", None):
        raise ValueError(
            "exact-bundle validation and bound source profiles require --phase native"
        )
    if not 1 <= args.workers <= 16:
        raise ValueError("review workers must be 1 to 16")
    if getattr(args, "resume_from", None):
        previous = Path(args.resume_from) / "source-review/summary.json"
        if not previous.is_file():
            if (Path(args.resume_from) / "source-review").is_dir():
                raise ValueError(
                    "source review stopped before handoff; automatic continuation is unsupported, and no replacement model calls were made"
                )
            return legacy(args)
        data = worker.read(previous)
        for name, value in data["effective_args"].items():
            setattr(args, name, value)
        args._source_prepared = str(previous)
        return legacy(args)
    started_run = time.monotonic()
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
                [str(scanner), *map(str, arguments)], stage, env, timeout
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
    if runtime.get("orchestration"):
        raise ValueError(
            "repository source review currently uses one configured model; use native phase for explicit experimental tiered bundles"
        )
    artifact_root = (
        worker.outside(args.artifact_root, root) if args.artifact_root else output
    )
    if not output.is_relative_to(artifact_root):
        raise ValueError("worker output must stay inside its declared artifact root")
    worker.validate_provider_command(
        command, runtime.get("provider"), skill, root, artifact_root
    )
    command_binding = context.digest(
        [
            command,
            [worker.digest_file(value) for value in command if Path(value).is_file()],
        ]
    )
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
    plan = native(
        [
            "investigate",
            "source-review-plan",
            root,
            "--inventory",
            inventory,
            "--review-ids",
            ",".join(ids),
        ]
    )
    worker.write(stage / "plan.json", plan)
    entries = {
        e["review_id"]: e for e in worker.read(inventory / "inventory.json")["entries"]
    }
    # Preserve native relationship/control facts without replaying its overlapping
    # source excerpts. The assigned original windows remain the source view.
    native_cards = {}
    if ids:
        original = stage / "native-inputs"
        native(
            [
                "investigate",
                "review-bundles",
                root,
                "--inventory",
                inventory,
                "--review-ids",
                ",".join(ids),
                "--output",
                original,
            ]
        )
        for bundle in worker.read(original / "manifest.json")["bundles"]:
            sweep = native(
                [
                    "investigate",
                    "review-sweep",
                    "--bundle",
                    original / "requests" / bundle["filename"],
                ]
            )
            for card in sweep["reviews"]:
                index = int(card["question_id"].split("-")[-1]) - 1
                native_cards[card["review_id"]] = {
                    "question": sweep["questions"][index],
                    "facts": {
                        k: card[k]
                        for k in (
                            "anchor",
                            "operand_facts",
                            "decision_facts",
                            "path_steps",
                            "source_configuration",
                            "truncation",
                            "suggested_lookups",
                        )
                        if k in card
                    },
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
        + context.sections(skill / "references/runtime-review.md", ["api_semantics"])[
            "text"
        ]
    )
    # Source review has its own native-bound assignment, not an invented vulnerability.
    api = context.research_api(skill)
    guidance = context.guidance_catalog(skill)
    source_metrics = []

    def assignment_job(assignment):
        directory = stage / "jobs" / assignment["id"]
        directory.mkdir(parents=True)
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
            for w in assignment["windows"]
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
            if any(
                w["path"] == e["path"] and w["start_line"] <= e["line"] <= w["end_line"]
                for w in assignment["windows"]
            )
        ]
        worker.write(directory / "context.json", packet)
        conversation = context.digest(
            [package["package_id"], "source_review", assignment["id"], str(output)]
        )
        facts = []
        inspected = []
        citation_windows = {
            "s" + str(i): {
                **{k: w[k] for k in ("path", "start_line", "end_line")},
                "anchor": True,
            }
            for i, w in enumerate(windows)
        }
        queries = 0
        received = 0
        calls = 0
        unknown_calls = 0
        started = time.monotonic()
        last = None
        working_chain = ""
        feedback = None

        def remaining():
            left = limits["timeout_seconds"] - (time.monotonic() - started)
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

        try:
            for turn in range(limits["rounds"] + 1):
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
                    "s" + str(i): w["artifact_id"] for i, w in enumerate(windows)
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
                    "review_role": "investigator",
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
                        "rounds_remaining": limits["rounds"] - turn,
                        "queries_remaining": (
                            limits["queries"] - queries
                            if turn < limits["rounds"]
                            else 0
                        ),
                        "bytes_remaining": limits["bytes"] - received,
                        "seconds_remaining": remaining(),
                        "artifact_handles": aliases,
                        "source_artifact_handles": source_handles,
                        "coverage_windows": {
                            "s" + str(i): {k: w[k] for k in ("path", "start_line", "end_line")}
                            for i, w in enumerate(windows)
                        },
                        "citation_windows": dict(citation_windows),
                        "results": [],
                        "working_chain": working_chain,
                        "progress": [],
                        "feedback": feedback,
                    },
                }
                worker.write(directory / (str(turn) + "-input.json"), frame)
                worker.write(directory / (str(turn) + "-facts.json"), {"facts": facts})
                calls += 1
                unknown_calls += 1
                response = worker.execute(
                    command, directory, env, remaining(), json.dumps(frame)
                )
                worker.write(directory / (str(turn) + "-response.json"), response)
                receipt = worker.observed_turn(
                    directory,
                    frame["research"] | {"conversation_id": conversation},
                    runtime.get("provider"),
                    require_complete_usage=False,
                )
                if runtime.get("provider") and receipt is None:
                    raise ValueError(
                        "source provider usage is unknown; no automatic retry"
                    )
                if receipt:
                    source_metrics.append(receipt)
                    unknown_calls -= 1
                elif not runtime.get("provider"):
                    unknown_calls -= 1
                if "draft" in response:
                    last = response["draft"]
                    break
                if turn == limits["rounds"]:
                    raise ValueError(
                        "source reviewer requested evidence after final consuming call"
                    )
                requests = response.get("research", [])
                if not requests:
                    raise ValueError(
                        "source reviewer returned neither a draft nor a deciding lookup"
                    )
                working_chain = response.get("working_chain", "")
                requests, prepared, feedback = worker.research_batch_plan(
                    requests,
                    root,
                    [],
                    directory,
                    limits["queries"] - queries,
                    api=api,
                    guidance=guidance,
                )
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
                    facts.append(item)
                    batch.append(item)
                    worker.write(directory / (str(turn) + "-lookups.json"), batch)
                    offer_source(result, "f" + str(len(facts) - 1))
                worker.write(directory / (str(turn) + "-lookups.json"), batch)
            if last is None:
                raise ValueError("source review did not finalize its assignment")
            expected = {
                (w["path"], w["start_line"], w["end_line"])
                for w in assignment["windows"]
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
                "queries": queries,
                "bytes": received,
                "calls": calls,
                "unknown_provider_calls": unknown_calls,
                "seconds": time.monotonic() - started,
            }
        except Exception as error:
            if unknown_calls and "frame" in locals():
                receipt = worker.observed_turn(
                    directory,
                    frame["research"] | {"conversation_id": conversation},
                    runtime.get("provider"),
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
            }
        worker.write(directory / "result.json", result)
        return result

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(assignment_job, a) for a in plan["assignments"]]
        for future in as_completed(futures):
            results.append(future.result())
            worker.write(stage / "progress.json", results)
    if native(["state", "work", *common, *runtime_options]) != package:
        raise ValueError("source work changed before native handoff")
    successful = [r for r in results if r["status"] == "complete"]
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
    priorities = {}
    for result in successful:
        for proposal in result["draft"]["proposals"]:
            identity = admitted["mapping"][
                result["assignment_id"] + ":" + proposal["key"]
            ]
            row = {**proposal["assessment"], "review_id": identity}
            if identity in assessments and assessments[identity] != row:
                raise ValueError("duplicate questions have conflicting assessments")
            assessments[identity] = row
            priorities[identity] = proposal["priority"]
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
    draft["runtime"] = runtime
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
    for rid in priorities:
        if rid not in eligible:
            draft["deferred_review_ids"][
                rid
            ] = "Source-discovered question retained for Comprehensive review."
    for rid in failed_ids:
        draft["deferred_review_ids"][
            rid
        ] = "Source assignment did not complete; no automatic replacement model call."
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
            "--output",
            bundles,
        ]
    )
    manifest = worker.read(bundles / "manifest.json")
    coverage = [w for r in successful for w in r["draft"]["coverage"]]
    counts = {
        status: sum(w["status"] == status for w in coverage)
        for status in ("examined", "needs_review", "deferred")
    }
    manifest.setdefault("scope", []).append(
        f"AI source review: {len(successful)}/{len(results)} assignments completed; "
        f"{counts['examined']} examined ranges, {counts['needs_review']} ranges needing context, "
        f"{counts['deferred']} deferred ranges. Source coverage is distinct from vulnerability verdicts; "
        "no findings does not establish source safety. See source-review.json for range records."
    )
    worker.write(bundles / "manifest.json", manifest)
    summary = {
        "schema_version": "1",
        "plan_id": plan["plan_id"],
        "source_fingerprint": plan["source_fingerprint"],
        "parent_work_package_id": package["package_id"],
        "elapsed_ms": round((time.monotonic() - started_run) * 1000),
        "assignments": len(plan["assignments"]),
        "completed_assignments": len(successful),
        "limitations": plan["limitations"],
        "coverage": coverage,
        "results": results,
        "assessments": assessments,
        "question_assignments": question_assignments,
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
    worker.write(stage / "summary.json", summary)
    with (stage / "provider-metrics.jsonl").open("w", encoding="utf8") as handle:
        for metric in source_metrics:
            handle.write(json.dumps(metric) + "\n")
    for name, value in summary["effective_args"].items():
        setattr(args, name, value)
    args._source_prepared = str(stage / "summary.json")
    return legacy(args)
