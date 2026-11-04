"""Inspect observable review execution. A trace is not a semantic correctness proof."""
import argparse
from collections import Counter
import json
from pathlib import Path
import threading
import time


class ReviewTrace:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.sequence = 0

    def emit(self, event, **data):
        # Diagnostic only: checkpoints/native history remain the state authority.
        if not self.path.parent.is_dir():
            return
        with self.lock:
            self.sequence += 1
            row = {"sequence":self.sequence, "time_ms":round(time.time()*1000), "event":event, **data}
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def jsonl(path):
    if not path.exists():
        return [], False
    rows, incomplete = [], False
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            incomplete = True
    return rows, incomplete


def query_flags(rows):
    flags, counts = [], Counter()
    for row in rows:
        query = row.get("query", {})
        if not query:
            continue
        key = json.dumps([query.get("tool"),query.get("arguments")], sort_keys=True)
        counts[key] += 1
        result = row.get("result", {})
        if result.get("error") or result.get("results") == []:
            flags.append({"kind":"empty_or_failed_navigation", "round":row.get("round"),
                "query":query, "interpretation":"Not proof that code or a control is absent."})
        if result.get("truncated") or result.get("source_complete") is False:
            flags.append({"kind":"partial_lookup", "round":row.get("round"), "query":query})
    for key, count in counts.items():
        if count > 1:
            flags.append({"kind":"repeated_query", "query":json.loads(key), "count":count,
                "interpretation":"Check whether repetition recovered new evidence; reuse alone is not an error."})
    return flags


def summarize(run, review_id=None):
    run = Path(run)
    if run.is_symlink() or not run.is_dir():
        raise ValueError("trace run must be an existing directory")
    events, torn = jsonl(run / "review-trace.jsonl")
    research, research_torn = jsonl(run / "research.jsonl")
    feedback, feedback_torn = jsonl(run / "review-feedback.jsonl")
    legacy_progress = {}
    if not events:
        for path in run.glob("progress-*.json"):
            context = run / ("context-" + path.name.removeprefix("progress-"))
            if not context.is_file():
                continue
            ids = [row["review_id"] for row in read(context).get("native_questions", [])]
            if review_id is not None and review_id not in ids:
                continue
            for identity in ids:
                legacy_progress[identity] = read(path)
    jobs = []
    for path in sorted((run / "jobs").glob("*.json")):
        job = read(path)
        ids = job.get("binding", {}).get("review_ids", [])
        if review_id is not None and review_id not in ids:
            continue
        jid = path.stem
        own = [e for e in events if e.get("job_id") == jid]
        conversations = {e["conversation_id"] for e in own if e.get("conversation_id")}
        lookups = job.get("results") or [r for r in research if r.get("query", {}).get("review_id") in ids]
        corrections = [r for r in feedback if r.get("conversation_id") in conversations]
        flags = query_flags(lookups)
        for event in own:
            if event["event"] == "native_failed":
                flags.append({"kind":"native_validation_failure", "operation":event.get("operation")})
            if event["event"] == "research_budget_deferred":
                flags.append({"kind":"research_budget_deferral", "round":event.get("round"),
                    "deferred_queries":event["feedback"]["deferred_queries"],
                    "interpretation":"These lookups did not execute; inspect the remaining question, not an inferred source fact."})
            if event["event"] == "progress_changed" and event.get("dropped_open_edges"):
                flags.append({"kind":"open_relationship_disappeared", "round":event.get("round"),
                    "edges":event["dropped_open_edges"],
                    "interpretation":"Review whether resolved, rephrased or abandoned; this is not a verdict override."})
        if not events:
            flags.append({"kind":"legacy_trace", "interpretation":"Reconstructed queries/checkpoint only; per-turn progress history is unavailable."})
        if corrections:
            flags.append({"kind":"protocol_correction", "count":len(corrections)})
        progress = job.get("progress")
        chain = job.get("working_chain")
        if progress is None:
            old = next((legacy_progress[identity] for identity in ids if identity in legacy_progress), {})
            progress, chain = old.get("edges"), old.get("working_chain")
        for edge in progress or []:
            if edge["status"] == "blocked":
                flags.append({"kind":"declared_blocker", "cause":edge.get("cause"), "edge":edge["edge"]})
        draft = job.get("draft", job.get("candidate_draft", {}))
        decisions = [{k:r.get(k) for k in ("review_id", "decision", "summary", "checks")}
                     for r in draft.get("results", [])]
        if any(r["decision"] == "needs_review" for r in decisions):
            flags.append({"kind":"unresolved_decision", "interpretation":"Inspect the named missing fact; pending is not an execution failure."})
        jobs.append({"job_id":jid, "review_ids":ids, "checkpoint_status":job.get("status"),
            "model_draft_recorded":bool(draft),
            "native_finalization_recorded":bool(job.get("combined_sha256") or job.get("assessment_sha256")),
            "calls":job.get("calls"), "query_units":job.get("queries"), "bytes":job.get("bytes"),
            "elapsed_seconds":job.get("elapsed_seconds"), "unknown_provider_calls":job.get("unknown_provider_calls",0),
            "latest_progress":progress, "working_chain":chain,
            "decisions":decisions, "attention_flags":flags, "events":own,
            "queries":[{k:r.get(k) for k in ("round","query","result_id","reused")} for r in lookups]})
    if review_id is not None and not jobs:
        raise ValueError("review ID is not present in this attempt")
    worker = read(run / "worker.json") if (run / "worker.json").is_file() else {}
    incomplete_jobs = [j["job_id"] for j in jobs if j["checkpoint_status"] != "drafted"]
    result = {"run":str(run.resolve()), "execution_status":worker.get("status", "running_or_unknown"),
        "semantic_quality":"not_established_by_execution_trace", "trace_history":"recorded" if events else "legacy_reconstruction",
        "mechanical_assessment":"admitted" if worker.get("status") == "admitted" else "not_admitted_or_still_running",
        "incomplete_trace_rows":torn or research_torn or feedback_torn,
        "job_count":len(jobs), "unfinished_jobs":incomplete_jobs,
        "model_drafts_recorded":sum(j["model_draft_recorded"] for j in jobs),
        "native_finalizations_recorded":sum(j["native_finalization_recorded"] for j in jobs),
        "drafts_without_recorded_native_finalization":[j["job_id"] for j in jobs
            if j["review_ids"] and j["checkpoint_status"] == "drafted" and not j["native_finalization_recorded"]],
        "attention_counts":dict(Counter(f["kind"] for j in jobs for f in j["attention_flags"])),
        "runtime_error":{k:worker[k] for k in ("reason","detail") if k in worker},
        "native_events":[e for e in events if e["event"].startswith("native_")],
        "prior_attempt":worker.get("recovered_from"),
        "jobs":jobs}
    return result


def markdown(result):
    lines = ["# Review execution", "", "Status: " + result["execution_status"] + ". Trace: " + result["trace_history"] + ".",
        "Execution records do not establish semantic correctness.", "",
        "| Review IDs | Job state | Calls | Query units | Attention flags |", "| --- | --- | ---: | ---: | --- |"]
    for job in result["jobs"]:
        lines.append("| " + ", ".join(job["review_ids"]) + " | " + str(job["checkpoint_status"]) + " | " +
            str(job["calls"]) + " | " + str(job["query_units"]) + " | " +
            ", ".join(sorted({f["kind"] for f in job["attention_flags"]})) + " |")
    for job in result["jobs"]:
        lines += ["", "## " + ", ".join(job["review_ids"]), ""]
        for event in job["events"]:
            label = event["event"] + (" (round " + str(event["round"]) + ")" if "round" in event else "")
            if event["event"] == "query_completed":
                label += ": `" + event["query"]["tool"] + "` — " + event["query"].get("purpose", "")
            if event.get("operation"):
                label += ": " + event["operation"]
            lines.append("- " + label)
            if event["event"] == "progress_changed":
                lines.extend("  - " + edge["status"] + ": " + edge["edge"] for edge in event.get("edges", []))
        if not job["events"]:
            for query in job["queries"]:
                lines.append("- Round " + str(query["round"]) + ": `" + query["query"]["tool"] + "` — " + query["query"].get("purpose", ""))
            if job["working_chain"]:
                lines.append("- Last recorded hypothesis: " + job["working_chain"])
        for row in job["decisions"]:
            lines.append("- " + str(row["decision"]) + ": " + str(row["summary"]))
            lines.extend("  - Remaining: " + q for q in row.get("checks") or [])
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--review-id")
    parser.add_argument("--format", choices=("json","markdown"), default="markdown")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = summarize(args.run, args.review_id)
    output = json.dumps(result, indent=2, ensure_ascii=False) + "\n" if args.format == "json" else markdown(result)
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        import sys
        sys.stdout.reconfigure(encoding="utf-8")
        print(output, end="")
