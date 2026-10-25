"""Bounded factual checks inside authority and token investigations."""
import json
from pathlib import Path


CAPABILITIES = {"authorization", "token_generation"}


def eligible_ids(task, packet=None):
    if task.get("kind") != "native_bundle" or task.get("review_role", "investigator") != "investigator":
        return []
    if packet is None:
        packet = json.loads(Path(task["evidence_packet"]).read_text(encoding="utf-8"))
    return [q["review_id"] for q in packet.get("native_questions", [])
            if q.get("capability") in CAPABILITIES and q["review_id"] in task["review_ids"]]


def extend_schema(schema, task, *, bound_handles=True):
    ids = eligible_ids(task)
    if not ids:
        return schema
    text = {"type":"string", "minLength":1, "maxLength":500}
    nullable = {"anyOf":[text,{"type":"null"}]}
    handles = task["research"].get("source_artifact_handles", [])
    artifacts = {"type":"array", "maxItems":8, "items":{"type":"string"}}
    if bound_handles:
        if handles:
            artifacts["items"]["enum"] = handles
        else:
            artifacts["maxItems"] = 0

    def table(properties, maximum):
        return {"type":"array", "maxItems":maximum, "items":{"type":"object",
            "additionalProperties":False, "properties":properties, "required":list(properties)}}

    properties = {
        "review_id":{"type":"string", "enum":ids},
        "effect":nullable, "requirement":nullable, "example":text, "observation":text,
        "status":{"type":"string", "enum":["counterexample","enforced","unresolved","no_boundary"]},
        "cause":{"type":["string","null"], "enum":[None,"search_limited","not_found_in_scope",
            "unsupported","external_required","human_required","budget_exhausted"]},
        "artifacts":artifacts,
        "controls":table({"condition":text, "failure_enforcement":text,
            "boundary_result":text,"artifacts":artifacts},6),
        "value_bindings":table({"origin":nullable,"presented_as":text,
            "effect_key":nullable,"remaining":nullable,"artifacts":artifacts},3)}
    final_only = bound_handles and schema["properties"]["action"]["enum"] == ["final"]
    schema["properties"] = {"action":schema["properties"].pop("action"),
        "boundary_checks":{"type":"array",
            "minItems":len(ids) if final_only else 0,
            "maxItems":len(ids),
            "items":{"type":"object", "additionalProperties":False,
                "properties":properties, "required":list(properties)}},
        **schema["properties"]}
    schema["required"].insert(1, "boundary_checks")
    return schema


def extend_prompt(prompt, task, packet, state):
    ids = eligible_ids(task, packet)
    if ids:
        assignment = (Path(__file__).resolve().parent.parent / "references/boundary-review.md").read_text(encoding="utf-8")
        prompt += "\n" + (assignment if state is None else
            "Keep the same application-effect scope, original ID verdicts and research budget. "
            "On research or handoff turns return boundary_checks=[]; use existing working_chain/progress for the deciding unread relationship. "
            "On action=final, complete the source-bound boundary_checks once before draft.")
        prompt += "\nBoundary-check IDs: " + json.dumps(ids)
    return prompt


def review_envelope(response, task, packet, envelope):
    ids = eligible_ids(task, packet)
    if not ids:
        if "boundary_checks" in response:
            raise ValueError("Boundary checks are not enabled for this task")
        return envelope(response)
    rows = response.get("boundary_checks")
    if response["action"] != "final":
        if rows != []:
            raise ValueError("Boundary checks belong only to the final response; use [] during research or handoff")
        return envelope({k:v for k,v in response.items() if k != "boundary_checks"})
    if not isinstance(rows,list) or sorted(r.get("review_id", "") for r in rows) != sorted(ids):
        raise ValueError("Boundary checks must cover offered IDs exactly once")
    eligible = set(task["research"].get("source_artifact_handles", []))
    for row in rows:
        citations = [*row["artifacts"],*[h for r in row["controls"] + row["value_bindings"] for h in r["artifacts"]]]
        if not set(citations) <= eligible:
            raise ValueError("Boundary check cites uninspected source")
        if row["status"] in ("enforced", "counterexample") and (
                not row["artifacts"] or not row["effect"] or not row["requirement"] or row["cause"] is not None):
            raise ValueError("Settled boundary check requires an effect, requirement and source")
        if row["status"] == "unresolved" and response["action"] == "final" and row["cause"] is None:
            raise ValueError("Final unresolved boundary check requires its cause")
    out = envelope({k:v for k,v in response.items() if k != "boundary_checks"})
    path = Path(task["evidence_packet"]).parent / (
        "boundary-checks-" + task["conversation_id"] + "-r" + str(task["research"]["round"]) + ".json")
    value = {"interpretation":"unvalidated_reviewer_observation", "source_binding":packet.get("source_binding"),
        "boundary_checks":rows,
        "source_artifacts":{handle:task["research"]["artifact_handles"][handle] for handle in eligible}}
    path.write_text(json.dumps(value,indent=2) + "\n",encoding="utf-8")
    return out
