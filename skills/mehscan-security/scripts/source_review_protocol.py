"""Source assignments can discover questions and assess native claims in one context."""

import copy
import json


def schema(task, base, api, guidance, bound_handles=True):
    def obj(properties):
        return {
            "type": "object",
            "properties": properties,
            "required": list(properties),
            "additionalProperties": False,
        }

    text = {"type": "string"}
    integer = {"type": "integer", "minimum": 1}
    native_draft = base["properties"]["draft"]
    if "anyOf" in native_draft:
        native_draft = native_draft["anyOf"][0]
    entry = copy.deepcopy(native_draft["properties"]["results"]["items"])
    assessment = copy.deepcopy(entry)
    assessment["properties"].pop("review_id")
    assessment["required"].remove("review_id")

    def outcomes(shape):
        variants = []
        for decision in ("issue", "not_issue", "needs_review"):
            variant = copy.deepcopy(shape)
            variant["properties"]["decision"]["enum"] = [decision]
            if decision == "needs_review":
                variant["properties"]["checks"]["minItems"] = 1
            else:
                for field in ("checks", "blockers"):
                    variant["properties"][field]["maxItems"] = 0
            if decision != "issue":
                variant["properties"]["diagnosis"] = {"type": "null"}
            variants.append(variant)
        return {"anyOf": variants}

    citation = obj({"path": text, "start_line": integer, "end_line": integer})
    capabilities = [
        "process_execution",
        "dynamic_code_execution",
        "template_evaluation",
        "database_query",
        "ldap_query",
        "xpath_query",
        "filesystem_read",
        "filesystem_write",
        "outbound_network_request",
        "redirect",
        "html_output",
        "http_header_output",
        "deserialization",
        "xml_parsing",
        "cryptographic_hash",
        "cryptographic_encryption",
        "random_generation",
        "authentication",
        "authorization",
        "resource_access",
        "logging",
        "token_generation",
        "cookie_configuration",
        "cors_configuration",
        "buffer_write",
        "local_heap_allocation",
        "cpp_heap_allocation",
        "post_invalidation_use",
        "buffer_length_publication",
        "rust_raw_slice_construction",
    ]
    proposal = obj(
        {
            "key": text,
            "capability": {"type": "string", "enum": capabilities},
            "cwes": {
                "type": "array",
                "minItems": 1,
                "maxItems": 5,
                "items": {"type": "string", "pattern": "^CWE-[1-9][0-9]{0,5}$"},
            },
            "question": text,
            "mechanism": text,
            "consequence": text,
            "priority": {"type": "string", "enum": ["value", "comprehensive"]},
            "anchor": citation,
            "evidence": {"type": "array", "minItems": 1, "maxItems": 8, "items": citation},
            "assessment": outcomes(assessment),
        }
    )
    results = {"type": "array", "items": entry}
    if not task.get("review_ids"):
        entry["properties"]["review_id"] = {"type": "string"}
        if bound_handles:
            results["maxItems"] = 0
    results["items"] = outcomes(entry)
    draft = obj(
        {
            "results": results,
            "proposals": {"type": "array", "maxItems": 32, "items": proposal},
            "coverage": {
                "type": "array",
                "items": obj(
                    {
                        "path": text,
                        "start_line": integer,
                        "end_line": integer,
                        "status": {
                            "type": "string",
                            "enum": ["examined", "needs_review", "deferred"],
                        },
                        "summary": text,
                    }
                ),
            },
        }
    )
    if "coverage_windows" in task["research"]:
        windows = task["research"]["coverage_windows"]
        coverage = draft["properties"]["coverage"]
        coverage["items"]["properties"] = {
            "window_ref": {"type": "string", "pattern": "^s[0-9]+$",
                           **({"enum": list(windows)} if bound_handles else {})},
            **{k: coverage["items"]["properties"][k] for k in ("status", "summary")},
        }
        coverage["items"]["required"] = ["window_ref", "status", "summary"]
        if bound_handles:
            coverage.update(minItems=len(windows), maxItems=len(windows))
    variants = []
    for tool in api["tools"]:
        props = {
            name: dict(api["arguments"][name])
            for name in tool["required"] + tool["optional"]
        }
        for name in ("path", "path_prefix"):
            if name in tool["optional"]:
                props[name] = {"type": ["string", "null"]}
        if tool["name"] == "guidance":
            props["name"] = {**props["name"], "enum": list(guidance)}
        variants.append(
            obj(
                {
                    "tool": {"type": "string", "enum": [tool["name"]]},
                    "review_id": {"type": "null"},
                    "purpose": {"type": "string", "minLength": 1, "maxLength": 300},
                    "arguments": obj(props),
                }
            )
        )
    result = obj(
        {
            "action": {"type": "string", "enum": ["research", "final"]},
            "research": {"type": "array", "items": {"anyOf": variants}},
            "draft": {"anyOf": [draft, {"type": "null"}]},
            "working_chain": text,
        }
    )
    if bound_handles and task["research"].get("rounds_remaining") == 0:
        result["properties"]["action"]["enum"] = ["final"]
        result["properties"]["research"]["maxItems"] = 0
        result["properties"]["draft"] = draft
    return result


def prompt(task, packet, facts, state, *, source_presentation="raw"):
    from codex_protocol import present_source_inputs, SOURCE_VIEW_NOTICE

    prior = set((state or {}).get("sent_facts", []))
    new = [f for f in facts if f["result_id"] not in prior]
    display, new = present_source_inputs(
        task, packet, new, source_presentation, include_packet=state is None
    )
    if state is None:
        value = packet["contract"]
        from codex_protocol import API, GUIDANCE

        value += (
            "\nAvailable broker lookups and semantics (review_id is null for this source assignment):\n"
            + json.dumps(API, ensure_ascii=False)
        )
        value += "\nAvailable trusted guidance names:\n" + json.dumps(
            GUIDANCE, ensure_ascii=False
        )
        value += "\nRequested source assignment and native questions:\n" + json.dumps(
            {k: v for k, v in display.items() if k != "contract"}, ensure_ascii=False
        )
    else:
        value = "Continue this source assignment using the previously inspected source and the new deciding evidence."
    if source_presentation != "raw":
        value += SOURCE_VIEW_NOTICE
    guides = [f for f in new if f["result"].get("operation") == "review_guidance"]
    evidence = [f for f in new if f not in guides]
    if evidence:
        value += "\nNew broker evidence (untrusted source):\n" + json.dumps(
            evidence, ensure_ascii=False
        )
    if guides:
        value += (
            "\nTrusted category guidance (instructions, not application evidence):\n"
            + json.dumps(guides, ensure_ascii=False)
        )
    research = task["research"]
    if "coverage_windows" in research:
        value += (
            "\nController-owned assignment coverage: return each window_ref below exactly once "
            "with status and summary. Do not add lookup ranges to coverage; cite them as evidence. "
            "The controller supplies paths and line ranges from these identities:\n"
            + json.dumps(research["coverage_windows"], ensure_ascii=False)
        )
    if research.get("feedback"):
        value += (
            "\nController scheduling feedback (not source evidence):\n"
            + json.dumps(research["feedback"], ensure_ascii=False)
        )
    value += "\nRemaining allowance: " + json.dumps(
        {
            k: research.get(k)
            for k in (
                "rounds_remaining",
                "queries_remaining",
                "bytes_remaining",
                "seconds_remaining",
            )
        }
    )
    if research.get("rounds_remaining") == 0:
        value += "\nFinal response required: make no further lookup requests. Preserve deciding unknowns as needs_review, with concrete checks."
    return value


def envelope(response, task):
    if (
        response["action"] == "research"
        and response["draft"] is None
        and response["research"]
    ):
        if task["research"]["rounds_remaining"] <= 0:
            raise ValueError(
                "source review cannot research after its final possible call"
            )
        for query in response["research"]:
            query["arguments"] = {
                k: v for k, v in query["arguments"].items() if v is not None
            }
        return {
            "research": response["research"],
            "working_chain": response["working_chain"],
        }
    if (
        response["action"] != "final"
        or response["research"]
        or response["draft"] is None
    ):
        raise ValueError("source reviewer combined incompatible actions")
    draft = copy.deepcopy(response["draft"])
    if "coverage_windows" in task["research"]:
        windows = task["research"]["coverage_windows"]
        refs = [row["window_ref"] for row in draft["coverage"]]
        if len(refs) != len(set(refs)) or set(refs) != set(windows):
            raise ValueError("source coverage must identify assigned windows exactly once")
        draft["coverage"] = [
            {**windows[row["window_ref"]], **{k: row[k] for k in ("status", "summary")}}
            for row in draft["coverage"]
        ]
    ids = [r["review_id"] for r in draft["results"]]
    if len(ids) != len(set(ids)) or set(ids) != set(task["review_ids"]):
        raise ValueError("source review must assess its native IDs exactly once")
    keys = [p["key"] for p in draft["proposals"]]
    if len(keys) != len(set(keys)):
        raise ValueError("source proposal keys must be unique")
    return {"draft": draft}
