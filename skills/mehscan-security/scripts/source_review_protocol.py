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

    def source_citation(anchor=False):
        if "citation_windows" not in task["research"]:
            return obj({"path": text, "start_line": integer, "end_line": integer})
        if not bound_handles:
            return obj({
                "source_ref": {
                    "type": "string",
                    "pattern": "^s[0-9]+$" if anchor else "^[sf][0-9]+$",
                },
                "line": integer if anchor else {"anyOf": [integer, {"type": "null"}]},
            })
        variants = []
        for ref, window in task["research"]["citation_windows"].items():
            if anchor and not window["anchor"]:
                continue
            line = {
                "type": "integer", "minimum": window["start_line"],
                "maximum": window["end_line"],
            }
            variants.append(obj({
                "source_ref": {"type": "string", "enum": [ref]},
                "line": line if anchor else {"anyOf": [line, {"type": "null"}]},
            }))
        return {"anyOf": variants} if variants else {"not": {}}

    citation = source_citation()
    native_draft = base["properties"]["draft"]
    if "anyOf" in native_draft:
        native_draft = native_draft["anyOf"][0]
    entry = copy.deepcopy(native_draft["properties"]["results"]["items"])
    entry["properties"]["evidence"]["items"] = citation
    entry["properties"]["source_leads"]["items"]["properties"]["evidence"] = citation
    if "claim_context" in entry["properties"]:
        entry["properties"]["claim_context"]["anyOf"][0]["properties"]["root"] = citation
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
            "anchor": source_citation(anchor=True),
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
    if "required_checks" in task["research"]:
        draft["properties"]["work_checks"] = {"type": "array", "items": obj({
            "check_id": text, "status": {"type": "string", "enum": ["satisfied", "violated", "unresolved", "not_checked"]},
            "summary": text, "evidence": {"type": "array", "maxItems": 8, "items": citation},
            "next_deciding_fact": {"type": ["string", "null"]}})}
        draft["required"].append("work_checks")
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
        notice = SOURCE_VIEW_NOTICE
        if "citation_windows" in task["research"]:
            notice = notice.replace(
                "Cite original paths/line ranges.",
                "Use original line numbers with the offered source references.",
            )
        value += notice
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
    if "required_checks" in research:
        value += ("\nAnswer every required check exactly once in draft.work_checks. A closed satisfied/violated answer "
            "requires deciding source citations and null next_deciding_fact. An unresolved/not_checked answer requires "
            "the concrete missing fact; it does not count as target completion. Finding severity and potential scheduling "
            "impact are separate. Required checks:\n" + json.dumps(research["required_checks"], ensure_ascii=False))
    if "citation_windows" in research:
        value += (
            "\nController-owned source citations: return source_ref and line, never paths or line ranges. "
            "Use an original line number for a precise single-line citation, or null for one complete "
            "offered evidence extent. Anchors require a specific line in an assigned s-reference; "
            "f-references are supporting evidence only. Cite separated extents separately. "
            "Prefer deciding single lines from source already inspected; cite the steps of a "
            "multi-step relationship separately within the evidence limit. Use null only when "
            "the claim needs the complete extent, for example to establish a missing guard. "
            "Keep sufficient proof context; do not repeat source lookups solely to shorten quotes. "
            "The controller supplies source citation extents:\n"
            + json.dumps(research["citation_windows"], ensure_ascii=False)
        )
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
    if "required_checks" in task["research"]:
        expected = {check["id"] for check in task["research"]["required_checks"]}
        actual = [check["check_id"] for check in draft.get("work_checks", [])]
        if len(actual) != len(set(actual)) or set(actual) != expected:
            raise ValueError("work checks must match controller-owned check identities exactly once")
    if "citation_windows" in task["research"]:
        windows = task["research"]["citation_windows"]

        def expand(cite, anchor=False):
            if not isinstance(cite, dict) or set(cite) != {"source_ref", "line"}:
                raise ValueError("source citation must identify one offered extent")
            ref, line = cite["source_ref"], cite["line"]
            window = windows.get(ref) if isinstance(ref, str) else None
            if window is None or (anchor and (not window["anchor"] or line is None)):
                raise ValueError("source citation is not offered for this role")
            if line is not None and (
                type(line) is not int
                or not window["start_line"] <= line <= window["end_line"]
            ):
                raise ValueError("source citation line is outside its delivered extent")
            return {
                "path": window["path"],
                "start_line": window["start_line"] if line is None else line,
                "end_line": window["end_line"] if line is None else line,
            }

        def assessment_citations(assessment):
            assessment["evidence"] = [expand(c) for c in assessment["evidence"]]
            if assessment.get("claim_context") is not None:
                assessment["claim_context"]["root"] = expand(assessment["claim_context"]["root"])
            for lead in assessment.get("source_leads", []):
                lead["evidence"] = expand(lead["evidence"])

        for assessment in draft["results"]:
            assessment_citations(assessment)
        for proposal in draft["proposals"]:
            proposal["anchor"] = expand(proposal["anchor"], anchor=True)
            proposal["evidence"] = [expand(c) for c in proposal["evidence"]]
            assessment_citations(proposal["assessment"])
        for check in draft.get("work_checks", []):
            check["evidence"] = [expand(c) for c in check["evidence"]]
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
