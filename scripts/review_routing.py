#!/usr/bin/env python3
"""Inspect source-bound native/workspace route proposals. No dispatch or verdicts."""
import argparse
import hashlib
import json
from pathlib import Path
import time

import review_context as context
import review_worker as worker
import review_workspace_planner as planner
from review_workspace import identity, label, references, shape, source


VERSION = "mehscanReviewRouting/experimental-v1"
SELECTION_VERSION = "mehscanReviewRoutingSelections/experimental-v1"
WORKSPACE_KINDS = {"shared_operation", "shared_dependency", "relationship", "packet_batch"}
MAX_CLAIMS = 128


def input_binding(inventory, manifest):
    return {"source_fingerprint":inventory["identity_catalog"]["source_fingerprint"],
            "inventory_sha256":identity(inventory), "manifest_sha256":identity(manifest)}


def local_strategy(entry):
    if entry["capability"] == "database_query" and entry["rule_id"] in planner.SQL_RULES:
        return ("local_sql", "Inspect SQL grammar, binding and relevant input transformations; keep impact qualifications separate.")
    if entry["capability"] == "cookie_configuration":
        return ("local_api", "Inspect the cookie options and the claim's distinct script-access or transport exposure conditions.")
    if entry["capability"] == "deserialization":
        return ("local_api", "Inspect the selected parser API, effective options and input contract; retain caller-scope limits.")
    if entry["rule_id"] in {"typescript-nosql-query-selector", "javascript-nosql-query-selector"}:
        return ("local_query", "Inspect query construction and the effective input/configuration branch; retrieve only deciding contract evidence.")
    return ("native_fallback", "Resolve the selected claim with bounded lookups; no shared investigation or local completeness is established by routing.")


def dispatch_effects(manifest, rows, investigations, packets):
    """Expose fragmentation, not an estimate of model calls or saved reasoning."""
    original = {r["review_id"]:r["original_bundle_id"] for r in rows}
    destinations = {bid:set() for bid in (b["bundle_fingerprint"] for b in manifest["bundles"])}
    for packet in packets:
        destinations[packet["original_bundle_id"]].add("native:"+packet["original_bundle_id"])
    groups = []
    for group in investigations:
        if group["route"] != "workspace":
            continue
        bids = sorted({original[rid] for rid in group["review_ids"]})
        for bid in bids: destinations[bid].add(group["id"])
        groups.append({"investigation_id":group["id"],"original_bundle_ids":bids,
                       "already_one_native_packet":len(bids)==1})
    proposed = len(packets)+len(groups)
    return {"original_native_packets":len(manifest["bundles"]),"proposed_native_packets":len(packets),
            "proposed_workspace_investigations":len(groups),"proposed_dispatch_units":proposed,
            "dispatch_unit_delta":proposed-len(manifest["bundles"]),
            "split_original_bundle_ids":[bid for bid,units in destinations.items() if len(units)>1],
            "workspace_groups":groups,
            "authority":"Proposed packet/context units, not model calls, saved work or proof that native investigates every member separately. Count fragmentation in the hybrid comparison."}


def build(root, inventory, manifest, *, planner_plan=None, selections=None, engine_sha256=None):
    root = Path(root).resolve(strict=True)
    # Native exports normalize the display root to '.'; it is not an absolute
    # source locator. Bind the supplied root plus selected physical files below.
    if manifest["root"] != "." and Path(manifest["root"]).resolve(strict=True) != root:
        raise ValueError("native manifest source root differs")
    if manifest.get("max_reviews_per_bundle") != 20:
        raise ValueError("routing requires ordinary native maximum 20, not singleton experiment bundles")
    entries = {e["review_id"]:e for e in inventory["entries"]}
    if len(entries) != len(inventory["entries"]):
        raise ValueError("inventory has duplicate claim IDs")
    bundles, selected, original = {}, [], {}
    for bundle in manifest["bundles"]:
        bid, ids = label(bundle["bundle_fingerprint"]), bundle["review_ids"]
        references(ids,entries)
        if bid in bundles or not 1 <= len(ids) <= 20 or set(ids) & original.keys():
            raise ValueError("native bundles must partition distinct claims with maximum 20")
        if bundle.get("review_count",len(ids)) != len(ids):
            raise ValueError("native bundle review count differs")
        bundles[bid] = bundle
        selected.extend(ids)
        original.update({rid:bid for rid in ids})
    if not 1 <= len(selected) <= MAX_CLAIMS or manifest.get("review_count",len(selected)) != len(selected):
        raise ValueError("routing requires 1..128 selected native claims with exact coverage")
    if manifest.get("bundle_count",len(bundles)) != len(bundles):
        raise ValueError("native bundle count differs")

    files, cache, file_bytes = {}, {}, {}
    def lines(path):
        if path not in cache:
            data = source(root,path)
            file_bytes[path] = len(data)
            if sum(file_bytes.values())>16*1024*1024:
                raise ValueError("routing source intake exceeds 16 MiB")
            files[path] = hashlib.sha256(data).hexdigest()
            cache[path] = context.source_lines(data.decode("utf-8"))
        return cache[path]

    def windows(values, *, bounded=True):
        if not isinstance(values,list) or not values or bounded and len(values)>8:
            raise ValueError("expected bounded source evidence windows")
        result, total = {}, 0
        for frame in values:
            shape(frame,("path","start_line","end_line","file_sha256"))
            path, first, last = frame["path"], frame["start_line"], frame["end_line"]
            text = lines(path)
            if files[path] != frame["file_sha256"]:
                raise ValueError("routing source changed: "+path)
            if type(first) is not int or type(last) is not int or not 1 <= first <= last <= len(text):
                raise ValueError("routing source coordinates differ")
            size = len("\n".join(text[first-1:last]).encode("utf-8"))
            if bounded and (last-first>=400 or size>16384):
                raise ValueError("routing source window exceeds 400 lines/16 KiB")
            key = (path,first,last)
            if key not in result:
                result[key] = dict(frame)
                total += size
        if bounded and total>65536:
            raise ValueError("routing source windows exceed 64 KiB")
        return [result[key] for key in sorted(result)]

    anchors = {}
    for rid in selected:
        entry = entries[rid]
        if type(entry["line"]) is not int or not 1 <= entry["line"] <= len(lines(entry["path"])):
            raise ValueError("claim anchor lies outside source")
        anchors[rid] = {**{k:entry[k] for k in planner.ENTRY_FIELDS},"file_sha256":files[entry["path"]]}

    if planner_plan is not None:
        if not engine_sha256:
            raise ValueError("planner validation requires the bound scanner hash")
        planner.validate(planner_plan,root,inventory,engine_sha256)
        if set(planner_plan["selected_review_ids"]) != set(selected):
            raise ValueError("planner selection differs from native bundles")
        for path,digest in planner_plan["files"].items():
            lines(path)
            if files[path] != digest:
                raise ValueError("planner source changed")

    chosen, investigations, promotion_limits = {}, [], {}
    def add(ids, route, kind, question, reason, checks, evidence, limits, origin):
        references(ids,original)
        if len(ids)>20 or set(ids) & chosen.keys():
            raise ValueError("routing selections overlap or exceed 20 claims")
        label(question); label(reason)
        if route == "workspace":
            if kind not in WORKSPACE_KINDS or kind == "relationship" and len(ids)!=1:
                raise ValueError("invalid workspace relationship selection")
            if kind != "relationship" and len(ids)<2:
                raise ValueError("shared investigation needs at least two claims")
            if not isinstance(checks,dict) or set(checks)!=set(ids):
                raise ValueError("workspace requires a distinct caller/check question for every claim")
            for check in checks.values(): label(check)
            evidence = windows(evidence)
        elif kind != "native_local" or checks or evidence:
            raise ValueError("native selection must not assert shared applicability")
        if not isinstance(limits,list) or not limits:
            raise ValueError("routing selection must retain limits")
        for limit in limits: label(limit)
        if kind == "packet_batch":
            limits = [*limits,"Packet co-location only: members may have different implementations and caller policies. Reuse facts only for explicitly applicable consumers; keep every verdict separate."]
        value = {"route":route,"kind":kind,"review_ids":ids,"deciding_question":question,
                 "reason":reason,"caller_checks":checks,"evidence_windows":evidence,
                 "limits":limits,"origin":origin}
        value["id"] = "investigation-"+identity(value)[:20]
        investigations.append(value)
        chosen.update({rid:value for rid in ids})

    if selections is not None:
        shape(selections,("schema_version","binding","selections"))
        if selections["schema_version"] != SELECTION_VERSION or selections["binding"] != input_binding(inventory,manifest):
            raise ValueError("routing selection binding differs")
        if not isinstance(selections["selections"],list) or len(selections["selections"])>MAX_CLAIMS:
            raise ValueError("invalid routing selections")
        for spec in selections["selections"]:
            shape(spec,("review_ids","route","kind","deciding_question","reason","caller_checks","evidence_windows","limits"))
            if spec["route"] not in {"native","workspace"}:
                raise ValueError("unknown routing path")
            add(spec["review_ids"],spec["route"],spec["kind"],spec["deciding_question"],spec["reason"],
                spec["caller_checks"],spec["evidence_windows"],spec["limits"],"explicit_selection")

    # Only demonstrated same-operation proposals promote claims automatically.
    # SQL group membership is useful batching evidence, not a workspace route.
    if planner_plan is not None:
        by_id = {c["entry"]["review_id"]:c for c in planner_plan["claims"]}
        for work in planner_plan["work"]:
            ids = [rid for rid in work["review_ids"] if rid not in chosen]
            if work["kind"] != "shared_operation" or len(ids)<2:
                continue
            frames = []
            for rid in ids:
                info = by_id[rid]
                frames.extend([info["unit"]["frame"],info["caller"]["frame"],*info["caller"]["binding_frames"]])
            evidence = [{k:f[k] for k in ("path","start_line","end_line","file_sha256")}
                        for f in frames]
            # A proposal can contain identical windows for several claims.
            evidence = windows(evidence,bounded=False)
            sizes = [len("\n".join(lines(f["path"])[f["start_line"]-1:f["end_line"]]).encode("utf-8")) for f in evidence]
            if (len(evidence)>8 or sum(sizes)>65536 or max(sizes)>16384
                    or any(f["end_line"]-f["start_line"]>=400 for f in evidence)):
                promotion_limits.update({rid:"Same-operation proposal exceeds routing source bounds; retain native batching." for rid in ids})
                continue  # Retain native fallback when a bounded proposal is unavailable.
            add(ids,"workspace","shared_operation",
                "Which identity/check-to-selector/effect relationship is shared by this bound registration, and which claim-specific effects differ?",
                work["reason"],{rid:"Bind this claim's actual checks, selected resource and effect independently; a peer's verdict is not proof." for rid in ids},
                evidence,list(work["limits"]),"planner:"+work["id"])

    planner_claims = {c["entry"]["review_id"]:c for c in planner_plan["claims"]} if planner_plan else {}
    planner_groups = {rid:w["id"] for w in planner_plan["work"] for rid in w["review_ids"]} if planner_plan else {}
    rows, packets = [], []
    for rid in selected:
        kind, question = local_strategy(entries[rid])
        selection = chosen.get(rid)
        rows.append({"review_id":rid,"original_bundle_id":original[rid],"anchor":anchors[rid],
            "route":selection["route"] if selection else "native",
            "strategy":selection["kind"] if selection else kind,
            "investigation_id":selection["id"] if selection and selection["route"]=="workspace" else None,
            "deciding_question":selection["deciding_question"] if selection else question,
            "reason":selection["reason"] if selection else "No selected shared/relational investigation; preserve ordinary native batching.",
            "selection_id":selection["id"] if selection else None,
            "planner_work_id":planner_groups.get(rid),
            "planner_abstention":planner_claims.get(rid,{}).get("abstention"),
            "promotion_limit":promotion_limits.get(rid)})
    by_id = {r["review_id"]:r for r in rows}
    for bid,bundle in bundles.items():
        ids = [rid for rid in bundle["review_ids"] if by_id[rid]["route"]=="native"]
        if ids:
            packets.append({"original_bundle_id":bid,"review_ids":ids,
                "workspace_review_ids":[rid for rid in bundle["review_ids"] if rid not in ids],
                "authority":"Packet batching only; preserve separate decisions and reassemble every original bundle ID before native validation."})
    value = {"schema_version":VERSION,"binding":{**input_binding(inventory,manifest),"source_root":str(root),
            "router_sha256":worker.digest_file(__file__),"planner_plan_sha256":identity(planner_plan) if planner_plan else None,
            "selections_sha256":identity(selections) if selections is not None else None},
        "selected_review_ids":selected,"claims":rows,"investigations":investigations,"native_packets":packets,"files":files,
        "dispatch_effects":dispatch_effects(manifest,rows,investigations,packets),
        "preparation":{"model_calls":0,"native_queries":0,"source_files_read":len(cache),"source_bytes_read":sum(file_bytes.values()),
                       "upstream_planner":planner_plan["planning"] if planner_plan else None,
                       "explicit_selection_count":len(selections["selections"]) if selections else 0,
                       "selection_labor_ms":None},
        "limits":["Proposed execution paths only: source binding does not certify sharing, caller applicability, completeness, severity or any verdict.",
                  "Native maximum remains 20. Mixed original bundles require result assembly; this artifact cannot be dispatched as a native bundle.",
                  "Selected-file freshness is checked; full snapshot freshness and native ownership/admission are not checked here.",
                  "No model dispatch, automatic handoff, facts or additional investigation allowances are created."],
        "native_admission":False,"dispatch_ready":False}
    value["routing_id"] = identity(value)
    return value


def validate(plan, root, inventory, manifest, **options):
    if plan != build(root,inventory,manifest,**options):
        raise ValueError("routing proposal, inputs, runtime or source differ")


def render(plan):
    def cell(value): return str(value).replace("|","\\|").replace("\n"," ").replace("\r"," ")
    rows = ["# Review routing proposal", "", "Inspection only; dispatch is not implemented by this artifact.", "",
            "| Claim | Route | Strategy | Original bundle | Deciding question | Reason |",
            "| --- | --- | --- | --- | --- | --- |"]
    for claim in plan["claims"]:
        rows.append("| "+" | ".join(cell(claim[k]) for k in ("review_id","route","strategy","original_bundle_id","deciding_question","reason"))+" |")
        if claim["planner_abstention"] or claim["promotion_limit"]:
            rows.append("| "+cell(claim["review_id"])+" | | Limit | | | "+cell(claim["promotion_limit"] or claim["planner_abstention"])+" |")
    effects = plan["dispatch_effects"]
    rows.extend(["", "## Dispatch effects", "",
                 str(effects["original_native_packets"])+" original native packets; "+str(effects["proposed_native_packets"])+
                 " proposed native packets + "+str(effects["proposed_workspace_investigations"])+" workspace investigations = "+
                 str(effects["proposed_dispatch_units"])+" proposed units (delta "+str(effects["dispatch_unit_delta"])+").", "",
                 effects["authority"], "", "Split original bundles: "+(", ".join(effects["split_original_bundle_ids"]) or "none")])
    for group in effects["workspace_groups"]:
        if group["already_one_native_packet"]:
            rows.append("\n- "+group["investigation_id"]+": all members already fit one native packet; workspace must justify its state/reuse value separately.")
    for group in plan["investigations"]:
        rows.extend(["", "## "+group["id"], "", cell(group["deciding_question"]), "", "Members: "+", ".join(group["review_ids"]),
                     "", "Origin: "+group["origin"], "", "Reason: "+cell(group["reason"])])
        for rid,check in group["caller_checks"].items(): rows.append("\n- "+rid+": "+cell(check))
        for frame in group["evidence_windows"]:
            rows.append("\n- Source: "+cell(frame["path"])+":"+str(frame["start_line"])+"–"+str(frame["end_line"])+" (`"+frame["file_sha256"]+"`)")
        for limit in group["limits"]: rows.append("\n- Limit: "+cell(limit))
    rows.extend(["", "## Limits", "", *["- "+cell(limit) for limit in plan["limits"]], ""])
    return "\n".join(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-root","inventory","manifest"):
        parser.add_argument("--"+name,required=True)
    parser.add_argument("--planner-plan")
    parser.add_argument("--scanner",help="hash only, required with a planner proposal; never executed")
    parser.add_argument("--selections")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output",help="new artifact directory outside application source")
    mode.add_argument("--check",help="existing artifact directory to validate without writing")
    args = parser.parse_args()
    if args.planner_plan and not args.scanner:
        parser.error("--planner-plan requires --scanner for binding validation")
    started = time.monotonic()
    root = Path(args.source_root).resolve(strict=True)
    inventory_path = Path(args.inventory)
    inventory = worker.read(inventory_path/"inventory.json" if inventory_path.is_dir() else inventory_path)
    manifest = worker.read(args.manifest)
    options = {"planner_plan":worker.read(args.planner_plan) if args.planner_plan else None,
               "selections":worker.read(args.selections) if args.selections else None,
               "engine_sha256":worker.digest_file(args.scanner) if args.planner_plan else None}
    if args.check:
        validate(worker.read(Path(args.check)/"routing.json"),root,inventory,manifest,**options)
        print(json.dumps({"valid":True,"model_calls":0,"native_queries":0,"native_admission":False}))
        return
    output = worker.outside(args.output,root,existing=False)
    if output.exists():
        raise ValueError("routing output already exists")
    plan = build(root,inventory,manifest,**options)
    output.mkdir(parents=True,exist_ok=False)
    worker.write(output/"routing.json",plan)
    worker.write_text(output/"routing.md",render(plan))
    receipt = {"routing_id":plan["routing_id"],"elapsed_ms":round(1000*(time.monotonic()-started)),
               "claims":len(plan["claims"]),"native_claims":sum(c["route"]=="native" for c in plan["claims"]),
               "workspace_claims":sum(c["route"]=="workspace" for c in plan["claims"]),
               "dispatch_effects":plan["dispatch_effects"],
               "model_calls":0,"native_queries":0,"native_admission":False,"dispatch_ready":False}
    worker.write(output/"preparation.json",receipt)
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
