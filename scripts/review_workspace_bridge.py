#!/usr/bin/env python3
"""Experimental native-bound, single-turn workspace checkpoint adapter.

Bootstraps from native state work, prepares fresh bundled-provider tasks and
finalizes original complete bundles. It never records decisions in native state.
"""
import argparse
from contextlib import contextmanager
from functools import wraps
import json
import os
from pathlib import Path
import sys
import time

import review_context as context
import review_source_profile as source_profiles
import review_worker as worker
from review_workspace import Workspace, encoded, identity, number, references, shape, render_review_package, MAX_CONTEXT_BYTES
import review_workspace_actions as actions


VERSION = "mehscanWorkspaceBridge/experimental-v1"


def provider_environment():
    return {key:os.environ[key] for key in ("PATH","SYSTEMROOT","WINDIR","TEMP","TMP","LANG","LC_ALL") if key in os.environ}


def observed(method):
    @wraps(method)
    def run(self, *args, **kwargs):
        started, completed = time.monotonic(), False
        try:
            result = method(self, *args, **kwargs)
            completed = True
            return result
        finally:
            self.trace("operation", operation=method.__name__, completed=completed,
                       elapsed_ms=round((time.monotonic() - started) * 1000))
    return run


def read(path):
    if Path(path).stat().st_size > 8 * 1024 * 1024:
        raise ValueError("bridge input exceeds bounded intake")
    return worker.read(path)


def implementation():
    directory = Path(__file__).resolve().parent
    return {name:worker.digest_file(directory / name) for name in (
        "review_workspace_bridge.py", "review_workspace.py", "review_workspace_actions.py",
        "review_workspace_planner.py", "review_workspace_evidence.py", "review_worker.py", "review_context.py",
        "review_source_profile.py")}


class NativeWorkspace:
    def __init__(self, args, *, creating=False):
        self.args = args
        self.root = Path(args.source_root).resolve(strict=True)
        self.directory = worker.outside(args.directory, self.root, existing=not creating)
        self.scanner = worker.outside(args.scanner, self.root)
        self.skill = worker.outside(args.skill_root, self.root)
        self.inventory = worker.outside(args.inventory, self.root)
        self.store = worker.outside(args.store, self.root)
        self.claim_path = worker.outside(args.claim, self.root)
        self.package_path = worker.outside(args.work_package, self.root)
        self.provider_path = worker.outside(args.provider_contract, self.root) if args.provider_contract else None
        # Ownership credentials stay in private inputs, outside exported artifacts.
        if self.claim_path.is_relative_to(self.directory) or self.store.is_relative_to(self.directory):
            raise ValueError("native store and ownership receipt must stay outside workspace artifacts")
        claim = read(self.claim_path)["result"]
        self.common = ["--store",str(self.store),"--stream",args.stream,"--inventory",str(self.inventory),
                       "--source-root",str(self.root),"--generation",str(claim["generation"]),"--owner",claim["owner"]]
        self.package = read(self.package_path)
        self.payload = self.package["payload"]
        self.runtime = self.payload.get("runtime")
        if not self.runtime or self.runtime.get("worker_protocol") != 2 or self.runtime.get("schema_version") != "1":
            raise ValueError("workspace bridge requires a current native runtime-bound plan")
        if self.runtime.get("policy") != self.payload["policy"] or self.runtime.get("orchestration"):
            raise ValueError("workspace checkpoint supports the ordinary single-model runtime only")
        if not self.payload["review_ids"]:
            raise ValueError("workspace checkpoint requires selected native claims")
        self.metadata = None if creating else read(self.directory / "native-binding.json")
        self.source_profile = (source_profiles.load(worker.outside(args.source_profile, self.root), self.payload)
                               if creating and getattr(args, "source_profile", None) else
                               self.metadata.get("source_profile") if self.metadata else None)
        if self.source_profile is not None:
            source_profiles.validate(self.source_profile, self.payload)
        self.profile_id = None if self.source_profile is None else identity(self.source_profile)
        self.catalog_id = None if creating else self.metadata.get("catalog_id")
        if not creating and self.catalog_id is None:
            raise ValueError("native context catalog binding missing; create a fresh workspace")
        self.experiment_binding = None if creating else {k:self.metadata[k] for k in ("limits","experiment")}
        self.workspace = None if creating else Workspace(self.directory / "workspace.sqlite", self.binding())

    def binding(self):
        return {"snapshot_id":self.payload["snapshot_id"], "plan_id":self.payload["plan_id"],
                "runtime_id":identity([self.package["package_id"], self.runtime, implementation(), self.experiment_binding,self.catalog_id,
                                      *([self.profile_id] if self.profile_id else [])])}

    def native(self, arguments, timeout=None):
        if arguments[:2] == ["state", "work"]:
            arguments = [*arguments,"--skill-root",str(self.skill)]
            if self.provider_path:
                arguments += ["--provider-contract",str(self.provider_path)]
        env = {key:value for key,value in os.environ.items() if key not in ("GH_TOKEN","GITHUB_TOKEN")
               and not key.startswith("GIT_CONFIG_") and not key.endswith("_API_KEY")}
        env.update(GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")
        started, completed = time.monotonic(), False
        try:
            value = worker.execute([str(self.scanner),*arguments], self.directory if self.directory.exists() else self.directory.parent,
                                   env, min(self.runtime["limits"]["timeout_seconds"], 600, timeout if timeout is not None else 600))
            completed = True
            return value
        finally:
            self.trace("native",operation="/".join(arguments[:2]),completed=completed,
                       elapsed_ms=round((time.monotonic() - started) * 1000))

    def trace(self, event, **values):
        if self.directory.is_dir():
            # The stream guard serializes bridge writers. Never log argv, owner,
            # provider configuration, target text or authentication here.
            with (self.directory / "bridge-trace.jsonl").open("a",encoding="utf-8") as handle:
                handle.write(json.dumps({"event":event,"time_ms":round(time.time()*1000),**values}) + "\n")

    def check(self):
        if worker.digest_file(self.scanner) != self.runtime["engine_sha256"] or context.skill_bundle_id(self.skill) != self.runtime["skill_bundle_id"]:
            raise ValueError("native runtime or trusted skill changed")
        if (read(self.provider_path) if self.provider_path else None) != self.runtime.get("provider"):
            raise ValueError("native provider binding differs")
        if read(self.package_path) != self.package:
            raise ValueError("supplied native work package changed")
        current = self.native(["state","work",*self.common,"--review-ids",",".join(self.payload["review_ids"])])
        if current != self.package:
            raise ValueError("native work package is stale or altered")
        if self.metadata:
            if (None if self.metadata.get("source_profile") is None else identity(self.metadata["source_profile"])) != self.profile_id:
                raise ValueError("workspace explicit source profile changed")
            expected = {"version":VERSION, "package":self.package, "source_root":str(self.root),
                        "implementation":implementation(),"catalog_id":self.catalog_id}
            if any(self.metadata.get(k) != v for k,v in expected.items()):
                raise ValueError("workspace native/implementation binding differs")
            if identity(self.metadata["bundles"]) != self.catalog_id:
                raise ValueError("native context catalog changed")
            for name, digest in self.metadata["artifacts"].items():
                if worker.digest_file(self.directory / name) != digest:
                    raise ValueError("bound workspace artifact changed: " + name)
            state = self.workspace.snapshot()
            if state["selection_id"] != self.metadata["selection_id"] or state["limits"] != self.metadata["limits"]:
                raise ValueError("workspace selection or allowance differs")

    @contextmanager
    def guarded(self, *, fresh=True):
        # Share the ordinary worker's stream lock, not just the SQLite lock.
        key = context.digest([str(self.root), self.args.stream])
        with worker.controller_lock(self.store / ("review-controller-" + key + ".lock")):
            if fresh:
                self.check()
            elif (self.metadata["package"] != self.package or self.metadata["implementation"] != implementation()):
                raise ValueError("accounting recovery binding differs")
            yield
            if fresh:
                self.check()

    def apply(self, key, action, *, before_commit=None):
        previous = self.workspace.operation(key)
        revision = previous["request"]["revision"] if previous else self.workspace.snapshot()["revision"]
        return self.workspace.apply(key, revision, action, before_commit=before_commit)["result"]

    @classmethod
    def create(cls, args, limits, experiment):
        started = time.monotonic()
        bridge = cls(args, creating=True)
        shape(limits, ("model_calls","queries","source_bytes"))
        shape(experiment, ("max_input_tokens","max_output_tokens","max_elapsed_seconds","context_max_bytes"),
                      ("protocol","max_received_query_bytes","bundle_max_reviews","prepare_application","knowledge_lookup"))
        if experiment.get("protocol","checkpoint") not in ("checkpoint",actions.VERSION):
            raise ValueError("unsupported workspace experiment protocol")
        if experiment.get("protocol") == actions.VERSION and any(bridge.payload[k] for k in ("parent_decisions","pending_questions","evidence_updates")):
            raise ValueError("workspace actions pilot requires fresh native work without inherited decisions/facts")
        for value in limits.values():
            number(value)
        for value in [limits["model_calls"], limits["source_bytes"], *[v for k,v in experiment.items() if k not in ("protocol","prepare_application","knowledge_lookup")]]:
            number(value, positive=True)
        if "prepare_application" in experiment and type(experiment["prepare_application"]) is not bool:
            raise ValueError("prepare_application must be boolean")
        if "knowledge_lookup" in experiment and type(experiment["knowledge_lookup"]) is not bool:
            raise ValueError("knowledge_lookup must be boolean")
        if experiment["max_elapsed_seconds"] > 3600 or experiment["context_max_bytes"] > MAX_CONTEXT_BYTES:
            raise ValueError("experiment exceeds bounded checkpoint limits")
        count = len(bridge.payload["review_ids"])
        ceilings = {"model_calls":count * (bridge.runtime["limits"]["rounds"] + 1),
                    "queries":count * bridge.runtime["limits"]["queries"],
                    "source_bytes":count * bridge.runtime["limits"]["bytes"]}
        if any(limits[k] > ceilings[k] for k in limits):
            raise ValueError("experiment allowance exceeds aggregate native ceilings")
        bridge.experiment_binding = {"limits":limits,"experiment":experiment}
        with bridge.guarded():
            bridge.directory.mkdir(exist_ok=False)
            bundle_args = ["investigate","review-bundles",str(bridge.root),"--inventory",str(bridge.inventory),
                           "--review-ids",",".join(bridge.payload["review_ids"]),"--output",str(bridge.directory / "run")]
            if "bundle_max_reviews" in experiment:
                bundle_args += ["--max-reviews",str(experiment["bundle_max_reviews"])]
            bridge.native(bundle_args)
            manifest = read(bridge.directory / "run/manifest.json")
            source_profiles.check_bundles(bridge.source_profile, [b["review_ids"] for b in manifest["bundles"]])
            claims, catalog, prepared, selected = [], {}, [], []
            initial = {}
            for bundle in manifest["bundles"]:
                name = bundle["filename"]
                if Path(name).name != name:
                    raise ValueError("native bundle filename must be flat")
                request_path = bridge.directory / "run/requests" / name
                request = read(request_path)
                sweep = bridge.native(["investigate","review-sweep","--bundle",str(request_path)])
                if request["review_ids"] != bundle["review_ids"] or sweep["bundle_fingerprint"] != bundle["bundle_fingerprint"]:
                    raise ValueError("native bundle catalog mismatch")
                questions = {q["id"]:q for q in sweep["questions"]}
                entries = []
                for card in sweep["reviews"]:
                    question, anchor = questions[card["question_id"]], card["anchor"]
                    claim = {"review_id":card["review_id"], "property":question["security_question"],
                             "path":anchor["location"]["path"],"line":anchor["location"]["start_line"],
                             "bundle_id":bundle["bundle_fingerprint"]}
                    claims.append(claim)
                    native_context = {key:card[key] for key in (
                        "anchor","operand_facts","decision_facts","nearby_locations","application_context",
                        "frontend_context","truncation","contract_keys") if key in card}
                    native_context.update(relationship=question["relationship"],
                        authority="Native observations and open leads; not a verdict, caller-applicability proof or mandatory investigation checklist.")
                    entries.append({**claim,"capability":anchor["capability"],"rule_id":anchor["rule_id"],
                                    "native_context":native_context})
                    selected.append(claim["review_id"])
                if set(request["review_ids"]) != {e["review_id"] for e in entries}:
                    raise ValueError("native sweep dropped bundle members")
                catalog[bundle["bundle_fingerprint"]] = {"filename":name, "review_ids":bundle["review_ids"],
                                                         "entries":entries,"playbooks":request["review_playbooks"],
                                                         "contracts":sweep.get("contracts",[])}
                for window in sweep["source_contexts"]:
                    consumers = [c["review_id"] for c in sweep["reviews"] if window["id"] in c["source_context_ids"]]
                    # Native supplies some helper windows only at bundle scope.
                    # Sharing source does not establish applicability to a claim.
                    if not consumers:
                        consumers = bundle["review_ids"]
                    if consumers:
                        prepared.append((window, consumers))
                if experiment.get("prepare_application"):
                    application = context.prepare_application(bridge.root,sweep,{},bridge.payload["snapshot_id"])
                    for window in application["windows"]:
                        prepared.append(({"location":{k:window[k] for k in ("path","start_line","end_line")}},bundle["review_ids"]))
                explicit = source_profiles.prepare(bridge.root, bridge.source_profile, bundle["review_ids"], bridge.payload["snapshot_id"])
                for window in explicit["windows"]:
                    prepared.append(({"location":{k:window[k] for k in ("path","start_line","end_line")},
                                      "excerpt":window["text"]}, bundle["review_ids"]))
            references(selected, bridge.payload["review_ids"])
            if set(selected) != set(bridge.payload["review_ids"]):
                raise ValueError("native generation dropped selected claims")
            bridge.catalog_id = identity(catalog)
            bridge.workspace = Workspace.create(bridge.directory / "workspace.sqlite", bridge.root, bridge.binding(), claims, limits)
            worker.write(bridge.directory / "seed.json",{"source_root":str(bridge.root),"binding":bridge.binding(),"claims":claims,"limits":limits})
            evidence_ids = []
            for i, (window, consumers) in enumerate(prepared):
                location = window["location"]
                last = location["end_line"]
                if "excerpt" in window:
                    # Sweep source-table endpoints may be AST end-exclusive.
                    # Import only the returned line content, never a neighbor.
                    if not window["excerpt"]:
                        continue
                    last = location["start_line"] + len(context.source_lines(window["excerpt"])) - 1
                # Preparation uses exact current source, not the sweep's prose.
                for first in range(location["start_line"], last + 1, 400):
                    action = {"kind":"source", "path":location["path"],
                        "start_line":first,"end_line":min(first + 399, last),"review_id":consumers[0]}
                    if "excerpt" in window:
                        offset = first - location["start_line"]
                        action["excerpt"] = "\n".join(context.source_lines(window["excerpt"])[offset:offset+400]) + "\n"
                    result = bridge.apply(f"prepare:{i}:{first}",action)
                    evidence_ids.append(result["evidence_id"])
                    for claim_id in consumers:
                        initial.setdefault(claim_id,[]).append(result["evidence_id"])
            bridge.apply("initial-focus", {"kind":"focus","work_id":"initial",
                                           "evidence_ids":sorted(set(evidence_ids)),"proposition_ids":[]})
            artifacts = {str(p.relative_to(bridge.directory)).replace("\\","/"):worker.digest_file(p)
                         for p in (bridge.directory / "run").rglob("*.json") if "responses" not in p.parts}
            artifacts["seed.json"] = worker.digest_file(bridge.directory / "seed.json")
            bridge.metadata = {"version":VERSION,"package":bridge.package,"source_root":str(bridge.root),
                               "implementation":implementation(),"artifacts":artifacts,"bundles":catalog,"catalog_id":bridge.catalog_id,
                               "selection_id":bridge.workspace.snapshot()["selection_id"],"limits":limits,"experiment":experiment,
                               "initial_evidence":{k:sorted(set(v)) for k,v in initial.items()}}
            bridge.metadata["source_profile"] = bridge.source_profile
            # Check the complete native source/runtime/owner binding again before publication.
            bridge.check()
            worker.write(bridge.directory / "native-binding.json", bridge.metadata)
        bridge.trace("operation",operation="init",completed=True,elapsed_ms=round((time.monotonic() - started)*1000))
        return bridge

    def _provider(self, config_path):
        path = worker.outside(config_path, self.root)
        if path.is_relative_to(self.directory):
            raise ValueError("provider configuration must stay outside workspace artifacts")
        argv = [sys.executable,str(self.skill / "scripts/codex_reviewer.py"),"--config",str(path)]
        descriptor = worker.execute([*argv,"--contract"], self.directory, provider_environment(), 30)
        if descriptor != self.runtime.get("provider"):
            raise ValueError("actual provider differs from native runtime")
        return argv

    def provider_packet(self, view):
        """Project a source-checked view; no session or execution authority."""
        ids = [c["review_id"] for c in view["claims"]] + list(view["answer_consumers"])
        entries = [entry for b in self.metadata["bundles"].values() for entry in b["entries"] if entry["review_id"] in ids]
        playbooks = {k:v for b in self.metadata["bundles"].values() for k,v in b["playbooks"].items() if k in ids}
        contract_keys = {key for entry in entries for key in entry["native_context"].get("contract_keys",[])}
        native_contracts = {c["contract"]:c for b in self.metadata["bundles"].values()
                            for c in b["contracts"] if c["contract"] in contract_keys}
        windows = [{"artifact_id":k, **{field:e[field] for field in
                    ("path","start_line","end_line","text","complete_file")}, "clipped":e.get("fragment",False)}
                   for k,e in view["evidence"].items()]
        for window in windows:
            window["line_range"] = {"start_line":window["start_line"],"end_line":window["end_line"],"inclusive":True}
        packet = {"schema_version":"1","package_id":self.package["package_id"],
                  "source_binding":{"snapshot_id":self.payload["snapshot_id"],
                                    "inventory_input_fingerprint":self.payload["inventory_input_fingerprint"]},
                  "contract":context.compile_contract(self.skill,"native_bundle",entries,[],playbooks),
                  "work":context.compact_work(self.payload,ids),"native_questions":entries,
                  "primary":{"windows":windows,"limits":view["preparation_limits"]},
                  "workspace_evidence":{"propositions":view["propositions"],"applicability":view["applicability"],
                                        "native_contracts":native_contracts,
                                        "deciding_evidence":view["deciding_evidence"],
                                        "questions":view["questions"],"authority":view["authority"]}}
        if view["answer_consumers"]:
            packet["workspace_evidence"]["answer_consumers"] = view["answer_consumers"]
        mode = self.metadata["experiment"].get("protocol","checkpoint")
        if mode == actions.VERSION:
            packet.update(workspace_protocol=mode,contract={"version":mode,"sources":[
                context.sections(self.skill / "references/runtime-review.md",["api_semantics"])]},
                          work={"runtime":self.runtime,"review_ids":ids,"policy":self.payload["policy"]})
            packet["workspace_evidence"]["lookups"] = view["lookups"]
            packet["workspace_guidance"] = list(view["guidance"].values())
        if len(encoded(packet).encode("utf-8")) > self.metadata["experiment"]["context_max_bytes"]:
            raise ValueError("assembled provider packet exceeds context limit; narrow the work item")
        return packet,ids

    @observed
    def prepare(self, work_id, config_path, operation_key, parent_session=None):
        with self.guarded():
            self._provider(config_path)
            view = self.workspace.view(work_id, self.metadata["experiment"]["context_max_bytes"])
            if not view["claims"]:
                raise ValueError("work item has no active claims")
            session = self.apply(operation_key, {"kind":"session","work_id":work_id,"parent_session":parent_session,
                                                "max_bytes":self.metadata["experiment"]["context_max_bytes"]})
            key = session["session_id"]
            stored = self.workspace.snapshot()["sessions"][key]
            if stored["retired"]:
                raise ValueError("prepared session has been replaced")
            comparison = {k:v for k,v in view.items() if k != "budget"}
            if comparison != {k:v for k,v in stored["packet"].items() if k != "budget"}:
                raise ValueError("preparation retry has a different working context")
            directory = self.directory / "sessions" / key
            if "artifacts" in stored:
                self._session(key,config_path)
                return {"session_id":key,"directory":str(directory),"review_ids":[c["review_id"] for c in view["claims"]]+list(view["answer_consumers"]),"native_admission":False}
            directory.mkdir(parents=True, exist_ok=True)
            packet,ids = self.provider_packet(view)
            windows = packet["primary"]["windows"]
            mode = self.metadata["experiment"].get("protocol","checkpoint")
            handles = {"source" + str(i):w["artifact_id"] for i,w in enumerate(windows,1)}
            task = {"kind":"native_bundle","conversation_id":key,"source_root":str(self.root),
                    "artifact_root":str(self.directory),"evidence_packet":str(directory / "context.json"),
                    "shared_facts":str(directory / "facts.json"),"review_ids":ids,"profile":"routine",
                    "review_role":"investigator","routing_allowed":False,
                    "provider_metrics":str(directory / "provider-metrics.jsonl"),
                    "research":{"round":0,"rounds_remaining":0,"queries_remaining":0,"bytes_remaining":0,
                                "seconds_remaining":self.runtime["limits"]["timeout_seconds"],"results":[],
                                "artifact_handles":handles,"source_artifact_handles":list(handles)}}
            if mode == actions.VERSION:
                task["workspace_protocol"] = mode
                task["research"]["queries_remaining"] = view["budget"]["limits"]["queries"] - view["budget"]["used"]["queries"]
                task["research"]["workspace_budget"] = view["budget"]
            worker.write(directory / "context.json",packet)
            worker.write(directory / "facts.json",{"facts":[]})
            worker.write(directory / "task.json",task)
            artifacts = {"provider_config_digest":worker.digest_file(config_path),
                         "files":{name:worker.digest_file(directory / name) for name in ("context.json","facts.json","task.json")}}
            self.apply("provider-packet:" + key,{"kind":"attach_session","session_id":key,"artifacts":artifacts})
            return {"session_id":key,"directory":str(directory),"review_ids":ids,"native_admission":False}

    def _session(self, session_id, config_path):
        if len(session_id) != 64 or any(c not in "0123456789abcdef" for c in session_id):
            raise ValueError("invalid workspace session identity")
        session = self.workspace.snapshot()["sessions"][session_id]
        directory = self.directory / "sessions" / session_id
        binding = session["artifacts"]
        if binding["provider_config_digest"] != worker.digest_file(config_path):
            raise ValueError("provider session binding differs")
        for name in ("context.json","facts.json","task.json"):
            if binding["files"][name] != worker.digest_file(directory / name):
                raise ValueError("prepared provider packet changed")
        if session["retired"]:
            raise ValueError("workspace session is retired")
        return directory, read(directory / "task.json"), read(directory / "context.json")

    def _remaining_seconds(self, work_id=None):
        state = self.workspace.snapshot()
        if state["received_query_bytes"] >= self.metadata["experiment"].get("max_received_query_bytes",2**63):
            raise ValueError("experiment received-query byte ceiling reached")
        totals = self.workspace.usage()["totals"]
        if state["calls"] and any(totals[k] is None for k in ("input_tokens","output_tokens")):
            raise ValueError("previous provider usage is unknown; reconcile before another call")
        experiment = self.metadata["experiment"]
        for key,limit in (("input_tokens","max_input_tokens"),("output_tokens","max_output_tokens")):
            if totals[key] >= experiment[limit]:
                raise ValueError("experiment observed token ceiling reached")
        started = min((c["started_epoch_ms"] for c in state["calls"].values()), default=round(time.time()*1000))
        remaining = experiment["max_elapsed_seconds"] - (round(time.time()*1000) - started) / 1000
        if remaining <= 0:
            raise ValueError("experiment elapsed-time ceiling reached")
        timeout = self.runtime["limits"]["timeout_seconds"]
        if work_id is not None:
            ancestors, current = set(), work_id
            while current is not None:
                ancestors.add(current)
                current = state["work"][current]["parent"]
            claims = set(state["work"][work_id]["claims"])
            sessions = {k:s for k,s in state["sessions"].items() if s["work_id"] == work_id or
                        s["work_id"] in ancestors and claims.intersection(c["review_id"] for c in s["packet"]["claims"])}
            starts = [s["prepared_epoch_ms"] for s in sessions.values() if "prepared_epoch_ms" in s]
            starts += [c["started_epoch_ms"] for c in state["calls"].values() if c["session_id"] in sessions]
            if starts:
                timeout -= (round(time.time()*1000)-min(starts))/1000
            if timeout <= 0:
                raise ValueError("work item absolute deadline reached")
        return min(remaining, timeout)

    def _usage(self, session_id, round_index=0):
        state = self.workspace.snapshot()
        suffix = session_id + (":" + str(round_index) if round_index else "")
        call_id = "call:" + suffix
        call = state["calls"][call_id]
        if call["usage"] is not None:
            return
        path = self.directory / "sessions" / session_id / "provider-metrics.jsonl"
        if not path.exists():
            return  # An interrupted or unobserved call remains unknown, never free.
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        if any(r.get("conversation_id") != session_id or r.get("provider") != self.runtime["provider"]
               or type(r.get("round")) is not int or r["round"] not in (0,1) for r in rows):
            raise ValueError("checkpoint metrics do not describe bound turns")
        matching = [r for r in rows if r["round"] == round_index]
        if len(rows) != len({r["round"] for r in rows}):
            raise ValueError("checkpoint metrics do not describe one exact bound turn")
        if not matching:
            return  # A prior receipt cannot price an interrupted correction.
        row = matching[0]
        usage = {k:row.get("usage",{}).get(k) for k in ("input_tokens","cached_input_tokens","output_tokens")}
        for key in row.get("unknown_delta_counters",[]):
            if key in usage:usage[key] = None
        usage["elapsed_ms"] = row.get("elapsed_ms")
        completion = {"kind":"finish_call","call_id":call_id,"usage":usage}
        candidate = path.with_name("reply-candidate-"+session_id+"-"+str(round_index)+".json")
        if candidate.is_file():
            if candidate.stat().st_size>128*1024:
                raise ValueError("candidate rejection record exceeds bounded intake")
            completion["candidate_rejection_sha256"]=worker.digest_file(candidate)
        self.apply("usage:" + suffix,completion)

    @observed
    def review(self, session_id, config_path, invoke=None):
        with self.guarded():
            argv = self._provider(config_path)
            directory, task, packet = self._session(session_id,config_path)
            if "call:" + session_id in self.workspace.snapshot()["calls"]:
                raise ValueError("checkpoint already dispatched; recover usage without redispatch")
            work_id = self.workspace.snapshot()["sessions"][session_id]["work_id"]
            for round_index in range(2):
                task["research"]["seconds_remaining"] = self._remaining_seconds(work_id)
                task["research"]["round"] = round_index
                if task.get("workspace_protocol") == actions.VERSION:
                    # The task's allowance includes the call about to be reserved.
                    # Refresh on correction too; its prepared budget predates the
                    # rejected paid turn and cannot authorize another lookup loop.
                    task["research"]["workspace_budget"]["used"] = self.workspace.snapshot()["used"].copy()
                suffix = session_id + (":" + str(round_index) if round_index else "")
                self.apply("call:" + suffix, {"kind":"start_call","session_id":session_id,"round":round_index})
                failed = None
                try:
                    if invoke is None:
                        response = worker.execute(argv,self.directory,provider_environment(),task["research"]["seconds_remaining"],json.dumps(task))
                    else:
                        response = invoke(task)  # Test seam: bundled adapter with a deterministic launcher.
                except worker.CommandFailure as error:
                    failed = error
                finally:
                    self._usage(session_id,round_index)
                if failed is None:
                    break
                feedback = worker.reply_validation_feedback(failed,task)
                call = self.workspace.snapshot()["calls"]["call:" + suffix]
                known = call["usage"] is not None and all(call["usage"].get(k) is not None for k in
                                                          ("input_tokens","cached_input_tokens","output_tokens"))
                if round_index or feedback is None or not known or not self.runtime["limits"]["rounds"]:
                    raise failed
                self.check()
                self.workspace.check_session(session_id)
                task["research"]["feedback"] = feedback
                self.trace("reply_validation_correction",session_id=session_id)
            self.check()  # Reject stale answers after paid work while retaining its usage.
            self.workspace.check_session(session_id)
            if task.get("workspace_protocol") == actions.VERSION:
                shape(response,("workspace_actions",))
                worker.write(directory / "answer.json",response)
                return actions.apply_response(self,session_id,task,packet,response["workspace_actions"])
            results = response.get("draft",{}).get("results",[])
            if response.get("research") or response.get("routing") or any(e.get("status") == "open" for e in response.get("progress",[])):
                raise ValueError("checkpoint must return final scoped results or explicit uncertainty")
            references([r["review_id"] for r in results],task["review_ids"])
            if {r["review_id"] for r in results} != set(task["review_ids"]):
                raise ValueError("checkpoint omitted active claims")
            view = self.workspace.snapshot()["sessions"][session_id]["packet"]
            dependencies = [{"proposition_id":k,"revision":p["revision"]} for k,p in view["propositions"].items()]
            drafts = []
            for result in results:
                for window in result.get("evidence",[]):
                    if not any(w["path"] == window["path"] and w["start_line"] <= window["start_line"] <= window["end_line"] <= w["end_line"]
                               for w in packet["primary"]["windows"]):
                        raise ValueError("checkpoint cites source outside its prepared context")
                applies = [k for k,a in view["applicability"].items() if a["review_id"] == result["review_id"]
                           and a["proposition_revision"] == view["propositions"][a["proposition_id"]]["revision"]]
                drafts.append({"result":result,"applicability":applies,"propositions":dependencies})
            # All presented propositions conservatively become dependencies, without
            # asserting that they apply or transferring a verdict between callers.
            accepted = self.apply("answer:" + session_id,{"kind":"draft_batch","drafts":drafts})
            worker.write(directory / "answer.json",response)
            return {"drafts":accepted,"usage":self.workspace.usage(),"native_admission":False}

    @observed
    def recover_usage(self, session_id):
        # Recover costs even if source/plan freshness prevents using the answer.
        with self.guarded(fresh=False):
            turns = [c.get("round",0) for c in self.workspace.snapshot()["calls"].values() if c["session_id"] == session_id]
            for round_index in sorted(set(turns)):
                self._usage(session_id,round_index)
            return self.workspace.usage()

    @observed
    def export_candidates(self, session_id, config_path, round_index=None):
        """Preview independently valid decisions; never apply rejected actions."""
        with self.guarded():
            argv=self._provider(config_path)
            directory,_,packet=self._session(session_id,config_path)
            self.workspace.check_session(session_id)
            state=self.workspace.snapshot()
            calls=[(key,c) for key,c in state["calls"].items() if c["session_id"]==session_id]
            if not calls:raise ValueError("candidate session has no dispatched call")
            latest=max(c.get("round",0) for _,c in calls)
            if round_index is None:round_index=latest
            if type(round_index) is not int or round_index!=latest:
                raise ValueError("candidate is not the latest dispatched turn")
            matching=[c for _,c in calls if c.get("round",0)==round_index]
            if len(matching)!=1:raise ValueError("candidate requires one exact recorded call")
            call=matching[0]
            if "candidate_rejection_sha256" not in call:
                raise ValueError("no eligible rejected candidate was recorded for this call")
            if call["usage"] is None:raise ValueError("candidate usage is unobserved")
            artifacts=state["sessions"][session_id]["artifacts"]["files"]
            request={"directory":str(directory),"session_id":session_id,"round":round_index,
                     "candidate_sha256":call["candidate_rejection_sha256"],"packet_sha256":artifacts["context.json"],
                     "task_file_sha256":artifacts["task.json"],"usage":call["usage"]}
            inspected=worker.execute([*argv,"--inspect-candidate"],self.directory,provider_environment(),30,json.dumps(request))
            shape(inspected,("decisions","binding","auxiliary_actions_accepted","native_admission"))
            if inspected["auxiliary_actions_accepted"] is not False or inspected["native_admission"] is not False:
                raise ValueError("candidate inspection cannot accept workspace actions")
            decisions=inspected["decisions"]
            references([d["review_id"] for d in decisions],[q["review_id"] for q in packet["native_questions"]])
            # Render uncertainty from saved questions, never from rejected updates.
            drafts={d["review_id"]:actions.native_decision(d,state) for d in decisions}
            binding={"schema_version":"mehscanCandidatePreview/v1","parent_package_id":self.package["package_id"],
                     "session_id":session_id,"round":round_index,"workspace_revision":state["revision"],
                     "candidate_rejection_sha256":call["candidate_rejection_sha256"],"returned_turn":inspected["binding"]}
            export=self.directory/"candidate-previews"/identity(binding)
            export.mkdir(parents=True,exist_ok=True)
            binding_path=export/"binding.json"
            if binding_path.exists() and read(binding_path)!=binding:
                raise ValueError("candidate preview binding changed")
            worker.write(binding_path,binding)
            worker.write(export/"model-decisions.json",decisions)
            run=export/"run"
            if not (run/"manifest.json").exists():
                self.native(["investigate","review-bundles",str(self.root),"--inventory",str(self.inventory),
                             "--review-ids",",".join(sorted(drafts)),"--output",str(run)])
            manifest=read(run/"manifest.json")
            if sorted(r for b in manifest["bundles"] for r in b["review_ids"])!=sorted(drafts):
                raise ValueError("candidate native run scope differs")
            responses,journals=export/"responses",export/"journals"
            responses.mkdir(exist_ok=True);journals.mkdir(exist_ok=True)
            for bundle in manifest["bundles"]:
                name=bundle["filename"]
                if Path(name).name!=name:raise ValueError("native bundle filename must be flat")
                path=export/("draft-"+name)
                worker.write(path,{"results":[drafts[rid] for rid in bundle["review_ids"]]})
                self.native(["investigate","review-bundle-finalize","--bundle",str(run/"requests"/name),
                             "--draft",str(path),"--source-root",str(self.root),"--journal-dir",str(journals),
                             "--output",str(responses/name)])
            report=self.native(["report","--run",str(run),"--responses",str(responses),"--source-root",str(self.root),
                                "--reviewer","independent-candidate-preview"])
            self.check();self.workspace.check_session(session_id)
            if state!=self.workspace.snapshot():raise ValueError("workspace changed during candidate preview")
            # Recheck the private reply, receipt and context after native validation.
            if worker.execute([*argv,"--inspect-candidate"],self.directory,provider_environment(),30,json.dumps(request))!=inspected:
                raise ValueError("candidate changed during source validation")
            worker.write(export/"candidate-report.json",report)
            result={"status":"candidate_only","review_ids":sorted(drafts),"native_source_validated":True,
                    "workspace_response_accepted":False,"auxiliary_actions_applied":False,"semantic_review_required":True,
                    "native_admission":False,"workspace_revision":state["revision"],"usage":self.workspace.usage(),
                    "omitted_review_ids":sorted(set(self.payload["review_ids"])-set(drafts)),
                    "model_decisions":str(export/"model-decisions.json"),"candidate_report":str(export/"candidate-report.json"),
                    "authority":"Independent source-validated decision candidates for reviewer inspection. The original response remains rejected; no question, draft, budget or admission state is changed."}
            worker.write(export/"preview.json",result)
            lines=["# Independent decision candidates","",result["authority"],"","Semantic source/flow review is required before adoption.",""]
            for d in decisions:
                lines.extend(["## "+d["review_id"],""])
                lines.extend("    "+line for line in "\n".join([d["decision"],d["summary"],d["reason"]]).splitlines())
                lines.append("")
            worker.write_text(export/"preview.md","\n".join(lines))
            return result

    @observed
    def export_completed(self):
        """Validate saved judgments in a new subset run; never fill missing claims."""
        with self.guarded():
            review = self.workspace.completed_review_package()
            ids = sorted(c["review_id"] for c in review["claims"])
            result = {"status":review["status"], "original_selection_count":review["original_selection_count"],
                      "completed_review_ids":ids, "incomplete_review_ids":review["incomplete_review_ids"],
                      "native_admission":False, "native_validated":False}
            if not ids:
                return result
            directory = self.directory / "partial-finalizations" / review["package_id"]
            directory.mkdir(parents=True,exist_ok=True)
            binding = {"parent_package_id":self.package["package_id"], "review_package_id":review["package_id"],
                       "review_ids":ids, "workspace_revision":review["workspace_revision"]}
            binding_path = directory / "binding.json"
            if binding_path.exists() and read(binding_path) != binding:
                raise ValueError("completed export binding changed")
            worker.write(binding_path,binding)
            run = directory / "run"
            if not (run / "manifest.json").exists():
                self.native(["investigate","review-bundles",str(self.root),"--inventory",str(self.inventory),
                             "--review-ids",",".join(ids),"--output",str(run)])
            manifest = read(run / "manifest.json")
            members = [rid for b in manifest["bundles"] for rid in b["review_ids"]]
            if sorted(members) != ids:
                raise ValueError("completed export scope differs from saved judgments")
            responses = directory / "responses"
            responses.mkdir(exist_ok=True)
            journals = directory / "journals"
            journals.mkdir(exist_ok=True)
            judgments = {c["review_id"]:c["result"] for c in review["claims"]}
            for bundle in manifest["bundles"]:
                name = bundle["filename"]
                if Path(name).name != name:
                    raise ValueError("native bundle filename must be flat")
                draft_path = directory / ("draft-" + name)
                worker.write(draft_path,{"results":[judgments[rid] for rid in bundle["review_ids"]]})
                self.native(["investigate","review-bundle-finalize","--bundle",str(run / "requests" / name),
                             "--draft",str(draft_path),"--source-root",str(self.root),
                             "--journal-dir",str(journals),
                             "--output",str(responses / name)])
            report = self.native(["report","--run",str(run),"--responses",str(responses),
                                  "--source-root",str(self.root),"--reviewer","workspace-completed"])
            self.check()
            if self.workspace.snapshot()["revision"] != review["workspace_revision"]:
                raise ValueError("workspace changed during completed export")
            worker.write(directory / "findings.json",report)
            worker.write(directory / "review-package.json",review)
            worker.write_text(directory / "review-package.md",render_review_package(review))
            result.update(native_validated=True, run=str(run), responses=str(responses),
                          findings=str(directory / "findings.json"), review_package=str(directory / "review-package.json"))
            worker.write(directory / "validated.json",{**binding, **result,
                         "files":{str(p.relative_to(directory)):worker.digest_file(p) for p in
                                  [directory / "findings.json", directory / "review-package.json",
                                   directory / "review-package.md", *sorted(responses.glob("*.json"))]}})
            return result

    @observed
    def finalize(self, bundle_id):
        with self.guarded():
            bundle = self.metadata["bundles"][bundle_id]
            review = self.workspace.review_package([bundle_id])
            draft = {"results":[c["result"] for c in review["claims"]]}
            if {r["review_id"] for r in draft["results"]} != set(bundle["review_ids"]):
                raise ValueError("workspace draft does not cover the original native bundle")
            directory = self.directory / "finalizations" / identity([bundle_id,draft,review["workspace_revision"]])
            directory.mkdir(parents=True,exist_ok=False)
            worker.write(directory / "draft.json",draft)
            journals = self.directory / "journals"
            journals.mkdir(exist_ok=True)
            self.native(["investigate","review-bundle-finalize","--bundle",str(self.directory / "run/requests" / bundle["filename"]),
                                   "--draft",str(directory / "draft.json"),"--source-root",str(self.root),
                                   "--journal-dir",str(journals),"--output",str(directory / "response.json")])
            self.check()
            if self.workspace.snapshot()["revision"] != review["workspace_revision"]:
                raise ValueError("workspace changed during finalization")
            worker.write(directory / "review-package.json",review)
            worker.write_text(directory / "review-package.md",render_review_package(review))
            worker.write(directory / "validated.json",{"bundle_id":bundle_id,"package_id":self.package["package_id"],
                         "response_sha256":worker.digest_file(directory / "response.json"),"native_admission":False,
                         "review_package_id":review["package_id"],
                         "review_package_sha256":worker.digest_file(directory / "review-package.json"),
                         "review_markdown_sha256":worker.digest_file(directory / "review-package.md")})
            return {"response":str(directory / "response.json"),"native_validated":True,"native_admission":False,
                    "review_package":str(directory / "review-package.json"),"review_markdown":str(directory / "review-package.md")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=("init","check","plan","prepare-evidence","prepare","review","recover-usage","finalize","export-completed","export-candidates"))
    for name in ("scanner","source-root","inventory","store","stream","claim","work-package","directory"):
        parser.add_argument("--" + name,required=True)
    parser.add_argument("--skill-root",default=str(Path(__file__).resolve().parents[1] / "skills/mehscan-security"))
    parser.add_argument("--provider-contract")
    parser.add_argument("--source-profile", help="source-only profile at initialization; stored in the workspace binding")
    parser.add_argument("--experiment",help="frozen JSON containing limits and experiment ceilings; required for init")
    parser.add_argument("--config")
    parser.add_argument("--work-id",default="initial")
    parser.add_argument("--operation-key")
    parser.add_argument("--parent-session")
    parser.add_argument("--session-id")
    parser.add_argument("--candidate-round",type=int,choices=(0,1))
    parser.add_argument("--bundle-id")
    parser.add_argument("--plan",help="source-bound deterministic work plan; for plan command")
    parser.add_argument("--evidence-request",help="question-linked source/dependency preparation JSON")
    args = parser.parse_args()
    if args.command == "init":
        if not args.experiment:
            parser.error("init requires --experiment")
        experiment = read(args.experiment)
        bridge = NativeWorkspace.create(args,experiment["limits"],experiment["experiment"])
        result = {"selection_id":bridge.workspace.snapshot()["selection_id"],"native_admission":False}
    else:
        if args.source_profile:
            parser.error("source-profile is supplied only at initialization")
        bridge = NativeWorkspace(args)
        if args.command == "check":
            with bridge.guarded():
                result = {"current":True,"native_admission":False}
        elif args.command == "plan":
            if not args.plan:
                parser.error("plan requires --plan")
            from review_workspace_planner import apply_plan
            with bridge.guarded():
                result = apply_plan(bridge,read(args.plan))
        elif args.command == "prepare":
            if not args.config or not args.operation_key:
                parser.error("prepare requires --config and --operation-key")
            result = bridge.prepare(args.work_id,args.config,args.operation_key,args.parent_session)
        elif args.command == "prepare-evidence":
            if not args.evidence_request or not args.operation_key:
                parser.error("prepare-evidence requires --evidence-request and --operation-key")
            from review_workspace_evidence import prepare
            with bridge.guarded():
                result = prepare(bridge.workspace,read(args.evidence_request),args.operation_key)
        elif args.command == "review":
            if not args.config or not args.session_id:
                parser.error("review requires --config and --session-id")
            result = bridge.review(args.session_id,args.config)
        elif args.command == "recover-usage":
            result = bridge.recover_usage(args.session_id)
        elif args.command == "export-completed":
            result = bridge.export_completed()
        elif args.command == "export-candidates":
            if not args.config or not args.session_id:
                parser.error("export-candidates requires --config and --session-id")
            result = bridge.export_candidates(args.session_id,args.config,args.candidate_round)
        else:
            result = bridge.finalize(args.bundle_id)
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (ValueError,KeyError,OSError,worker.CommandFailure) as error:
        # Native/provider stderr and ownership arguments are deliberately not echoed.
        print(json.dumps({"error":str(error) if not isinstance(error,worker.CommandFailure) else "native or provider command failed",
                          "native_admission":False}))
        raise SystemExit(2)
