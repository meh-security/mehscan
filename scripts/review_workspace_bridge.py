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
import review_worker as worker
from review_workspace import Workspace, encoded, identity, number, references, shape
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
        "review_workspace_planner.py", "review_workspace_evidence.py", "review_worker.py", "review_context.py")}


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
        self.experiment_binding = None if creating else {k:self.metadata[k] for k in ("limits","experiment")}
        self.workspace = None if creating else Workspace(self.directory / "workspace.sqlite", self.binding())

    def binding(self):
        return {"snapshot_id":self.payload["snapshot_id"], "plan_id":self.payload["plan_id"],
                "runtime_id":identity([self.package["package_id"], self.runtime, implementation(), self.experiment_binding])}

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
            expected = {"version":VERSION, "package":self.package, "source_root":str(self.root),
                        "implementation":implementation()}
            if any(self.metadata.get(k) != v for k,v in expected.items()):
                raise ValueError("workspace native/implementation binding differs")
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

    def apply(self, key, action):
        previous = self.workspace.operation(key)
        revision = previous["request"]["revision"] if previous else self.workspace.snapshot()["revision"]
        return self.workspace.apply(key, revision, action)["result"]

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
        if experiment["max_elapsed_seconds"] > 3600 or experiment["context_max_bytes"] > 128 * 1024:
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
                    entries.append({**claim,"capability":anchor["capability"],"rule_id":anchor["rule_id"]})
                    selected.append(claim["review_id"])
                if set(request["review_ids"]) != {e["review_id"] for e in entries}:
                    raise ValueError("native sweep dropped bundle members")
                catalog[bundle["bundle_fingerprint"]] = {"filename":name, "review_ids":bundle["review_ids"],
                                                         "entries":entries,"playbooks":request["review_playbooks"]}
                for window in sweep["source_contexts"]:
                    consumers = [c["review_id"] for c in sweep["reviews"] if window["id"] in c["source_context_ids"]]
                    if len(bundle["review_ids"]) == 1:
                        consumers = bundle["review_ids"]
                    if consumers:
                        prepared.append((window, consumers))
                if experiment.get("prepare_application"):
                    application = context.prepare_application(bridge.root,sweep,{},bridge.payload["snapshot_id"])
                    for window in application["windows"]:
                        prepared.append(({"location":{k:window[k] for k in ("path","start_line","end_line")}},bundle["review_ids"]))
            references(selected, bridge.payload["review_ids"])
            if set(selected) != set(bridge.payload["review_ids"]):
                raise ValueError("native generation dropped selected claims")
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
                        action["excerpt"] = "\n".join(context.source_lines(window["excerpt"])[offset:offset+400])
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
                               "implementation":implementation(),"artifacts":artifacts,"bundles":catalog,
                               "selection_id":bridge.workspace.snapshot()["selection_id"],"limits":limits,"experiment":experiment,
                               "initial_evidence":{k:sorted(set(v)) for k,v in initial.items()}}
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
                return {"session_id":key,"directory":str(directory),"review_ids":[c["review_id"] for c in view["claims"]],"native_admission":False}
            directory.mkdir(parents=True, exist_ok=True)
            ids = [c["review_id"] for c in view["claims"]]
            entries = [entry for b in self.metadata["bundles"].values() for entry in b["entries"] if entry["review_id"] in ids]
            playbooks = {k:v for b in self.metadata["bundles"].values() for k,v in b["playbooks"].items() if k in ids}
            windows = [{"artifact_id":k, **{field:e[field] for field in
                        ("path","start_line","end_line","text","complete_file")}, "clipped":e.get("fragment",False)}
                       for k,e in view["evidence"].items()]
            packet = {"schema_version":"1","package_id":self.package["package_id"],
                      "source_binding":{"snapshot_id":self.payload["snapshot_id"],
                                        "inventory_input_fingerprint":self.payload["inventory_input_fingerprint"]},
                      "contract":context.compile_contract(self.skill,"native_bundle",entries,[],playbooks),
                      "work":context.compact_work(self.payload,ids),"native_questions":entries,
                      "primary":{"windows":windows,"limits":view["preparation_limits"]},
                      "workspace_evidence":{"propositions":view["propositions"],"applicability":view["applicability"],
                                            "deciding_evidence":view["deciding_evidence"],
                                            "questions":view["questions"],"authority":view["authority"]}}
            mode = self.metadata["experiment"].get("protocol","checkpoint")
            if mode == actions.VERSION:
                packet.update(workspace_protocol=mode,contract={"version":mode,"sources":[
                    context.sections(self.skill / "references/runtime-review.md",["api_semantics"])]},
                              work={"runtime":self.runtime,"review_ids":ids,"policy":self.payload["policy"]})
                packet["workspace_evidence"]["lookups"] = view["lookups"]
                packet["workspace_guidance"] = list(view["guidance"].values())
            if len(encoded(packet).encode("utf-8")) > self.metadata["experiment"]["context_max_bytes"]:
                raise ValueError("assembled provider packet exceeds context limit; narrow the work item")
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

    def _remaining_seconds(self):
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
        return min(remaining, self.runtime["limits"]["timeout_seconds"])

    def _usage(self, session_id):
        state = self.workspace.snapshot()
        call_id = "call:" + session_id
        call = state["calls"][call_id]
        if call["usage"] is not None:
            return
        path = self.directory / "sessions" / session_id / "provider-metrics.jsonl"
        if not path.exists():
            return  # An interrupted or unobserved call remains unknown, never free.
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        if len(rows) != 1 or rows[0]["conversation_id"] != session_id or rows[0]["round"] != 0 or rows[0]["provider"] != self.runtime["provider"]:
            raise ValueError("checkpoint metrics do not describe one fresh bound turn")
        row = rows[0]
        usage = {k:row.get("usage",{}).get(k) for k in ("input_tokens","cached_input_tokens","output_tokens")}
        usage["elapsed_ms"] = row.get("elapsed_ms")
        self.apply("usage:" + session_id, {"kind":"finish_call","call_id":call_id,"usage":usage})

    @observed
    def review(self, session_id, config_path, invoke=None):
        with self.guarded():
            argv = self._provider(config_path)
            directory, task, packet = self._session(session_id,config_path)
            if "call:" + session_id in self.workspace.snapshot()["calls"]:
                raise ValueError("checkpoint already dispatched; recover usage without redispatch")
            task["research"]["seconds_remaining"] = self._remaining_seconds()
            self.apply("call:" + session_id, {"kind":"start_call","session_id":session_id})
            try:
                if invoke is None:
                    response = worker.execute(argv,self.directory,provider_environment(),task["research"]["seconds_remaining"],json.dumps(task))
                else:
                    response = invoke(task)  # Test seam: bundled adapter with a deterministic launcher.
            finally:
                self._usage(session_id)
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
            self._usage(session_id)
            return self.workspace.usage()

    @observed
    def finalize(self, bundle_id):
        with self.guarded():
            bundle = self.metadata["bundles"][bundle_id]
            draft = self.workspace.bundle_draft(bundle_id)
            if {r["review_id"] for r in draft["results"]} != set(bundle["review_ids"]):
                raise ValueError("workspace draft does not cover the original native bundle")
            directory = self.directory / "finalizations" / identity([bundle_id,draft,self.workspace.snapshot()["revision"]])
            directory.mkdir(parents=True,exist_ok=False)
            worker.write(directory / "draft.json",draft)
            journals = self.directory / "journals"
            journals.mkdir(exist_ok=True)
            self.native(["investigate","review-bundle-finalize","--bundle",str(self.directory / "run/requests" / bundle["filename"]),
                                   "--draft",str(directory / "draft.json"),"--source-root",str(self.root),
                                   "--journal-dir",str(journals),"--output",str(directory / "response.json")])
            self.check()
            worker.write(directory / "validated.json",{"bundle_id":bundle_id,"package_id":self.package["package_id"],
                         "response_sha256":worker.digest_file(directory / "response.json"),"native_admission":False})
            return {"response":str(directory / "response.json"),"native_validated":True,"native_admission":False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=("init","check","plan","prepare-evidence","prepare","review","recover-usage","finalize"))
    for name in ("scanner","source-root","inventory","store","stream","claim","work-package","directory"):
        parser.add_argument("--" + name,required=True)
    parser.add_argument("--skill-root",default=str(Path(__file__).resolve().parents[1] / "skills/mehscan-security"))
    parser.add_argument("--provider-contract")
    parser.add_argument("--experiment",help="frozen JSON containing limits and experiment ceilings; required for init")
    parser.add_argument("--config")
    parser.add_argument("--work-id",default="initial")
    parser.add_argument("--operation-key")
    parser.add_argument("--parent-session")
    parser.add_argument("--session-id")
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
