#!/usr/bin/env python3
"""Source-bound investigation proposals. No model, verdict, or native admission."""
import argparse
from collections import defaultdict
import hashlib
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import re
import time

import review_context as context
import review_worker as worker
from review_workspace import identity, source

VERSION = "mehscanWorkPlanner/experimental-v1"
SQL_RULES = {"typescript-database-query", "javascript-database-query"}
AUTH_CAPABILITIES = {"resource_access", "authorization"}
IDENT = r"[A-Za-z_$][\w$]*"
MEMBER = IDENT + r"(?:\." + IDENT + r")*"
ENTRY_FIELDS = ("review_id", "path", "line", "symbol", "rule_id", "capability")


def mask_js(text):
    """Preserve offsets/newlines, masking comments and literal contents.

    This is a bounded syntax recognizer, not a JS parser. Template expressions,
    JSX, computed calls and multiline imports are deliberately not resolved.
    """
    out, i = list(text), 0
    while i < len(text):
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = len(text) if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i+2)
            end = len(text) if end < 0 else end+2
        elif text[i] == "/" and (not text[:i].rstrip() or text[:i].rstrip()[-1] in "(=[:,!&|?;{" or
                re.search(r"(?:\breturn|\bthrow|\bcase|=>)\s*$",text[max(0,i-16):i])):
            # Regex literals may contain quotes, comment markers and braces.
            # Recognize expression-start positions, escapes and character sets.
            end, character_set, closed = i+1, False, False
            while end < len(text):
                char = text[end]
                if char in "\r\n":
                    raise ValueError("unsupported regular-expression lexical context")
                if char == "\\":
                    end += 2; continue
                if char == "[": character_set = True
                if char == "]": character_set = False
                if char == "/" and not character_set:
                    end += 1
                    while end < len(text) and text[end].isalpha(): end += 1
                    closed = True
                    break
                end += 1
            if not closed:
                raise ValueError("unterminated regular-expression context")
        elif text[i] in "\"'`":
            quote, end = text[i], i+1
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                elif text[end] == quote:
                    end += 1
                    break
                else:
                    end += 1
        else:
            i += 1
            continue
        for j in range(i, min(end, len(text))):
            if out[j] not in "\r\n":
                out[j] = " "
        i = end
    return "".join(out)


def arguments(text):
    masked, stack, start, values = mask_js(text), [], 0, []
    pairs = {")":"(", "]":"[", "}":"{"}
    for i,char in enumerate(masked):
        if char in "([{":
            stack.append(char)
        elif char in ")]}":
            if not stack or stack.pop() != pairs[char]:
                return None
        elif char == "," and not stack:
            values.append(text[start:i].strip()); start = i+1
    if stack:
        return None
    values.append(text[start:].strip())
    return values if all(values) else ([] if not text.strip() else None)


def expression(text, depth=0):
    """Accept static names/calls and literal arguments; never execute them."""
    if depth > 4:
        return None
    text = text.strip()
    if re.fullmatch(MEMBER, text):
        return (text, None)
    match = re.fullmatch("("+MEMBER+r")\s*\((.*)\)", text)
    if not match:
        return None
    args = arguments(match[2])
    if args is None:
        return None
    for value in args:
        if not (re.fullmatch(r"(?:true|false|null|\d+|['\"][^'\"\\]*['\"])", value)
                or expression(value, depth+1)):
            return None
    return match[1], args


def registration(line):
    match = re.match(r"^\s*("+MEMBER+r")\.(get|post|put|patch|delete)\s*\(", line)
    if not match:
        return None
    masked, level, close = mask_js(line), 1, None
    for i in range(match.end(), len(masked)):
        if masked[i] == "(": level += 1
        if masked[i] == ")": level -= 1
        if level == 0:
            close = i; break
    if close is None or masked[close+1:].strip() not in ("", ";"):
        return None
    args = arguments(line[match.end():close])
    if not args or len(args) < 2 or not re.fullmatch(r"['\"]/[^'\"\\]*['\"]", args[0]):
        return None
    if any(expression(arg) is None for arg in args[1:]):
        return None
    return {"receiver":match[1], "method":match[2], "route":args[0][1:-1], "chain":args[1:]}


class Discovery:
    def __init__(self, root, native):
        self.root, self.native = Path(root).resolve(strict=True), native
        self.files, self.cache, self.reads = {}, {}, {}

    def read(self, path):
        if path not in self.reads:
            data = source(self.root, path)
            text = data.decode("utf-8")
            self.files[path] = hashlib.sha256(data).hexdigest()
            self.reads[path] = (text.splitlines(), mask_js(text).splitlines())
        return self.reads[path]

    def query(self, operation, *args):
        key = (operation, *args)
        if key not in self.cache:
            self.cache[key] = self.native(operation, *args)
        return self.cache[key]

    def frame(self, path, first, last):
        lines, _ = self.read(path)
        if not 1 <= first <= last <= len(lines)+1 or last-first >= 400:
            raise ValueError("implementation context is unavailable or exceeds 400 lines")
        size = len("\n".join(lines[first-1:last]).encode("utf-8"))
        if size > 32768:
            raise ValueError("implementation context exceeds 32 KiB")
        return {"path":path, "start_line":first, "end_line":last,
                "file_sha256":self.files[path], "bytes":size}

    def enclosing(self, path, line):
        value = self.query("enclosing-at", "--path", path, "--line", str(line))
        if value.get("truncated") or value.get("provenance",{}).get("resolution") != "ast":
            return None
        return (value.get("results") or {}).get("symbol")

    def unit(self, symbol):
        if not symbol or symbol.get("symbol_type") != "function":
            raise ValueError("no unambiguous native function unit")
        loc = symbol["location"]
        frame = self.frame(loc["path"],loc["start"]["line"],loc["end"]["line"])
        exported = bool(symbol.get("is_exported")) and bool(re.match(
            r"^export\s+(?:async\s+)?(?:function|const)\b",symbol.get("signature", "").strip()))
        return {"name":symbol["name"], "frame":frame,"direct_export":exported,
                "id":identity([symbol["name"],frame])}

    def imports(self, path):
        lines, masked = self.read(path)
        result = {}
        for i,line in enumerate(lines):
            if not re.match(r"^\s*import\b", masked[i]):
                continue
            match = re.fullmatch(r"\s*import\s+(\{[^}\n]+\}|\*\s+as\s+"+IDENT+
                r")\s+from\s+['\"](\.[^'\"]+)['\"]\s*;?\s*(?://.*)?", line)
            if not match:
                continue
            relative = posixpath.normpath((PurePosixPath(path).parent / match[2]).as_posix())
            candidates = [relative] if Path(relative).suffix else [relative+ext for ext in
                (".ts", ".js", ".mts", ".mjs", "/index.ts", "/index.js")]
            found = []
            for candidate in candidates:
                try:
                    file = context.relative_file(self.root,candidate)
                    if file.is_file():
                        found.append(file.relative_to(self.root).as_posix())
                except (ValueError,OSError):
                    continue
            if len(found) != 1:
                continue
            frame = self.frame(path,i+1,i+1)
            if match[1].startswith("*"):
                name = match[1].split()[-1]
                result[name] = (found[0], None, frame)
            else:
                for item in match[1][1:-1].split(","):
                    binding = re.fullmatch("("+IDENT+r")(?:\s+as\s+("+IDENT+"))?", item.strip())
                    if binding:
                        result[binding[2] or binding[1]] = (found[0],binding[1],frame)
        return result

    def binding(self, path, name, local=None):
        names = name.split(".")
        imported = self.imports(path).get(names[0])
        if imported:
            if local and not local["direct_export"]:
                return None
            module, exported, frame = imported
            if exported is None and len(names) == 2:
                return module, names[1], [frame]
            if exported is not None and len(names) == 1:
                return module, exported, [frame]
        if local and path == local["frame"]["path"] and name == local["name"]:
            return path, name, []
        return None

    def leaves(self, value):
        node = expression(value)
        if node is None:
            return []
        name,args = node
        if args is None or not args:
            return [name]
        # Unary wrapper syntax is shared context, not proof of transparent dispatch.
        return self.leaves(args[0]) if len(args) == 1 else []

    def scope_valid(self, path, line, name, unit):
        lines, masked = self.read(path)
        enclosing = self.enclosing(path,line)
        start = enclosing["location"]["start"]["line"] if enclosing else 1
        prefix = "\n".join(masked[start-1:line-1])
        depth = prefix.count("{")-prefix.count("}")
        if depth != (1 if enclosing else 0):
            return False
        root = name.split(".")[0]
        if enclosing:
            signature = enclosing.get("signature", "")
            parameters = signature[signature.find("(")+1:signature.rfind(")")]
            if re.search(r"\b"+re.escape(root)+r"\b", parameters):
                return False
        for i,text in enumerate(masked,1):
            if path == unit["frame"]["path"] and i == unit["frame"]["start_line"]:
                continue
            if re.search(r"\b(?:const|let|var|function|class)\s+"+re.escape(root)+r"\b", text):
                return False
            if re.search(r"\b"+re.escape(root)+r"\s*=(?!=|>)",text):
                return False
            if re.search(r"\b(?:const|let|var)\s*\{[^}]*\b"+re.escape(root)+r"\b",text):
                return False
        return True

    def callers(self, unit):
        result = self.query("references", "--symbol",unit["name"],"--limit","64")
        if result.get("truncated"):
            raise ValueError("caller reference search truncated")
        sites = set()
        for row in result.get("results",[]):
            loc = row.get("location",{})
            if loc:
                sites.add((loc["path"],loc["start"]["line"]))
        # Resolve direct named aliases in the files the native search returned.
        for path in sorted({path for path,_ in sites}):
            if Path(path).suffix not in (".ts", ".js", ".mts", ".mjs"):
                continue
            for alias,(module,exported,_) in self.imports(path).items():
                if unit["direct_export"] and module == unit["frame"]["path"] and (exported is None or
                        exported == unit["name"] and alias != unit["name"]):
                    extra = self.query("references","--symbol",alias,"--path",path,"--limit","64")
                    if extra.get("truncated"):
                        raise ValueError("aliased caller reference search truncated")
                    sites.update((r["location"]["path"],r["location"]["start"]["line"])
                                 for r in extra.get("results",[]) if r.get("location"))
        callers, unresolved = {}, False
        for path,line in sorted(sites):
            if Path(path).suffix not in (".ts", ".js", ".mts", ".mjs"):
                continue
            lines,masked = self.read(path)
            raw = lines[line-1]
            parsed = registration(raw) if re.match(r"^\s*"+MEMBER+r"\.",masked[line-1]) else None
            bound_names = []
            extended_binding = False
            # A source-bound alias must actually refer to this implementation.
            # Raw matching makes uncertain lexing conservative: a hidden bound
            # reference blocks grouping instead of silently dropping a caller.
            names = set(re.findall(MEMBER,raw))
            imports = self.imports(path)
            namespace_escape = any(name in imports and imports[name][0] == unit["frame"]["path"] and
                                   imports[name][1] is None for name in names)
            for name in names:
                binding = self.binding(path,name,unit)
                if binding and binding[:2] == (unit["frame"]["path"],unit["name"]):
                    bound_names.append(name)
                parts = name.split(".")
                for end in range(1,len(parts)):
                    prefix = self.binding(path,".".join(parts[:end]),unit)
                    if prefix and prefix[:2] == (unit["frame"]["path"],unit["name"]):
                        extended_binding = True
            if extended_binding:
                unresolved = True; continue
            if not bound_names:
                if namespace_escape and not re.match(r"^\s*import\b",masked[line-1]):
                    unresolved = True
                continue
            if line == unit["frame"]["start_line"] and path == unit["frame"]["path"]:
                continue
            if re.match(r"^\s*import\b",masked[line-1]):
                continue
            if not parsed:
                unresolved = True; continue
            matched = [name for arg in parsed["chain"] for name in self.leaves(arg)
                       if name in bound_names]
            if len(matched) != 1 or not self.scope_valid(path,line,matched[0],unit):
                unresolved = True; continue
            frame = self.frame(path,line,line)
            binding = self.binding(path,matched[0],unit)
            item = {**parsed,"frame":frame,"binding_frames":binding[2],"implementation_id":unit["id"]}
            item["id"] = identity(item)
            callers[item["id"]] = item
        if unresolved:
            raise ValueError("a bound reference has unsupported dispatch, shadowing or registration syntax")
        return list(callers.values())

    def claim(self, entry):
        info = {"entry":{k:entry[k] for k in ENTRY_FIELDS},"unit":None,"caller":None,"abstention":None}
        sql = entry["capability"] == "database_query" and entry["rule_id"] in SQL_RULES
        if not sql and entry["capability"] not in AUTH_CAPABILITIES:
            info["abstention"] = "closure family has no implemented grouping strategy"
            return info
        try:
            enclosing = self.enclosing(entry["path"],entry["line"])
            if enclosing and enclosing["name"] == entry["symbol"]:
                unit = self.unit(enclosing)
            elif not sql:
                raw = self.read(entry["path"])[0][entry["line"]-1]
                route = registration(raw)
                matches = []
                for value in (route or {}).get("chain",[]):
                    for name in self.leaves(value):
                        if name.split(".")[-1] != entry["symbol"]:
                            continue
                        binding = self.binding(entry["path"],name)
                        if binding:
                            symbols = self.query("symbol","--name",binding[1],"--path",binding[0],"--limit","8")
                            if not symbols.get("truncated") and len(symbols.get("results",[])) == 1:
                                candidate = self.unit(symbols["results"][0])
                                if candidate["direct_export"]:
                                    matches.append(candidate)
                if len(matches) != 1:
                    raise ValueError("registration does not resolve to one direct implementation")
                unit = matches[0]
            else:
                raise ValueError("SQL construction lacks a complete native function unit")
            info["unit"] = unit
            if not sql:
                callers = self.callers(unit)
                if len(callers) != 1:
                    raise ValueError("implementation has zero or multiple explicit caller contexts")
                info["caller"] = callers[0]
        except (ValueError,OSError,IndexError) as error:
            info["abstention"] = str(error)
        return info


def form_work(claims, max_group_size=4, max_source_bytes=32768):
    if type(max_group_size) is not int or not 2 <= max_group_size <= 4:
        raise ValueError("group size must be 2..4")
    if type(max_source_bytes) is not int or not 1 <= max_source_bytes <= 65536:
        raise ValueError("source group budget must be 1..65536 bytes")
    buckets, singles = defaultdict(list), []
    for info in claims:
        entry = info["entry"]
        if info["abstention"]:
            singles.append(("singleton",[info])); continue
        if entry["capability"] == "database_query" and entry["rule_id"] in SQL_RULES:
            key = ("local_sql",entry["rule_id"])
        elif info["caller"]:
            key = ("shared_operation",info["unit"]["id"],info["caller"]["id"])
        else:
            singles.append(("singleton",[info])); continue
        buckets[key].append(info)
    collected = list(singles)
    for key,members in buckets.items():
        batch, sizes = [], {}
        for info in members:
            unit = info["unit"]
            proposed = {**sizes,unit["id"]:unit["frame"]["bytes"]}
            if batch and (len(batch) == max_group_size or sum(proposed.values()) > max_source_bytes):
                collected.append((key[0] if len(batch)>1 else "singleton",batch)); batch,sizes = [],{}
            batch.append(info); sizes[unit["id"]] = unit["frame"]["bytes"]
        if batch:
            collected.append((key[0] if len(batch)>1 else "singleton",batch))
    order = {c["entry"]["review_id"]:i for i,c in enumerate(claims)}
    work = []
    for kind,members in collected:
        ids = [c["entry"]["review_id"] for c in members]
        caller = members[0]["caller"] if kind == "shared_operation" else None
        reason = ("SQL-construction candidates with complete function windows; keep independent source chains and decisions."
                  if kind == "local_sql" else
                  "Same native implementation and one identical source-bound registration/callback chain."
                  if kind == "shared_operation" else
                  members[0]["abstention"] or "No compatible peer within the group budget.")
        limit = ("Local construction batch: independent verdicts; a complete function window does not prove complete query construction, shared callers or operation-wide safety."
                 if kind == "local_sql" else
                 "Scope is the identified registration and implementation, not proof of authorization or complete caller discovery. Dynamic/re-export callers are not resolved."
                 if kind == "shared_operation" else "No shared investigation is assumed: "+reason)
        work.append({"id":"work-"+identity([kind,sorted(ids),caller])[:20],"kind":kind,"review_ids":ids,
            "reason":reason,"caller":caller,"limits":[limit]})
    return sorted(work,key=lambda w:min(order[rid] for rid in w["review_ids"]))


def build(root, inventory, selected_ids, native, engine_sha256, **limits):
    entries = {e["review_id"]:e for e in inventory["entries"]}
    if not selected_ids or len(selected_ids)>32 or len(set(selected_ids)) != len(selected_ids) or not set(selected_ids)<=entries.keys():
        raise ValueError("select 1..32 distinct inventory claim IDs")
    started = time.monotonic()
    discovery = Discovery(root,native)
    claims = [discovery.claim(entries[rid]) for rid in selected_ids]
    work = form_work(claims,**limits)
    plan = {"schema_version":VERSION,"binding":{"source_fingerprint":inventory["identity_catalog"]["source_fingerprint"],
        "inventory_input_fingerprint":inventory["input_fingerprint"],"engine_sha256":engine_sha256,
        "planner_sha256":worker.digest_file(__file__)},
        "selected_review_ids":selected_ids,"claims":claims,"work":work,"files":discovery.files,
        "settings":{"max_group_size":limits.get("max_group_size",4),"max_source_bytes":limits.get("max_source_bytes",32768)},
        "planning":{"native_queries":len(discovery.cache),"elapsed_ms":round((time.monotonic()-started)*1000)},
        "authority":"Controller grouping proposal; no verdict, caller completeness, effect or authorization proof.",
        "native_admission":False}
    plan["plan_id"] = identity(plan)
    return plan


def validate(plan, root, inventory, engine_sha256):
    if plan.get("schema_version") != VERSION or plan.get("plan_id") != identity({k:v for k,v in plan.items() if k != "plan_id"}):
        raise ValueError("planner version or content identity differs")
    expected = {"source_fingerprint":inventory["identity_catalog"]["source_fingerprint"],
                "inventory_input_fingerprint":inventory["input_fingerprint"],"engine_sha256":engine_sha256,
                "planner_sha256":worker.digest_file(__file__)}
    if plan["binding"] != expected:
        raise ValueError("planner source/inventory/engine binding differs")
    entries = {e["review_id"]:e for e in inventory["entries"]}
    ids = plan["selected_review_ids"]
    if not ids or len(ids)>32 or len(set(ids)) != len(ids) or not set(ids)<=entries.keys():
        raise ValueError("planner claim selection differs")
    if [c["entry"] for c in plan["claims"]] != [{k:entries[rid][k] for k in ENTRY_FIELDS} for rid in ids]:
        raise ValueError("planner claim anchors differ")
    if plan["work"] != form_work(plan["claims"],**plan["settings"]):
        raise ValueError("planner work membership differs")
    flattened = [rid for w in plan["work"] for rid in w["review_ids"]]
    if len(flattened) != len(ids) or set(flattened) != set(ids):
        raise ValueError("planner must cover every claim exactly once")
    for path,digest in plan["files"].items():
        if hashlib.sha256(source(Path(root),path)).hexdigest() != digest:
            raise ValueError("planner source changed: "+path)


def apply_plan(bridge, plan):
    """Caller holds the native guard. One atomic, replayable preparation action."""
    inventory = worker.read(bridge.inventory / "inventory.json")
    validate(plan,bridge.root,inventory,bridge.runtime["engine_sha256"])
    state = bridge.workspace.snapshot()
    if set(plan["selected_review_ids"]) != set(state["claims"]):
        raise ValueError("planner selection differs from workspace")
    by_id = {c["entry"]["review_id"]:c for c in plan["claims"]}
    work = []
    for item in plan["work"]:
        frames = []
        for rid in item["review_ids"]:
            info = by_id[rid]
            if info["unit"]:
                frames.append({**info["unit"]["frame"],"review_id":rid})
            if info["caller"]:
                frames.extend({**frame,"review_id":rid} for frame in
                              [info["caller"]["frame"],*info["caller"]["binding_frames"]])
        work.append({"work_id":item["id"],"review_ids":item["review_ids"],"strategy":item["kind"]+": "+item["reason"],
            "evidence_ids":sorted({eid for rid in item["review_ids"] for eid in bridge.metadata["initial_evidence"][rid]}),
            "windows":[{k:v for k,v in frame.items() if k != "bytes"} for frame in frames],
            "limits":item["limits"]})
    action = {"kind":"prepare_work","planning_id":plan["plan_id"],"work":work,
              "max_context_bytes":bridge.metadata["experiment"]["context_max_bytes"]}
    artifact = bridge.directory / ("plan-"+plan["plan_id"]+".json")
    if artifact.exists() and worker.read(artifact) != plan:
        raise ValueError("saved planning artifact changed")
    if not artifact.exists():
        worker.write(artifact,plan)
    return bridge.apply("plan:"+plan["plan_id"],action)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("scanner","source-root","inventory","review-ids","output"):
        parser.add_argument("--"+name,required=True)
    parser.add_argument("--max-group-size",type=int,default=4)
    args = parser.parse_args()
    root = Path(args.source_root).resolve(strict=True)
    output = worker.outside(args.output,root,existing=False)
    scanner = str(Path(args.scanner).resolve(strict=True))
    if output.exists():
        raise ValueError("planner output already exists")
    journal = output.with_name(output.name+".queries.jsonl")
    if journal.exists():
        raise ValueError("planner journal already exists")
    started, calls = time.monotonic(), 0
    def native(operation,*values):
        nonlocal calls
        remaining = 180-(time.monotonic()-started)
        if calls >= 96 or remaining <= 0:
            raise ValueError("planner discovery allowance reached")
        calls += 1
        env = {k:os.environ[k] for k in ("PATH","SYSTEMROOT","WINDIR","TEMP","TMP") if k in os.environ}
        return worker.execute([scanner,"investigate",operation,str(root),*values,"--journal",str(journal)],
                              output.parent,env,remaining)
    plan = build(root,worker.read(Path(args.inventory)/"inventory.json"),args.review_ids.split(","),native,
                 worker.digest_file(scanner),max_group_size=args.max_group_size)
    plan["planning"].update(attempted_native_queries=calls,
                           journal_sha256=worker.digest_file(journal) if journal.exists() else None)
    plan["plan_id"] = identity({k:v for k,v in plan.items() if k != "plan_id"})
    worker.write(output,plan)
    print(json.dumps({"output":str(output),"work_items":len(plan["work"]),"claims":len(plan["selected_review_ids"]),
                      "native_queries":calls,"model_calls":0,"native_admission":False}))


if __name__ == "__main__":
    main()
