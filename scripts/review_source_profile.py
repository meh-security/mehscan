"""Explicit, source-only preparation shared by native and workspace reviewers."""
import hashlib
import json
import re
import subprocess
from pathlib import Path

import review_context as context

VERSION = "mehscanSourceProfile/v1"


def validate(profile, payload):
    if (not isinstance(profile, dict) or set(profile) != {
            "schema_version", "repository", "inventory_input_fingerprint", "targets"}
            or profile["schema_version"] != VERSION):
        raise ValueError("invalid explicit source profile")
    if len(json.dumps(profile, ensure_ascii=False).encode()) > 65536:
        raise ValueError("explicit source profile exceeds 64 KiB")
    if (profile["repository"] != payload["repository"] or
            profile["inventory_input_fingerprint"] != payload["inventory_input_fingerprint"]):
        raise ValueError("explicit source profile binding differs")
    targets = profile["targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= 16:
        raise ValueError("expected one to sixteen explicit source targets")
    seen = set()
    for target in targets:
        if not isinstance(target, dict) or set(target) != {"review_ids", "windows"}:
            raise ValueError("explicit source targets contain only claim IDs and windows")
        ids = target["review_ids"]
        if (not isinstance(ids, list) or not 1 <= len(ids) <= 100 or
                any(not isinstance(i, str) for i in ids) or len(set(ids)) != len(ids)
                or not set(ids) <= set(payload["review_ids"]) or seen.intersection(ids)):
            raise ValueError("explicit source profile claim scope differs or overlaps")
        seen.update(ids)
        windows = target["windows"]
        if not isinstance(windows, list) or not 1 <= len(windows) <= 8:
            raise ValueError("expected one to eight explicit source windows")
        unique = set()
        for window in windows:
            if not isinstance(window, dict) or set(window) != {"path", "start_line", "end_line", "file_sha256"}:
                raise ValueError("invalid explicit source window")
            path, first, last = window["path"], window["start_line"], window["end_line"]
            if (not isinstance(path, str) or not path or ":" in path or "\\" in path
                    or any(p in ("", ".", "..", ".git") for p in path.split("/"))):
                raise ValueError("explicit source path must stay relative")
            if type(first) is not int or type(last) is not int or first < 1 or not first <= last < first + 400:
                raise ValueError("explicit source window must contain 1 to 400 lines")
            if not isinstance(window["file_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", window["file_sha256"]):
                raise ValueError("explicit source requires a whole-file SHA-256")
            key = (path, first, last)
            if key in unique:
                raise ValueError("duplicate explicit source window")
            unique.add(key)
    return profile


def load(path, payload):
    path = Path(path)
    if path.stat().st_size > 65536:
        raise ValueError("explicit source profile exceeds 64 KiB")
    return validate(json.loads(path.read_text(encoding="utf-8-sig")), payload)


def check_bundles(profile, groups):
    if profile is not None:
        actual = {frozenset(ids) for ids in groups}
        if any(frozenset(t["review_ids"]) not in actual for t in profile["targets"]):
            raise ValueError("explicit source target differs from native bundle membership")


def prepare(root, profile, review_ids, snapshot_id):
    if profile is None:
        return {"windows":[], "limits":[]}
    ids = set(review_ids)
    matching = [t for t in profile["targets"] if ids.intersection(t["review_ids"])]
    if not matching:
        return {"windows":[], "limits":[]}
    if len(matching) != 1 or set(matching[0]["review_ids"]) != ids:
        raise ValueError("explicit source target differs from native bundle membership")
    root = Path(root).resolve(strict=True)
    windows, files, total = [], {}, 0
    profile_id = context.digest(profile)
    for window in matching[0]["windows"]:
        path, first, last = window["path"], window["start_line"], window["end_line"]
        if path not in files:
            file = context.relative_file(root, path)
            if file.stat().st_size > context.MAX_FILE_BYTES:
                raise ValueError("explicit source file exceeds preparation bound")
            data = file.read_bytes()
            files[path] = (hashlib.sha256(data).hexdigest(), context.source_lines(data.decode("utf-8")))
        digest, lines = files[path]
        if digest != window["file_sha256"]:
            raise ValueError("explicit source file changed")
        if last > len(lines):
            raise ValueError("explicit source range exceeds actual source")
        text = "\n".join(lines[first - 1:last]) + "\n"
        size = len(text.encode())
        total += size
        if size > 16384 or total > 65536:
            raise ValueError("explicit source exceeds preparation byte bound; source was not clipped")
        item = {"side":"current", "path":path, "start_line":first, "end_line":last,
                "line_range":{"start_line":first,"end_line":last,"inclusive":True},
                "text":text, "clipped":False, "file_line_count":len(lines),
                "complete_file":first == 1 and last == len(lines)}
        item["artifact_id"] = "mehscanExplicitSource/v1:" + context.digest([snapshot_id, profile_id, item])
        windows.append(item)
    return {"windows":windows, "limits":[], "profile_id":profile_id}


def combine(*groups):
    """Deduplicate identical source; current and pinned-base windows stay distinct."""
    result, seen = [], set()
    for group in groups:
        for window in group:
            key = (window.get("side", "current"), window["path"], window["start_line"],
                   window["end_line"], "\n".join(context.source_lines(window["text"])))
            if key not in seen:
                seen.add(key)
                result.append(window)
    return result


def dependency_leads(root, card, lookup, cache, trace):
    """Navigate explicit imports and literal Passport registration candidates.

    Returned bytes are evidence candidates. Constructor annotations, registration
    declarations and module imports never certify a runtime provider or verdict.
    No recursive import closure or application-specific names are followed.
    """
    rid = card["review_id"]
    location = (card.get("anchor") or {}).get("location") or {}
    path = location.get("path", "")
    if Path(path).suffix not in (".ts", ".tsx", ".js", ".mjs", ".mts"):
        return []

    def query(argv):
        key = tuple(argv)
        if key not in cache:
            if sum(isinstance(k, tuple) for k in cache) >= 80:
                trace.append({"review_id":rid,"status":"dependency_navigation_budget"})
                return {"results":[],"truncated":True}
            try:
                cache[key] = lookup(["investigate", *argv[:1], str(root), *argv[1:]])
            except subprocess.CalledProcessError:
                trace.append({"review_id":rid,"status":"dependency_navigation_failed","query":argv})
                cache[key] = {"results":[],"truncated":True}
        return cache[key]

    def lines(p):
        key = "source:" + p
        if key not in cache:
            file = context.relative_file(root, p)
            if file.stat().st_size > context.MAX_FILE_BYTES:
                return []
            cache[key] = context.source_lines(file.read_text(encoding="utf-8"))
        return cache[key]

    def imports(p):
        result = query(["import-targets", "--path", p])
        return result.get("results", []) if not result.get("truncated") else []

    def bindings(row):
        symbol = row.get("import", row)
        loc = symbol["location"]
        statement = "\n".join(lines(loc["path"])[loc["start"]["line"]-1:loc["end"]["line"]])
        match = re.fullmatch(r"\s*import\s+(?!type\b)(.+?)\s+from\s+(['\"]).+?\2\s*;?\s*", statement, re.S)
        if not match:
            return {}
        body = match[1];result = {}
        default = body.split(",", 1)[0].strip()
        if re.fullmatch(r"[A-Za-z_$][\w$]*", default):result["default"] = default
        named = re.search(r"\{([^}]+)\}", body, re.S)
        for part in named[1].split(",") if named else []:
            m = re.fullmatch(r"\s*([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?\s*", part)
            if m:result[m[1]] = m[2] or m[1]
        return result

    def symbols(p):
        value = query(["outline", "--path", p])
        return (value.get("results") or {}).get("symbols", []) if not value.get("truncated") else []

    def source_candidates(p, methods=()):
        content = lines(p)
        if not content:return []
        if len(content) <= 400 and len("\n".join(content).encode()) < 16384:
            return [(p,1,len(content),"explicit_import_source_provider_unproven")]
        return [(p,s["location"]["start"]["line"],s["location"]["end"]["line"],"declared_member_provider_unproven")
                for s in symbols(p) if s["name"] in methods and s.get("symbol_type") in ("method","function","constructor")]

    source = lines(path)
    first, last = location.get("start_line",1), location.get("end_line",1)
    region = "\n".join(source[max(0,first-11):last])
    outline = symbols(path)
    owners = {s.get("parent") for s in outline if s["location"]["start"]["line"] <= first <= s["location"]["end"]["line"] and s.get("parent")}
    # Scanner anchors may begin on a method decorator, before the method's AST
    # span. Recover the enclosing class without guessing from adjacent methods.
    owners.update(s["name"] for s in outline if s.get("symbol_type") == "class"
                  and s["location"]["start"]["line"] <= first <= s["location"]["end"]["line"])
    for owner in owners:
        declaration = next((s for s in outline if s["name"] == owner and s.get("symbol_type") == "class"), None)
        if declaration:
            start = declaration["location"]["start"]["line"]
            member_start = min((s["location"]["start"]["line"] for s in outline if s.get("parent") == owner), default=start+10)
            region += "\n" + "\n".join(source[start-1:min(member_start-1,start+20)])
    constructors = "\n".join("\n".join(source[s["location"]["start"]["line"]-1:s["location"]["end"]["line"]])
                             for s in outline if s["name"] == "constructor" and s.get("parent") in owners)
    typed = {}
    for receiver, method in re.findall(r"\bthis\.([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*\(",region):
        m = re.search(r"\b"+re.escape(receiver)+r"\s*:\s*([A-Za-z_$][\w$]*)",constructors)
        if m:typed.setdefault(m[1],set()).add(method)
    selected = []
    import_rows = imports(path)
    # Invoked declared dependencies precede passive DTO/type imports under the
    # shared source-window limit. This is navigation priority, not a verdict.
    import_rows = sorted(import_rows, key=lambda row: not any(local in typed for local in bindings(row).values()))
    for row in import_rows:
        names = bindings(row)
        used = [local for local in names.values() if local in typed or re.search(r"(?<![\w$])"+re.escape(local)+r"(?![\w$])",region)]
        if not used:continue
        target = row.get("source_path")
        trace.append({"review_id":rid,"importer":path,"source_path":target,"status":"import_module_"+row["status"],
                      "scope":"export, injected provider and runtime applicability unproven"})
        if not target:continue
        methods = set().union(*(typed.get(local,set()) for local in used))
        selected.extend(source_candidates(target,methods))
        # Recognize the library API through its actual static import, including aliases.
        for entry in imports(target):
            if entry["import"]["name"].strip("'\"") != "@nestjs/passport":continue
            factory = bindings(entry).get("AuthGuard")
            if not factory:continue
            guard_calls = query(["structural","--language","typescript","--path",target,
                                 "--pattern",factory+"($KEY)","--limit","20"])
            for call in guard_calls.get("results",[]):
                match = re.fullmatch(re.escape(factory)+r"\(\s*(['\"])([A-Za-z0-9_-]{1,80})\1\s*\)",call["text"])
                if not match:continue
                key = match[2]
                registry = query(["imports","--name","@nestjs/passport","--limit","40"])
                trace.append({"review_id":rid,"registry_key":key,"status":"literal_registration_navigation",
                              "search_incomplete":registry.get("truncated",False),"scope":"declaration candidates, not active registration"})
                for declaration in registry.get("results",[]):
                    producer = bindings(declaration).get("PassportStrategy")
                    if not producer:continue
                    candidate = declaration["location"]["path"]
                    found = query(["structural","--language","typescript","--path",candidate,
                                   "--pattern",producer+"($BASE, '"+key+"')","--limit","20"])
                    if not found.get("results"):continue
                    selected.extend(source_candidates(candidate,("constructor","validate")))
                    trace.append({"review_id":rid,"registry_key":key,"path":candidate,
                                  "status":"registration_declaration_provider_unproven"})
                    classes = [s["name"] for s in symbols(candidate) if s.get("symbol_type")=="class"]
                    for name in classes[:2]:
                        registration = query(["imports","--name",name,"--limit","20"])
                        for owner in registration.get("results",[]):
                            owner_path = owner["location"]["path"]
                            # Require an explicit module resolution back to the declaration file.
                            if any(r.get("source_path")==candidate for r in imports(owner_path)):
                                selected.extend(source_candidates(owner_path))
    return list(dict.fromkeys(selected))


def build_from_sweeps(root, payload, sweeps, lookup, *, dependencies=False):
    """Prepare native-named declarations and clipped contexts, without verdicts.

    A unique declaration is navigation evidence, not a resolved caller binding.
    Lookup is the controller's read-only native command callback. No recursive
    caller discovery, historical decisions or application-specific names enter.
    """
    root = Path(root).resolve(strict=True)
    targets, trace, symbols, files, dependency_cache = [], [], {}, {}, {}

    def window(path, first, last, allow_eof):
        file = context.relative_file(root, path)
        if file.stat().st_size > context.MAX_FILE_BYTES:
            return None, "file_size_bound"
        if path not in files:
            raw = file.read_bytes()
            files[path] = (hashlib.sha256(raw).hexdigest(), context.source_lines(raw.decode("utf-8")))
        digest, lines = files[path]
        if allow_eof and type(last) is int:
            last = min(last, len(lines))
        if type(first) is not int or type(last) is not int or not 1 <= first <= last <= len(lines):
            return None, "invalid_native_range"
        if last - first >= 400:
            return None, "range_bound"
        size = len(("\n".join(lines[first - 1:last]) + "\n").encode("utf-8"))
        if size > 16384:
            return None, "window_byte_bound"
        return ({"path":path,"start_line":first,"end_line":last,"file_sha256":digest}, size), None

    for sweep in sweeps:
        cards = sweep.get("reviews", [])
        ids = [card["review_id"] for card in cards]
        if not ids or not set(ids) <= set(payload["review_ids"]):
            raise ValueError("preparation sweep outside selected claims")
        queues = []
        for card in cards:
            candidates = dependency_leads(root, card, lookup, dependency_cache, trace) if dependencies else []
            captures = (card.get("anchor") or {}).get("captures") or {}
            for key, name in sorted(captures.items()):
                if not key.startswith("related_handler_") or not isinstance(name, str) or not 1 <= len(name) <= 200:
                    continue
                cached = name in symbols
                if not cached:
                    symbols[name] = lookup(["investigate", "symbol", str(root), "--name", name, "--limit", "20"])
                found = symbols[name]
                matches = {json.dumps(row.get("location"), sort_keys=True):row for row in found.get("results", [])}
                status = "ambiguous_or_missing"
                if not found.get("truncated") and len(matches) == 1:
                    loc = next(iter(matches.values())).get("location") or {}
                    if loc.get("path"):
                        candidates.append((loc["path"], loc.get("start", {}).get("line"), loc.get("end", {}).get("line"), "named_declaration"))
                        status = "unique_declaration_binding_unproven"
                trace.append({"review_id":card["review_id"],"name":name,"status":status,"lookup_reused":cached})
            for lead in card.get("suggested_lookups", []):
                a = lead.get("arguments", {})
                if lead.get("operation") == "source" and set(a) >= {"path", "start-line", "end-line"}:
                    candidates.append((a["path"], int(a["start-line"]), int(a["end-line"]), "native_source_lead"))
            queues.append((card["review_id"], candidates))
        windows, total = [], 0
        # Round-robin claims so one large operation does not consume all slots.
        for index in range(max((len(q) for _, q in queues), default=0)):
            for rid, queue in queues:
                if index >= len(queue):
                    continue
                path, first, last, origin = queue[index]
                if type(first) is not int or type(last) is not int or not 1 <= first <= last:
                    trace.append({"review_id":rid,"path":path,"status":"invalid_native_range","origin":origin})
                    continue
                if any(w["path"] == path and w["start_line"] <= first <= last <= w["end_line"] for w in windows):
                    trace.append({"review_id":rid,"path":path,"status":"already_prepared","origin":origin})
                    continue
                if len(windows) >= 8:
                    trace.append({"review_id":rid,"path":path,"status":"window_count_bound","origin":origin})
                    continue
                try:
                    prepared, reason = window(path, first, last, origin == "native_source_lead")
                except (OSError, UnicodeDecodeError):
                    prepared, reason = None, "source_unavailable"
                if prepared and total + prepared[1] > 65536:
                    prepared, reason = None, "total_byte_bound"
                trace.append({"review_id":rid,"path":path,"start_line":first,"end_line":last,
                              "origin":origin,"status":reason or "prepared",
                              "returned_end_line":prepared[0]["end_line"] if prepared else None})
                if prepared:
                    windows.append(prepared[0]);total += prepared[1]
        if windows:
            targets.append({"review_ids":ids,"windows":windows})
    profile = {"schema_version":VERSION,"repository":payload["repository"],
               "inventory_input_fingerprint":payload["inventory_input_fingerprint"],"targets":targets}
    if targets:
        validate(profile, payload)
    return {"profile":profile if targets else None,"trace":trace,
            "limits":{"windows_per_bundle":8,"bytes_per_bundle":65536},
            "semantics":"Source only; declaration uniqueness does not establish import, dispatch or caller applicability."}


if __name__ == "__main__":
    import argparse
    import subprocess
    parser = argparse.ArgumentParser(description="Build an opt-in bounded source profile from native review sweeps.")
    for name in ("scanner", "source-root", "work-package", "sweeps", "output", "trace"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--dependencies", action="store_true", help="Include explicit import and literal registration source candidates; experimental")
    args = parser.parse_args()
    root = Path(args.source_root).resolve(strict=True)
    scanner = Path(args.scanner).resolve(strict=True)
    outputs = [Path(args.output).resolve(), Path(args.trace).resolve()]
    if scanner.is_relative_to(root) or any(p.is_relative_to(root) for p in outputs) or outputs[0] == outputs[1]:
        parser.error("scanner and distinct output files must be outside the source checkout")
    work = json.loads(Path(args.work_package).read_text(encoding="utf-8"))
    sweeps = json.loads(Path(args.sweeps).read_text(encoding="utf-8"))
    def lookup(argv):
        result = subprocess.run([str(scanner), *argv], check=True, capture_output=True,
                                text=True, encoding="utf-8", timeout=120)
        return json.loads(result.stdout)
    result = build_from_sweeps(root, work["payload"], sweeps, lookup, dependencies=args.dependencies)
    outputs[1].write_text(json.dumps(result, indent=2), encoding="utf-8")
    if result["profile"] is None:
        parser.exit(2, "No bounded source windows available; inspect trace and retain ordinary preparation.\n")
    outputs[0].write_text(json.dumps(result["profile"], indent=2), encoding="utf-8")
