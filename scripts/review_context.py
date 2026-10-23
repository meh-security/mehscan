"""Trusted runtime-contract compilation and bounded old/current change windows."""
import difflib
import hashlib
import json
from pathlib import Path
import re
import subprocess

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_WINDOWS = 8


def skill_bundle_id(root):
    rows, entries, byte_count = [], 0, 0
    def visit(directory):
        nonlocal entries, byte_count
        for path in directory.iterdir():
            entries += 1
            if entries > 1024:
                raise ValueError("skill package exceeds entry limit")
            if path.name in (".git", "__pycache__"):
                continue
            if path.is_symlink():
                raise ValueError("trusted skill package cannot contain symlinks")
            if path.is_dir():
                visit(path)
            elif path.is_file():
                byte_count += path.stat().st_size
                if byte_count > 8 * 1024 * 1024:
                    raise ValueError("skill package exceeds byte limit")
                rows.append([path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()])
            else:
                raise ValueError("skill package requires regular files")
    visit(root)
    if not any(path == "SKILL.md" for path, _ in rows):
        raise ValueError("skill package requires SKILL.md")
    encoded = json.dumps(["mehscanSkillBundle/v1", sorted(rows)], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return "mehscanSkillBundle/v1:" + hashlib.sha256(encoded).hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def source_lines(text):
    """Match Rust str::lines coordinates (LF/CRLF, preserving lone CR)."""
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") and (index < len(lines) - 1 or text.endswith("\n")) else line
            for index, line in enumerate(lines)] or [""]


def relative_file(root, path):
    if (not isinstance(path, str) or not path or ":" in path or "\\" in path
            or any(part in ("", ".", "..", ".git") for part in path.split("/"))):
        raise ValueError("context path must be source relative")
    result = root / path
    if not result.resolve().is_relative_to(root):
        raise ValueError("context path escapes authorized source")
    return result


def base_object(root, base, path, env, timeout):
    relative_file(root, path)
    prefix = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-prefix"], env=env,
                            capture_output=True, timeout=timeout)
    if prefix.returncode:
        raise ValueError("base source root is not in the pinned Git repository")
    return base + ":" + prefix.stdout.decode("utf-8").rstrip("\r\n") + path


def sections(path, names):
    raw = path.read_text(encoding="utf-8")
    selected = []
    for name in names:
        start, end = "<!-- runtime:" + name + " -->", "<!-- /runtime:" + name + " -->"
        if raw.count(start) != 1 or raw.count(end) != 1:
            raise ValueError("trusted runtime section is missing or duplicated")
        selected.append(raw.split(start, 1)[1].split(end, 1)[0].strip())
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "sections": names, "text": "\n\n".join(selected)}


def compile_contract(skill_root, kind, entries, paths, playbooks=None, role="investigator"):
    core = skill_root / "references/runtime-review.md"
    result = [sections(core, ["common", "dependency_research" if role == "research" else kind] + (["guard_changes"] if kind == "change_pass" else []))]
    if role in ("verification", "adjudication", "final_qa"):
        result.append(sections(core, [role]))
    elif role not in ("investigator", "research"):
        raise ValueError("unknown reviewer role")
    if any(entry.get("capability") == "html_output" for entry in entries) or any(
            Path(path).suffix.lower() in (".html", ".htm", ".vue", ".jsx", ".tsx") for path in paths):
        result.append(sections(skill_root / "references/html-output-review.md", ["chain", "frontend", "dom", "writers", "decisions"]))
    buckets = {"interpreted_input", "resource_boundary", "authorization", "credential_state",
               "state_integrity", "crypto_configuration", "native_memory", "operation_policy"}
    selected = sorted({value["bucket"] for value in (playbooks or {}).values()})
    for bucket in selected:
        if bucket not in buckets:
            raise ValueError("unknown trusted review bucket")
        if bucket == "interpreted_input" and entries and all(entry.get("capability") == "html_output" for entry in entries):
            continue  # The complete specialized HTML contract applies to this bundle.
        guide = skill_root / "references/buckets" / (bucket.replace("_", "-") + ".md")
        result.append({"path": str(guide), "sha256": hashlib.sha256(guide.read_bytes()).hexdigest(),
                       "sections": ["complete"], "text": guide.read_text(encoding="utf-8")})
    router = skill_root / "SKILL.md"
    value = {"version": "1", "router_sha256": hashlib.sha256(router.read_bytes()).hexdigest(), "sources": result}
    value["contract_id"] = "mehscanRuntime/v1:" + digest(value)
    return value


def change_ranges(old, current, context=15):
    """Independent old/new line coordinates, including insertion/deletion anchors."""
    ranges = {"base": [], "current": []}
    for kind, a, b, c, d in difflib.SequenceMatcher(None, old, current, autojunk=True).get_opcodes():
        if kind == "equal":
            continue
        for side, first, last, lines in (("base", a, b, old), ("current", c, d, current)):
            if not lines:
                continue
            start = max(1, min(first + 1, len(lines)) - context)
            end = min(len(lines), max(last, first + 1) + context)
            if ranges[side] and start <= ranges[side][-1][1] + 1:
                ranges[side][-1][1] = max(end, ranges[side][-1][1])
            else:
                ranges[side].append([start, end])
    return ranges


def prepare_changes(root, scope, native, env, timeout):
    if scope is None:
        return {"windows": [], "hunks": [], "limits": []}
    windows, limits, hunks = [], [], []
    comparison = scope.get("comparison")
    base = (comparison.get("merge_base_commit") or comparison["base_commit"]) if comparison else None
    if base is not None and not re.fullmatch(r"[0-9a-fA-F]{40,64}", base):
        raise ValueError("base evidence requires a pinned commit")
    for changed in scope["changed_files"]:
        path = changed["path"]
        previous = changed.get("previous_path") or path
        current_path = relative_file(root, path)
        relative_file(root, previous)
        # Reads are data only; actual work freshness is checked around preparation.
        if current_path.is_file() and current_path.stat().st_size > MAX_FILE_BYTES:
            limits.append({"path": path, "reason": "primary text exceeds bounded preparation"})
            continue
        current_bytes = current_path.read_bytes() if current_path.is_file() else None
        old_bytes = None
        if base is not None:
            obj = base_object(root, base, previous, env, timeout)
            command = ["git", "--no-pager", "-C", str(root), "-c", "core.hooksPath=", "cat-file", "blob", obj]
            size = subprocess.run(["git", "-C", str(root), "cat-file", "-s", obj],
                                  env=env, capture_output=True, timeout=timeout)
            if size.returncode == 0 and int(size.stdout) > MAX_FILE_BYTES:
                limits.append({"path": path, "reason": "old primary text exceeds bounded preparation"})
                continue
            proc = subprocess.run(command, env=env, capture_output=True, timeout=timeout)
            if proc.returncode == 0:
                old_bytes = proc.stdout
            elif changed["status"] not in ("added", "untracked"):
                raise ValueError("pinned old primary source is unavailable")
        try:
            old = source_lines(old_bytes.decode("utf-8")) if old_bytes is not None else []
            current = source_lines(current_bytes.decode("utf-8")) if current_bytes is not None else []
        except UnicodeDecodeError:
            limits.append({"path": path, "reason": "primary source is not UTF-8 text"})
            continue
        ranges = change_ranges(old, current) if base is not None else {"base": [], "current": [[1, len(current)]] if current else []}
        opcodes = difflib.SequenceMatcher(None, old, current, autojunk=True).get_opcodes() if old else []

        def old_line(line, ending=False):
            index = line - 1
            for kind, a, b, c, d in opcodes:
                if c <= index < d:
                    return a + index - c + 1 if kind == "equal" else max(1, b if ending else a + 1)
            return max(1, len(old))
        if not any(ranges.values()):
            ranges = {"base": [[1, min(len(old), 30)]] if old else [],
                      "current": [[1, min(len(current), 30)]] if current else []}
        # Small files are cheaper to supply whole than to rediscover their imports
        # and final writers. Large files retain hunk/enclosing windows.
        for side, lines in (("base", old), ("current", current)):
            if lines and len(lines) <= 80:
                ranges[side] = [[1, len(lines)]]
        # Current AST coordinates never substitute for old-side coordinates.
        for region in changed.get("changed_lines", [])[:MAX_WINDOWS]:
            if not current:
                break
            try:
                enclosing = native(["investigate", "enclosing-at", str(root), "--path", path, "--line", str(region["start"])])
                location = ((enclosing.get("results") or {}).get("symbol") or {}).get("location")
                if location:
                    first, last = location["start"]["line"], location["end"]["line"]
                    for window in ranges["current"]:
                        if window[0] <= region["start"] <= window[1] and last - first < 400:
                            window[0], window[1] = min(window[0], first), max(window[1], last)
                            if old:
                                mapped_first, mapped_last = old_line(first), old_line(last, True)
                                anchor = old_line(region["start"])
                                for old_window in ranges["base"]:
                                    if old_window[0] <= anchor <= old_window[1]:
                                        old_window[0] = min(old_window[0], mapped_first)
                                        old_window[1] = max(old_window[1], min(mapped_last, len(old)))
                    if last - first >= 400:
                        limits.append({"path": path, "reason": "enclosing unit exceeds prepared line budget; expand decisive branches"})
            except RuntimeError:
                limits.append({"path": path, "reason": "AST enclosing context unavailable; use primary windows and targeted source"})
        hunks.append({"path": path, "previous_path": previous, "status": changed["status"], "ranges": ranges})
        for side, values in ranges.items():
            lines = old if side == "base" else current
            source_path = previous if side == "base" else path
            if len(values) > MAX_WINDOWS:
                limits.append({"path": path, "reason": side + " changed windows exceed preparation budget"})
            for first, last in values[:MAX_WINDOWS]:
                clipped = last - first >= 400
                end = min(last, first + 399)
                text = "\n".join(lines[first - 1:end])
                while len(text.encode("utf-8")) > 64 * 1024 and end > first:
                    end -= 1
                    text = "\n".join(lines[first - 1:end])
                    clipped = True
                if len(text.encode("utf-8")) > 64 * 1024:
                    limits.append({"path": path, "reason": side + " primary line exceeds 64 KiB"})
                    continue
                item = {"side": side, "path": source_path, "start_line": first, "end_line": end,
                        "text": text, "clipped": clipped, "file_line_count": len(lines),
                        "complete_file": first == 1 and end == len(lines) and not clipped}
                item["artifact_id"] = "mehscanPreparedSource/v1:" + digest([base if side == "base" else None, item])
                windows.append(item)
                if clipped:
                    limits.append({"path": path, "reason": side + " primary window clipped; expand through source research"})
    return {"windows": windows, "hunks": hunks, "limits": limits}


def compact_work(payload, ids):
    return {key: payload[key] for key in ("assessment_context", "policy", "repository", "impact_scope", "change_pass")} | {
        "runtime": payload.get("runtime"), "review_ids": ids, "pending_questions": payload.get("pending_questions", []),
        "evidence_updates": payload.get("evidence_updates", []),
        "parent_decisions": payload.get("parent_decisions", {})}


def prepare_application(root, sweep, cache, snapshot_id):
    """Read native same-project policy leads once per source-bound attempt."""
    leads = {}
    for card in sweep.get("reviews", []):
        for lead in card.get("application_context", []):
            location = lead["location"]
            key = (location["path"], location["start_line"], location["end_line"])
            priority = 0 if lead.get("role") == "application_policy_context" else 1
            leads[key] = min(priority, leads.get(key, priority))
    windows, limits, total = [], [], 0
    for path, first, last in sorted(leads, key=lambda key: (leads[key], key)):
        if any(item["path"] == path and item["start_line"] <= first <= last <= item["end_line"] for item in windows):
            continue
        if len(windows) == 4:
            limits.append({"path": path, "reason": "application policy windows exceed preparation budget; inspect remaining native leads"})
            continue
        if type(first) is not int or type(last) is not int or first < 1 or last < first:
            raise ValueError("invalid native application context coordinates")
        key = (snapshot_id, path, first, last)
        if key not in cache:
            file = relative_file(root, path)
            if file.stat().st_size > MAX_FILE_BYTES:
                limits.append({"path": path, "reason": "application context file exceeds preparation size bound"})
                continue
            try:
                lines = source_lines(file.read_bytes().decode("utf-8"))
            except UnicodeDecodeError:
                limits.append({"path": path, "reason": "application context is not UTF-8"})
                continue
            if last > len(lines):
                raise ValueError("native application context exceeds actual source")
            end = min(last, first + 399)
            text = "\n".join(lines[first - 1:end])
            while len(text.encode("utf-8")) > 16 * 1024 and end > first:
                end -= 1
                text = "\n".join(lines[first - 1:end])
            item = {"side": "current", "path": path, "start_line": first, "end_line": end,
                    "text": text, "clipped": end < last, "file_line_count": len(lines),
                    "complete_file": first == 1 and end == len(lines) and end == last}
            item["artifact_id"] = "mehscanPreparedSource/v1:" + digest([snapshot_id, item])
            cache[key] = item
        item = cache[key]
        size = len(item["text"].encode("utf-8"))
        if size > 16 * 1024 or total + size > 64 * 1024:
            limits.append({"path": path, "reason": "application policy source exceeds preparation byte budget"})
            continue
        total += size
        windows.append(item)
        if item["clipped"]:
            limits.append({"path": path, "reason": "application policy window clipped; unread remainder cannot prove policy absence"})
    return {"windows": windows, "limits": limits}
