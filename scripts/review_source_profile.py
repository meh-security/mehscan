"""Explicit, source-only preparation shared by native and workspace reviewers."""
import hashlib
import json
import re
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
