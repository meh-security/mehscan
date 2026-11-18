"""Run the existing structured review protocol through the OpenAI Responses API."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import urllib.error
import urllib.request
import uuid

import codex_launcher


ENDPOINT = "https://api.openai.com/v1/responses"
MAX_DOCUMENT = 16 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        raise urllib.error.HTTPError(ENDPOINT, code, "unexpected redirect", headers, fp)


def request_response(payload, key, timeout):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if len(body) > MAX_DOCUMENT:
        raise ValueError("provider request exceeds the private transcript limit")
    request = urllib.request.Request(ENDPOINT, data=body, method="POST", headers={
        "Authorization": "Bearer " + key, "Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as result:
            data = result.read(MAX_DOCUMENT + 1)
    except urllib.error.HTTPError as error:
        error.close()
        raise codex_launcher.ProviderExecutionError(error.code, "", "") from None
    except (urllib.error.URLError, OSError):
        raise codex_launcher.ProviderExecutionError(1, "", "") from None
    if len(data) > MAX_DOCUMENT:
        raise ValueError("provider response exceeds its intake limit")
    response = json.loads(data)
    if not isinstance(response, dict) or response.get("status") != "completed":
        raise codex_launcher.ProviderExecutionError(1, "", "")
    return response


def review_reply(output):
    text = []
    if not isinstance(output, list):
        raise ValueError("provider response has no output items")
    for item in output:
        if not isinstance(item, dict):
            raise ValueError("provider returned an unsupported output item")
        if item["type"] == "reasoning":
            continue
        if item["type"] != "message" or item["role"] != "assistant" or item["status"] != "completed":
            raise ValueError("provider returned an unsupported output item")
        for part in item["content"]:
            if part["type"] != "output_text" or not isinstance(part["text"], str):
                raise ValueError("provider did not return a structured review")
            text.append(part["text"])
    value = json.loads("".join(text))
    if not isinstance(value, dict):
        raise ValueError("provider review must be a JSON object")
    return value


def reported_usage(response):
    usage = response.get("usage") or {}
    input_details = usage.get("input_tokens_details") or {}
    output_details = usage.get("output_tokens_details") or {}
    counters = {"input_tokens": usage.get("input_tokens"), "output_tokens": usage.get("output_tokens"),
        "cached_input_tokens": input_details.get("cached_tokens"),
        "reasoning_output_tokens": output_details.get("reasoning_tokens")}
    return {name: value for name, value in counters.items() if type(value) is int and 0 <= value <= 2**63 - 1}


class ResponsesLauncher:
    def __init__(self, config, session):
        self.config = config
        self.history = Path(session) / "responses-input.json"
        with Path(config["auth_file"]).open("rb") as handle:
            raw = handle.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise ValueError("invalid Responses API authentication file")
        auth = json.loads(raw)
        key = auth.get("OPENAI_API_KEY") if isinstance(auth, dict) else None
        if not isinstance(key, str) or not re.fullmatch(r"sk-[A-Za-z0-9_-]{16,512}", key):
            raise ValueError("Responses API requires an explicit project API key")
        self.key = key
        self.credential_digest = hashlib.sha256(key.encode("ascii")).hexdigest()

    def review(self, prompt, schema, thread_id=None, timeout=600):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 3600:
            raise ValueError("provider deadline must be finite and bounded")
        if codex_launcher.CANCELLED:
            raise TimeoutError("provider cancelled")
        if self.history.exists():
            if not thread_id or self.history.stat().st_size > MAX_DOCUMENT:
                raise ValueError("cannot restart or extend this Responses API conversation")
            history = json.loads(self.history.read_text(encoding="utf-8"))
            if history["thread_id"] != thread_id or history.get("credential_digest") != self.credential_digest:
                raise ValueError("Responses API continuation does not match its conversation or credential")
            inputs = history["input"]
        elif thread_id:
            raise ValueError("Responses API continuation has no local transcript")
        else:
            thread_id, inputs = str(uuid.uuid4()), []
        inputs.append({"role": "user", "content": prompt})
        model = self.config["model"]
        response = request_response({"model": model, "reasoning": {"effort": self.config["reasoning_effort"]},
            "instructions": codex_launcher.REVIEWER_INSTRUCTIONS.read_text(encoding="utf-8"),
            "input": inputs, "tools": [], "store": False, "include": ["reasoning.encrypted_content"],
            "max_output_tokens": 16384, "text": {"format": {"type": "json_schema", "name": "mehscan_review",
                "strict": True, "schema": schema}}}, self.key, timeout)
        returned = response.get("model")
        if not isinstance(returned, str) or (returned != model and not returned.startswith(model + "-")):
            raise ValueError("provider returned an unexpected model")
        output = response.get("output")
        reply = review_reply(output)
        if codex_launcher.CANCELLED:
            raise TimeoutError("provider cancelled")
        history = json.dumps({"thread_id": thread_id, "credential_digest": self.credential_digest,
                              "input": inputs + output}, ensure_ascii=False)
        pending = self.history.with_suffix(".tmp")
        with pending.open("x", encoding="utf-8") as handle:
            pending.chmod(0o600)
            handle.write(history)
        os.replace(pending, self.history)
        # Use the existing reviewer event boundary. These counters cover one
        # Responses request, unlike the CLI's cumulative conversation counters.
        events = [{"type": "thread.started", "thread_id": thread_id},
                  {"type": "turn.completed", "usage": reported_usage(response)}]
        return reply, "\n".join(json.dumps(event) for event in events), ""
