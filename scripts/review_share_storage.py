"""Turso transport and immutable records for enrolled review sharing."""

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request


MAX_DOCUMENT = 4 * 1024 * 1024
READ_TOKEN_MINUTES = 15
EVENT_COLUMNS = "seq, id, kind, actor, stream, commit_sha, created_at"
SCHEMA = (
    """CREATE TABLE IF NOT EXISTS mehscan_sharing (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        enrollment TEXT NOT NULL, schema_version INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS mehscan_shared_events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        digest TEXT NOT NULL,
        kind TEXT NOT NULL,
        actor TEXT NOT NULL,
        stream TEXT,
        commit_sha TEXT,
        created_at INTEGER NOT NULL,
        item_id TEXT,
        parent TEXT,
        payload TEXT NOT NULL,
        UNIQUE(item_id, parent))""",
)


class ShareError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def canonical(document):
    return json.dumps(document, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def digest(document):
    return hashlib.sha256(canonical(document).encode("ascii")).hexdigest()


def parse_document(data):
    def fields(pairs):
        value = dict(pairs)
        if len(value) != len(pairs):
            raise ValueError("duplicate JSON field")
        return value

    def constant(_):
        raise ValueError("nonfinite JSON number")

    return json.loads(data, object_pairs_hook=fields, parse_constant=constant)


def request_json(url, method="GET", token=None, document=None, *, api_status=False):
    headers = {"Accept": "application/json", "Cache-Control": "no-store"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if document is not None:
        data = canonical(document).encode("ascii")
        if len(data) > MAX_DOCUMENT:
            raise ShareError(413, "sharing document exceeds the size limit")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, method=method, headers=headers, data=data)
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=15) as response:
            data = response.read(MAX_DOCUMENT * 2 + 1)
            if len(data) > MAX_DOCUMENT * 2:
                raise ShareError(502, "sharing response exceeds the size limit")
            return parse_document(data)
    except urllib.error.HTTPError as error:
        with error:
            if api_status and error.code in (400, 401, 403, 404, 409, 413, 503):
                raise ShareError(error.code, f"sharing service rejected the request (HTTP {error.code})") from None
            raise ShareError(502, f"sharing backend request failed (HTTP {error.code})") from None
    except (OSError, ValueError, RecursionError):
        raise ShareError(502, "sharing backend returned an unavailable or invalid response") from None


def cloud_directory(organization, database):
    if any(not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", value) for value in (organization, database)):
        raise ShareError(400, "invalid Turso organization or database name")
    return f"https://api.turso.tech/v1/organizations/{organization}/databases/{database}"


def turso_origin(remote):
    parsed = urllib.parse.urlsplit(remote)
    if (parsed.scheme != "https"
            or not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,4}turso\.io", parsed.netloc)
            or parsed.path or parsed.query or parsed.fragment):
        raise ShareError(400, "invalid Turso database origin")
    return remote


def sql_database(remote, token):
    turso_origin(remote)

    def typed(arg):
        if arg is None:
            return {"type": "null"}
        if isinstance(arg, int):
            return {"type": "integer", "value": str(arg)}
        return {"type": "text", "value": arg}

    def execute(sql, *args):
        response = request_json(remote + "/v2/pipeline", "POST", token, {"requests": [
            {"type": "execute", "stmt": {"sql": sql, "args": [typed(arg) for arg in args]}},
            {"type": "close"},
        ]})
        try:
            fetched, closed = response["results"]
            if fetched["type"] != "ok" or closed["type"] != "ok":
                raise ShareError(502, "Turso rejected a sharing storage operation")
            result = fetched["response"]["result"]
            columns = [column["name"] for column in result["cols"]]
            return [dict(zip(columns, [int(cell["value"]) if cell["type"] == "integer"
                        else cell.get("value") for cell in row], strict=True)) for row in result["rows"]]
        except (KeyError, TypeError, ValueError):
            raise ShareError(502, "Turso returned an invalid sharing storage response") from None

    return execute


def platform_token():
    token = os.environ.get("MEHSCAN_TURSO_PLATFORM_TOKEN")
    if not token:
        raise ShareError(503, "Turso read credential issuance is unavailable")
    return token


def cloud_database(organization, database):
    result = request_json(cloud_directory(organization, database), token=platform_token())
    try:
        identity = result["database"]
        database_id = identity["DbId"]
        if not isinstance(database_id, str) or not database_id or len(database_id) > 128:
            raise ValueError()
        return database_id, turso_origin("https://" + identity["Hostname"])
    except (TypeError, KeyError, ValueError):
        raise ShareError(502, "Turso returned an invalid database identity") from None


def cloud_reader(enrollment):
    organization, database = enrollment["organization"], enrollment["database_name"]
    if cloud_database(organization, database) != (enrollment["database_id"], enrollment["remote"]):
        raise ShareError(409, "Turso database identity changed since enrollment")
    cloud_store(enrollment).check_binding()
    response = request_json(
        cloud_directory(organization, database) + f"/auth/tokens?expiration={READ_TOKEN_MINUTES}m&authorization=read-only",
        "POST", platform_token(),
    )
    token = response.get("jwt") if isinstance(response, dict) else None
    if not isinstance(token, str) or not token:
        raise ShareError(502, "Turso did not issue a read credential")
    return {"remote": enrollment["remote"], "token": token,
            "expires_in_seconds": READ_TOKEN_MINUTES * 60}


def cloud_store(enrollment):
    token = os.environ.get(enrollment["writer_env"])
    if not token:
        raise ShareError(503, "Turso publication storage is unavailable")
    return EventStore(sql_database(enrollment["remote"], token), enrollment["id"])


class EventStore:
    def __init__(self, execute, enrollment):
        self.execute = execute
        self.enrollment = enrollment

    def initialize(self):
        self.check_tables()
        self.execute(SCHEMA[0])
        self.execute("INSERT INTO mehscan_sharing VALUES (1, ?, 1) ON CONFLICT DO NOTHING", self.enrollment)
        self.check_identity()
        self.execute(SCHEMA[1])

    def check_binding(self):
        self.check_identity()
        self.check_tables()

    def check_tables(self):
        names = self.execute("SELECT name FROM sqlite_schema WHERE type IN ('table', 'view', 'trigger') "
                             "AND substr(name, 1, 7) != 'sqlite_'")
        if set(row["name"] for row in names) - {"mehscan_sharing", "mehscan_shared_events"}:
            raise ShareError(409, "sharing enrollment requires a dedicated Turso database")

    def check_identity(self):
        if self.execute("SELECT enrollment, schema_version FROM mehscan_sharing WHERE singleton = 1") != [
                {"enrollment": self.enrollment, "schema_version": 1}]:
            raise ShareError(409, "review database is bound to another sharing enrollment or schema")

    def get(self, event_id):
        rows = self.execute(f"SELECT {EVENT_COLUMNS}, digest, payload FROM mehscan_shared_events WHERE id = ?", event_id)
        if not rows:
            return None
        event = rows[0]
        event["payload"] = parse_document(event["payload"])
        return event

    def list(self, after):
        return self.execute(f"SELECT {EVENT_COLUMNS} FROM mehscan_shared_events WHERE seq > ? ORDER BY seq LIMIT 100", after)

    def append(self, *, event_id, request_digest, kind, actor, stream, commit, payload, item_id=None, parent=None):
        encoded = canonical(payload)
        if len(encoded) > MAX_DOCUMENT:
            raise ShareError(413, "sharing payload exceeds the size limit")
        rows = self.execute(f"""
            INSERT INTO mehscan_shared_events (id, digest, kind, actor, stream, commit_sha, created_at, item_id, parent, payload)
            SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            FROM mehscan_sharing WHERE singleton = 1 AND enrollment = ? AND schema_version = 1
            ON CONFLICT DO NOTHING RETURNING {EVENT_COLUMNS}, digest""",
            event_id, request_digest, kind, actor, stream, commit, int(time.time()), item_id, parent, encoded, self.enrollment)
        event = rows[0] if rows else self.get(event_id)
        if event is None:
            raise ShareError(409, "the shared record changed before this submission")
        if event["digest"] != request_digest:
            raise ShareError(409, "sharing operation ID was already used for a different submission")
        return event
