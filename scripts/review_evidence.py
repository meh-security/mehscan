"""Controller-owned atomic working state shared by case and workspace adapters."""
import copy
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


class AtomicState:
    version = None
    action_limit = 128 * 1024

    def __init__(self, path, binding):
        self.path = Path(path).resolve()
        self.binding = copy.deepcopy(binding)
        if not self.path.is_file():
            raise ValueError("workspace does not exist")
        self.snapshot()

    @staticmethod
    def publish(path, state):
        """Exclusive atomic publication; never replace state or prior receipts."""
        descriptor, pending = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
        os.close(descriptor)
        try:
            with closing(sqlite3.connect(pending)) as db, db:
                db.executescript("CREATE TABLE workspace (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL);"
                                 "CREATE TABLE receipts (key TEXT PRIMARY KEY, request TEXT NOT NULL, response TEXT NOT NULL);")
                db.execute("INSERT INTO workspace VALUES (1, ?)", (encoded(state),))
            os.link(pending, path)
        finally:
            os.unlink(pending)

    def _load(self, db):
        state = json.loads(db.execute("SELECT body FROM workspace WHERE id=1").fetchone()[0])
        if state["version"] != self.version or state["binding"] != self.binding:
            raise ValueError("workspace source/plan/runtime binding differs")
        return state

    def snapshot(self):
        with closing(sqlite3.connect(self.path, timeout=0)) as db:
            return self._load(db)

    def operation(self, operation_key):
        self._key(operation_key)
        with closing(sqlite3.connect(self.path, timeout=0)) as db:
            self._load(db)
            row = db.execute("SELECT request, response FROM receipts WHERE key=?", (operation_key,)).fetchone()
            return None if row is None else {"request":json.loads(row[0]), "response":json.loads(row[1])}

    @staticmethod
    def _key(value):
        if not isinstance(value, str) or not value.strip() or len(value) > 1000:
            raise ValueError("expected bounded nonempty text")

    def apply(self, operation_key, expected_revision, action, *, before_commit=None):
        self._key(operation_key)
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("expected a nonnegative integer")
        request = encoded({"revision":expected_revision, "action":action})
        if len(request.encode("utf-8")) > self.action_limit:
            raise ValueError("workspace action exceeds intake limit")
        with closing(sqlite3.connect(self.path, timeout=0)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            state = self._load(db)
            old = db.execute("SELECT request, response FROM receipts WHERE key=?", (operation_key,)).fetchone()
            if old:
                if old[0] != request:
                    raise ValueError("operation key reused for different input")
                if before_commit is not None:
                    before_commit()
                return {**json.loads(old[1]), "replayed":True}
            if expected_revision != state["revision"]:
                raise ValueError("stale workspace revision")
            result = self._action(state, action, operation_key)
            state["revision"] += 1
            receipt = {"revision":state["revision"], "result":result, "replayed":False, "native_admission":False}
            if before_commit is not None:
                before_commit()
            db.execute("UPDATE workspace SET body=? WHERE id=1", (encoded(state),))
            db.execute("INSERT INTO receipts VALUES (?, ?, ?)", (operation_key, request, encoded(receipt)))
            return receipt
