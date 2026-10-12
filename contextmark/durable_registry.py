"""Authenticated single-owner SQLite attempt ledger.

Durability relies on SQLite EXTRA synchronization and a local filesystem honoring
its flush/locking contract. Authentication is not anti-rollback. The owner lock
is held across backend calls, so only a later owner may retire pending entries.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3

from .canonical import canonical_bytes


class DurableRegistryError(ValueError):
    pass


class DurableRegistry:
    VERSION = "contextmark-sqlite-v1"
    ENTRY_DOMAIN = b"contextmark/durable-entry/v1\0"
    HEADER_DOMAIN = b"contextmark/durable-header/v1\0"

    def __init__(self, path, *, master_key: bytes, chain_id: str):
        self.path = Path(path).resolve()
        self.key = bytes(master_key)
        self.chain_id = chain_id
        self.connection = None
        self.owner = None
        self.locked = False
        try:
            # Never unlink this file: a second inode would split lock ownership.
            self.owner = open(str(self.path) + ".owner", "a+b")
            self.owner.seek(0, os.SEEK_END)
            if self.owner.tell() == 0:
                self.owner.write(b"0")
                self.owner.flush()
            self.owner.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.owner.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.owner.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.locked = True
            existed = self.path.exists()
            self.connection = sqlite3.connect(str(self.path), isolation_level=None, check_same_thread=False)
            mode = self.connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            self.connection.execute("PRAGMA synchronous=EXTRA")
            if mode != "delete" or self.connection.execute("PRAGMA synchronous").fetchone()[0] != 3:
                raise DurableRegistryError("required SQLite durability settings unavailable")
            if not existed:
                self.connection.execute("BEGIN IMMEDIATE")
                self.connection.execute("CREATE TABLE attempts (request_id TEXT PRIMARY KEY, context TEXT UNIQUE NOT NULL, body BLOB NOT NULL, tag TEXT NOT NULL)")
                self.connection.execute("CREATE TABLE header (id INTEGER PRIMARY KEY CHECK(id=1), body BLOB NOT NULL, tag TEXT NOT NULL)")
                self._write_header(0, 0)
                self.connection.execute("COMMIT")
            self.load_entries()  # Existing malformed or unauthenticated files never reset.
        except Exception as exc:
            self.close()
            if isinstance(exc, DurableRegistryError):
                raise
            raise DurableRegistryError("durable registry open/ownership failed") from exc

    def _tag(self, domain, body):
        return hmac.new(self.key, domain + body, hashlib.sha256).hexdigest()

    def _decode(self, body, tag, domain):
        if not isinstance(body, bytes) or not isinstance(tag, str):
            raise DurableRegistryError("durable registry encoding invalid")
        if not hmac.compare_digest(tag, self._tag(domain, body)):
            raise DurableRegistryError("durable registry authentication failed")
        value = json.loads(body)
        if canonical_bytes(value) != body or not isinstance(value, dict):
            raise DurableRegistryError("durable registry is not canonical")
        return value

    def _header(self):
        rows = self.connection.execute("SELECT id,body,tag FROM header").fetchall()
        if len(rows) != 1 or rows[0][0] != 1:
            raise DurableRegistryError("durable registry header missing")
        value = self._decode(rows[0][1], rows[0][2], self.HEADER_DOMAIN)
        if (set(value) != {"version", "chain_id", "entry_count", "revision"}
                or value["version"] != self.VERSION or value["chain_id"] != self.chain_id
                or type(value["entry_count"]) is not int or value["entry_count"] < 0
                or type(value["revision"]) is not int or value["revision"] < 0):
            raise DurableRegistryError("durable registry header invalid")
        return value

    def _write_header(self, count, revision):
        body = canonical_bytes(dict(version=self.VERSION, chain_id=self.chain_id,
                                    entry_count=count, revision=revision))
        self.connection.execute("INSERT OR REPLACE INTO header VALUES (1,?,?)",
                                (body, self._tag(self.HEADER_DOMAIN, body)))

    def _entry(self, row):
        request_id, context, body, tag = row
        value = self._decode(body, tag, self.ENTRY_DOMAIN)
        if value.get("request_id") != request_id or value.get("context") != context:
            raise DurableRegistryError("durable registry index mismatch")
        return value

    def load_entries(self):
        header = self._header()
        rows = self.connection.execute("SELECT request_id,context,body,tag FROM attempts ORDER BY request_id").fetchall()
        if len(rows) != header["entry_count"]:
            raise DurableRegistryError("durable registry entry count mismatch")
        return [self._entry(row) for row in rows]

    def write_entries(self, entries, *, reserve=False):
        """Commit all supplied inserts or pending-to-terminal updates atomically."""
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            header = self._header()
            count = header["entry_count"]
            for entry in entries:
                request_id, context = entry["request_id"], entry["context"]
                body = canonical_bytes(entry)
                tag = self._tag(self.ENTRY_DOMAIN, body)
                if reserve:
                    if entry["status"] not in {"pending", "success", "failed"}:
                        raise DurableRegistryError("invalid reserved state")
                    self.connection.execute("INSERT INTO attempts VALUES (?,?,?,?)", (request_id, context, body, tag))
                    count += 1
                else:
                    row = self.connection.execute("SELECT request_id,context,body,tag FROM attempts WHERE request_id=?", (request_id,)).fetchone()
                    old = self._entry(row) if row else None
                    if (old is None or old["status"] != "pending" or entry["status"] not in {"success", "failed"}
                            or any(entry[k] != old[k] for k in ("context", "unsigned", "request_program_hex"))):
                        raise DurableRegistryError("invalid terminal transition")
                    self.connection.execute("UPDATE attempts SET body=?,tag=? WHERE request_id=?", (body, tag, request_id))
            self._write_header(count, header["revision"] + 1)
            self.connection.execute("COMMIT")
        except Exception as exc:
            try:
                if self.connection.in_transaction:
                    self.connection.execute("ROLLBACK")
            except Exception as rollback_exc:
                raise DurableRegistryError("durable registry rollback failed; reopen before issuing") from rollback_exc
            raise DurableRegistryError("durable registry commit failed; reopen before issuing") from exc

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if self.owner is not None:
            if self.locked:
                self.owner.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(self.owner.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.owner.fileno(), fcntl.LOCK_UN)
            self.owner.close()
            self.owner = None
            self.locked = False
