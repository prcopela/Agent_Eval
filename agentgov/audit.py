"""Tamper-evident audit trail.

Every decision the control layer makes is appended to the log. Entries are
hash-chained (each entry stores the SHA-256 of the previous one), so editing or
deleting a past entry is detectable with :meth:`AuditLog.verify`.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.entries: list[dict[str, Any]] = []
        self._last_hash = GENESIS
        if self.path and self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    self.entries.append(json.loads(line))
            if self.entries:
                self._last_hash = self.entries[-1]["hash"]

    def record(self, **fields: Any) -> dict[str, Any]:
        entry = {"seq": len(self.entries), "ts": time.time(), **fields, "prev_hash": self._last_hash}
        entry["hash"] = _hash(entry)
        self._last_hash = entry["hash"]
        self.entries.append(entry)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        return entry

    def verify(self) -> tuple[bool, str]:
        prev = GENESIS
        for e in self.entries:
            if e["prev_hash"] != prev:
                return False, f"chain broken at seq {e['seq']}"
            body = {k: v for k, v in e.items() if k != "hash"}
            if _hash(body) != e["hash"]:
                return False, f"entry {e['seq']} was modified"
            prev = e["hash"]
        return True, f"{len(self.entries)} entries verified"

    def for_session(self, session_id: str) -> list[dict[str, Any]]:
        return [e for e in self.entries if e.get("session_id") == session_id]

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)


def _hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
