"""
capllm.core.audit
=================

Tamper-evident, append-only audit log based on a SHA-256 hash chain.

How the chain works
-------------------
Each entry stores the hash of the previous entry (``previous_hash``) and its
own hash (``entry_hash``)::

    entry_hash[i] = SHA256( canonical_json( fields[i] + previous_hash[i] ) )
    previous_hash[i] = entry_hash[i-1]          (GENESIS_HASH for i = 0)

Modifying, deleting, inserting or re-ordering *any* entry changes its hash,
which breaks the ``previous_hash`` link of every subsequent entry.
``verify_chain`` recomputes all hashes and reports the first broken index, so
integrity can be checked mathematically by anyone holding the log.

Limitation worth stating in a defense: an attacker who can rewrite the
*entire* log can recompute a fresh, valid chain.  Production systems close
this gap by periodically anchoring the head hash externally (WORM storage,
transparency log, TPM quote).  ``head_hash`` is exposed for that purpose.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

GENESIS_HASH = "0" * 64


class EventType(str, Enum):
    """Security event taxonomy."""

    TOKEN_ISSUED = "TOKEN_ISSUED"
    SYSCALL_INTERCEPTED = "SYSCALL_INTERCEPTED"
    ACCESS_ALLOWED = "ACCESS_ALLOWED"
    ACCESS_DENIED = "ACCESS_DENIED"
    TOKEN_REVOKED = "TOKEN_REVOKED"
    PROCESS_TERMINATED = "PROCESS_TERMINATED"


class Verdict(str, Enum):
    """Outcome attached to an event.

    PENDING is used only for SYSCALL_INTERCEPTED on the slow path: the call
    is suspended while deep validation runs, and its final ALLOW/BLOCK is
    recorded in the immediately following ACCESS_* event.
    """

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    PENDING = "PENDING"


@dataclass(frozen=True)
class AuditEvent:
    """A single immutable audit record."""

    sequence: int
    event_id: str
    timestamp: float
    event_type: str
    tenant_id: str
    agent_id: str
    syscall_name: str
    target_resource: str
    verdict: str
    details: Dict[str, Any] = field(default_factory=dict)
    previous_hash: str = GENESIS_HASH
    entry_hash: str = ""

    def compute_hash(self) -> str:
        """SHA-256 over every field except ``entry_hash`` itself."""
        body = asdict(self)
        body.pop("entry_hash")
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, default=str)


class AuditLogger:
    """Thread-safe, append-only, hash-chained security event log.

    Events are kept in memory (for fast verification in the demo) and,
    optionally, appended to a JSON-Lines file opened in append mode.  The
    class intentionally exposes *no* update or delete API.
    """

    def __init__(self, log_path: Optional[Path] = None) -> None:
        self._lock = threading.Lock()
        self._events: List[AuditEvent] = []
        self._head_hash: str = GENESIS_HASH
        self._log_path = Path(log_path) if log_path else None
        if self._log_path is not None:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            # Start a fresh chain file for this run.
            self._log_path.write_text("", encoding="utf-8")

    # ------------------------------------------------------------------ #
    # Append
    # ------------------------------------------------------------------ #
    def log_event(
        self,
        event_type: EventType,
        tenant_id: str,
        agent_id: str,
        syscall_name: str,
        target_resource: str,
        verdict: Verdict,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Append one event and extend the hash chain atomically."""
        with self._lock:
            draft = AuditEvent(
                sequence=len(self._events),
                event_id=str(uuid.uuid4()),
                timestamp=time.time(),
                event_type=EventType(event_type).value,
                tenant_id=tenant_id,
                agent_id=agent_id,
                syscall_name=syscall_name,
                target_resource=target_resource,
                verdict=Verdict(verdict).value,
                details=dict(details or {}),
                previous_hash=self._head_hash,
            )
            event = replace(draft, entry_hash=draft.compute_hash())
            self._events.append(event)
            self._head_hash = event.entry_hash
            if self._log_path is not None:
                with self._log_path.open("a", encoding="utf-8") as fh:
                    fh.write(event.to_json() + "\n")
            return event

    # ------------------------------------------------------------------ #
    # Read-only accessors
    # ------------------------------------------------------------------ #
    @property
    def events(self) -> Tuple[AuditEvent, ...]:
        """Immutable snapshot of all events."""
        with self._lock:
            return tuple(self._events)

    @property
    def head_hash(self) -> str:
        """Hash of the most recent entry -- anchor this externally."""
        with self._lock:
            return self._head_hash

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)

    def count_by_type(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for ev in self.events:
            counts[ev.event_type] = counts.get(ev.event_type, 0) + 1
        return counts

    # ------------------------------------------------------------------ #
    # Verification
    # ------------------------------------------------------------------ #
    @staticmethod
    def verify_events(events: Sequence[AuditEvent]) -> Tuple[bool, Optional[int], str]:
        """Verify an arbitrary sequence of events.

        Returns ``(ok, first_bad_index, reason)``.
        Two checks per entry:
          1. linkage  -- previous_hash equals the prior entry's hash;
          2. content  -- entry_hash equals the recomputed hash.
        """
        expected_prev = GENESIS_HASH
        for idx, ev in enumerate(events):
            if ev.previous_hash != expected_prev:
                return False, idx, "broken link: previous_hash mismatch (entry removed/reordered)"
            if ev.compute_hash() != ev.entry_hash:
                return False, idx, "content hash mismatch (entry modified)"
            expected_prev = ev.entry_hash
        return True, None, "chain intact"

    def verify_chain(self) -> Tuple[bool, Optional[int], str]:
        """Verify the in-memory chain."""
        return self.verify_events(self.events)

    @classmethod
    def verify_file(cls, log_path: Path) -> Tuple[bool, Optional[int], str]:
        """Verify a JSON-Lines log file written by this class."""
        events: List[AuditEvent] = []
        with Path(log_path).open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    events.append(AuditEvent(**json.loads(line)))
        return cls.verify_events(events)
