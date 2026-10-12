"""
capllm.core.audit
=================

Tamper-evident audit log based on a SHA-256 cryptographic hash chain.

How the chain works
-------------------
Each entry stores the hash of the previous entry (``previous_hash``) and its
own hash (``entry_hash``)::

    entry_hash[i] = SHA256( canonical_json( fields[i] + previous_hash[i] ) )
    previous_hash[i] = entry_hash[i-1]          (GENESIS_HASH for i = 0)

Modifying, deleting, inserting or re-ordering *any* interior entry changes its
hash, which breaks the ``previous_hash`` link of every subsequent entry.
``verify_chain`` recomputes all hashes and reports the first broken index, so
internal integrity can be checked mathematically.

Threat Model & Essential Security Boundaries
--------------------------------------------
1. **Fresh Per-Run Ledger Semantics**:
   When constructed with a `log_path`, `AuditLogger` initializes a fresh,
   per-run ledger for the current process session. If `log_path` points to an
   existing file, it is intentionally truncated to initialize a new chain
   starting at sequence 0 from `GENESIS_HASH`.
   **Do NOT treat this as durable append-only storage across distinct runs.**

2. **Flushing vs. fsync()**:
   Each appended record performs an explicit `flush()` on the file handle to
   transfer userspace Python buffers to the operating system. However, `flush()`
   is NOT an `fsync()` or disk barrier: it does not guarantee that data has been
   committed to non-volatile physical storage in the event of an OS crash or power failure.
   Furthermore, standard userspace file writing provides no kernel-enforced
   append-only immutability (such as Linux `chattr +a` or hardware WORM).

3. **Checkpointing Requirement (Tail Truncation & Total Replacement)**:
   A standalone local hash chain CANNOT independently detect:
     * Tail truncation (an attacker silently deleting the newest N entries: the
       remaining prefix still forms a mathematically valid hash chain from genesis).
     * Total log replacement (an attacker synthesizing an entirely new, internally
       consistent chain from genesis).
   Tamper evidence against these attacks is achieved ONLY when the log's head
   hash is anchored to an externally retained checkpoint (e.g. an external witness,
   WORM storage, append-only transparency log, or TPM quote). The verification
   methods accept an ``expected_head_hash`` checkpoint parameter to enforce this.
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
    """Thread-safe, hash-chained security event log for a single execution session.

    Session Lifecycle:
      Instantiating ``AuditLogger(log_path)`` creates a fresh per-run ledger.
      If ``log_path`` exists, it is truncated upon initialization to begin a new
      cryptographic chain from ``GENESIS_HASH``.

    Storage Notice:
      Entries are held in memory and appended to disk with ``flush()``. This is
      not durable across distinct runs and does not issue an ``fsync()`` sync.
    """

    def __init__(self, log_path: Optional[Path] = None) -> None:
        self._lock = threading.Lock()
        self._events: List[AuditEvent] = []
        self._head_hash: str = GENESIS_HASH
        self._log_path = Path(log_path) if log_path else None
        if self._log_path is not None:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            # Fresh per-run ledger: truncate any previous run file
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
                    fh.flush()  # Flushes userspace buffer to OS (not fsync)
            return event

    # ------------------------------------------------------------------ #
    # Read-only accessors
    # ------------------------------------------------------------------ #
    @property
    def events(self) -> Tuple[AuditEvent, ...]:
        """Immutable snapshot of all events in this session."""
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
    def verify_events(
        events: Sequence[AuditEvent],
        expected_head_hash: Optional[str] = None,
    ) -> Tuple[bool, Optional[int], str]:
        """Verify an arbitrary sequence of events.

        Returns ``(ok, first_bad_index, reason)``.
        Performs:
          1. linkage  -- previous_hash equals the prior entry's hash;
          2. content  -- entry_hash equals the recomputed hash;
          3. checkpoint -- if expected_head_hash is given, ensures the head
             matches. This is essential to detect tail truncation or wholesale
             log replacement.
        """
        expected_prev = GENESIS_HASH
        for idx, ev in enumerate(events):
            if ev.previous_hash != expected_prev:
                return False, idx, "broken link: previous_hash mismatch (entry removed/reordered)"
            if ev.compute_hash() != ev.entry_hash:
                return False, idx, "content hash mismatch (entry modified)"
            expected_prev = ev.entry_hash

        if expected_head_hash is not None:
            actual_head = events[-1].entry_hash if events else GENESIS_HASH
            if actual_head != expected_head_hash:
                return (
                    False,
                    len(events),
                    f"checkpoint mismatch: expected head {expected_head_hash[:16]}..., "
                    f"got {actual_head[:16]}... (tail truncated or log replaced)",
                )

        return True, None, "chain intact"

    def verify_chain(
        self, expected_head_hash: Optional[str] = None
    ) -> Tuple[bool, Optional[int], str]:
        """Verify the in-memory chain, optionally against an external checkpoint."""
        return self.verify_events(self.events, expected_head_hash=expected_head_hash)

    @classmethod
    def verify_file(
        cls, log_path: Path, expected_head_hash: Optional[str] = None
    ) -> Tuple[bool, Optional[int], str]:
        """Verify a JSON-Lines log file written by this class."""
        events: List[AuditEvent] = []
        with Path(log_path).open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    events.append(AuditEvent(**json.loads(line)))
        return cls.verify_events(events, expected_head_hash=expected_head_hash)
