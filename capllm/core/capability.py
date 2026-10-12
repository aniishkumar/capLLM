"""
capllm.core.capability
======================

Capability-based authority for LLM agents.

Security model (the "why")
--------------------------
Classic ACL systems ask *"who are you?"* and then consult a global policy.
Capability systems instead ask *"what unforgeable token of authority are you
presenting?"*.  Every agent process receives exactly one ``CapabilityToken``
that enumerates the *only* resources it may touch (principle of least
privilege).  Anything not explicitly listed is denied (default-deny).

Unforgeability is provided by an HMAC-SHA256 signature computed with a secret
key that only the supervisor (the reference monitor) knows.  A tampered token
(e.g. an attacker widening ``allowed_paths``) produces a signature mismatch and
is rejected.

Liveness of authority is provided by:
  * ``valid_until`` -- tokens expire automatically (bounded lifetime);
  * ``revoke_token`` -- the operator can kill authority instantly.  Revocation
    is authoritative *server side* (a revocation set inside the manager), so a
    stolen copy of the token cannot "un-revoke" itself.

Performance is provided by an in-memory decision cache.  Static policy
evaluation results (does prefix X grant permission Y?) are cached, while the
*dynamic* properties (signature/expiry/revocation) are re-checked on every
request with O(1) dictionary/set lookups.  This is what keeps the fast path in
the low-microsecond range without ever serving a stale ALLOW after revocation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import TYPE_CHECKING, Dict, FrozenSet, Iterable, Mapping, Optional, Set, Tuple

if TYPE_CHECKING:  # pragma: no cover - import only for type checkers
    from capllm.core.audit import AuditLogger

# Permissions a path capability may grant.
VALID_PERMISSIONS: FrozenSet[str] = frozenset({"read", "write", "exec"})

# Key type used by the fast-path decision cache:
# (token_id, syscall_name, normalized_resource, permission)
CacheKey = Tuple[str, str, str, str]


# --------------------------------------------------------------------------- #
# Path helpers -- the single source of truth for path comparison.
# --------------------------------------------------------------------------- #
def normalize_path(path: str, cwd: Optional[str] = None) -> str:
    """Return a canonical, absolute, symlink-resolved path.

    This defeats the classic confused-path tricks:
      * relative paths        ("secret.txt" -> "<cwd>/secret.txt")
      * traversal sequences   ("ws/../../tenant_a" -> "/tmp/tenant_a")
      * symlink escapes       (realpath follows links to their real target)
      * case games on Windows (normcase lower-cases the path)

    Both the *policy* (allowed prefixes) and the *request* go through this
    function, so they are always compared in the same canonical space.
    """
    if not os.path.isabs(path):
        path = os.path.join(cwd or os.getcwd(), path)
    return os.path.normcase(os.path.realpath(path))


def path_is_within(candidate: str, prefix: str) -> bool:
    """True iff ``candidate`` equals ``prefix`` or lies underneath it.

    Uses component-wise comparison (``os.path.commonpath``) rather than naive
    ``str.startswith`` so that ``/tmp/tenant_a_evil`` is NOT considered to be
    inside ``/tmp/tenant_a``.  Both arguments must already be normalized.
    """
    try:
        return os.path.commonpath([candidate, prefix]) == prefix
    except ValueError:
        # Raised e.g. on Windows when paths live on different drives.
        return False


# --------------------------------------------------------------------------- #
# Capability token
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, eq=False)
class CapabilityToken:
    """An immutable, signed grant of authority to one agent of one tenant.

    The dataclass is ``frozen`` and all collection fields are converted to
    immutable types, so a token can never be mutated in place.  State changes
    (PID binding, revocation) create a *new* token version via
    ``dataclasses.replace`` inside the ``CapabilityManager``.
    """

    token_id: str
    tenant_id: str
    agent_id: str
    pid: Optional[int]
    # normalized path prefix -> frozenset({"read", "write", "exec"})
    allowed_paths: Mapping[str, FrozenSet[str]]
    allowed_syscalls: FrozenSet[str]
    allowed_network_endpoints: Tuple[Tuple[str, int], ...]
    valid_until: float
    issued_at: float = field(default_factory=time.time)
    is_revoked: bool = False
    signature: str = ""

    def __post_init__(self) -> None:
        # Defensive conversion to immutable containers.  object.__setattr__ is
        # the documented way to initialise fields of a frozen dataclass.
        object.__setattr__(
            self,
            "allowed_paths",
            MappingProxyType({k: frozenset(v) for k, v in dict(self.allowed_paths).items()}),
        )
        object.__setattr__(self, "allowed_syscalls", frozenset(self.allowed_syscalls))
        object.__setattr__(
            self,
            "allowed_network_endpoints",
            tuple((str(h), int(p)) for h, p in self.allowed_network_endpoints),
        )

    def signing_payload(self) -> bytes:
        """Canonical byte representation covered by the HMAC.

        Canonical = sorted keys, sorted collections, no whitespace.  Any
        semantically-identical token always yields identical bytes, and any
        change to a security-relevant field changes the bytes.

        ``signature`` is excluded (it is the output) and ``is_revoked`` is
        excluded because revocation is enforced server side, not by the token.
        """
        body = {
            "token_id": self.token_id,
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "pid": self.pid,
            "allowed_paths": {k: sorted(v) for k, v in sorted(self.allowed_paths.items())},
            "allowed_syscalls": sorted(self.allowed_syscalls),
            "allowed_network_endpoints": sorted([h, p] for h, p in self.allowed_network_endpoints),
            "valid_until": self.valid_until,
            "issued_at": self.issued_at,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def remaining_lifetime(self) -> float:
        """Seconds until expiry (negative if already expired)."""
        return self.valid_until - time.time()

    def short_id(self) -> str:
        """First 8 hex chars of the UUID, for human-readable logs."""
        return self.token_id[:8]


@dataclass(frozen=True)
class TokenValidation:
    """Result of a token validity check."""

    valid: bool
    reason: str


# --------------------------------------------------------------------------- #
# Capability manager -- the trusted issuer and validator
# --------------------------------------------------------------------------- #
class CapabilityManager:
    """Issues, validates, caches and revokes capability tokens.

    Thread-safety: every piece of mutable state is guarded by a single
    re-entrant lock.  Critical sections are tiny dictionary operations, so
    contention stays negligible while giving us linearizable revocation:
    once ``revoke_token`` returns, no subsequent ``validate_token`` call on
    any thread can return ``valid=True`` for that token.
    """

    def __init__(
        self,
        secret_key: Optional[bytes] = None,
        audit_logger: Optional["AuditLogger"] = None,
        default_ttl_seconds: float = 300.0,
    ) -> None:
        # 256-bit key from the OS CSPRNG if the caller does not supply one.
        self._key: bytes = secret_key or secrets.token_bytes(32)
        self._audit = audit_logger
        self._default_ttl = default_ttl_seconds

        self._lock = threading.RLock()
        self._registry: Dict[str, CapabilityToken] = {}   # token_id -> current version
        self._revoked: Set[str] = set()                    # authoritative revocation set
        self._verified_sigs: Dict[str, str] = {}           # token_id -> signature already verified
        self._decision_cache: Dict[CacheKey, bool] = {}    # fast-path policy cache

        # Simple counters, useful in the evaluation report.
        self.cache_hits = 0
        self.cache_misses = 0

    # ------------------------------------------------------------------ #
    # Signing
    # ------------------------------------------------------------------ #
    def _sign(self, token: CapabilityToken) -> str:
        """HMAC-SHA256 over the canonical payload, hex encoded."""
        return hmac.new(self._key, token.signing_payload(), hashlib.sha256).hexdigest()

    def verify_signature(self, token: CapabilityToken) -> bool:
        """Full (uncached) cryptographic verification of a presented token.

        ``hmac.compare_digest`` runs in constant time to avoid leaking how
        many leading characters of a forged signature were correct.
        """
        return hmac.compare_digest(self._sign(token), token.signature)

    # ------------------------------------------------------------------ #
    # Issuance
    # ------------------------------------------------------------------ #
    def issue_token(
        self,
        tenant_id: str,
        agent_id: str,
        allowed_paths: Mapping[str, Iterable[str]],
        allowed_syscalls: Iterable[str],
        allowed_network_endpoints: Iterable[Tuple[str, int]] = (),
        ttl_seconds: Optional[float] = None,
        pid: Optional[int] = None,
    ) -> CapabilityToken:
        """Mint a new signed token granting *only* the listed authority."""
        normalized_paths: Dict[str, FrozenSet[str]] = {}
        for raw_prefix, perms in allowed_paths.items():
            perm_set = frozenset(perms)
            unknown = perm_set - VALID_PERMISSIONS
            if unknown:
                raise ValueError(f"unknown permission(s) {sorted(unknown)} for {raw_prefix!r}")
            # Policy prefixes are canonicalized exactly like requests are.
            normalized_paths[normalize_path(raw_prefix)] = perm_set

        now = time.time()
        unsigned = CapabilityToken(
            token_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            agent_id=agent_id,
            pid=pid,
            allowed_paths=normalized_paths,
            allowed_syscalls=frozenset(allowed_syscalls),
            allowed_network_endpoints=tuple(allowed_network_endpoints),
            valid_until=now + (ttl_seconds if ttl_seconds is not None else self._default_ttl),
            issued_at=now,
        )
        token = replace(unsigned, signature=self._sign(unsigned))

        with self._lock:
            self._registry[token.token_id] = token
            self._verified_sigs[token.token_id] = token.signature

        if self._audit is not None:
            from capllm.core.audit import EventType, Verdict

            self._audit.log_event(
                event_type=EventType.TOKEN_ISSUED,
                tenant_id=tenant_id,
                agent_id=agent_id,
                syscall_name="-",
                target_resource=f"token:{token.short_id()}",
                verdict=Verdict.ALLOW,
                details={
                    "paths": {k: sorted(v) for k, v in token.allowed_paths.items()},
                    "syscalls": sorted(token.allowed_syscalls),
                    "network": [f"{h}:{p}" for h, p in token.allowed_network_endpoints],
                    "ttl_s": round(token.remaining_lifetime(), 3),
                },
            )
        return token

    def bind_pid(self, token_id: str, pid: int) -> CapabilityToken:
        """Bind a token to the OS process that will exercise it, and re-sign.

        PID binding prevents a token from being replayed by a different
        process (token theft / confused deputy): the engine rejects requests
        whose originating PID differs from ``token.pid``.
        """
        with self._lock:
            current = self._registry[token_id]
            rebound = replace(current, pid=pid, signature="")
            rebound = replace(rebound, signature=self._sign(rebound))
            self._registry[token_id] = rebound
            self._verified_sigs[token_id] = rebound.signature
            return rebound

    # ------------------------------------------------------------------ #
    # Validation
    # ------------------------------------------------------------------ #
    def get_token(self, token_id: str) -> Optional[CapabilityToken]:
        """Return the authoritative current version of a token (or None)."""
        with self._lock:
            return self._registry.get(token_id)

    def validate_token(self, token_id: str) -> TokenValidation:
        """Check existence, revocation, signature and lifetime -- in O(1).

        Order matters: revocation is checked first because it is the
        operator's emergency brake and must win over everything else.
        """
        with self._lock:
            token = self._registry.get(token_id)
            if token is None:
                return TokenValidation(False, "unknown token")
            if token_id in self._revoked or token.is_revoked:
                return TokenValidation(False, "token revoked")

            # Signature: the expensive HMAC is computed once per token version;
            # afterwards we only compare against the remembered verified value.
            if self._verified_sigs.get(token_id) != token.signature:
                if not self.verify_signature(token):
                    return TokenValidation(False, "invalid signature (token tampered)")
                self._verified_sigs[token_id] = token.signature

        if time.time() > token.valid_until:
            return TokenValidation(False, "token expired")
        return TokenValidation(True, "ok")

    def validate_presented_token(self, presented: CapabilityToken) -> TokenValidation:
        """Validate a token object received from an untrusted party.

        Unlike ``validate_token`` this never trusts the cache: it recomputes
        the HMAC over the *presented* fields, so a locally modified copy
        (e.g. with widened paths) is detected.
        """
        if not self.verify_signature(presented):
            return TokenValidation(False, "invalid signature (token tampered)")
        return self.validate_token(presented.token_id)

    # ------------------------------------------------------------------ #
    # Policy evaluation (+ fast-path cache)
    # ------------------------------------------------------------------ #
    @staticmethod
    def path_grants(token: CapabilityToken, normalized_path: str, permission: str) -> bool:
        """Does any allowed prefix contain the path *and* grant the permission?"""
        for prefix, perms in token.allowed_paths.items():
            if permission in perms and path_is_within(normalized_path, prefix):
                return True
        return False

    @staticmethod
    def endpoint_granted(token: CapabilityToken, host: str, port: int) -> bool:
        """Exact (host, port) match against the token's network allow-list."""
        return (host, port) in token.allowed_network_endpoints

    def cached_path_decision(
        self, token: CapabilityToken, syscall_name: str, normalized_path: str, permission: str
    ) -> Tuple[bool, bool]:
        """Fast-path policy lookup.

        Returns ``(allowed, was_cache_hit)``.  Only the *static* policy result
        is cached; validity (expiry/revocation) is checked separately by the
        caller on every request, so caching can never extend authority.
        """
        key: CacheKey = (token.token_id, syscall_name, normalized_path, permission)
        with self._lock:
            cached = self._decision_cache.get(key)
            if cached is not None:
                self.cache_hits += 1
                return cached, True
            allowed = syscall_name in token.allowed_syscalls and self.path_grants(
                token, normalized_path, permission
            )
            self._decision_cache[key] = allowed
            self.cache_misses += 1
            return allowed, False

    # ------------------------------------------------------------------ #
    # Revocation
    # ------------------------------------------------------------------ #
    def revoke_token(self, token_id: str, reason: str = "operator request") -> bool:
        """Instantly and permanently invalidate a token.  Thread-safe.

        Returns True if the token existed and was not already revoked.
        """
        with self._lock:
            token = self._registry.get(token_id)
            if token is None or token_id in self._revoked:
                return False
            self._revoked.add(token_id)
            self._registry[token_id] = replace(token, is_revoked=True)
            # Purge cached decisions for hygiene.  (Correctness does not depend
            # on this: validate_token already rejects the revoked token.)
            for key in [k for k in self._decision_cache if k[0] == token_id]:
                del self._decision_cache[key]

        if self._audit is not None:
            from capllm.core.audit import EventType, Verdict

            self._audit.log_event(
                event_type=EventType.TOKEN_REVOKED,
                tenant_id=token.tenant_id,
                agent_id=token.agent_id,
                syscall_name="-",
                target_resource=f"token:{token.short_id()}",
                verdict=Verdict.BLOCK,
                details={"reason": reason},
            )
        return True

    def is_revoked(self, token_id: str) -> bool:
        with self._lock:
            return token_id in self._revoked
