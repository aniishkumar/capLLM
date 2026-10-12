"""
capllm.core.capability_space
============================

Capability Space Manager for CapLLM-Kernel.

This module implements:
1. `CapabilityToken`: Fine-grained, unforgeable authority token scoped by tenant,
   PID / cgroup, filesystem paths, syscalls, network endpoints, and lifetime.
2. `TokenAuthority`: Trusted reference monitor responsible for issuing HMAC-SHA256
   signed tokens, fast-path permission checking, instant revocation, and maintaining
   a tamper-evident SHA-256 hash-chained audit log.

Academic Defense & Viva Notes:
------------------------------
- Architecture: Decentralized authority model based on capability-based addressing
  rather than ambient authority. An agent process only exercises permissions explicitly
  enumerated in its active capability token.
- Integrity: Tokens are cryptographically bound to their tenant and process boundary (PID)
  via HMAC-SHA256. Any modification to permissions or lifetime invalidates the signature.
- Fast Lookup: Static permissions are cached per (tenant, pid, operation, canonical_resource)
  while dynamic checks (revocation set and TTL) execute in O(1) time.
- Tamper Evidence: The audit log uses a cryptographic hash chain:
    H_i = SHA256( canonical_json(entry_i) || H_{i-1} )
  Any tampering, deletion, or re-ordering of audit events is mathematically detectable.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import unittest
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union


# --------------------------------------------------------------------------- #
# Data Structures
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class PathPermission:
    """Represents an allowed filesystem path prefix and its permitted access modes."""
    path: str
    modes: str  # e.g., 'r', 'w', 'rw', 'rwx'

    def allows(self, required_mode: str) -> bool:
        """Check if all required modes ('r', 'w', or 'x') are granted."""
        return all(m in self.modes for m in required_mode)


@dataclass
class CapabilityToken:
    """Unforgeable capability token granting bounded authority to an agent.

    Attributes:
        token_id: Unique UUID identifying this capability token.
        tenant_id: Tenant namespace identifier.
        pid: Bound process ID (or process group / namespace root).
        cgroup_id: Bound Linux cgroup identifier (defaults to pid if not isolated).
        allowed_paths: List of allowed filesystem path prefixes and their modes ('r', 'w', 'rw').
        allowed_syscalls: Set of permitted system call names (e.g. {'openat', 'read', 'write'}).
        allowed_network_endpoints: List of allowed (host/IP, port) tuples.
        valid_until: Unix epoch timestamp when authority expires.
        is_revoked: Revocation flag (authoritatively tracked in TokenAuthority).
        signature: Hex-encoded HMAC-SHA256 signature over canonical token attributes.
        issued_at: Unix epoch timestamp when token was minted.
    """
    token_id: uuid.UUID
    tenant_id: str
    pid: int
    cgroup_id: int
    allowed_paths: List[PathPermission]
    allowed_syscalls: Set[str]
    allowed_network_endpoints: List[Tuple[str, int]]
    valid_until: float
    is_revoked: bool = False
    signature: str = ""
    issued_at: float = field(default_factory=time.time)

    def canonical_payload(self) -> bytes:
        """Serializes token attributes deterministically for HMAC signing."""
        sorted_paths = sorted([{"path": p.path, "modes": "".join(sorted(set(p.modes)))} for p in self.allowed_paths],
                              key=lambda x: x["path"])
        payload = {
            "token_id": str(self.token_id),
            "tenant_id": self.tenant_id,
            "pid": self.pid,
            "cgroup_id": self.cgroup_id,
            "allowed_paths": sorted_paths,
            "allowed_syscalls": sorted(list(self.allowed_syscalls)),
            "allowed_network_endpoints": sorted([[h, p] for h, p in self.allowed_network_endpoints]),
            "valid_until": round(self.valid_until, 6),
            "issued_at": round(self.issued_at, 6),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class AuditAction(str, Enum):
    TOKEN_ISSUED = "TOKEN_ISSUED"
    TOKEN_REVOKED = "TOKEN_REVOKED"
    ACCESS_ALLOWED = "ACCESS_ALLOWED"
    ACCESS_DENIED = "ACCESS_DENIED"


@dataclass(frozen=True)
class AuditEntry:
    """Tamper-evident audit record linked to the previous entry via SHA-256 hash."""
    sequence: int
    entry_id: str
    timestamp: float
    action: AuditAction
    tenant_id: str
    pid: int
    operation: str
    resource: str
    verdict: str  # "ALLOW" or "BLOCK"
    reason: str
    previous_hash: str
    entry_hash: str

    @classmethod
    def create(
        cls,
        sequence: int,
        action: AuditAction,
        tenant_id: str,
        pid: int,
        operation: str,
        resource: str,
        verdict: str,
        reason: str,
        previous_hash: str,
    ) -> "AuditEntry":
        entry_id = str(uuid.uuid4())
        ts = time.time()
        
        # Canonical representation excluding entry_hash itself
        body = {
            "sequence": sequence,
            "entry_id": entry_id,
            "timestamp": ts,
            "action": action.value,
            "tenant_id": tenant_id,
            "pid": pid,
            "operation": operation,
            "resource": resource,
            "verdict": verdict,
            "reason": reason,
            "previous_hash": previous_hash,
        }
        canonical_bytes = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        entry_hash = hashlib.sha256(canonical_bytes).hexdigest()
        
        return cls(
            sequence=sequence,
            entry_id=entry_id,
            timestamp=ts,
            action=action,
            tenant_id=tenant_id,
            pid=pid,
            operation=operation,
            resource=resource,
            verdict=verdict,
            reason=reason,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )

    def verify_hash(self) -> bool:
        """Recompute and verify SHA-256 hash integrity of this record."""
        body = {
            "sequence": self.sequence,
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "action": self.action.value,
            "tenant_id": self.tenant_id,
            "pid": self.pid,
            "operation": self.operation,
            "resource": self.resource,
            "verdict": self.verdict,
            "reason": self.reason,
            "previous_hash": self.previous_hash,
        }
        canonical_bytes = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest() == self.entry_hash


# --------------------------------------------------------------------------- #
# Path Helpers
# --------------------------------------------------------------------------- #

def canonicalize_path(target_path: str, cwd: Optional[str] = None) -> str:
    """Resolves symlinks, traverses '..', and normalizes path casing for uniform comparison."""
    if not os.path.isabs(target_path):
        target_path = os.path.join(cwd or os.getcwd(), target_path)
    return os.path.normcase(os.path.realpath(os.path.abspath(target_path)))


def is_subpath(candidate: str, allowed_prefix: str) -> bool:
    """Checks if candidate path is equal to or contained within allowed_prefix."""
    try:
        common = os.path.commonpath([candidate, allowed_prefix])
        return common == allowed_prefix
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Token Authority (Reference Monitor)
# --------------------------------------------------------------------------- #

class TokenAuthority:
    """The central reference monitor in CapLLM-Kernel.

    Responsibilities:
    1. Issues HMAC-signed capability tokens with cryptographic integrity.
    2. Fast-path lookup for check_permission(tenant_id, pid, operation, resource).
    3. Thread-safe instant revocation of capabilities.
    4. Tamper-evident, append-only in-memory audit logger with SHA-256 chain verification.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, hmac_key: Optional[bytes] = None) -> None:
        self._secret_key: bytes = hmac_key or secrets.token_bytes(32)
        self._lock = threading.RLock()
        
        # Primary storage: token_id -> CapabilityToken
        self._tokens: Dict[uuid.UUID, CapabilityToken] = {}
        
        # Process binding map: (tenant_id, pid) -> token_id
        self._proc_tokens: Dict[Tuple[str, int], uuid.UUID] = {}
        
        # Authoritative revocation set
        self._revoked_tokens: Set[uuid.UUID] = set()
        
        # Fast permission lookup cache:
        # Key: (tenant_id, pid, operation, canonical_resource, required_mode) -> bool
        self._permission_cache: Dict[Tuple[str, int, str, str, str], bool] = {}
        
        # Append-only hash-chained audit log
        self._audit_log: List[AuditEntry] = []
        self._head_hash: str = self.GENESIS_HASH

    # ----------------------------------------------------------------------- #
    # Cryptographic Operations
    # ----------------------------------------------------------------------- #
    def _sign_token(self, token: CapabilityToken) -> str:
        """Generate HMAC-SHA256 signature for a token."""
        return hmac.new(self._secret_key, token.canonical_payload(), hashlib.sha256).hexdigest()

    def verify_token_signature(self, token: CapabilityToken) -> bool:
        """Constant-time verification of token HMAC signature."""
        expected = self._sign_token(token)
        return hmac.compare_digest(expected, token.signature)

    # ----------------------------------------------------------------------- #
    # Audit Logger
    # ----------------------------------------------------------------------- #
    def _append_audit(
        self,
        action: AuditAction,
        tenant_id: str,
        pid: int,
        operation: str,
        resource: str,
        verdict: str,
        reason: str,
    ) -> AuditEntry:
        """Append an event to the tamper-evident hash chain (caller holds lock)."""
        entry = AuditEntry.create(
            sequence=len(self._audit_log),
            action=action,
            tenant_id=tenant_id,
            pid=pid,
            operation=operation,
            resource=resource,
            verdict=verdict,
            reason=reason,
            previous_hash=self._head_hash,
        )
        self._audit_log.append(entry)
        self._head_hash = entry.entry_hash
        return entry

    def verify_audit_log(self) -> Tuple[bool, Optional[int], str]:
        """Mathematically verifies the integrity of the audit hash chain.

        Returns:
            (is_valid, first_invalid_sequence_index, reason)
        """
        with self._lock:
            expected_prev = self.GENESIS_HASH
            for idx, entry in enumerate(self._audit_log):
                if entry.previous_hash != expected_prev:
                    return False, idx, f"Broken link: previous_hash mismatch at index {idx}"
                if not entry.verify_hash():
                    return False, idx, f"Integrity failure: content hash mismatch at index {idx}"
                expected_prev = entry.entry_hash
            return True, None, "Audit chain intact and verified"

    def get_audit_log(self) -> List[AuditEntry]:
        """Returns a snapshot of the audit entries."""
        with self._lock:
            return list(self._audit_log)

    # ----------------------------------------------------------------------- #
    # Token Issuance
    # ----------------------------------------------------------------------- #
    def issue_token(
        self,
        tenant_id: str,
        pid: int,
        allowed_paths: List[Union[PathPermission, Tuple[str, str], Dict[str, str]]],
        allowed_syscalls: Set[str],
        allowed_network_endpoints: List[Tuple[str, int]],
        ttl_seconds: float = 300.0,
        cgroup_id: Optional[int] = None,
    ) -> CapabilityToken:
        """Issues an HMAC-signed capability token bound to a tenant and process.

        Args:
            tenant_id: Tenant namespace.
            pid: Bound process ID.
            allowed_paths: Paths with permitted modes (e.g. [('/workspace', 'rw')]).
            allowed_syscalls: Allowed syscall names.
            allowed_network_endpoints: Allowed (host, port) network tuples.
            ttl_seconds: Lifetime in seconds from now.
            cgroup_id: Optional cgroup ID (defaults to pid).
        """
        token_id = uuid.uuid4()
        now = time.time()
        valid_until = now + ttl_seconds
        cg_id = cgroup_id if cgroup_id is not None else pid

        normalized_paths: List[PathPermission] = []
        for p in allowed_paths:
            if isinstance(p, PathPermission):
                normalized_paths.append(PathPermission(canonicalize_path(p.path), p.modes))
            elif isinstance(p, tuple):
                normalized_paths.append(PathPermission(canonicalize_path(p[0]), p[1]))
            elif isinstance(p, dict):
                normalized_paths.append(PathPermission(canonicalize_path(p["path"]), p.get("modes", "r")))

        token = CapabilityToken(
            token_id=token_id,
            tenant_id=tenant_id,
            pid=pid,
            cgroup_id=cg_id,
            allowed_paths=normalized_paths,
            allowed_syscalls=set(allowed_syscalls),
            allowed_network_endpoints=list(allowed_network_endpoints),
            valid_until=valid_until,
            is_revoked=False,
            issued_at=now,
        )
        token.signature = self._sign_token(token)

        with self._lock:
            self._tokens[token_id] = token
            self._proc_tokens[(tenant_id, pid)] = token_id
            self._append_audit(
                action=AuditAction.TOKEN_ISSUED,
                tenant_id=tenant_id,
                pid=pid,
                operation="ISSUE",
                resource=str(token_id),
                verdict="ALLOW",
                reason=f"Issued token valid for {ttl_seconds:.1f}s",
            )

        return token

    # ----------------------------------------------------------------------- #
    # Revocation
    # ----------------------------------------------------------------------- #
    def revoke_token(self, token_id: Union[uuid.UUID, str], reason: str = "operator revocation") -> bool:
        """Instantly revokes a capability token and invalidates cached permissions.

        Returns:
            True if token was active and is now revoked; False if token was unknown or already revoked.
        """
        if isinstance(token_id, str):
            token_id = uuid.UUID(token_id)

        with self._lock:
            token = self._tokens.get(token_id)
            if token is None or token_id in self._revoked_tokens or token.is_revoked:
                return False

            # Authoritatively mark as revoked
            token.is_revoked = True
            self._revoked_tokens.add(token_id)

            # Invalidate any cache entries associated with this tenant/pid
            cached_keys_to_delete = [
                k for k in self._permission_cache.keys()
                if k[0] == token.tenant_id and k[1] == token.pid
            ]
            for k in cached_keys_to_delete:
                del self._permission_cache[k]

            # Audit revocation
            self._append_audit(
                action=AuditAction.TOKEN_REVOKED,
                tenant_id=token.tenant_id,
                pid=token.pid,
                operation="REVOKE",
                resource=str(token_id),
                verdict="BLOCK",
                reason=reason,
            )
            return True

    # ----------------------------------------------------------------------- #
    # Fast-Path Permission Evaluation
    # ----------------------------------------------------------------------- #
    def check_permission(
        self,
        tenant_id: str,
        pid: int,
        operation: str,
        resource: str,
        mode: str = "r",
    ) -> bool:
        """Evaluates whether an agent has authorization to perform an operation on a resource.

        Supported Operations:
        - Filesystem / Syscalls: 'read', 'write', 'openat', 'unlinkat', 'execve', etc.
        - Network: 'connect', 'bind' with resource formatted as 'host:port' or (host, port).

        Fast-Path Evaluation Flow:
        1. Look up token by (tenant_id, pid).
        2. Validate dynamic invariants: revocation status, expiry TTL, cryptographic signature.
        3. Consult in-memory fast-lookup cache.
        4. On cache miss: evaluate capability scope (path permissions, syscall whitelist, network).
        5. Log verdict to tamper-evident audit log.
        """
        now = time.time()
        op_lower = operation.lower()

        with self._lock:
            token_id = self._proc_tokens.get((tenant_id, pid))
            if token_id is None:
                self._append_audit(
                    AuditAction.ACCESS_DENIED, tenant_id, pid, operation, resource, "BLOCK",
                    "No capability token bound to process"
                )
                return False

            token = self._tokens.get(token_id)
            if token is None:
                self._append_audit(
                    AuditAction.ACCESS_DENIED, tenant_id, pid, operation, resource, "BLOCK",
                    "Capability token not found in registry"
                )
                return False

            # Check Revocation
            if token.is_revoked or token_id in self._revoked_tokens:
                self._append_audit(
                    AuditAction.ACCESS_DENIED, tenant_id, pid, operation, resource, "BLOCK",
                    "Capability token is revoked"
                )
                return False

            # Check Expiry
            if now > token.valid_until:
                self._append_audit(
                    AuditAction.ACCESS_DENIED, tenant_id, pid, operation, resource, "BLOCK",
                    f"Capability token expired at {token.valid_until:.1f} (current: {now:.1f})"
                )
                return False

            # Cryptographic Signature Verification
            if not self.verify_token_signature(token):
                self._append_audit(
                    AuditAction.ACCESS_DENIED, tenant_id, pid, operation, resource, "BLOCK",
                    "Token signature verification failed (tampered token)"
                )
                return False

            # Canonicalize resource if path
            norm_res = resource
            if op_lower in {"open", "openat", "read", "write", "execve", "unlink", "unlinkat", "mkdir", "mkdirat"}:
                norm_res = canonicalize_path(resource)

            cache_key = (tenant_id, pid, op_lower, norm_res, mode)
            if cache_key in self._permission_cache:
                allowed = self._permission_cache[cache_key]
                if not allowed:
                    self._append_audit(
                        AuditAction.ACCESS_DENIED, tenant_id, pid, operation, resource, "BLOCK",
                        "Denied (cached decision)"
                    )
                return allowed

            # Evaluate Policy Scope
            allowed, reason = self._evaluate_policy(token, op_lower, norm_res, mode)
            self._permission_cache[cache_key] = allowed

            if allowed:
                self._append_audit(
                    AuditAction.ACCESS_ALLOWED, tenant_id, pid, operation, resource, "ALLOW", reason
                )
            else:
                self._append_audit(
                    AuditAction.ACCESS_DENIED, tenant_id, pid, operation, resource, "BLOCK", reason
                )
            return allowed

    def _evaluate_policy(
        self,
        token: CapabilityToken,
        operation: str,
        resource: str,
        mode: str,
    ) -> Tuple[bool, str]:
        """Evaluates whether the token's allowed scopes grant the requested operation."""
        # 1. Syscall Check
        # Map high-level operations to typical underlying syscall names
        syscall_mapping = {
            "read": "read",
            "write": "write",
            "open": "openat",
            "openat": "openat",
            "exec": "execve",
            "execve": "execve",
            "connect": "connect",
            "bind": "bind",
        }
        relevant_syscall = syscall_mapping.get(operation, operation)
        if relevant_syscall not in token.allowed_syscalls:
            return False, f"Syscall '{relevant_syscall}' not permitted by capability"

        # 2. Network Endpoint Check
        if operation in {"connect", "bind"}:
            try:
                if ":" in resource:
                    host, port_str = resource.split(":", 1)
                    port = int(port_str)
                else:
                    return False, f"Malformed network endpoint format '{resource}', expected 'host:port'"
            except ValueError:
                return False, f"Invalid port in network endpoint '{resource}'"

            for allowed_host, allowed_port in token.allowed_network_endpoints:
                if allowed_host == host and (allowed_port == port or allowed_port == 0):
                    return True, f"Network access granted to {host}:{port}"
            return False, f"Network endpoint {host}:{port} not in allow-list"

        # 3. Path Permission Check
        # If the operation operates on filesystem paths
        if operation in {"read", "write", "open", "openat", "exec", "execve", "unlink", "unlinkat"}:
            for path_perm in token.allowed_paths:
                if is_subpath(resource, path_perm.path):
                    req_mode = "w" if operation == "write" else mode
                    if operation in {"exec", "execve"}:
                        req_mode = "x"
                    if path_perm.allows(req_mode):
                        return True, f"Path access granted for {resource} with mode '{req_mode}'"
                    return False, f"Path {resource} matches prefix but lacks mode '{req_mode}' (has '{path_perm.modes}')"
            return False, f"Path '{resource}' not within any permitted capability prefix"

        # Default fallback for standalone syscalls with no path/net resource constraints
        return True, f"Operation '{operation}' permitted"


# --------------------------------------------------------------------------- #
# Standalone Unit Tests
# --------------------------------------------------------------------------- #

class TestCapabilitySpace(unittest.TestCase):
    """Self-contained test suite validating token issuance, expiry, scope violation,

    revocation, and audit log tamper detection.
    """

    def setUp(self) -> None:
        self.auth = TokenAuthority()
        self.workspace = canonicalize_path("./test_sandbox_workspace")
        self.os_etc = canonicalize_path("/etc" if os.name != "nt" else "C:\\Windows")

    def test_issuance_and_signature(self) -> None:
        """Validates that newly issued tokens have valid HMAC-SHA256 signatures."""
        token = self.auth.issue_token(
            tenant_id="tenant_alpha",
            pid=1001,
            allowed_paths=[(self.workspace, "rw")],
            allowed_syscalls={"openat", "read", "write"},
            allowed_network_endpoints=[("127.0.0.1", 8080)],
            ttl_seconds=60.0,
        )
        self.assertIsNotNone(token.token_id)
        self.assertTrue(self.auth.verify_token_signature(token))
        self.assertFalse(token.is_revoked)

    def test_permission_allow(self) -> None:
        """Validates that in-scope benign access is permitted."""
        self.auth.issue_token(
            tenant_id="tenant_alpha",
            pid=1002,
            allowed_paths=[(self.workspace, "rw")],
            allowed_syscalls={"openat", "read", "write"},
            allowed_network_endpoints=[("127.0.0.1", 8080)],
        )
        test_file = os.path.join(self.workspace, "data.txt")
        # Read check
        self.assertTrue(self.auth.check_permission("tenant_alpha", 1002, "openat", test_file, mode="r"))
        # Write check
        self.assertTrue(self.auth.check_permission("tenant_alpha", 1002, "write", test_file, mode="w"))

    def test_scope_violation_path(self) -> None:
        """Validates that unauthorized paths or directory escapes are denied."""
        self.auth.issue_token(
            tenant_id="tenant_beta",
            pid=1003,
            allowed_paths=[(self.workspace, "r")],  # Read-only
            allowed_syscalls={"openat", "read", "write"},
            allowed_network_endpoints=[],
        )
        # Attempt to access sensitive system directory
        system_file = os.path.join(self.os_etc, "passwd" if os.name != "nt" else "win.ini")
        self.assertFalse(self.auth.check_permission("tenant_beta", 1003, "openat", system_file, mode="r"))

        # Attempt to write to read-only workspace
        test_file = os.path.join(self.workspace, "data.txt")
        self.assertFalse(self.auth.check_permission("tenant_beta", 1003, "write", test_file, mode="w"))

        # Traversal sequence '../'
        traversal = os.path.join(self.workspace, "..", "secret.txt")
        self.assertFalse(self.auth.check_permission("tenant_beta", 1003, "openat", traversal, mode="r"))

    def test_scope_violation_syscall(self) -> None:
        """Validates that system calls outside the whitelist are blocked."""
        self.auth.issue_token(
            tenant_id="tenant_gamma",
            pid=1004,
            allowed_paths=[(self.workspace, "r")],
            allowed_syscalls={"openat", "read"},  # No execve
            allowed_network_endpoints=[],
        )
        binary = os.path.join(self.workspace, "tool.bin")
        self.assertFalse(self.auth.check_permission("tenant_gamma", 1004, "execve", binary))

    def test_scope_violation_network(self) -> None:
        """Validates that network requests to unauthorized endpoints are blocked."""
        self.auth.issue_token(
            tenant_id="tenant_delta",
            pid=1005,
            allowed_paths=[(self.workspace, "rw")],
            allowed_syscalls={"connect"},
            allowed_network_endpoints=[("127.0.0.1", 443)],
        )
        # Permitted endpoint
        self.assertTrue(self.auth.check_permission("tenant_delta", 1005, "connect", "127.0.0.1:443"))
        # Exfiltration attempt to unauthorized port / host
        self.assertFalse(self.auth.check_permission("tenant_delta", 1005, "connect", "203.0.113.5:80"))
        self.assertFalse(self.auth.check_permission("tenant_delta", 1005, "connect", "127.0.0.1:22"))

    def test_expiry(self) -> None:
        """Validates that tokens automatically invalidate when their TTL expires."""
        token = self.auth.issue_token(
            tenant_id="tenant_ephemeral",
            pid=1006,
            allowed_paths=[(self.workspace, "r")],
            allowed_syscalls={"openat", "read"},
            allowed_network_endpoints=[],
            ttl_seconds=0.05,  # 50 milliseconds
        )
        test_file = os.path.join(self.workspace, "data.txt")
        self.assertTrue(self.auth.check_permission("tenant_ephemeral", 1006, "openat", test_file))
        time.sleep(0.08)
        self.assertFalse(self.auth.check_permission("tenant_ephemeral", 1006, "openat", test_file))

    def test_revocation(self) -> None:
        """Validates that instant revocation takes immediate effect and invalidates cache."""
        token = self.auth.issue_token(
            tenant_id="tenant_rev",
            pid=1007,
            allowed_paths=[(self.workspace, "rw")],
            allowed_syscalls={"openat", "read"},
            allowed_network_endpoints=[],
            ttl_seconds=300.0,
        )
        test_file = os.path.join(self.workspace, "data.txt")
        # Warm the lookup cache
        self.assertTrue(self.auth.check_permission("tenant_rev", 1007, "openat", test_file))

        # Revoke token instantly
        self.assertTrue(self.auth.revoke_token(token.token_id, reason="Security anomaly"))

        # Subsequent check must immediately fail
        self.assertFalse(self.auth.check_permission("tenant_rev", 1007, "openat", test_file))

    def test_audit_chain_tamper_evident(self) -> None:
        """Validates that modifying or tampering with an audit record breaks hash verification."""
        self.auth.issue_token(
            tenant_id="tenant_audit",
            pid=1008,
            allowed_paths=[(self.workspace, "r")],
            allowed_syscalls={"openat"},
            allowed_network_endpoints=[],
        )
        test_file = os.path.join(self.workspace, "data.txt")
        self.auth.check_permission("tenant_audit", 1008, "openat", test_file)
        self.auth.check_permission("tenant_audit", 1008, "openat", "/unauthorized/path")

        # Live audit log must verify intact
        valid, idx, msg = self.auth.verify_audit_log()
        self.assertTrue(valid, msg)

        # Simulate attacker tampering with audit log entry
        entries = self.auth.get_audit_log()
        self.assertGreater(len(entries), 2)
        
        # Tamper entry #1 verdict from ALLOW to BLOCK
        tampered_entry = dataclasses.replace(entries[1], verdict="BLOCK")
        self.auth._audit_log[1] = tampered_entry

        # Chain verification must now detect tampering
        valid_after_tamper, bad_idx, err_msg = self.auth.verify_audit_log()
        self.assertFalse(valid_after_tamper)
        self.assertEqual(bad_idx, 1)
        self.assertIn("Integrity failure", err_msg)


if __name__ == "__main__":
    unittest.main()
