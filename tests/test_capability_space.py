"""
Tests for Capability Space backward compatibility wrapper.
"""

from __future__ import annotations

import dataclasses
import os
import time
import unittest

from capllm.core.audit import AuditLogger
from capllm.core.capability_space import (
    PathPermission,
    TokenAuthority,
    canonicalize_path,
)


class TestCapabilitySpace(unittest.TestCase):
    """Validates that the backward-compatibility TokenAuthority API functions correctly."""

    def setUp(self) -> None:
        self.audit = AuditLogger()
        self.auth = TokenAuthority(audit_logger=self.audit)
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
        self.assertTrue(self.auth.check_permission("tenant_alpha", 1002, "openat", test_file, mode="r"))
        self.assertTrue(self.auth.check_permission("tenant_alpha", 1002, "write", test_file, mode="w"))

    def test_scope_violation_path(self) -> None:
        """Validates that unauthorized paths or directory escapes are denied."""
        self.auth.issue_token(
            tenant_id="tenant_beta",
            pid=1003,
            allowed_paths=[(self.workspace, "r")],
            allowed_syscalls={"openat", "read", "write"},
            allowed_network_endpoints=[],
        )
        system_file = os.path.join(self.os_etc, "passwd" if os.name != "nt" else "win.ini")
        self.assertFalse(self.auth.check_permission("tenant_beta", 1003, "openat", system_file, mode="r"))

        test_file = os.path.join(self.workspace, "data.txt")
        self.assertFalse(self.auth.check_permission("tenant_beta", 1003, "write", test_file, mode="w"))

        traversal = os.path.join(self.workspace, "..", "secret.txt")
        self.assertFalse(self.auth.check_permission("tenant_beta", 1003, "openat", traversal, mode="r"))

    def test_scope_violation_syscall(self) -> None:
        """Validates that system calls outside the whitelist are blocked."""
        self.auth.issue_token(
            tenant_id="tenant_gamma",
            pid=1004,
            allowed_paths=[(self.workspace, "r")],
            allowed_syscalls={"openat", "read"},
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
        self.assertTrue(self.auth.check_permission("tenant_delta", 1005, "connect", "127.0.0.1:443"))
        self.assertFalse(self.auth.check_permission("tenant_delta", 1005, "connect", "203.0.113.5:80"))
        self.assertFalse(self.auth.check_permission("tenant_delta", 1005, "connect", "127.0.0.1:22"))

    def test_expiry(self) -> None:
        """Validates that tokens automatically invalidate when their TTL expires."""
        self.auth.issue_token(
            tenant_id="tenant_ephemeral",
            pid=1006,
            allowed_paths=[(self.workspace, "r")],
            allowed_syscalls={"openat", "read"},
            allowed_network_endpoints=[],
            ttl_seconds=0.05,
        )
        test_file = os.path.join(self.workspace, "data.txt")
        self.assertTrue(self.auth.check_permission("tenant_ephemeral", 1006, "openat", test_file))
        time.sleep(0.08)
        self.assertFalse(self.auth.check_permission("tenant_ephemeral", 1006, "openat", test_file))

    def test_revocation(self) -> None:
        """Validates that instant revocation takes immediate effect."""
        token = self.auth.issue_token(
            tenant_id="tenant_rev",
            pid=1007,
            allowed_paths=[(self.workspace, "rw")],
            allowed_syscalls={"openat", "read"},
            allowed_network_endpoints=[],
            ttl_seconds=300.0,
        )
        test_file = os.path.join(self.workspace, "data.txt")
        self.assertTrue(self.auth.check_permission("tenant_rev", 1007, "openat", test_file))

        self.assertTrue(self.auth.revoke_token(token.token_id, reason="Security anomaly"))
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

        valid, idx, msg = self.auth.verify_audit_log()
        self.assertTrue(valid, msg)

        # Simulate attacker tampering with audit log entry
        entries = list(self.auth.get_audit_log())
        self.assertGreater(len(entries), 2)

        # Tamper entry #1 verdict
        tampered_entry = dataclasses.replace(entries[1], verdict="BLOCK")
        self.auth._audit._events[1] = tampered_entry

        valid_after_tamper, bad_idx, err_msg = self.auth.verify_audit_log()
        self.assertFalse(valid_after_tamper)
        self.assertEqual(bad_idx, 1)
        self.assertIn("content hash mismatch", err_msg)

    def test_legacy_positional_issue_token_and_check_permission(self) -> None:
        """Validates that legacy callers passing arguments positionally without keywords succeed."""
        # Former signature: (tenant_id, pid, allowed_paths, allowed_syscalls, allowed_network_endpoints, ttl_seconds, cgroup_id)
        token = self.auth.issue_token(
            "tenant_pos",
            7777,
            [(self.workspace, "rw")],
            {"openat", "read", "write", "connect"},
            [("127.0.0.1", 9000)],
            120.0,
            7777,
        )
        self.assertEqual(token.tenant_id, "tenant_pos")
        self.assertEqual(token.pid, 7777)
        self.assertTrue(self.auth.verify_token_signature(token))

        # Check permission using bound PID
        test_file = os.path.join(self.workspace, "pos_data.txt")
        self.assertTrue(self.auth.check_permission("tenant_pos", 7777, "openat", test_file, mode="r"))
        self.assertTrue(self.auth.check_permission("tenant_pos", 7777, "write", test_file, mode="w"))
        self.assertTrue(self.auth.check_permission("tenant_pos", 7777, "connect", "127.0.0.1:9000"))

        # Unbound foreign PID must fail
        self.assertFalse(self.auth.check_permission("tenant_pos", 8888, "openat", test_file, mode="r"))


if __name__ == "__main__":
    unittest.main()
