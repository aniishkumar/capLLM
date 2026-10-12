"""
Unit tests for CapLLM canonical capability tokens and CapabilityManager.
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from dataclasses import replace

from capllm.core.capability import (
    CapabilityManager,
    CapabilityToken,
    PathPermission,
    normalize_path,
    path_is_within,
)


class TestCapabilityTokenAndManager(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = normalize_path(self.temp_dir.name)
        self.mgr = CapabilityManager()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_token_issue_and_signature(self) -> None:
        """Token issuance creates an immutable token with a valid HMAC-SHA256 signature."""
        token = self.mgr.issue_token(
            tenant_id="tenant_alpha",
            agent_id="agent_1",
            allowed_paths={self.workspace: {"read", "write"}},
            allowed_syscalls={"openat", "read", "write"},
            allowed_network_endpoints=[("127.0.0.1", 8080)],
            ttl_seconds=60.0,
            pid=1234,
            cgroup_id=1234,
        )
        self.assertIsInstance(token.token_id, str)
        self.assertEqual(token.tenant_id, "tenant_alpha")
        self.assertEqual(token.agent_id, "agent_1")
        self.assertEqual(token.pid, 1234)
        self.assertEqual(token.cgroup_id, 1234)
        self.assertTrue(self.mgr.verify_signature(token))
        self.assertFalse(token.is_revoked)

        # Token immutability: attempting to mutate attributes must raise FrozenInstanceError
        with self.assertRaises(Exception):
            token.is_revoked = True  # type: ignore

    def test_tampered_token_rejected(self) -> None:
        """Tampering with any security-relevant field invalidates the HMAC signature."""
        token = self.mgr.issue_token(
            tenant_id="tenant_alpha",
            agent_id="agent_1",
            allowed_paths={self.workspace: {"read"}},
            allowed_syscalls={"openat", "read"},
            allowed_network_endpoints=[("127.0.0.1", 8080)],
            ttl_seconds=60.0,
        )
        self.assertTrue(self.mgr.verify_signature(token))

        # Attacker attempts to widen allowed_paths
        widened_paths = {**token.allowed_paths, normalize_path("/"): frozenset({"read", "write"})}
        tampered_paths = replace(token, allowed_paths=widened_paths)
        v = self.mgr.validate_presented_token(tampered_paths)
        self.assertFalse(v.valid)
        self.assertIn("tampered", v.reason)

        # Attacker attempts to add syscall
        tampered_syscalls = replace(token, allowed_syscalls=frozenset({"openat", "read", "execve"}))
        v2 = self.mgr.validate_presented_token(tampered_syscalls)
        self.assertFalse(v2.valid)

        # Attacker attempts to extend TTL
        tampered_ttl = replace(token, valid_until=token.valid_until + 10000.0)
        v3 = self.mgr.validate_presented_token(tampered_ttl)
        self.assertFalse(v3.valid)

    def test_pid_binding(self) -> None:
        """Binding a token to a process updates the process map and re-signs the token."""
        token = self.mgr.issue_token(
            tenant_id="tenant_alpha",
            agent_id="agent_1",
            allowed_paths={self.workspace: {"read"}},
            allowed_syscalls={"openat", "read"},
        )
        self.assertIsNone(token.pid)

        rebound = self.mgr.bind_pid(token.token_id, pid=9999)
        self.assertEqual(rebound.pid, 9999)
        self.assertTrue(self.mgr.verify_signature(rebound))

        # Check permission for the bound process
        test_file = os.path.join(self.workspace, "test.txt")
        self.assertTrue(self.mgr.check_permission("tenant_alpha", 9999, "openat", test_file, mode="r"))

        # Check permission for an unbound foreign process must fail
        self.assertFalse(self.mgr.check_permission("tenant_alpha", 8888, "openat", test_file, mode="r"))

    def test_token_expiry(self) -> None:
        """Expired tokens fail validation immediately."""
        token = self.mgr.issue_token(
            tenant_id="tenant_alpha",
            agent_id="agent_1",
            allowed_paths={self.workspace: {"read"}},
            allowed_syscalls={"openat", "read"},
            ttl_seconds=0.05,
            pid=1111,
        )
        test_file = os.path.join(self.workspace, "test.txt")
        self.assertTrue(self.mgr.check_permission("tenant_alpha", 1111, "openat", test_file, mode="r"))

        time.sleep(0.08)
        v = self.mgr.validate_token(token.token_id)
        self.assertFalse(v.valid)
        self.assertIn("expired", v.reason)
        self.assertFalse(self.mgr.check_permission("tenant_alpha", 1111, "openat", test_file, mode="r"))

    def test_dynamic_revocation(self) -> None:
        """Revocation is immediate, permanent, and invalidates authority."""
        token = self.mgr.issue_token(
            tenant_id="tenant_alpha",
            agent_id="agent_1",
            allowed_paths={self.workspace: {"read", "write"}},
            allowed_syscalls={"openat", "write"},
            pid=2222,
        )
        test_file = os.path.join(self.workspace, "test.txt")
        self.assertTrue(self.mgr.check_permission("tenant_alpha", 2222, "openat", test_file, mode="w"))

        revoked = self.mgr.revoke_token(token.token_id, reason="Security alert")
        self.assertTrue(revoked)
        self.assertTrue(self.mgr.is_revoked(token.token_id))

        v = self.mgr.validate_token(token.token_id)
        self.assertFalse(v.valid)
        self.assertIn("revoked", v.reason)
        self.assertFalse(self.mgr.check_permission("tenant_alpha", 2222, "openat", test_file, mode="w"))

    def test_path_boundary_and_normalization(self) -> None:
        """Path normalization defeats directory traversal and prefix collisions."""
        # Normalize handles relative paths and '..'
        norm = normalize_path("foo/../bar", cwd=self.workspace)
        expected = os.path.normcase(os.path.join(self.workspace, "bar"))
        self.assertEqual(norm, expected)

        # path_is_within avoids naive prefix substring false positives
        prefix = normalize_path(os.path.join(self.workspace, "tenant_a"))
        inside = normalize_path(os.path.join(self.workspace, "tenant_a", "file.txt"))
        outside_colliding = normalize_path(os.path.join(self.workspace, "tenant_a_evil", "file.txt"))

        self.assertTrue(path_is_within(inside, prefix))
        self.assertFalse(path_is_within(outside_colliding, prefix))

    def test_endpoint_and_syscall_allow_deny(self) -> None:
        """Permission checks enforce syscall and endpoint allow-lists."""
        self.mgr.issue_token(
            tenant_id="tenant_net",
            agent_id="agent_net",
            allowed_paths={self.workspace: {"read"}},
            allowed_syscalls={"openat", "connect"},
            allowed_network_endpoints=[("127.0.0.1", 8080), ("api.local", 443)],
            pid=3333,
        )
        # Permitted endpoints
        self.assertTrue(self.mgr.check_permission("tenant_net", 3333, "connect", "127.0.0.1:8080"))
        self.assertTrue(self.mgr.check_permission("tenant_net", 3333, "connect", "api.local:443"))

        # Forbidden endpoints
        self.assertFalse(self.mgr.check_permission("tenant_net", 3333, "connect", "127.0.0.1:22"))
        self.assertFalse(self.mgr.check_permission("tenant_net", 3333, "connect", "malicious.com:80"))

        # Unpermitted syscall (execve is not in allowed_syscalls)
        self.assertFalse(self.mgr.check_permission("tenant_net", 3333, "execve", "/bin/sh", mode="x"))

    def test_decision_cache_invalidation_after_revocation(self) -> None:
        """Revocation purges fast-path cached decisions and denies subsequent requests."""
        token = self.mgr.issue_token(
            tenant_id="tenant_cache",
            agent_id="agent_cache",
            allowed_paths=[PathPermission(self.workspace, "rw")],
            allowed_syscalls={"openat", "read"},
            pid=4444,
        )
        test_file = os.path.join(self.workspace, "cache_target.txt")

        # First call is a cache miss
        initial_hits = self.mgr.cache_hits
        initial_misses = self.mgr.cache_misses
        self.assertTrue(self.mgr.check_permission("tenant_cache", 4444, "openat", test_file, mode="r"))
        self.assertEqual(self.mgr.cache_misses, initial_misses + 1)

        # Second call hits the decision cache
        self.assertTrue(self.mgr.check_permission("tenant_cache", 4444, "openat", test_file, mode="r"))
        self.assertEqual(self.mgr.cache_hits, initial_hits + 1)

        # Revoke the token: must clear decision cache entries for this token
        self.mgr.revoke_token(token.token_id)
        cache_keys_for_token = [k for k in self.mgr._decision_cache if k[0] == token.token_id]
        self.assertEqual(len(cache_keys_for_token), 0)

        # Subsequent check must be blocked
        self.assertFalse(self.mgr.check_permission("tenant_cache", 4444, "openat", test_file, mode="r"))


if __name__ == "__main__":
    unittest.main()
