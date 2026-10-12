"""
tests.test_sandbox_linux
========================

Unit and integration tests for Linux workload isolation, namespace containment,
and cgroups v2 manager (Stage 2).

Tests are designed to run cleanly on all platforms:
- On Linux with required prerequisites, tests validate genuine namespace inodes,
  cgroup limits, sentinel invisibility, and network isolation.
- On non-Linux or unsupported platforms, tests validate honest probe reporting,
  clean fallback behavior, and skip Linux-specific kernel operations with explicit reasons.
"""

import json
import os
import platform
import socket
import sys
import tempfile
import unittest
from pathlib import Path

from capllm.core.audit import AuditLogger
from capllm.core.capability import CapabilityManager
from capllm.runtime.interceptor import RunOutcome, SandboxSupervisor
from capllm.runtime.sandbox_linux import (
    IS_LINUX,
    CgroupV2Manager,
    LinuxPrerequisites,
    LinuxSandboxResult,
    LinuxSandboxRunner,
    probe_linux_prerequisites,
)


class TestLinuxPrerequisiteProbe(unittest.TestCase):
    """Validates the Linux prerequisite probe functionality and truthfulness."""

    def test_probe_structure_and_serialization(self) -> None:
        """Probe must return a well-formed LinuxPrerequisites object serializable to dict/JSON."""
        probe = probe_linux_prerequisites()
        self.assertIsInstance(probe, LinuxPrerequisites)
        self.assertIsInstance(probe.platform_system, str)
        self.assertIsInstance(probe.distribution, str)
        self.assertIsInstance(probe.kernel_version, str)
        self.assertIsInstance(probe.architecture, str)
        self.assertIsInstance(probe.python_version, str)
        self.assertIsInstance(probe.is_linux, bool)
        self.assertIsInstance(probe.unprivileged_userns_enabled, bool)
        self.assertIsInstance(probe.cgroups_v2_available, bool)
        self.assertIsInstance(probe.cgroup_delegated, bool)
        self.assertIsInstance(probe.mount_and_ns_permitted, bool)
        self.assertIsInstance(probe.unsupported_reasons, list)

        # Verify JSON round-trip
        data = probe.to_dict()
        serialized = json.dumps(data)
        self.assertIn("platform_system", serialized)
        self.assertIn("distribution", serialized)

    def test_probe_honesty_on_host_environment(self) -> None:
        """Probe must never fake a pass on unsupported operating systems."""
        probe = probe_linux_prerequisites()
        if not IS_LINUX:
            self.assertFalse(probe.is_linux)
            self.assertFalse(probe.fully_supported)
            self.assertGreater(len(probe.unsupported_reasons), 0)
            self.assertTrue(any("Linux namespaces and cgroups v2 require a Linux kernel" in r for r in probe.unsupported_reasons))
        else:
            self.assertTrue(probe.is_linux)


class TestCgroupV2Manager(unittest.TestCase):
    """Validates cgroups v2 management, limits, and fallback behavior."""

    def setUp(self) -> None:
        self.manager = CgroupV2Manager()
        self.probe = probe_linux_prerequisites()

    def test_manager_fallback_when_unsupported(self) -> None:
        """When cgroup delegation or Linux is unavailable, operations return clean fallbacks."""
        if not self.manager.is_available():
            self.assertFalse(self.manager.is_available())
            ctx = self.manager.create_workload_cgroup(
                tenant_id="tenant_test",
                agent_id="agent_test",
                memory_max_bytes=10 * 1024 * 1024,
                pids_max=5,
            )
            self.assertIsNone(ctx)

    @unittest.skipUnless(IS_LINUX, "Linux-only: requires Linux kernel and cgroups v2")
    def test_cgroup_v2_lifecycle_on_linux(self) -> None:
        """Tests cgroup creation, PID attachment, and cleanup on delegated Linux host."""
        if not self.probe.cgroup_delegated:
            self.skipTest("Cgroup v2 user delegation is not configured in this Linux environment")

        ctx = self.manager.create_workload_cgroup(
            tenant_id="test_tenant",
            agent_id="test_agent",
            memory_max_bytes=50 * 1024 * 1024,
            pids_max=10,
        )
        self.assertIsNotNone(ctx)
        assert ctx is not None
        self.assertTrue(ctx.cgroup_path.exists())

        # Attach self PID
        attached = self.manager.attach_pid(ctx, os.getpid())
        self.assertTrue(attached)

        # Cleanup
        self.manager.cleanup_cgroup(ctx)
        self.assertFalse(ctx.active)


class TestLinuxSandboxRunner(unittest.TestCase):
    """Validates Linux container-style sandbox runner and fallback paths."""

    def setUp(self) -> None:
        self.runner = LinuxSandboxRunner()
        self.probe = probe_linux_prerequisites()
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_unsupported_host_fallback(self) -> None:
        """On an unsupported host, run_isolated_workload must return an explicit unsupported outcome."""
        if not self.runner.is_supported():
            def dummy_task() -> dict:
                return {"status": "ok"}

            res = self.runner.run_isolated_workload(
                task=dummy_task,
                workspace_dir=self.temp_dir.name,
                tenant_id="tenant_a",
                agent_id="agent_1",
            )
            self.assertIsInstance(res, LinuxSandboxResult)
            self.assertFalse(res.supported)
            self.assertEqual(res.error, "Linux isolation unsupported")
            self.assertIsNotNone(res.reason)
            self.assertIn("Linux", res.reason)

    def test_supervisor_integration_with_isolation_mode(self) -> None:
        """SandboxSupervisor with isolation_mode='linux_namespaces' handles unsupported hosts cleanly."""
        caps = CapabilityManager(secret_key=b"test-secret-key-32-bytes-minimum!!")
        audit = AuditLogger(os.path.join(self.temp_dir.name, "audit.jsonl"))
        supervisor = SandboxSupervisor(caps, audit)

        token = caps.issue_token(tenant_id="t1", agent_id="a1")

        def simple_task() -> dict:
            return {"hello": "world"}

        result = supervisor.run_agent(
            task=simple_task,
            workspace=self.temp_dir.name,
            token=token,
            isolation_mode="linux_namespaces",
        )

        if not self.runner.is_supported():
            self.assertEqual(result.outcome, RunOutcome.UNSUPPORTED)
            self.assertIn("Linux namespaces isolation unsupported", str(result.error))
        else:
            self.assertEqual(result.outcome, RunOutcome.COMPLETED)

    @unittest.skipUnless(IS_LINUX, "Linux-only: requires Linux kernel and user namespaces")
    def test_linux_namespace_isolation_and_containment(self) -> None:
        """Validates namespace separation, sentinel file barrier, and cross-tenant workspace barrier."""
        if not self.runner.is_supported():
            self.skipTest(f"Linux isolation unsupported: {self.runner.probe.unsupported_reasons}")

        # Setup host sentinel file outside sandbox workspace
        sentinel_path = os.path.join(self.temp_dir.name, "host_sentinel.txt")
        Path(sentinel_path).write_text("SUPER_SECRET_HOST_DATA", encoding="utf-8")

        # Setup foreign tenant workspace
        foreign_workspace = os.path.join(self.temp_dir.name, "tenant_b_workspace")
        os.makedirs(foreign_workspace, exist_ok=True)
        Path(os.path.join(foreign_workspace, "secret.txt")).write_text("TENANT_B_SECRET", encoding="utf-8")

        # Setup target workspace for tenant A
        agent_workspace = os.path.join(self.temp_dir.name, "tenant_a_workspace")
        os.makedirs(agent_workspace, exist_ok=True)

        def agent_task() -> dict:
            return {"task": "done", "cwd": os.getcwd()}

        res = self.runner.run_isolated_workload(
            task=agent_task,
            workspace_dir=agent_workspace,
            tenant_id="tenant_a",
            agent_id="agent_1",
            host_sentinel_path=sentinel_path,
            foreign_workspace_path=foreign_workspace,
        )

        self.assertTrue(res.supported)
        self.assertEqual(res.user_ns_status, "PASS")
        self.assertEqual(res.pid_ns_status, "PASS")
        self.assertEqual(res.mount_ns_status, "PASS")
        self.assertTrue(res.host_sentinel_blocked)
        self.assertTrue(res.cross_tenant_blocked)

    @unittest.skipUnless(IS_LINUX, "Linux-only: requires Linux kernel and network namespace")
    def test_linux_network_namespace_isolation(self) -> None:
        """Validates network namespace isolation by probing a host listening socket."""
        if not self.runner.is_supported():
            self.skipTest(f"Linux isolation unsupported: {self.runner.probe.unsupported_reasons}")

        # Bind host socket on loopback
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        host_port = server.getsockname()[1]

        try:
            def net_task() -> dict:
                return {"net": "checked"}

            res = self.runner.run_isolated_workload(
                task=net_task,
                workspace_dir=self.temp_dir.name,
                tenant_id="tenant_net",
                agent_id="agent_net",
                probe_host_port=host_port,
            )

            self.assertTrue(res.supported)
            self.assertEqual(res.net_ns_status, "PASS")
            self.assertTrue(res.network_isolated)
        finally:
            server.close()


if __name__ == "__main__":
    unittest.main()
