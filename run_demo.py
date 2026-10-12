"""
CapLLM-Kernel: Research Prototype Demo & Benchmark Runner
=========================================================

Self-contained driver demonstrating:
  1. CapabilityToken lifecycle (HMAC-SHA256 signature, fast lookup, instant revocation).
  2. Cryptographic audit chain with tamper detection.
  3. Hybrid dual-path system call supervisor with PEP 578 / seccomp-style interception.
  4. 4 real-world multi-tenant agent execution and attack scenarios:
       S1: Benign Execution (Tenant A workspace operations)
       S2: Path Traversal & Exfiltration (Agent B attempts /etc/passwd, traversal, symlink escape, network exfil)
       S3: Arbitrary Code Execution (Agent B reverse shell, curl pipe sh, unauthorized binary)
       S4: Dynamic Capability Revocation & Expiry (Mid-task revocation and TTL expiry)
  5. Latency metrics (p50, p95, p99 in microseconds), confusion matrix, and overhead comparison.
"""

import argparse
import json
import logging
import os
import sys
import tempfile
import time
from pathlib import Path

# Ensure the workspace is on python's sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from capllm.benchmarks.eval_suite import EvaluationSuite
from capllm.runtime.sandbox_linux import (
    IS_LINUX,
    LinuxSandboxResult,
    LinuxSandboxRunner,
    probe_linux_prerequisites,
)


def configure_logging(verbose: bool = True) -> None:
    """Configures structured and clean console output for viva/demo evaluation."""
    log_format = "%(asctime)s [%(levelname)-5s] %(name)s: %(message)s"
    date_format = "%H:%M:%S"
    level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(level=level, format=log_format, datefmt=date_format, stream=sys.stdout)


def run_linux_isolation_demo() -> int:
    """Executes the Stage 2 Linux workload isolation demo and prerequisite probe."""
    print("\n" + "=" * 100)
    print("   CapLLM-Kernel: Linux Workload Isolation & Prerequisite Probe (Stage 2)")
    print("=" * 100)
    print("Boundary: Linux Namespaces (user/pid/mount/net) + cgroups v2 (Unified Hierarchy)")
    print("Security Scope: Workload OS Containment (Does NOT imply kernel syscall interception)")
    print("=" * 100 + "\n")

    probe = probe_linux_prerequisites()
    print("### 1. Host Platform & Linux Prerequisite Probe")
    print(f"  Distribution:                 {probe.distribution}")
    print(f"  Kernel Version:               {probe.kernel_version}")
    print(f"  Architecture:                 {probe.architecture}")
    print(f"  Python Version:               {probe.python_version}")
    print(f"  Is Linux Kernel:              {'YES' if probe.is_linux else 'NO (Unsupported Host)'}")
    print(f"  Unprivileged User Namespaces: {'YES' if probe.unprivileged_userns_enabled else 'NO'}")
    print(f"  cgroups v2 Unified Hierarchy: {'YES' if probe.cgroups_v2_available else 'NO'}")
    print(f"  cgroup Subtree Delegated:     {'YES' if probe.cgroup_delegated else 'NO'}")
    if probe.user_cgroup_path:
        print(f"    -> User cgroup path:        {probe.user_cgroup_path}")
    print(f"  Mount & Namespace Operations: {'PERMITTED' if probe.mount_and_ns_permitted else 'DENIED / UNAVAILABLE'}")

    if probe.unsupported_reasons:
        print("\n  [Diagnostic Warnings / Unsupported Reasons]:")
        for reason in probe.unsupported_reasons:
            print(f"    - {reason}")
    print("-" * 100)

    # Prepare directories and tests
    results_dir = WORKSPACE_ROOT / "artifacts"
    results_dir.mkdir(parents=True, exist_ok=True)
    results_file = results_dir / "linux_isolation_results.json"

    runner = LinuxSandboxRunner()
    print("\n### 2. Workload Isolation Execution")

    with tempfile.TemporaryDirectory() as tmp_base:
        sentinel_path = os.path.join(tmp_base, "host_sentinel.txt")
        Path(sentinel_path).write_text("TOP_SECRET_HOST_SENTINEL", encoding="utf-8")

        foreign_ws = os.path.join(tmp_base, "tenant_a_workspace")
        os.makedirs(foreign_ws, exist_ok=True)
        Path(os.path.join(foreign_ws, "secret.txt")).write_text("TENANT_A_DATA", encoding="utf-8")

        target_ws = os.path.join(tmp_base, "tenant_b_workspace")
        os.makedirs(target_ws, exist_ok=True)

        def sample_workload() -> dict:
            return {"status": "success", "cwd": os.getcwd()}

        res = runner.run_isolated_workload(
            task=sample_workload,
            workspace_dir=target_ws,
            tenant_id="tenant_b",
            agent_id="agent_isolated_1",
            host_sentinel_path=sentinel_path,
            foreign_workspace_path=foreign_ws,
            memory_max_bytes=50 * 1024 * 1024,
            pids_max=16,
        )

    print(f"  Sandbox Launcher PID:         {res.sandbox_pid or 'N/A (Host unsupported)'}")
    print(f"  User Namespace Isolation:     {res.user_ns_status}")
    if res.parent_ns_inodes.get("user") and res.child_ns_inodes.get("user"):
        print(f"    -> Inode Evidence:          parent={res.parent_ns_inodes.get('user')} vs child={res.child_ns_inodes.get('user')}")
    print(f"  PID Namespace Isolation:      {res.pid_ns_status}")
    if res.parent_ns_inodes.get("pid") and res.child_ns_inodes.get("pid"):
        print(f"    -> Inode Evidence:          parent={res.parent_ns_inodes.get('pid')} vs child={res.child_ns_inodes.get('pid')}")
    print(f"  Mount Namespace Isolation:    {res.mount_ns_status}")
    if res.parent_ns_inodes.get("mnt") and res.child_ns_inodes.get("mnt"):
        print(f"    -> Inode Evidence:          parent={res.parent_ns_inodes.get('mnt')} vs child={res.child_ns_inodes.get('mnt')}")
    print(f"  Network Namespace Isolation:  {res.net_ns_status}")
    if res.parent_ns_inodes.get("net") and res.child_ns_inodes.get("net"):
        print(f"    -> Inode Evidence:          parent={res.parent_ns_inodes.get('net')} vs child={res.child_ns_inodes.get('net')}")

    sentinel_str = "PASS (Invisible / Blocked)" if res.host_sentinel_blocked else ("SKIP (Non-Linux)" if not res.supported else "FAIL (Accessible)")
    cross_str = "PASS (Inaccessible / Blocked)" if res.cross_tenant_blocked else ("SKIP (Non-Linux)" if not res.supported else "FAIL (Accessible)")
    print(f"  Host Sentinel Invisibility:   {sentinel_str}")
    print(f"  Cross-Tenant Data Barrier:    {cross_str}")

    cg_path_str = res.cgroup_path or "N/A (Delegation unavailable / Unsupported)"
    print(f"  cgroups v2 Slice:             {cg_path_str}")
    mem_str = f"requested={res.cgroup_memory_requested} B | observed={res.cgroup_memory_observed} B" if res.cgroup_memory_observed is not None else (f"requested={res.cgroup_memory_requested} B | observed=N/A (Delegation unavailable)")
    pids_str = f"requested={res.cgroup_pids_requested} | observed={res.cgroup_pids_observed}" if res.cgroup_pids_observed is not None else (f"requested={res.cgroup_pids_requested} | observed=N/A (Delegation unavailable)")
    print(f"  cgroups v2 memory.max:        {mem_str}")
    print(f"  cgroups v2 pids.max:          {pids_str}")
    print(f"  cgroups v2 Membership:        {'VERIFIED (Attached & Present in cgroup.procs)' if res.cgroup_attached else ('N/A (Delegation unavailable)' if not res.cgroup_path else 'FAILED')}")

    final_status = "PASS" if res.supported and res.user_ns_status == "PASS" else ("UNSUPPORTED_FALLBACK" if not res.supported else "FAIL")
    print("\n" + "=" * 100)
    print(f"  FINAL RESULT: {final_status}")
    if not res.supported:
        print(f"  STATUS NOTE: Explicit unsupported fallback executed. {res.reason}")
    print("=" * 100 + "\n")

    # Write machine-readable JSON artifact
    payload = {
        "timestamp": time.time(),
        "probe": probe.to_dict(),
        "result": {
            "supported": res.supported,
            "platform": res.platform,
            "sandbox_pid": res.sandbox_pid,
            "user_ns_status": res.user_ns_status,
            "pid_ns_status": res.pid_ns_status,
            "mount_ns_status": res.mount_ns_status,
            "net_ns_status": res.net_ns_status,
            "parent_ns_inodes": res.parent_ns_inodes,
            "child_ns_inodes": res.child_ns_inodes,
            "host_sentinel_blocked": res.host_sentinel_blocked,
            "cross_tenant_blocked": res.cross_tenant_blocked,
            "network_isolated": res.network_isolated,
            "cgroup_attached": res.cgroup_attached,
            "cgroup_path": res.cgroup_path,
            "cgroup_memory_requested": res.cgroup_memory_requested,
            "cgroup_memory_observed": res.cgroup_memory_observed,
            "cgroup_pids_requested": res.cgroup_pids_requested,
            "cgroup_pids_observed": res.cgroup_pids_observed,
            "final_status": final_status,
            "error": res.error,
            "reason": res.reason,
        },
    }
    results_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Machine-readable JSON artifact saved to: {results_file}\n")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="CapLLM-Kernel Evaluation & Isolation Demo")
    parser.add_argument(
        "--linux-isolation",
        action="store_true",
        help="Run the Stage 2 Linux workload isolation demo and prerequisite probe",
    )
    args = parser.parse_args()

    configure_logging(verbose=True)

    if args.linux_isolation:
        return run_linux_isolation_demo()

    print("\n" + "=" * 100)
    print("   CapLLM-Kernel: Capability-Based Security & Interception for Multi-Tenant LLM Runtimes")
    print("=" * 100)
    print("Architecture: Reference Monitor with Dual-Path Syscall Mediation & Hash-Chained Audit Logs")
    print("Platform: " + sys.platform + " | Python " + sys.version.split()[0])
    print("=" * 100 + "\n")

    audit_file = WORKSPACE_ROOT / "capllm_audit.jsonl"
    
    # Initialize the automated evaluation suite
    suite = EvaluationSuite(
        audit_log_path=audit_file,
        benchmark_ops=100,         # file ops for baseline vs kernel comparison
        micro_iterations=2000,      # iterations for micro-benchmark latency distributions
        verbose=True,
    )

    # Execute all scenarios, micro-benchmarks, and cryptographic self-tests
    success = suite.run_all()

    # Print the comprehensive academic evaluation report (tables, confusion matrix, latencies)
    suite.print_report()

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
