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

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# Ensure the workspace is on python's sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from capllm.benchmarks.eval_suite import EvaluationSuite


def configure_logging(verbose: bool = True) -> None:
    """Configures structured and clean console output for viva/demo evaluation."""
    log_format = "%(asctime)s [%(levelname)-5s] %(name)s: %(message)s"
    date_format = "%H:%M:%S"
    level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(level=level, format=log_format, datefmt=date_format, stream=sys.stdout)


def main() -> int:
    configure_logging(verbose=True)
    
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
