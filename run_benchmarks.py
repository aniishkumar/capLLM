"""
CapLLM-Kernel: In-Process Benchmark Harness Runner
==================================================

Launches the in-process synthetic benchmark harness measuring:
- Synthetic policy evaluation across 4 threat scenarios (traversal, process spawning, network exfil, revocation)
- In-memory policy decision latency distributions (p50, p95, p99 in microseconds)
- Policy enforcement simulation confusion matrix on synthetic workloads
- Memory footprint of the active capability table across tenant scales
- Comparison table of baseline check vs in-memory CapabilityManager check

Note: Measurements evaluate Python userspace policy execution only, not Linux kernel
seccomp-bpf or container namespace mediation.
"""

import sys
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from capllm.benchmarks.harness import BenchmarkHarness

def main() -> int:
    harness = BenchmarkHarness(cases_per_scenario=100)
    harness.print_benchmark_report()
    return 0

if __name__ == "__main__":
    sys.exit(main())
