"""
CapLLM-Kernel: Benchmark & Evaluation Harness Runner
====================================================

Launches the automated benchmark harness measuring:
- Synthetic threat scenario evaluations (traversal, process spawning, network exfil, revocation)
- Decision latency distributions (p50, p95, p99 in microseconds)
- Enforcement accuracy confusion matrix
- Memory footprint of the active capability table across tenant scales
- Comparison table of baseline execution vs CapLLM-Kernel security mediation overhead
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
