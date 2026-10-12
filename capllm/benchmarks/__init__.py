"""Evaluation suite: multi-tenant attack scenarios, benchmark metrics, and harness engine."""

__all__ = [
    "EvaluationSuite",
    "BenchmarkHarness",
    "SyntheticWorkloadGenerator",
    "ThreatScenario",
]

def __getattr__(name: str):
    if name == "EvaluationSuite":
        from capllm.benchmarks.eval_suite import EvaluationSuite
        return EvaluationSuite
    elif name in ("BenchmarkHarness", "SyntheticWorkloadGenerator", "ThreatScenario"):
        from capllm.benchmarks.harness import BenchmarkHarness, SyntheticWorkloadGenerator, ThreatScenario
        return locals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
