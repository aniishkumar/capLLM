"""
CapLLM-Kernel
=============

Research prototype for capability-based security and dynamic system-call
mediation for isolated, multi-tenant LLM agent runtimes.

Package layout
--------------
capllm.core.capability     -- HMAC-signed capability tokens + CapabilityManager
capllm.core.audit          -- SHA-256 hash-chained, append-only audit log
capllm.runtime.interceptor -- Supervisor, syscall shim and dual-path decision engine
capllm.benchmarks.eval_suite -- Multi-tenant attack scenarios + metrics engine
"""

__version__ = "0.1.0"
