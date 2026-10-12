---
name: capllm-eval
description: >-
  Operational runbook and evaluation guide for the CapLLM security framework.
  Use this skill when running unit tests, executing synthetic policy benchmarks,
  running end-to-end multi-tenant demos, verifying audit log hash-chains,
  or checking git formatting hygiene.
---

# CapLLM Evaluation & Verification Runbook

This skill provides step-by-step procedures for validating code correctness, measuring in-process policy evaluation performance, verifying cryptographic audit chains, and ensuring formatting hygiene across the CapLLM codebase.

---

## 1. Unit Test Suite Execution

Execute the full automated unit test suite using Python's standard `unittest` discovery:

```bash
python -m unittest discover tests -v
```

### Expected Coverage & Results
- **Target Test Count**: Exactly 30 tests across 4 modules:
  1. `tests/test_capability.py`: Token minting, HMAC signatures, PID binding, TTL expiry, dynamic revocation, and path normalization (8 tests).
  2. `tests/test_audit.py`: Sequential SHA-256 hash chaining, entry tampering detection, reordering/deletion detection, fresh per-run truncation, flush behavior, and tail truncation checkpoint requirement (7 tests).
  3. `tests/test_decision_engine.py`: Fast-path caching, PID mismatch enforcement, dynamic revocation blocking, traversal detection, reverse shell blocking, and network endpoint filtering (6 tests).
  4. `tests/test_capability_space.py`: Legacy `TokenAuthority` compatibility, positional `issue_token()` argument translation, PID binding, and scope violation checks (9 tests).
- **Pass Criteria**: All 30 tests must pass with `OK` (exit code `0`).

---

## 2. In-Process Synthetic Policy Benchmarking

Run the synthetic policy evaluation harness:

```bash
python run_benchmarks.py
```

### How to Interpret Results
1. **Scope Banner**: Verify the banner states:
   - Host platform and Python runtime version.
   - Workload case count (100 operations per scenario category).
   - Warning that measurements reflect in-process Python policy-evaluation latency and **not** Linux kernel-enforced system-call mediation (no `seccomp`, namespaces, or `cgroups`).
2. **Latency Distributions**:
   - `FILE_TRAVERSAL`: Evaluates path canonicalization and prefix boundary checks.
   - `PROCESS_SPAWN`: Evaluates executable name and argument inspection.
   - `NETWORK_EXFILTRATION`: Evaluates IP address and port tuple validation.
   - `REVOKED_ACCESS`: Evaluates token revocation lookup latency.
   - Note: p50, p95, p99, and Mean are measured dynamically in microseconds (us).
3. **Confusion Matrix**:
   - Evaluates policy discrimination against 400 synthetic operations (200 attacks, 200 benign).
   - Reports True Positives, True Negatives, False Positives, False Negatives, Precision, Recall, and F1.
4. **Tenant Table Footprint**:
   - Measures deep in-memory byte size of active capability tables scaled across 10, 50, 200, and 1000 agents.

---

## 3. End-to-End Multiprocess Demo & Attacks

Run the live supervisor reference demonstration:

```bash
python run_demo.py
```

### Scenario Execution Flow
- **Scenario S1 (Benign Execution)**:
  - Agent A performs valid reads, writes, and local API connections within its workspace.
  - Expected: 15 operations permitted (`ALLOW`), process completes normally (`COMPLETED`).
- **Scenario S2 (Path Traversal & Exfiltration Attacks)**:
  - Agent B attempts `/etc/passwd`, directory traversal `../../tenant_a`, absolute foreign paths, and unauthorized network egress.
  - Expected: All attacks blocked (`BLOCK`), rogue child processes terminated with `KILL`.
  - *Windows Environment Note*: `S2d-symlink-escape` checks symlink creation. If unprivileged on Windows, it raises `WinError 1314` and is gracefully recorded as skipped.
- **Scenario S3 (Arbitrary Code Execution)**:
  - Agent B attempts `/bin/sh` reverse shells, `curl | sh`, and unauthorized binaries.
  - Expected: All attempts blocked, processes terminated with `KILL`.
- **Scenario S4 (Dynamic Revocation & Expiry)**:
  - S4a: Live token is revoked after 4 operations; operation 5 is blocked and process killed.
  - S4b: Short TTL token expires; subsequent operation is blocked and process killed.
- **Cryptographic Self-Tests**:
  - Verifies authentic token acceptance and forged token rejection.
  - Verifies live and on-disk JSONL audit chain continuity.
  - Validates that modifying or deleting entry #133 is detected mathematically.
- **Audit Ledger Summary**:
  - Confirms entries count (typically 260+ events), `chain=INTACT`, and external head hash anchor.

---

## 4. Audit Log Hash-Chain Verification

The audit log is written to `capllm_audit.jsonl`. Verify its integrity programmatically or via unit test:

```python
from capllm.core.audit import AuditLogger

logger = AuditLogger.load_from_jsonl("capllm_audit.jsonl")
is_valid, reason, broken_idx = logger.verify_chain()
print(f"Chain Valid: {is_valid}, Reason: {reason}, Broken Index: {broken_idx}")
```

### Ledger Rules
- **Fresh Ledger**: Each new `AuditLogger(log_path)` truncates the target file on instantiation.
- **Tail Truncation**: A file truncated from the end retains internal hash-chain continuity. External anchoring (recording the head hash periodically or shipping records off-box) is required to detect tail truncation or file replacement.

---

## 5. Code Hygiene & Formatting Checks

Before staging or committing any code, verify Git formatting hygiene:

```bash
git diff --check
```

- **Pass Criteria**: Exit code `0` with zero output. No trailing whitespace or stray blank lines at EOF.
