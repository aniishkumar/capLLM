# CapLLM Architectural & Operational Rules

These rules define strict architectural constraints, security boundaries, and validation requirements for the `CapLLM` repository.

---

## 1. Canonical Capability and Permission Routing

- **Single Authority Model**: All capability minting, validation, signature checking, and permission evaluations must route strictly through `capllm.core.capability.CapabilityManager`.
- **Capability Token Format**: All tokens must be instances of the canonical, immutable `capllm.core.capability.CapabilityToken` frozen dataclass.
- **Legacy Compatibility Adapter**:
  - `capllm.core.capability_space.TokenAuthority` exists solely as a deprecated backward-compatibility adapter.
  - New internal components, supervisors, interceptors, and benchmarks must never bypass `CapabilityManager` to implement disjoint or ad-hoc token checking logic.
  - Do not introduce duplicate token representations, separate path matching routines, or parallel permission caches.

---

## 2. Security Boundaries & Measurement Integrity

- **Current Implementation Reality (Stage 1.1)**:
  - System-call mediation is currently enforced in userspace via **CPython PEP 578 audit hooks (`sys.addaudithook`)** and supervisory IPC (`multiprocessing.Pipe`).
  - Do NOT assume or claim kernel-level isolation, Linux namespaces (`CLONE_NEWPID`, `CLONE_NEWNS`, `CLONE_NEWNET`, `CLONE_NEWUSER`), control groups (`cgroups v2`), or kernel syscall trapping (`seccomp-bpf` / `SECCOMP_RET_USER_NOTIF`) prior to their actual implementation in Stage 2 and Stage 3.
  - Do NOT hard-code expected syscall latency values or make unsupported performance claims (e.g., "sub-microsecond", "<50 us", "hardware non-repudiation").
  - Benchmark measurements must always be explicitly labeled as **in-process synthetic policy-evaluation measurements** rather than kernel-enforced system-call interception.

---

## 3. Audit Ledger Semantics

- **Fresh Per-Run Ledger**:
  - `AuditLogger(log_path)` initializes a fresh session ledger by truncating any pre-existing log file at `log_path` on instantiation and resetting hash-chain sequence numbering from `GENESIS_HASH`.
  - Never document or treat the audit log as append-only or durable across process runs.
  - `flush()` flushes userspace application and OS runtime buffers; it is not hardware `fsync()`.
  - External checkpoints or continuous log streaming are required to detect tail truncation or file replacement.

---

## 4. Verification and Hygiene Standards

- **Zero-Failure Test Execution**:
  - All modifications must pass the full test suite cleanly via:
    ```bash
    python -m unittest discover tests -v
    ```
  - Zero test failures or regressions are permitted.
- **Clean Whitespace and Formatting**:
  - Before committing or completing tasks, verify that:
    ```bash
    git diff --check
    ```
    returns clean output with exit code `0` (no trailing whitespace, no extra blank lines at EOF).
- **Windows Platform Awareness**:
  - Symlink creation on Windows may fail with `WinError 1314` unless running with Developer Mode or elevated privileges. Scenario `S2d` in test runners must safely skip and report this without crashing.
