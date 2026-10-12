# CapLLM-Kernel: Systems Architecture & Security Implementation Audit

**Author:** Senior Linux Security Engineer & Python Systems Developer  
**Date:** October 12, 2026  
**Repository:** [https://github.com/aniishkumar/capLLM](https://github.com/aniishkumar/capLLM)  
**Target Systems:** Linux Kernel (x86_64 / aarch64), CPython 3.10+, POSIX Container Runtimes  

---

## 1. Executive Summary & Assessment

CapLLM-Kernel is conceptualized as a capability-based security reference monitor for multi-tenant LLM agent workloads. The research proposal outlines five core objectives:
1. **Capability Space Manager**: Decentralized authority model utilizing cryptographically signed tokens.
2. **Hybrid System-Call Interception & Enforcement**: Dual-path mediation for low-latency common operations and deep-inspection security mediation.
3. **Dynamic Capability Revocation & Tamper-Evident Auditing**: Sub-millisecond revocation and mathematically verifiable hash-chained audit trails.
4. **Isolated Linux Container Workloads**: Hard boundary isolation with namespaces, cgroups, and filesystem sandboxing.
5. **Security Evaluation & Reproducible Measurements**: Automated benchmarks assessing latency distributions, overhead, and threat scenarios.

### Critical Audit Findings
* **Architectural Schism**: The codebase contains **two parallel, mutually incompatible implementations** of capability management and audit logging:
  - Branch A (`capllm/core/capability.py`, `capllm/core/audit.py`, `capllm/runtime/interceptor.py`, `capllm/benchmarks/eval_suite.py`): Live multiprocess supervisor utilizing CPython PEP 578 audit hooks and SHA-256 hash chaining.
  - Branch B (`capllm/core/capability_space.py`, `capllm/benchmarks/harness.py`, `tests/test_capability_space.py`): Monolithic in-memory simulation (`TokenAuthority`) with distinct data classes and zero process isolation.
* **Interception Mechanism Reality**: Syscall mediation is currently **simulated at the Python runtime level using CPython PEP 578 audit hooks** (`sys.addaudithook`) in Branch A, and **pure in-memory dictionary checks** in Branch B. **Zero real Linux kernel system calls are trapped via kernel primitives (`seccomp-bpf` / `SECCOMP_RET_USER_NOTIF`).** Native C/Rust extensions, `ctypes`, or child binaries spawned directly can bypass Python audit hooks entirely.
* **Missing Container Isolation**: Workload isolation currently relies on `os.chdir(workspace)` and OS child processes (`multiprocessing.Process`). No Linux namespaces (`CLONE_NEWPID`, `CLONE_NEWNS`, `CLONE_NEWNET`), cgroups (v2), or `pivot_root`/chroot containment exist. The `cgroup_id` attribute in `capability_space.py` is an unverified dummy integer.
* **Platform Limitations**: The current implementation runs on Windows/CPython without packaging definitions (`pyproject.toml`, `requirements.txt`). Filesystem symlink escape testing fails on Windows unless elevated privileges or Developer Mode are enabled.

---

## 2. Repository Entry Points, Class Map & Dependencies

### 2.1 Dependencies
* **External Dependencies**: **None**. The codebase strictly depends on the Python standard library (`hashlib`, `hmac`, `json`, `os`, `secrets`, `threading`, `time`, `uuid`, `dataclasses`, `multiprocessing`, `socket`, `subprocess`, `tempfile`, `unittest`).
* **Missing Build/Packaging Infrastructure**: No `pyproject.toml`, `setup.cfg`, `requirements.txt`, or C/Rust compilation toolchain configurations exist.

### 2.2 Entry Points
| Entry Point | Path | Target Invocation | Primary Classes & Flow |
| :--- | :--- | :--- | :--- |
| **End-to-End Demo** | `run_demo.py` | `python run_demo.py` | `EvaluationSuite.run_all()`: Orchestrates S1-S4 live multiprocess attack scenarios, micro-benchmarks, and cryptographic self-tests. |
| **Synthetic Benchmark** | `run_benchmarks.py` | `python run_benchmarks.py` | `BenchmarkHarness.print_benchmark_report()`: Evaluates 400 in-memory synthetic operations against `TokenAuthority`. |
| **Unit Test Suite** | `tests/test_capability_space.py` | `python -m unittest discover tests` | Imports and executes `TestCapabilitySpace` from `capllm.core.capability_space`. |
| **Module Standalone** | `capllm/core/capability_space.py` | `python -m capllm.core.capability_space` | Runs embedded `TestCapabilitySpace(unittest.TestCase)`. |
| **Harness Standalone** | `capllm/benchmarks/harness.py` | `python -m capllm.benchmarks.harness` | Direct execution of `BenchmarkHarness`. |

### 2.3 Class Map & Component Architecture
```text
capllm/
├── core/
│   ├── capability.py (Branch A)
│   │   ├── CapabilityToken (frozen dataclass: token_id: str, paths: MappingProxyType, frozenset)
│   │   ├── TokenValidation (valid: bool, reason: str)
│   │   └── CapabilityManager (HMAC-SHA256 signing, PID binding, cache, revocation set)
│   ├── capability_space.py (Branch B - Monolithic Duplicate)
│   │   ├── PathPermission (path: str, modes: str)
│   │   ├── CapabilityToken (dataclass: token_id: UUID, cgroup_id: int, List[PathPermission])
│   │   ├── AuditAction (Enum: TOKEN_ISSUED, TOKEN_REVOKED, ACCESS_ALLOWED, ACCESS_DENIED)
│   │   ├── AuditEntry (dataclass: sequence, hash chain linking, verify_hash())
│   │   ├── TokenAuthority (Standalone manager + embedded audit log + permission cache)
│   │   └── TestCapabilitySpace (Embedded unittest suite)
│   └── audit.py (Branch A)
│       ├── EventType (Enum: TOKEN_ISSUED, SYSCALL_INTERCEPTED, ACCESS_*, PROCESS_TERMINATED)
│       ├── Verdict (Enum: ALLOW, BLOCK, PENDING)
│       ├── AuditEvent (frozen dataclass: SHA-256 canonical hash chaining)
│       └── AuditLogger (Thread-safe append-only memory & JSONL ledger, verify_chain())
├── runtime/
│   └── interceptor.py (Branch A)
│       ├── MediationPath (FAST, SLOW), EnforcementMode (KILL, ERRNO), RunOutcome
│       ├── SyscallRequest, Decision (verdict, path, latency_ns)
│       ├── DecisionEngine (Gate 0 validity, Gate 1 PID bind, fast cache, deep validator)
│       ├── _install_syscall_shim (PEP 578 sys.addaudithook in untrusted child)
│       └── SandboxSupervisor (multiprocessing spawn, Pipe IPC, KILL enforcement)
└── benchmarks/
    ├── eval_suite.py (Branch A Driver)
    │   ├── task_* (benign, traversal, execve, exfiltration, revocation tasks)
    │   └── EvaluationSuite (S1-S4 scenarios, overhead timing, cryptographic self-tests)
    └── harness.py (Branch B Driver)
        ├── ThreatScenario, TestCase, TestEvaluation, ConfusionStats
        ├── SyntheticWorkloadGenerator (synthetic traversal, process, net, revoke cases)
        └── BenchmarkHarness (synthetic in-memory execution against TokenAuthority)
```

---

## 3. Detailed Architectural Comparison: `capability.py` vs. `capability_space.py`

A critical defect in the current repository design is the coexistence of two divergent capability representations:

| Architectural Dimension | `capllm/core/capability.py` (Runtime Supervisor Branch) | `capllm/core/capability_space.py` (Harness & Test Branch) | Divergence Impact |
| :--- | :--- | :--- | :--- |
| **Token Representation** | `CapabilityToken` (frozen dataclass, `token_id: str`, immutable `MappingProxyType` and `frozenset`). | `CapabilityToken` (mutable dataclass, `token_id: uuid.UUID`, `cgroup_id: int`, `List[PathPermission]`). | **Incompatible types.** Passing one token to the other manager triggers attribute and serialization errors. |
| **Path Authority Model** | Direct dictionary mapping canonical path prefix to `FrozenSet[str]` (`{"read", "write", "exec"}`). | Wrapper dataclass `PathPermission` with mode string (`'r'`, `'w'`, `'rw'`, `'rwx'`). | Inconsistent policy declaration syntax across benchmarks. |
| **Token Identifier** | String UUID (`str(uuid.uuid4())`). | Native `uuid.UUID` object. | Serialization and hashing payload discrepancies. |
| **Process Binding** | Optional PID (`pid: Optional[int]`), dynamically bound via `bind_pid()` after `proc.start()`. | Bound at mint time (`pid: int`, `cgroup_id: int`). | Branch B cannot bind real processes spawned asynchronously. |
| **Audit Logging Architecture** | Decoupled; delegates to `capllm.core.audit.AuditLogger` with explicit events (`SYSCALL_INTERCEPTED`, `PENDING`). | Tight coupling; `TokenAuthority` maintains its own `_audit_log: List[AuditEntry]`. | Two divergent audit event schemas and chain verifiers. |
| **Path Canonicalization** | `normalize_path(path, cwd)`: calls `os.path.normcase(os.path.realpath(...))`. | `canonicalize_path(target_path, cwd)`: calls `os.path.normcase(os.path.realpath(os.path.abspath(...)))`. | Redundant implementations of identical POSIX/Windows normalization. |
| **Subpath Validation** | `path_is_within(candidate, prefix)`: verifies `os.path.commonpath([candidate, prefix]) == prefix`. | `is_subpath(candidate, allowed_prefix)`: identical `os.path.commonpath` comparison. | Code duplication. |
| **Consumers** | `capllm.runtime.interceptor`, `capllm.benchmarks.eval_suite`, `run_demo.py`. | `capllm.benchmarks.harness`, `tests/test_capability_space.py`, `run_benchmarks.py`. | The unit tests in `tests/` do not test the actual runtime supervisor! |

---

## 4. Execution Trace Analysis

### 4.1 Trace: `run_demo.py` (Live Multiprocess Scenario Evaluation)
1. **Bootstrap**: `main()` configures root logging and initializes `EvaluationSuite(audit_log_path="capllm_audit.jsonl")`.
2. **Environment Setup**: `prepare_environment()` creates temporary directory hierarchies for `tenant_a`, `tenant_b`, and `capllm_bench`. Writes mock target `/data/secret.txt`. Binds ephemeral TCP listener on `127.0.0.1` as mock tool API.
3. **Scenario S1 (Benign Execution)**:
   - `_token_tenant_a()` issues HMAC-signed token granting access to `tenant_a/workspace` and `127.0.0.1:<api_port>`.
   - `SandboxSupervisor.run_agent()` spawns a clean child via `multiprocessing.get_context("spawn")`.
   - Child calls `_sandbox_entrypoint()` -> `os.chdir(workspace)` -> installs PEP 578 hook `_install_syscall_shim()`.
   - Child executes `task_benign_tenant`: file writes/reads trigger `sys.addaudithook("open")`.
   - The shim packages a `SyscallRequest` dictionary and transmits it across `multiprocessing.Pipe`.
   - Supervisor intercepts in `_mediate()`, runs `DecisionEngine.decide()`.
   - Gate 0 (validity), Gate 1 (PID binding), and Fast Path (`cached_path_decision`) pass.
   - Supervisor replies `{"verdict": "ALLOW"}`. Child unblocks and completes.
4. **Scenario S2 (Path Traversal & Exfiltration)**:
   - Evaluates attacks S2a (`/etc/passwd`), S2b (`../../tenant_a`), S2c (absolute cross-tenant path), S2d (symlink escape), and S2e (unauthorized IP `203.0.113.66:4444`).
   - S2a-c and S2e trigger `DecisionEngine._slow_path()`: path classification flags traversal or unlisted destination.
   - Engine issues synchronous `SYSCALL_INTERCEPTED` with `Verdict.PENDING`, followed by `ACCESS_DENIED` with `Verdict.BLOCK`.
   - In `EnforcementMode.KILL`, supervisor executes `proc.kill()`, terminates child, and logs `PROCESS_TERMINATED`.
   - *Anomaly*: S2d fails with Windows error 1314 (missing privilege) and is recorded as skipped.
5. **Scenario S3 (Arbitrary Code Execution)**:
   - Agent B attempts `task_reverse_shell` (`/dev/tcp`), `task_download_and_execute` (`curl | sh`), and `task_unpermitted_binary`.
   - Ingested via Python audit hooks on `subprocess.Popen` / `os.system`.
   - In `_validate_exec()`, regular expressions flag reverse shells; unpermitted paths fail path capability checks. Process is killed.
6. **Scenario S4 (Dynamic Revocation & Expiry)**:
   - S4a: Background thread executes `caps.revoke_token()` after 4 operations. Operation 5 is denied at Gate 0 and child killed.
   - S4b: Short TTL (2s) expires during agent sleep. Subsequent call is rejected as expired and child killed.
7. **Overhead & Cryptographic Self-Tests**:
   - Compares unmediated baseline vs. mediated file I/O operations.
   - Inverts tokens (forgery check) and edits/deletes entries in the SHA-256 audit chain to confirm mathematical tamper detection.

### 4.2 Trace: `run_benchmarks.py` (Synthetic Policy Benchmark)
1. **Bootstrap**: `main()` instantiates `BenchmarkHarness(cases_per_scenario=100)`.
2. **Setup**: Instantiates `TokenAuthority` from `capability_space.py` and pre-allocates tokens for `tenant_alpha`, `tenant_beta`, `tenant_gamma`, and `tenant_delta`.
3. **Execution**:
   - `SyntheticWorkloadGenerator.generate_suite()` generates 400 `TestCase` instances (100 per category: `FILE_TRAVERSAL`, `PROCESS_SPAWN`, `NETWORK_EXFILTRATION`, `REVOKED_ACCESS`).
   - For each case, `BenchmarkHarness.run_enforcement_evaluation()` calls `auth.check_permission(tenant_id, pid, op, resource, mode)` directly in-memory.
   - **No processes are spawned, no pipes are used, and no system calls are intercepted.**
4. **Memory Profiling**: Iterates across tenant scales (10, 50, 200, 1000) using `deep_getsizeof` on internal dictionary tables.
5. **Report**: Formats terminal Markdown tables detailing confusion matrix and decision latency.

---

## 5. Interception Analysis: Intercepted vs. Simulated / Checked in Python

A foundational requirement of a systems security audit is distinguishing real mediation from simulated policy checks.

```mermaid
flowchart TD
    subgraph Userspace_Agent_Process [Untrusted Agent Process]
        A[Python Source Code] -->|open / socket / Popen| B[CPython Interpreter]
        B -->|PEP 578 Event| C[_install_syscall_shim Hook]
        A -.->|Native C / ctypes / dlopen| D[Direct glibc / syscall instruction]
    end

    subgraph IPC_Boundary [IPC Channel]
        C -->|JSON over Pipe| E[SandboxSupervisor]
    end

    subgraph Supervisor_Process [Trusted Supervisor Process]
        E --> F[DecisionEngine]
        F --> G[CapabilityManager]
        F --> H[AuditLogger]
    end

    subgraph Kernel_Boundary [Linux Kernel Boundary - UNPROTECTED CURRENTLY]
        D ==>|Direct Syscall: sys_openat, sys_connect| K[Linux Kernel VFS / Sockets]
        K -.->|Bypasses PEP 578 Entirely!| L[Host Resources]
    end
```

### 5.1 Actually Intercepted Operations (Via CPython PEP 578 Hooks)
When agent tasks execute inside CPython, the following standard library operations raise audit events that are suspended and sent to the supervisor:
* `open` / file open flags -> mapped to simulated `openat` (read or write perm).
* `os.listdir` / `os.scandir` -> mapped to simulated `getdents64` (read perm).
* `os.mkdir` -> mapped to simulated `mkdirat` (write perm).
* `os.remove` / `os.rmdir` -> mapped to simulated `unlinkat` (write perm).
* `subprocess.Popen` / `os.system` / `os.exec*` / `os.spawn*` / `os.startfile` -> mapped to simulated `execve` (exec perm).
* `socket.connect` / `socket.bind` -> mapped to simulated `connect` / `bind`.
* `os.kill` -> mapped to simulated `kill`.
* `ctypes.dlopen` -> mapped to simulated `dlopen`.

### 5.2 Simulated / Python-Checked Operations (No Kernel Enforcement)
* **All operations in `run_benchmarks.py`**: Synthetic tests do not execute operations; they pass strings to `check_permission()`.
* **Direct Native System Calls**: Any executable binary, compiled C/Rust extension, or inline assembly using `syscall` (e.g., `SYS_openat`, `SYS_connect`) completely bypasses PEP 578 audit hooks.
* **Non-Python Executables**: If an agent spawns an authorized binary (e.g., `worker_tool`), any syscalls executed by that child binary are completely unmonitored.
* **Process Confinement**: `os.chdir()` is not a sandbox. Calling `open("/etc/passwd")` is checked only because Python raises `"open"`. If a sub-process calls `openat(AT_FDCWD, ...)`, no chroot or mount namespace prevents access.

---

## 6. Target Linux Kernel Features, Privileges & Build Requirements

To elevate CapLLM-Kernel from a Python research prototype to a true kernel-enforced system, the following Linux kernel primitives, privileges, and tooling are required:

### 6.1 Linux Kernel Features
1. **`seccomp-bpf` with `SECCOMP_RET_USER_NOTIF`**:
   - **Mechanism**: The supervisor sets up a seccomp filter on the agent process with `SECCOMP_FILTER_FLAG_NEW_LISTENER`, obtaining a notification file descriptor (`notif_fd`).
   - **Interception**: Kernel traps target syscalls (`openat`, `openat2`, `execve`, `execveat`, `connect`, `bind`, `unlinkat`, `mkdirat`, `clone3`) before execution.
   - **Inspection**: Supervisor issues `ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_RECV, &req)`. Reads memory arguments (paths, sockaddr) via `process_vm_readv()` to avoid TOCTOU races.
   - **Enforcement**: Supervisor returns `SECCOMP_IOCTL_NOTIF_SEND` with `flags = 0` and `val = 0` (ALLOW), or `error = -EACCES` / kills process with `pidfd_send_signal()`.
2. **Linux Namespaces**:
   - `CLONE_NEWPID`: Process isolation preventing visibility of host processes.
   - `CLONE_NEWNS` (Mount): Private mount namespace with `pivot_root` into a minimal, read-only rootfs + private tmpfs workspace.
   - `CLONE_NEWNET`: Network isolation; unprivileged agents have only a loopback interface or a veth pair governed by eBPF/tc.
   - `CLONE_NEWUSER`: Rootless execution mapping container UID/GID to unprivileged host users.
   - `CLONE_NEWIPC` & `CLONE_NEWUTS`: Hostname and IPC isolation.
3. **Control Groups v2 (`cgroups v2`)**:
   - Real confinement for `cgroup_id`: attach to `/sys/fs/cgroup/capllm/<tenant_id>/<agent_id>/cgroup.procs`.
   - Resource limits: `memory.max`, `pids.max` (fork-bomb prevention), `cpu.max`.
4. **Filesystem Sandboxing**:
   - `openat2` with `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS` to prevent traversal at the kernel VFS layer.

### 6.2 Required System Privileges
* **With Root / Daemon Privilege**: `CAP_SYS_ADMIN` (namespaces, mounts, seccomp listeners), `CAP_NET_ADMIN` (network setup).
* **Rootless / Unprivileged Mode**: `PR_SET_NO_NEW_PRIVS` allows unprivileged users to attach seccomp filters and configure user namespaces (`CLONE_NEWUSER`).

### 6.3 Build Tools & System Libraries
* **Build Toolchain**: GCC or Clang (C11), GNU Make / CMake, or Rust (MSRV 1.75+) with `cargo`.
* **System Libraries**:
  - `libseccomp` (`libseccomp-dev`, version >= 2.5.0).
  - `libcap` (`libcap-dev`) for POSIX capability manipulation.
* **Python Interoperability**:
  - `cffi` or Rust `pyo3` bindings to compile the low-level seccomp supervisor loop into an importable extension module (`capllm._seccomp`).

---

## 7. Research Proposal Objective Mapping

| Proposal Objective | Existing Code Base | Missing Implementations | Required Verification Evidence | Status |
| :--- | :--- | :--- | :--- | :--- |
| **1. Capability Space Manager** | `capllm/core/capability.py` (`CapabilityManager`), `capllm/core/capability_space.py` (`TokenAuthority`). | Unified data model, persistent token authority, integration with cgroups v2 hierarchy. | Type-safe tests validating uniform token issuance across runtime and benchmarks. | **Partially Implemented** |
| **2. Hybrid Syscall Interception & Enforcement** | `capllm/runtime/interceptor.py` (`DecisionEngine`, PEP 578 shim, dual-path cache). | Real kernel interception (`SECCOMP_RET_USER_NOTIF`), BPF filter generator, `process_vm_readv` memory reader. | Seccomp filter trapping a compiled C binary calling raw `openat` and `connect`. | **Partially Implemented (Python Only)** |
| **3. Dynamic Revocation & Tamper-Evident Auditing** | `capllm/core/audit.py` (`AuditLogger`), `capability.py` (thread-safe revocation, Gate 0). | External hash anchoring (WORM storage / RFC 6962 transparency log / TPM quote). | Benchmark showing zero-latency window on multi-threaded revocation + cryptographic verification. | **Implemented (In-Memory & JSONL)** |
| **4. Isolated Linux Container Workloads** | Stand-in `os.chdir(workspace)` and child processes in `interceptor.py`. Dummy `cgroup_id` in `capability_space.py`. | Linux namespaces (`user`, `pid`, `mount`, `net`), rootfs creation, `pivot_root`, cgroups v2 controller. | `/proc/self/status` and `/proc/self/ns/*` inspection demonstrating isolated namespaces and memory quotas. | **Unimplemented** |
| **5. Security Evaluation & Reproducible Measurements** | `eval_suite.py` (S1-S4 scenarios), `harness.py` (synthetic confusion matrix), `run_demo.py`. | Automated Linux test runner, CI workflow, container workload benchmarks, real syscall latency profiling. | Automated execution of full test suite and harness inside a Linux container environment. | **Partially Implemented** |

---

## 8. Gap Analysis & Defects

### 8.1 Duplications
1. **`CapabilityToken`**: Defined as a frozen dataclass in `capability.py` and a mutable dataclass in `capability_space.py`.
2. **Audit Logging**: Implemented as `AuditLogger`/`AuditEvent` in `audit.py` and replicated as `AuditEntry`/`AuditAction` inside `capability_space.py`.
3. **Path Handling**: Redundant canonicalization and prefix checks (`normalize_path` vs `canonicalize_path`; `path_is_within` vs `is_subpath`).
4. **Benchmark Runners**: Disjoint metrics engines in `eval_suite.py` (live child processes) and `harness.py` (in-memory synthetic calls).

### 8.2 Missing Integrations & Gaps
1. **Broken Packaging**: No `pyproject.toml` or `setup.py`. Imports rely on manual `sys.path.insert(0, str(WORKSPACE_ROOT))`.
2. **Unconnected Unit Tests**: `tests/test_capability_space.py` only tests the isolated `capability_space.py` class. No unit tests exist for `capllm.core.capability`, `capllm.core.audit`, or `capllm.runtime.interceptor`.
3. **Unverified Windows Execution**: Scenario S2d (`symlink_escape`) cannot create symlinks on Windows without administrator privileges, leading to an unverified test step in `run_demo.py`.

---

## 9. Prioritized Multi-Stage Implementation Plan

### Stage 1: Core Architecture Harmonization & Unified Capability Space
* **Goal**: Eliminate architectural duplication, unify `CapabilityToken`, and establish standard packaging.
* **Dependencies**: None.
* **Work Items**:
  1. Unify `CapabilityToken` into `capllm/core/capability.py` supporting path permissions, syscall sets, endpoint tuples, and cgroup identifiers.
  2. Deprecate the duplicate implementations in `capllm/core/capability_space.py`, refactoring `TokenAuthority` and `BenchmarkHarness` to use the unified `CapabilityManager` and `AuditLogger`.
  3. Create `pyproject.toml` specifying Python 3.10+ build standards and test dependencies.
  4. Expand `tests/` with dedicated unit test suites for `CapabilityManager`, `AuditLogger`, and `DecisionEngine`.
* **Acceptance Criteria**: All unit tests pass; `run_demo.py` and `run_benchmarks.py` utilize the exact same core classes.

### Stage 2: Linux Workload Isolation (Namespaces & cgroups v2)
* **Goal**: Provide real container boundaries for agent child processes on Linux.
* **Dependencies**: Stage 1, Linux environment.
* **Work Items**:
  1. Implement a Linux sandbox runner (`capllm/runtime/sandbox_linux.py`) using `unshare(2)` / `clone3(2)` for PID, mount, and network namespaces.
  2. Implement rootfs isolation: construct a minimal tenant jail, perform `pivot_root`, and mount a private tmpfs workspace.
  3. Implement cgroups v2 management: create tenant cgroup slices, bind PIDs to `cgroup.procs`, and enforce `memory.max` and `pids.max`.
  4. Provide a fallback mock sandbox for non-Linux host development.
* **Acceptance Criteria**: Running an agent process on Linux confirms isolation via unshared namespace inodes and constrained cgroup limits.

### Stage 3: Real Linux Kernel Syscall Interception (`seccomp_user_notif`)
* **Goal**: Replace interpreter-level PEP 578 hooks with kernel-level seccomp notification mediation.
* **Dependencies**: Stage 2, `libseccomp` / C/Rust FFI.
* **Work Items**:
  1. Build a BPF filter generator in C/Rust or via Python `cffi` installing `SECCOMP_RET_USER_NOTIF` on sensitive syscalls (`openat`, `execve`, `connect`).
  2. Implement the supervisor notification loop listening on the seccomp listener file descriptor.
  3. Implement memory inspection: use `process_vm_readv` to read target strings directly from child memory buffers.
  4. Connect the seccomp listener directly to the existing `DecisionEngine` fast and slow paths.
* **Acceptance Criteria**: A compiled C binary attempting unauthorized `openat` or `connect` inside the sandbox is blocked and terminated, regardless of Python hooks.

### Stage 4: Cryptographic Anchoring & External Audit Verification
* **Goal**: Provide mathematical non-repudiation against log alteration.
* **Dependencies**: Stage 1.
* **Work Items**:
  1. Implement an external hash-anchor provider (e.g., periodic signed head checkpoint or file-backed append ledger).
  2. Add cryptographic verification CLI command (`python -m capllm.audit verify <log_path>`).
* **Acceptance Criteria**: Verifier mathematically validates chain continuity and detects any modification to past records.

### Stage 5: Reproducible End-to-End Evaluation & Benchmarks
* **Goal**: Validate performance and security under production container conditions.
* **Dependencies**: Stages 1 through 4.
* **Work Items**:
  1. Build a Docker/containerized evaluation testbed (`Dockerfile`) containing the Linux kernel test environment.
  2. Update `harness.py` to run live syscall benchmarks measuring real `seccomp_user_notif` latency overhead alongside PEP 578 baseline.
  3. Automate full benchmark regression in GitHub Actions CI running on Linux runners.
* **Acceptance Criteria**: Full evaluation suite executes autonomously on Linux, producing verified latency distributions and 100% detection accuracy.
