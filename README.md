# CapLLM-Kernel

> **Capability-Based Security & Interception for Multi-Tenant LLM Runtimes**

CapLLM-Kernel is a research prototype implementing fine-grained, capability-based access control and system-call mediation for isolated, multi-tenant Large Language Model (LLM) agent runtimes.

---

## 🚀 Key Features

1. **Capability Tokens**:
   - Cryptographically signed (HMAC-SHA256) capability tokens.
   - Fine-grained permission model encompassing file system paths, allowed syscalls, and network endpoints.
   - O(1) in-memory lookup cache with instant revocation support and TTL expiry.

2. **Dual-Path Syscall Interceptor & Reference Monitor**:
   - **Fast Path**: Sub-millisecond verification via signed cache for benign, common operations.
   - **Slow Path**: Deep inspection for path traversal detection, symlink resolution, network domain filtering, and high-risk syscalls.
   - **Mediation Reality**: CPython PEP 578 userspace audit hooks in child processes. Raw kernel syscall interception (`seccomp-bpf` / `SECCOMP_RET_USER_NOTIF`) is scheduled for Stage 3.

3. **Linux Workload Isolation (Stage 2)**:
   - **Namespaces**: User (`CLONE_NEWUSER`), PID (`CLONE_NEWPID` with child as PID 1), Mount (`CLONE_NEWNS` with `MS_REC | MS_PRIVATE`), and Network (`CLONE_NEWNET`).
   - **Filesystem Containment**: Private workspaces, host-sentinel invisibility, and cross-tenant isolation barriers.
   - **Resource Limits (cgroups v2)**: Per-workload slice allocation, PID attachment, and configurable `memory.max` and `pids.max` enforcement.
   - **Host Transparency**: Automatic prerequisite probe that honestly reports unsupported environments on non-Linux hosts.

4. **Tamper-Evident Audit Logging**:
   - Cryptographic SHA-256 hash-chained event ledger per run.
   - Verifiable integrity proof detecting log alteration or deletion.

5. **Multi-Tenant Evaluation Suite**:
   - **Scenario 1**: Benign workspace operations.
   - **Scenario 2**: Path traversal and unauthorized network exfiltration attempts.
   - **Scenario 3**: Arbitrary code execution (reverse shells, unauthorized binary execution).
   - **Scenario 4**: Dynamic capability revocation and expiry mid-task.

---

## 📁 Repository Structure

```text
capLLM/
├── capllm/
│   ├── core/
│   │   ├── audit.py             # SHA-256 hash-chained audit trail & tamper detection
│   │   ├── capability.py        # Canonical HMAC-signed capability tokens & manager
│   │   └── capability_space.py  # Backward-compatible TokenAuthority adapter
│   ├── runtime/
│   │   ├── interceptor.py       # Dual-path syscall mediation & SandboxSupervisor
│   │   └── sandbox_linux.py     # Linux namespaces, containment & cgroups v2 manager
│   └── benchmarks/
│       ├── eval_suite.py        # Threat scenarios & multi-tenant live simulation
│       └── harness.py           # In-process synthetic policy benchmark
├── tests/                       # Automated unit and integration test suite
├── run_demo.py                  # End-to-end interactive demo & Linux isolation probe
└── run_benchmarks.py            # Synthetic policy latency and enforcement runner
```

---

## 🛠️ Getting Started

### Prerequisites
- Python 3.10+
- **Linux Workload Isolation Requirements (Stage 2)**:
  - Linux kernel 5.8+ (x86_64 or aarch64)
  - Unprivileged user namespaces enabled (`/proc/sys/kernel/unprivileged_userns_clone = 1`)
  - cgroups v2 unified hierarchy mounted at `/sys/fs/cgroup` with writable user delegation
  - *Non-Linux Hosts (Windows, macOS)*: The framework runs via cross-platform PEP 578 child supervision and executes an explicit unsupported fallback for Stage 2 isolation.

### Running the End-to-End Demo
Execute the supervisor demonstration covering capability enforcement, attack mediation, and audit verification:
```bash
python run_demo.py
```

### Running the Linux Workload Isolation Demo
Execute the Stage 2 Linux prerequisite probe, namespace containment, and cgroups v2 demonstration:
```bash
python run_demo.py --linux-isolation
```

### Running the In-Process Policy Benchmarks
Run the in-process synthetic policy evaluation harness:
```bash
python run_benchmarks.py
```

### Running the Test Suite
```bash
python -m unittest discover tests -v
```
