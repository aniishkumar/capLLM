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

3. **Tamper-Evident Audit Logging**:
   - Cryptographic SHA-256 hash-chained append-only event ledger.
   - Verifiable integrity proof detecting log alteration or deletion.

4. **Multi-Tenant Evaluation Suite**:
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
│   │   ├── capability.py        # HMAC-signed capability tokens & lifecycle management
│   │   └── capability_space.py  # Capability space & tenant isolation
│   ├── runtime/
│   │   └── interceptor.py       # Dual-path syscall mediation & reference monitor
│   └── benchmarks/
│       ├── eval_suite.py        # Threat scenarios & multi-tenant simulation
│       └── harness.py           # Latency metrics (p50, p95, p99) & confusion matrix
├── tests/
│   └── test_capability_space.py # Unit tests
├── run_demo.py                  # End-to-end interactive demonstration
└── run_benchmarks.py            # Latency and enforcement benchmark runner
```

---

## 🛠️ Getting Started

### Prerequisites
- Python 3.10+

### Running the Demo
Execute the full demonstration covering token issuance, execution scenarios, and audit verification:
```bash
python run_demo.py
```

### Running the Benchmarks
Run the latency and threat evaluation harness:
```bash
python run_benchmarks.py
```

### Running Unit Tests
```bash
python -m unittest discover tests
```
