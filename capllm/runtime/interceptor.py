"""
capllm.runtime.interceptor
==========================

The Hybrid System-Call Interception and Decision Engine.

Architecture (mirrors Linux ``seccomp`` with ``SECCOMP_RET_USER_NOTIF``)
------------------------------------------------------------------------

::

    +---------------------- supervisor process (trusted) ----------------------+
    |  SandboxSupervisor  --->  DecisionEngine  --->  CapabilityManager        |
    |         ^   |                    |                AuditLogger (chain)    |
    |  notif  |   | verdict / SIGKILL  |                                       |
    +---------|---|--------------------|---------------------------------------+
              |   v
    +---------+-------- agent child process (untrusted, one per agent) --------+
    |  syscall shim (PEP 578 audit hook)  <-- traps open/exec/connect/...      |
    |  agent task code (LLM tool calls)   chdir()'ed into its isolated dir     |
    +--------------------------------------------------------------------------+

1. Each agent runs in its own OS child process, chdir'ed into an isolated
   per-tenant workspace (a lightweight stand-in for a container sandbox).
2. Before agent code runs, a *syscall shim* is installed in the child using
   CPython's runtime audit hooks (PEP 578).  CPython raises an audit event
   immediately *before* performing sensitive operations (``open``,
   ``subprocess.Popen``, ``os.system``, ``socket.connect``, ``os.kill``...).
   The shim translates each event into a syscall-shaped request
   (``openat``, ``execve``, ``connect``, ``kill``...).
3. The shim sends the request to the supervisor over a pipe and *blocks*.
   The operation is therefore suspended exactly like a syscall held by a
   seccomp user-notification filter.
4. The supervisor's ``DecisionEngine`` decides:
     * FAST path  -- low-risk file ops matching the token: cached O(1) lookup;
     * SLOW path  -- high-risk ops (execve, connect, ptrace, kill, dlopen),
       traversal sequences, sensitive paths, invalid tokens, or anything the
       fast path could not positively allow: deep parameter validation and a
       synchronous audit record *before* the verdict is released.
5. Enforcement: on ALLOW the supervisor replies and the child proceeds.  On
   BLOCK (default ``KILL`` mode) the supervisor never replies -- it SIGKILLs
   the child while the call is still suspended, so the operation can never
   complete -- and logs the incident.

Honest scope statement (important for a viva)
---------------------------------------------
PEP 578 hooks run *inside* the untrusted interpreter; they are an excellent,
portable, compiler-free *interception* mechanism but are not by themselves a
kernel-grade isolation boundary (native code via ctypes could bypass them,
which is why ``dlopen`` is mediated and denied by default).  In a production
deployment the same request/verdict protocol would be fed by a kernel seccomp
filter (``SECCOMP_RET_USER_NOTIF``), and the ``DecisionEngine`` below would be
reused unchanged.  The decision logic -- the research contribution -- is
independent of the interception transport.
"""

from __future__ import annotations

import json
import logging
import multiprocessing
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from capllm.core.audit import AuditLogger, EventType, Verdict
from capllm.core.capability import (
    CapabilityManager,
    CapabilityToken,
    normalize_path,
    path_is_within,
)

log = logging.getLogger("capllm.supervisor")

# --------------------------------------------------------------------------- #
# Syscall taxonomy and risk policy
# --------------------------------------------------------------------------- #
# File-system syscalls that are *candidates* for the fast path.
FILE_SYSCALLS = frozenset({"openat", "getdents64", "mkdirat", "unlinkat"})

# Syscalls that always escalate to the slow path (deep validation + audit).
HIGH_RISK_SYSCALLS = frozenset({"execve", "connect", "bind", "ptrace", "kill", "dlopen"})

# Paths that are never delegable to an agent, whatever its token says.
_RAW_SENSITIVE_PREFIXES = [
    "/etc",
    "/proc",
    "/sys",
    "/root",
    "/boot",
    "/dev",
    "/var/run",
    os.path.join(os.path.expanduser("~"), ".ssh"),
    os.path.join(os.path.expanduser("~"), ".aws"),
]
if os.name == "nt":
    _RAW_SENSITIVE_PREFIXES.append(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32"))

# Network destinations blocked unconditionally (cloud metadata -> credential theft).
BLOCKED_NETWORK_HOSTS = frozenset({"169.254.169.254", "metadata.google.internal", "100.100.100.200"})

# Argument patterns that indicate a reverse shell / download-and-execute.
REVERSE_SHELL_PATTERNS = [
    re.compile(r"/dev/(tcp|udp)/"),
    re.compile(r"\b(nc|ncat|netcat)\b.*\s-(e|c)\b"),
    re.compile(r"\bbash\s+-i\b"),
    re.compile(r"\b(curl|wget)\b.*\|\s*(ba|z)?sh\b"),
    re.compile(r"\bsocket\b.*\bconnect\b.*\b(dup2|pty)\b", re.S),
    re.compile(r"\bmkfifo\b"),
]


class MediationPath(str, Enum):
    FAST = "FAST"
    SLOW = "SLOW"


class EnforcementMode(str, Enum):
    """What to do with a BLOCK verdict.

    KILL  -- terminate the child while the call is suspended (default; like
             ``SECCOMP_RET_KILL_PROCESS``).
    ERRNO -- return EPERM to the child (``PermissionError``), like
             ``SECCOMP_RET_ERRNO``; useful for micro-benchmarks.
    """

    KILL = "KILL"
    ERRNO = "ERRNO"


class RunOutcome(str, Enum):
    COMPLETED = "COMPLETED"
    KILLED = "KILLED"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    CRASHED = "CRASHED"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class SyscallRequest:
    """A syscall-shaped request as seen by the supervisor."""

    seq: int
    pid: int
    tenant_id: str
    agent_id: str
    syscall: str
    resource: str
    perm: str
    cwd: str
    args: Dict[str, Any]
    audit_event: str
    received_at: float

    @classmethod
    def from_message(cls, msg: Dict[str, Any], tenant_id: str, agent_id: str) -> "SyscallRequest":
        """Build a request from an (untrusted) child message, type-checking every field."""
        args = msg.get("args") if isinstance(msg.get("args"), dict) else {}
        return cls(
            seq=int(msg.get("seq", -1)),
            pid=int(msg.get("pid", -1)),
            tenant_id=tenant_id,  # identity comes from the supervisor, never the child
            agent_id=agent_id,
            syscall=str(msg.get("syscall", "unknown")),
            resource=str(msg.get("resource", "")),
            perm=str(msg.get("perm", "-")),
            cwd=str(msg.get("cwd", "")),
            args={str(k): str(v) for k, v in args.items()},
            audit_event=str(msg.get("audit_event", "")),
            received_at=time.time(),
        )


@dataclass(frozen=True)
class Decision:
    """The engine's verdict for one request."""

    verdict: Verdict
    path: MediationPath
    reason: str
    latency_ns: int
    cache_hit: bool = False

    @property
    def latency_us(self) -> float:
        return self.latency_ns / 1000.0


# --------------------------------------------------------------------------- #
# Decision engine (runs in the trusted supervisor)
# --------------------------------------------------------------------------- #
class DecisionEngine:
    """Dual-path mediation: cached fast path + escalated deep-validation slow path.

    Invariant (fail-closed): the fast path can only ever return ALLOW.
    Anything it cannot positively allow is escalated, so every denial is
    deeply validated and synchronously audited.
    """

    def __init__(self, capabilities: CapabilityManager, audit: AuditLogger) -> None:
        self.caps = capabilities
        self.audit = audit
        self.sensitive_prefixes = [normalize_path(p) for p in _RAW_SENSITIVE_PREFIXES]

    # ------------------------------------------------------------------ #
    # Entry point
    # ------------------------------------------------------------------ #
    def decide(self, token_id: str, req: SyscallRequest) -> Decision:
        t0 = time.perf_counter_ns()
        escalation: List[str] = []

        # Gate 0 -- authority must be live: signature, expiry, revocation (O(1)).
        validity = self.caps.validate_token(token_id)
        token = self.caps.get_token(token_id)
        if not validity.valid or token is None:
            return self._slow_path(token, req, None, [f"token invalid: {validity.reason}"], t0, force_deny=validity.reason)

        # Gate 1 -- PID binding: the request must come from the bound process.
        if token.pid is not None and token.pid != req.pid:
            return self._slow_path(token, req, None, ["pid mismatch"], t0,
                                   force_deny=f"pid {req.pid} not bound to token (bound to {token.pid})")

        # Canonicalize file targets once; reused by both paths.
        norm: Optional[str] = None
        if req.syscall in FILE_SYSCALLS and not req.resource.startswith("fd:"):
            norm = normalize_path(req.resource, req.cwd or None)

        # Risk classification decides which path handles the request.
        escalation.extend(self._classify_risk(req, norm))

        if not escalation and norm is not None:
            # ---------------- FAST PATH ----------------
            allowed, hit = self.caps.cached_path_decision(token, req.syscall, norm, req.perm)
            if allowed:
                return Decision(
                    verdict=Verdict.ALLOW,
                    path=MediationPath.FAST,
                    reason=f"capability match ({'cache hit' if hit else 'cache miss'})",
                    latency_ns=time.perf_counter_ns() - t0,
                    cache_hit=hit,
                )
            escalation.append("fast path found no matching capability")

        # ---------------- SLOW PATH ----------------
        return self._slow_path(token, req, norm, escalation, t0)

    # ------------------------------------------------------------------ #
    # Risk classification
    # ------------------------------------------------------------------ #
    def _classify_risk(self, req: SyscallRequest, norm: Optional[str]) -> List[str]:
        """Return the list of reasons for escalation (empty == low risk)."""
        reasons: List[str] = []
        if req.syscall in HIGH_RISK_SYSCALLS:
            reasons.append(f"high-risk syscall '{req.syscall}'")
        elif req.syscall not in FILE_SYSCALLS:
            reasons.append(f"unknown syscall '{req.syscall}'")
        if req.syscall in FILE_SYSCALLS:
            if req.resource.startswith("fd:"):
                reasons.append("fd-based open")
            if self._has_traversal(req.resource):
                reasons.append("path traversal sequence '..'")
            if norm is not None and self._is_sensitive(norm):
                reasons.append("sensitive system path")
        return reasons

    @staticmethod
    def _has_traversal(raw_path: str) -> bool:
        parts = re.split(r"[\\/]+", raw_path)
        return ".." in parts

    def _is_sensitive(self, norm: str) -> bool:
        return any(path_is_within(norm, p) for p in self.sensitive_prefixes)

    # ------------------------------------------------------------------ #
    # Slow path
    # ------------------------------------------------------------------ #
    def _slow_path(
        self,
        token: Optional[CapabilityToken],
        req: SyscallRequest,
        norm: Optional[str],
        escalation: List[str],
        t0: int,
        force_deny: Optional[str] = None,
    ) -> Decision:
        # 1. Record the interception synchronously, BEFORE any approval.
        self.audit.log_event(
            EventType.SYSCALL_INTERCEPTED, req.tenant_id, req.agent_id, req.syscall,
            req.resource, Verdict.PENDING,
            {"pid": req.pid, "escalation": escalation, "perm": req.perm, "args": req.args},
        )

        # 2. Deep parameter validation, dispatched per syscall class.
        if force_deny is not None or token is None:
            allowed, reason = False, force_deny or "no token"
        elif req.syscall == "execve":
            allowed, reason = self._validate_exec(token, req)
        elif req.syscall in ("connect", "bind"):
            allowed, reason = self._validate_network(token, req)
        elif req.syscall in FILE_SYSCALLS:
            allowed, reason = self._validate_path(token, req, norm)
        else:
            allowed, reason = self._validate_privileged(token, req)

        verdict = Verdict.ALLOW if allowed else Verdict.BLOCK
        latency_ns = time.perf_counter_ns() - t0

        # 3. Record the final verdict (still before the child is released).
        self.audit.log_event(
            EventType.ACCESS_ALLOWED if allowed else EventType.ACCESS_DENIED,
            req.tenant_id, req.agent_id, req.syscall, req.resource, verdict,
            {"path": "SLOW", "reason": reason, "latency_us": round(latency_ns / 1000, 2)},
        )
        return Decision(verdict, MediationPath.SLOW, reason, latency_ns)

    # --- deep validators ------------------------------------------------ #
    def _validate_path(self, token: CapabilityToken, req: SyscallRequest, norm: Optional[str]) -> Tuple[bool, str]:
        if norm is None:  # fd-based open: the fd was obtained via an earlier mediated open
            ok = req.syscall in token.allowed_syscalls
            return ok, "fd reuse of previously mediated file" if ok else f"'{req.syscall}' not granted"
        if req.syscall not in token.allowed_syscalls:
            return False, f"syscall '{req.syscall}' not granted by token"
        granted = self.caps.path_grants(token, norm, req.perm)
        if self._has_traversal(req.resource):
            if granted:
                return True, f"traversal resolves inside sandbox ({norm})"
            return False, f"path traversal escapes sandbox -> {norm}"
        if self._is_sensitive(norm):
            return False, f"sensitive system path {norm} is non-delegable"
        lexical = os.path.normcase(os.path.normpath(os.path.join(req.cwd, req.resource)))
        if granted:
            return True, "capability match after deep validation"
        if lexical != norm:
            return False, f"symlink redirection outside sandbox -> {norm}"
        return False, f"no capability grants '{req.perm}' on {norm}"

    def _validate_exec(self, token: CapabilityToken, req: SyscallRequest) -> Tuple[bool, str]:
        if "execve" not in token.allowed_syscalls:
            return False, "execve not granted by token"
        argv = req.args.get("argv", "")
        for pattern in REVERSE_SHELL_PATTERNS:
            if pattern.search(argv):
                return False, f"reverse-shell / dropper pattern detected ({pattern.pattern})"
        binary = req.resource
        if not os.path.isabs(binary):
            return False, f"non-absolute executable '{binary}' (PATH hijack risk)"
        if not self.caps.path_grants(token, normalize_path(binary), "exec"):
            return False, f"binary {binary} lacks 'exec' capability"
        return True, "binary and arguments validated"

    def _validate_network(self, token: CapabilityToken, req: SyscallRequest) -> Tuple[bool, str]:
        if req.syscall not in token.allowed_syscalls:
            return False, f"'{req.syscall}' not granted by token"
        host = req.args.get("host", "")
        try:
            port = int(req.args.get("port", "-1"))
        except ValueError:
            return False, "malformed port"
        if host in BLOCKED_NETWORK_HOSTS:
            return False, f"cloud metadata endpoint {host} is never reachable"
        if not self.caps.endpoint_granted(token, host, port):
            return False, f"endpoint {host}:{port} not in allow-list (exfiltration?)"
        return True, f"endpoint {host}:{port} in allow-list"

    def _validate_privileged(self, token: CapabilityToken, req: SyscallRequest) -> Tuple[bool, str]:
        if req.syscall not in token.allowed_syscalls:
            return False, f"privileged syscall '{req.syscall}' not granted (default deny)"
        if req.syscall in ("kill", "ptrace"):
            target = req.args.get("target_pid", "")
            if target != str(req.pid):
                return False, f"{req.syscall} targets foreign pid {target} (cross-tenant)"
        return True, f"'{req.syscall}' granted"


# --------------------------------------------------------------------------- #
# Child side: audit-event -> syscall translation (runs in UNTRUSTED process)
# --------------------------------------------------------------------------- #
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND


def _as_str(path: Any) -> str:
    return os.fsdecode(os.fspath(path))


def _tr_open(args: tuple) -> Optional[Dict[str, Any]]:
    path, mode, flags = (list(args) + [None, None, None])[:3]
    if path is None:
        return None
    if isinstance(mode, str):
        is_write = any(c in mode for c in "wax+")
    else:
        is_write = bool((flags or 0) & _WRITE_FLAGS)
    perm = "write" if is_write else "read"
    if isinstance(path, int):
        return {"syscall": "openat", "resource": f"fd:{path}", "perm": perm}
    return {"syscall": "openat", "resource": _as_str(path), "perm": perm}


def _tr_listdir(args: tuple) -> Dict[str, Any]:
    path = args[0] if args and args[0] is not None else "."
    if isinstance(path, int):
        return {"syscall": "getdents64", "resource": f"fd:{path}", "perm": "read"}
    return {"syscall": "getdents64", "resource": _as_str(path), "perm": "read"}


def _tr_mkdir(args: tuple) -> Dict[str, Any]:
    return {"syscall": "mkdirat", "resource": _as_str(args[0]), "perm": "write"}


def _tr_remove(args: tuple) -> Dict[str, Any]:
    return {"syscall": "unlinkat", "resource": _as_str(args[0]), "perm": "write"}


def _argv_to_str(argv: Any) -> str:
    if isinstance(argv, (list, tuple)):
        return " ".join(_as_str(a) if isinstance(a, (str, bytes, os.PathLike)) else str(a) for a in argv)
    return str(argv)


def _tr_popen(args: tuple) -> Dict[str, Any]:
    executable, argv = args[0], args[1]
    if executable is None:
        first = argv[0] if isinstance(argv, (list, tuple)) and argv else str(argv).split(" ")[0]
        executable = first
    return {"syscall": "execve", "resource": _as_str(executable), "perm": "exec",
            "args": {"argv": _argv_to_str(argv)}}


def _default_shell() -> str:
    return os.environ.get("ComSpec", r"C:\Windows\System32\cmd.exe") if os.name == "nt" else "/bin/sh"


def _tr_system(args: tuple) -> Dict[str, Any]:
    return {"syscall": "execve", "resource": _default_shell(), "perm": "exec",
            "args": {"argv": f"{_default_shell()} -c {args[0]}"}}


def _tr_exec(args: tuple) -> Dict[str, Any]:
    # os.exec*: (path, args, env); os.posix_spawn: (path, argv, env)
    return {"syscall": "execve", "resource": _as_str(args[0]), "perm": "exec",
            "args": {"argv": _argv_to_str(args[1]) if len(args) > 1 else ""}}


def _tr_spawn(args: tuple) -> Dict[str, Any]:
    # os.spawn*: (mode, path, args, env)
    return {"syscall": "execve", "resource": _as_str(args[1]), "perm": "exec",
            "args": {"argv": _argv_to_str(args[2]) if len(args) > 2 else ""}}


def _tr_socket(syscall: str) -> Callable[[tuple], Dict[str, Any]]:
    def translate(args: tuple) -> Dict[str, Any]:
        address = args[1]
        if isinstance(address, tuple) and len(address) >= 2:
            host, port = str(address[0]), str(address[1])
        else:  # AF_UNIX path or exotic family
            host, port = str(address), "-1"
        return {"syscall": syscall, "resource": f"{host}:{port}", "perm": "-",
                "args": {"host": host, "port": port}}
    return translate


def _tr_kill(args: tuple) -> Dict[str, Any]:
    return {"syscall": "kill", "resource": f"pid:{args[0]}", "perm": "-",
            "args": {"target_pid": str(args[0]), "signal": str(args[1])}}


def _tr_dlopen(args: tuple) -> Dict[str, Any]:
    return {"syscall": "dlopen", "resource": str(args[0]), "perm": "exec"}


# CPython audit event name -> translator into a syscall-shaped request.
AUDIT_EVENT_TRANSLATORS: Dict[str, Callable[[tuple], Optional[Dict[str, Any]]]] = {
    "open": _tr_open,
    "os.listdir": _tr_listdir,
    "os.scandir": _tr_listdir,
    "os.mkdir": _tr_mkdir,
    "os.remove": _tr_remove,
    "os.rmdir": _tr_remove,
    "subprocess.Popen": _tr_popen,
    "os.system": _tr_system,
    "os.exec": _tr_exec,
    "os.posix_spawn": _tr_exec,
    "os.spawn": _tr_spawn,
    "os.startfile": lambda a: {"syscall": "execve", "resource": _as_str(a[0]), "perm": "exec",
                               "args": {"argv": _as_str(a[0])}},
    "socket.connect": _tr_socket("connect"),
    "socket.bind": _tr_socket("bind"),
    "os.kill": _tr_kill,
    "ctypes.dlopen": _tr_dlopen,
}


class _ShimState:
    """Mutable state of the in-child syscall shim."""

    def __init__(self, conn: Any) -> None:
        self.conn = conn
        self.seq = 0
        self.disarmed = False
        self.pipe_lock = threading.Lock()  # one outstanding notification at a time
        self.local = threading.local()     # per-thread re-entrancy guard


def _install_syscall_shim(conn: Any) -> _ShimState:
    """Install the PEP 578 audit hook that suspends sensitive calls.

    The hook is *fail-closed*: any error while talking to the supervisor
    (pipe closed, malformed reply...) aborts the operation.
    """
    state = _ShimState(conn)

    def hook(event: str, args: tuple) -> None:
        translator = AUDIT_EVENT_TRANSLATORS.get(event)
        if translator is None or state.disarmed or getattr(state.local, "busy", False):
            return
        state.local.busy = True  # ignore events raised by our own IPC
        try:
            request = translator(args)
            if request is None:
                return
            with state.pipe_lock:
                state.seq += 1
                request.update(seq=state.seq, pid=os.getpid(), cwd=os.getcwd(), audit_event=event, type="syscall")
                try:
                    # JSON (not pickle) so the reply path triggers no import/unpickle events.
                    state.conn.send_bytes(json.dumps(request).encode("utf-8"))
                    reply = json.loads(state.conn.recv_bytes().decode("utf-8"))
                except Exception as exc:  # fail closed
                    raise PermissionError(f"[CapLLM] supervisor unreachable, denying {request['syscall']}: {exc}")
            if reply.get("verdict") != "ALLOW":
                raise PermissionError(f"[CapLLM] {request['syscall']} {request['resource']} denied: {reply.get('reason')}")
        finally:
            state.local.busy = False

    sys.addaudithook(hook)
    return state


def _sandbox_entrypoint(
    conn: Any,
    task: Callable[..., Dict[str, Any]],
    task_kwargs: Dict[str, Any],
    workspace: str,
    mediated: bool,
) -> None:
    """Child process main(): confine, arm the shim, run the agent task."""
    os.chdir(workspace)  # isolated per-tenant working directory
    # Pre-import every module the agent may lazily need: once the shim is
    # armed, loading a module would itself be an (unauthorized) file read.
    import socket  # noqa: F401
    import subprocess  # noqa: F401

    state = _install_syscall_shim(conn) if mediated else None
    try:
        result = task(**task_kwargs)
        payload: Dict[str, Any] = {"type": "done", "result": result}
    except Exception as exc:  # report, do not crash silently
        payload = {"type": "error", "error": f"{type(exc).__name__}: {exc}"}
    if state is not None:
        state.disarmed = True  # trusted epilogue: stop mediating interpreter shutdown
    conn.send_bytes(json.dumps(payload, default=str).encode("utf-8"))
    conn.close()


# --------------------------------------------------------------------------- #
# Supervisor (trusted parent)
# --------------------------------------------------------------------------- #
@dataclass
class AgentRunResult:
    """Everything observed while supervising one agent process."""

    label: str
    tenant_id: str
    agent_id: str
    pid: Optional[int] = None
    outcome: RunOutcome = RunOutcome.COMPLETED
    decisions: List[Tuple[SyscallRequest, Decision]] = field(default_factory=list)
    child_result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    kill_reason: Optional[str] = None
    wall_time_s: float = 0.0

    @property
    def allowed(self) -> int:
        return sum(1 for _, d in self.decisions if d.verdict is Verdict.ALLOW)

    @property
    def blocked(self) -> int:
        return sum(1 for _, d in self.decisions if d.verdict is Verdict.BLOCK)


DecisionCallback = Callable[[SyscallRequest, Decision, AgentRunResult], None]


class SandboxSupervisor:
    """Launches agent tasks in isolated child processes and mediates their syscalls."""

    def __init__(
        self,
        capabilities: CapabilityManager,
        audit: AuditLogger,
        mode: EnforcementMode = EnforcementMode.KILL,
    ) -> None:
        self.caps = capabilities
        self.audit = audit
        self.engine = DecisionEngine(capabilities, audit)
        self.mode = mode
        # "spawn" gives a fresh interpreter on every OS: no inherited state.
        self._ctx = multiprocessing.get_context("spawn")

    def run_agent(
        self,
        task: Callable[..., Dict[str, Any]],
        workspace: str,
        token: Optional[CapabilityToken] = None,
        task_kwargs: Optional[Dict[str, Any]] = None,
        label: str = "agent",
        mediated: bool = True,
        timeout_s: float = 20.0,
        on_decision: Optional[DecisionCallback] = None,
        verbose: bool = True,
        isolation_mode: str = "process",
    ) -> AgentRunResult:
        """Run ``task`` in a sandboxed child and enforce ``token`` on every syscall."""
        if mediated and token is None:
            raise ValueError("mediated execution requires a capability token")
        tenant = token.tenant_id if token else "baseline"
        agent = token.agent_id if token else label
        result = AgentRunResult(label=label, tenant_id=tenant, agent_id=agent)
        parent_conn, child_conn = self._ctx.Pipe(duplex=True)
        started = time.perf_counter()

        if isolation_mode == "linux_namespaces":
            from capllm.runtime.sandbox_linux import LinuxSandboxRunner
            runner = LinuxSandboxRunner()
            if not runner.is_supported():
                parent_conn.close()
                child_conn.close()
                reasons = "; ".join(runner.probe.unsupported_reasons)
                result.outcome = RunOutcome.UNSUPPORTED
                result.error = f"Linux namespaces isolation unsupported: {reasons}"
                return result

            proc = runner.launch_supervised_process(
                child_conn=child_conn,
                task=task,
                task_kwargs=task_kwargs or {},
                workspace=workspace,
                mediated=mediated,
                tenant_id=tenant,
                agent_id=agent,
            )
            child_conn.close()
            if getattr(proc, "error", None) or not proc.pid:
                parent_conn.close()
                if hasattr(proc, "cleanup"):
                    proc.cleanup()
                result.outcome = RunOutcome.ERROR
                result.error = f"Linux sandbox launch failed: {getattr(proc, 'error', 'failed spawning workload')}"
                return result

            result.pid = proc.pid
            if mediated and token is not None:
                token = self.caps.bind_pid(token.token_id, proc.pid)  # PID binding
                if verbose:
                    log.info("[%s/%s] spawned linux sandbox workload pid=%s cwd=%s token=%s",
                             tenant, agent, proc.pid, workspace, token.short_id())
        else:
            proc = self._ctx.Process(
                target=_sandbox_entrypoint,
                args=(child_conn, task, task_kwargs or {}, workspace, mediated),
                daemon=True,
                name=f"capllm-{label}",
            )
            proc.start()
            child_conn.close()  # parent keeps only its end
            result.pid = proc.pid
            if mediated and token is not None:
                token = self.caps.bind_pid(token.token_id, proc.pid)  # PID binding
                if verbose:
                    log.info("[%s/%s] spawned sandbox pid=%s cwd=%s token=%s",
                             tenant, agent, proc.pid, workspace, token.short_id())

        deadline = time.monotonic() + timeout_s
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._terminate(proc, result, "wall-clock timeout exceeded", RunOutcome.TIMEOUT)
                    break
                if not parent_conn.poll(min(remaining, 0.05)):
                    if not proc.is_alive() and not parent_conn.poll():
                        result.outcome = RunOutcome.CRASHED
                        result.error = f"child exited with code {proc.exitcode}"
                        break
                    continue
                try:
                    msg = json.loads(parent_conn.recv_bytes().decode("utf-8"))
                except (EOFError, OSError, ValueError) as exc:
                    result.outcome, result.error = RunOutcome.CRASHED, f"ipc failure: {exc}"
                    break

                kind = msg.get("type")
                if kind == "done":
                    result.child_result = msg.get("result")
                    break
                if kind == "error":
                    result.outcome, result.error = RunOutcome.ERROR, msg.get("error")
                    break
                if kind != "syscall":
                    self._terminate(proc, result, f"protocol violation: {kind!r}", RunOutcome.KILLED)
                    break

                assert token is not None
                if not self._mediate(proc, parent_conn, token, msg, result, on_decision, verbose):
                    break
        finally:
            proc.join(timeout=3)
            if proc.is_alive():
                proc.kill()
                proc.join(timeout=3)
            if hasattr(proc, "cleanup"):
                proc.cleanup()
            parent_conn.close()
            result.wall_time_s = time.perf_counter() - started
        return result

    # ------------------------------------------------------------------ #
    def _mediate(
        self,
        proc: Any,
        conn: Any,
        token: CapabilityToken,
        msg: Dict[str, Any],
        result: AgentRunResult,
        on_decision: Optional[DecisionCallback],
        verbose: bool,
    ) -> bool:
        """Decide one suspended call. Returns False if the child was terminated."""
        req = SyscallRequest.from_message(msg, token.tenant_id, token.agent_id)
        # Never trust the PID the child claims: substitute the OS-observed one
        # if they disagree, so the engine's PID-binding check catches spoofing.
        if req.pid != proc.pid:
            req = SyscallRequest(**{**req.__dict__, "pid": -abs(req.pid)})
        decision = self.engine.decide(token.token_id, req)
        result.decisions.append((req, decision))

        level = logging.INFO if (verbose or decision.verdict is Verdict.BLOCK) else logging.DEBUG
        log.log(level, "[%s/%s] %-10s %-46s -> %-5s %s %7.1fus  %s",
                req.tenant_id, req.agent_id, req.syscall, _short(req.resource),
                decision.verdict.value, decision.path.value, decision.latency_us, decision.reason)

        if decision.verdict is Verdict.ALLOW:
            conn.send_bytes(json.dumps({"verdict": "ALLOW"}).encode("utf-8"))
            if decision.path is MediationPath.FAST:
                # Fast-path ALLOWs are audited *after* release (off the critical path).
                self.audit.log_event(EventType.ACCESS_ALLOWED, req.tenant_id, req.agent_id,
                                     req.syscall, req.resource, Verdict.ALLOW,
                                     {"path": "FAST", "cache_hit": decision.cache_hit,
                                      "latency_us": round(decision.latency_us, 2)})
            keep_running = True
        elif self.mode is EnforcementMode.ERRNO:
            conn.send_bytes(json.dumps({"verdict": "BLOCK", "reason": decision.reason}).encode("utf-8"))
            keep_running = True
        else:
            # KILL mode: do not answer; kill while the call is still suspended.
            self._terminate(proc, result, f"{req.syscall} {req.resource}: {decision.reason}", RunOutcome.KILLED)
            keep_running = False

        if on_decision is not None:
            on_decision(req, decision, result)
        return keep_running

    def _terminate(self, proc: Any, result: AgentRunResult, reason: str, outcome: RunOutcome) -> None:
        """Immediately SIGKILL/TerminateProcess the rogue child and audit it."""
        proc.kill()
        proc.join(timeout=3)
        result.outcome = outcome
        result.kill_reason = reason
        self.audit.log_event(EventType.PROCESS_TERMINATED, result.tenant_id, result.agent_id,
                             "-", f"pid:{proc.pid}", Verdict.BLOCK, {"reason": reason})
        log.warning("[%s/%s] *** TERMINATED pid=%s *** %s", result.tenant_id, result.agent_id, proc.pid, reason)


def _short(text: str, width: int = 46) -> str:
    return text if len(text) <= width else "..." + text[-(width - 3):]
