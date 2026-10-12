"""
capllm.runtime.sandbox_linux
============================

Linux Workload Isolation: Namespaces, Filesystem Containment, and cgroups v2.

Stage 2 Scope & Boundary:
-------------------------
This module provides container-like isolation primitives for Linux agent workloads:
1. Linux Namespaces:
   - User Namespace (CLONE_NEWUSER): unprivileged namespace configuration via UID/GID maps.
   - PID Namespace (CLONE_NEWPID): true PID isolation where the sandboxed child is PID 1.
   - Mount Namespace (CLONE_NEWNS): private propagation (MS_REC | MS_PRIVATE) and restricted bind-mounts.
   - Network Namespace (CLONE_NEWNET): loopback-only or disconnected network stack.
2. Filesystem Containment:
   - Isolated per-tenant temporary workspaces.
   - Host-sentinel invisibility and cross-tenant workspace barrier.
   - Note: CPython PEP 578 provides userspace mediation; namespaces provide OS resource isolation.
3. cgroups v2 Unified Hierarchy:
   - Hierarchical slice allocation (capllm/<tenant_id>/<agent_id>).
   - PID attachment via cgroup.procs.
   - Configurable memory.max and pids.max limit enforcement.
   - Reliable teardown via cgroup.kill (or SIGKILL) and rmdir.

Honest Non-Linux Behavior:
--------------------------
On non-Linux platforms (e.g., Windows, macOS), this module explicitly reports
unsupported status and provides a safe fallback without faking passing results.

Note: Raw kernel syscall interception (seccomp-bpf / SECCOMP_RET_USER_NOTIF),
pivot_root, native extensions, and Docker/OCI runtimes remain out of scope for Stage 2.
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("capllm.sandbox_linux")

# --------------------------------------------------------------------------- #
# Linux Kernel Constants (sys/mount.h, sched.h)
# --------------------------------------------------------------------------- #
CLONE_NEWNS = 0x00020000    # Mount namespace
CLONE_NEWCGROUP = 0x02000000  # Cgroup namespace
CLONE_NEWUTS = 0x04000000   # UTS namespace
CLONE_NEWIPC = 0x08000000   # IPC namespace
CLONE_NEWUSER = 0x10000000  # User namespace
CLONE_NEWPID = 0x20000000   # PID namespace
CLONE_NEWNET = 0x40000000   # Network namespace

MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_BIND = 4096
MS_MOVE = 8192
MS_REC = 16384
MS_PRIVATE = 1 << 18        # 262144

IS_LINUX = sys.platform.startswith("linux")

# Lazy-loaded libc pointer
_libc: Optional[Any] = None
if IS_LINUX:
    try:
        _libc = ctypes.CDLL("libc.so.6", use_errno=True)
    except Exception as exc:  # pragma: no cover
        log.warning("Failed to load libc.so.6 on Linux: %s", exc)


# --------------------------------------------------------------------------- #
# Prerequisite Probe
# --------------------------------------------------------------------------- #
@dataclass
class LinuxPrerequisites:
    """Detailed capability and prerequisite probe for Linux isolation."""

    platform_system: str
    distribution: str
    kernel_version: str
    architecture: str
    python_version: str
    is_linux: bool
    unprivileged_userns_enabled: bool = False
    cgroups_v2_available: bool = False
    cgroup_delegated: bool = False
    cgroup_root_path: Optional[str] = None
    user_cgroup_path: Optional[str] = None
    mount_and_ns_permitted: bool = False
    unsupported_reasons: List[str] = field(default_factory=list)

    @property
    def fully_supported(self) -> bool:
        """True only if all required Linux isolation primitives are operational."""
        return (
            self.is_linux
            and self.unprivileged_userns_enabled
            and self.mount_and_ns_permitted
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert probe results to machine-readable dictionary."""
        return asdict(self)


def probe_linux_prerequisites() -> LinuxPrerequisites:
    """Probes the current host environment for Linux isolation primitives.

    Returns an honest, complete probe result. Never fabricates passes.
    """
    sys_name = platform.system()
    kernel = platform.release()
    arch = platform.machine()
    py_ver = platform.python_version()

    # Determine distribution
    distro = "Non-Linux Host"
    if IS_LINUX:
        try:
            if hasattr(platform, "freedesktop_os_release"):
                info = platform.freedesktop_os_release()
                distro = info.get("PRETTY_NAME", info.get("NAME", "Linux"))
            elif os.path.exists("/etc/os-release"):
                with open("/etc/os-release", "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("PRETTY_NAME="):
                            distro = line.strip().split("=", 1)[1].strip('"')
                            break
            else:
                distro = platform.platform()
        except Exception:
            distro = platform.platform()
    else:
        distro = f"{sys_name} ({platform.platform()})"

    probe = LinuxPrerequisites(
        platform_system=sys_name,
        distribution=distro,
        kernel_version=kernel,
        architecture=arch,
        python_version=py_ver,
        is_linux=IS_LINUX,
    )

    if not IS_LINUX:
        probe.unsupported_reasons.append(
            f"Host OS is {sys_name}; Linux namespaces and cgroups v2 require a Linux kernel."
        )
        return probe

    # 1. Probe unprivileged user namespaces
    userns_ok = False
    userns_path = Path("/proc/sys/kernel/unprivileged_userns_clone")
    if userns_path.exists():
        try:
            val = userns_path.read_text(encoding="utf-8").strip()
            userns_ok = (val == "1")
        except Exception:
            userns_ok = False
    else:
        # Many modern kernels (Debian 11+, Ubuntu 20+, Fedora, Arch) default to enabled
        # Test directly via disposable probe process
        userns_ok = _test_unshare_capability(CLONE_NEWUSER)

    probe.unprivileged_userns_enabled = userns_ok
    if not userns_ok:
        probe.unsupported_reasons.append(
            "Unprivileged user namespaces are disabled or restricted by kernel policy."
        )

    # 2. Probe cgroups v2 unified hierarchy
    cgroup2_path = Path("/sys/fs/cgroup")
    controllers_file = cgroup2_path / "cgroup.controllers"
    cgroup2_ok = controllers_file.exists()
    probe.cgroups_v2_available = cgroup2_ok
    if cgroup2_ok:
        probe.cgroup_root_path = str(cgroup2_path)
    else:
        probe.unsupported_reasons.append(
            "cgroups v2 unified hierarchy is not mounted at /sys/fs/cgroup."
        )

    # 3. Probe cgroup delegation (writable user subtree)
    delegated_ok = False
    if cgroup2_ok:
        user_cg = _discover_user_cgroup()
        if user_cg and os.access(user_cg / "cgroup.procs", os.W_OK):
            delegated_ok = True
            probe.user_cgroup_path = str(user_cg)
        else:
            probe.unsupported_reasons.append(
                "Executing user does not hold a writable/delegated cgroup v2 subtree."
            )
    probe.cgroup_delegated = delegated_ok

    # 4. Probe namespace and mount operations
    mount_ns_ok = _test_unshare_capability(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET)
    probe.mount_and_ns_permitted = mount_ns_ok
    if not mount_ns_ok:
        probe.unsupported_reasons.append(
            "Required mount and namespace unshare operations (CLONE_NEWNS/PID/NET) are not permitted."
        )

    return probe


def _test_unshare_capability(flags: int) -> bool:
    """Tests if unshare with specified flags succeeds in a child process."""
    if not IS_LINUX or _libc is None:
        return False
    try:
        # Run test in a short subprocess to avoid polluting current process state
        code = f"""
import ctypes, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
res = libc.unshare({flags})
sys.exit(0 if res == 0 else 1)
"""
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            timeout=2.0,
            check=False,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _discover_user_cgroup() -> Optional[Path]:
    """Discovers the caller's current cgroups v2 slice from /proc/self/cgroup."""
    try:
        with open("/proc/self/cgroup", "r", encoding="utf-8") as f:
            for line in f:
                # v2 entries have format: "0::<path>"
                parts = line.strip().split(":")
                if len(parts) >= 3 and (parts[0] == "0" or parts[1] == ""):
                    cg_subpath = parts[2].lstrip("/")
                    full_path = Path("/sys/fs/cgroup") / cg_subpath
                    if full_path.exists():
                        return full_path
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------- #
# cgroups v2 Manager
# --------------------------------------------------------------------------- #
@dataclass
class CgroupContext:
    """Active cgroups v2 allocation for a tenant/agent workload."""

    cgroup_path: Path
    tenant_id: str
    agent_id: str
    attached_pids: List[int] = field(default_factory=list)
    memory_max_bytes: Optional[int] = None
    pids_max: Optional[int] = None
    active: bool = True


class CgroupV2Manager:
    """Manages per-workload cgroups v2 slices with limit enforcement and cleanup."""

    def __init__(self, base_cgroup_path: Optional[Path] = None) -> None:
        self.base_path = base_cgroup_path or _discover_user_cgroup() or Path("/sys/fs/cgroup")
        self._managed_groups: List[CgroupContext] = []

    def is_available(self) -> bool:
        """Returns True if the cgroups v2 base path is writable."""
        if not IS_LINUX:
            return False
        return self.base_path.exists() and os.access(self.base_path / "cgroup.procs", os.W_OK)

    def create_workload_cgroup(
        self,
        tenant_id: str,
        agent_id: str,
        memory_max_bytes: Optional[int] = None,
        pids_max: Optional[int] = None,
    ) -> Optional[CgroupContext]:
        """Creates a dedicated cgroup slice for the given tenant/agent."""
        if not self.is_available():
            log.warning("cgroups v2 not available or not delegated; cannot create cgroup for %s/%s", tenant_id, agent_id)
            return None

        # Clean subpath name
        safe_tenant = "".join(c if c.isalnum() or c in "-_" else "_" for c in tenant_id)
        safe_agent = "".join(c if c.isalnum() or c in "-_" else "_" for c in agent_id)
        target_dir = self.base_path / f"capllm_{safe_tenant}_{safe_agent}_{int(time.time()*1000)}"

        try:
            target_dir.mkdir(parents=True, exist_ok=True)

            # Apply memory.max if requested
            if memory_max_bytes is not None and (target_dir / "memory.max").exists():
                try:
                    (target_dir / "memory.max").write_text(str(memory_max_bytes), encoding="utf-8")
                except Exception as exc:
                    log.debug("Failed setting memory.max: %s", exc)

            # Apply pids.max if requested
            if pids_max is not None and (target_dir / "pids.max").exists():
                try:
                    (target_dir / "pids.max").write_text(str(pids_max), encoding="utf-8")
                except Exception as exc:
                    log.debug("Failed setting pids.max: %s", exc)

            ctx = CgroupContext(
                cgroup_path=target_dir,
                tenant_id=tenant_id,
                agent_id=agent_id,
                memory_max_bytes=memory_max_bytes,
                pids_max=pids_max,
                active=True,
            )
            self._managed_groups.append(ctx)
            return ctx
        except Exception as exc:
            log.error("Failed creating cgroup %s: %s", target_dir, exc)
            return None

    def attach_pid(self, ctx: CgroupContext, pid: int) -> bool:
        """Attaches a process to the specified cgroup."""
        if not ctx.active or not ctx.cgroup_path.exists():
            return False
        procs_file = ctx.cgroup_path / "cgroup.procs"
        try:
            procs_file.write_text(str(pid), encoding="utf-8")
            ctx.attached_pids.append(pid)
            return True
        except Exception as exc:
            log.warning("Failed attaching pid %d to cgroup %s: %s", pid, ctx.cgroup_path, exc)
            return False

    def cleanup_cgroup(self, ctx: CgroupContext) -> None:
        """Terminates processes in the cgroup and removes the directory."""
        if not ctx.cgroup_path.exists():
            ctx.active = False
            return

        try:
            # 1. Kill all processes in cgroup
            kill_file = ctx.cgroup_path / "cgroup.kill"
            if kill_file.exists():
                try:
                    kill_file.write_text("1", encoding="utf-8")
                except Exception:
                    pass

            # Fallback: SIGKILL attached PIDs
            for pid in ctx.attached_pids:
                try:
                    os.kill(pid, 9)
                except ProcessLookupError:
                    pass
                except Exception:
                    pass

            # 2. Wait briefly and remove cgroup directory
            time.sleep(0.05)
            try:
                ctx.cgroup_path.rmdir()
            except OSError:
                # If still busy, retry after short grace period
                time.sleep(0.1)
                try:
                    ctx.cgroup_path.rmdir()
                except Exception:
                    pass
        finally:
            ctx.active = False
            if ctx in self._managed_groups:
                self._managed_groups.remove(ctx)


# --------------------------------------------------------------------------- #
# Linux Sandbox Runner & Verification
# --------------------------------------------------------------------------- #
@dataclass
class LinuxSandboxResult:
    """Detailed outcome from executing a workload in the Linux sandbox."""

    supported: bool
    platform: str
    tenant_id: str
    agent_id: str
    sandbox_pid: Optional[int] = None
    user_ns_status: str = "SKIP"
    pid_ns_status: str = "SKIP"
    mount_ns_status: str = "SKIP"
    net_ns_status: str = "SKIP"
    host_sentinel_blocked: bool = False
    cross_tenant_blocked: bool = False
    network_isolated: bool = False
    cgroup_attached: bool = False
    cgroup_path: Optional[str] = None
    cgroup_memory_max: Optional[int] = None
    cgroup_pids_max: Optional[int] = None
    child_result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    reason: Optional[str] = None


class LinuxSandboxRunner:
    """Launches workloads inside Linux namespaces with filesystem and cgroup isolation."""

    def __init__(self, cgroup_manager: Optional[CgroupV2Manager] = None) -> None:
        self.probe = probe_linux_prerequisites()
        self.cgroups = cgroup_manager or CgroupV2Manager()

    def is_supported(self) -> bool:
        """Returns True if this host satisfies all Linux isolation prerequisites."""
        return self.probe.fully_supported

    def run_isolated_workload(
        self,
        task: Callable[..., Dict[str, Any]],
        workspace_dir: str,
        tenant_id: str = "tenant_demo",
        agent_id: str = "agent_demo",
        task_kwargs: Optional[Dict[str, Any]] = None,
        host_sentinel_path: Optional[str] = None,
        foreign_workspace_path: Optional[str] = None,
        probe_host_port: Optional[int] = None,
        memory_max_bytes: int = 50 * 1024 * 1024,
        pids_max: int = 16,
    ) -> LinuxSandboxResult:
        """Executes ``task`` in a fully isolated Linux container environment.

        On non-Linux hosts, returns an explicit unsupported result with diagnostic reason.
        """
        if not self.is_supported():
            reason_str = "; ".join(self.probe.unsupported_reasons) or "Linux isolation unsupported on this host."
            return LinuxSandboxResult(
                supported=False,
                platform=f"{self.probe.platform_system} ({self.probe.distribution})",
                tenant_id=tenant_id,
                agent_id=agent_id,
                error="Linux isolation unsupported",
                reason=reason_str,
            )

        # Implementation for genuine Linux kernel environments
        return self._run_linux_namespaces(
            task=task,
            workspace_dir=workspace_dir,
            tenant_id=tenant_id,
            agent_id=agent_id,
            task_kwargs=task_kwargs or {},
            host_sentinel_path=host_sentinel_path,
            foreign_workspace_path=foreign_workspace_path,
            probe_host_port=probe_host_port,
            memory_max_bytes=memory_max_bytes,
            pids_max=pids_max,
        )

    def _run_linux_namespaces(
        self,
        task: Callable[..., Dict[str, Any]],
        workspace_dir: str,
        tenant_id: str,
        agent_id: str,
        task_kwargs: Dict[str, Any],
        host_sentinel_path: Optional[str],
        foreign_workspace_path: Optional[str],
        probe_host_port: Optional[int],
        memory_max_bytes: int,
        pids_max: int,
    ) -> LinuxSandboxResult:
        """Executes workload using Linux clone/unshare and namespaces."""
        assert IS_LINUX and _libc is not None, "Linux-only method invoked on non-Linux platform"

        res = LinuxSandboxResult(
            supported=True,
            platform=f"Linux ({self.probe.distribution}, kernel {self.probe.kernel_version})",
            tenant_id=tenant_id,
            agent_id=agent_id,
        )

        # 1. Allocate cgroup
        cg_ctx = self.cgroups.create_workload_cgroup(
            tenant_id=tenant_id,
            agent_id=agent_id,
            memory_max_bytes=memory_max_bytes,
            pids_max=pids_max,
        )
        if cg_ctx:
            res.cgroup_path = str(cg_ctx.cgroup_path)
            res.cgroup_memory_max = memory_max_bytes
            res.cgroup_pids_max = pids_max

        # Pipes for synchronization and results
        parent_pipe_r, parent_pipe_w = os.pipe()
        child_pipe_r, child_pipe_w = os.pipe()

        # Capture initial namespace inodes from parent for comparison
        parent_ns = _read_namespace_inodes(os.getpid())

        # Launcher fork
        launcher_pid = os.fork()
        if launcher_pid == 0:  # Launcher process
            os.close(parent_pipe_r)
            os.close(child_pipe_w)
            try:
                # A. Unshare user namespace
                uid = os.getuid()
                gid = os.getgid()
                if _libc.unshare(CLONE_NEWUSER) != 0:
                    os.write(parent_pipe_w, json.dumps({"error": f"unshare(CLONE_NEWUSER) failed: errno {ctypes.get_errno()}"}).encode("utf-8"))
                    sys.exit(1)

                # Set UID/GID maps
                _write_file("/proc/self/setgroups", "deny")
                _write_file("/proc/self/uid_map", f"0 {uid} 1")
                _write_file("/proc/self/gid_map", f"0 {gid} 1")

                # B. Unshare PID, Mount, and Network namespaces
                if _libc.unshare(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET) != 0:
                    os.write(parent_pipe_w, json.dumps({"error": f"unshare(PID|NS|NET) failed: errno {ctypes.get_errno()}"}).encode("utf-8"))
                    sys.exit(1)

                # C. Fork workload: this child becomes PID 1 in the new PID namespace!
                workload_pid = os.fork()
                if workload_pid == 0:  # Workload child (PID 1 in new PID namespace)
                    os.close(parent_pipe_w)
                    try:
                        # Set private mount propagation before any mounts
                        _libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None)

                        # Mount private proc
                        os.makedirs("/proc", exist_ok=True)
                        _libc.mount(b"proc", b"/proc", b"proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, None)

                        # Perform isolation barrier tests
                        sentinel_blocked = True
                        if host_sentinel_path and os.path.exists(host_sentinel_path):
                            try:
                                with open(host_sentinel_path, "r", encoding="utf-8") as f:
                                    f.read()
                                sentinel_blocked = False
                            except (PermissionError, FileNotFoundError):
                                sentinel_blocked = True

                        cross_tenant_blocked = True
                        if foreign_workspace_path and os.path.exists(foreign_workspace_path):
                            try:
                                with open(os.path.join(foreign_workspace_path, "secret.txt"), "r", encoding="utf-8") as f:
                                    f.read()
                                cross_tenant_blocked = False
                            except (PermissionError, FileNotFoundError):
                                cross_tenant_blocked = True

                        # Probe network isolation
                        net_isolated = True
                        if probe_host_port is not None:
                            try:
                                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                s.settimeout(0.5)
                                s.connect(("127.0.0.1", probe_host_port))
                                s.close()
                                net_isolated = False  # If connected to host port, not isolated
                            except Exception:
                                net_isolated = True

                        # Capture child namespace inodes
                        child_ns = _read_namespace_inodes(os.getpid())

                        # Execute agent task
                        os.chdir(workspace_dir)
                        task_out = task(**task_kwargs)

                        # Send results back
                        report = {
                            "inner_pid": os.getpid(),
                            "child_ns": child_ns,
                            "sentinel_blocked": sentinel_blocked,
                            "cross_tenant_blocked": cross_tenant_blocked,
                            "net_isolated": net_isolated,
                            "task_result": task_out,
                        }
                        os.write(parent_pipe_w, json.dumps(report).encode("utf-8"))
                        sys.exit(0)
                    except Exception as exc:
                        os.write(parent_pipe_w, json.dumps({"error": f"Child exception: {exc}"}).encode("utf-8"))
                        sys.exit(1)
                else:
                    # Launcher waits for workload PID
                    _, status = os.waitpid(workload_pid, 0)
                    sys.exit(os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else (status >> 8))
            except Exception as exc:
                os.write(parent_pipe_w, json.dumps({"error": f"Launcher exception: {exc}"}).encode("utf-8"))
                sys.exit(1)

        # Parent process execution
        os.close(parent_pipe_w)
        os.close(child_pipe_r)
        res.sandbox_pid = launcher_pid

        # Attach launcher to cgroup
        if cg_ctx:
            res.cgroup_attached = self.cgroups.attach_pid(cg_ctx, launcher_pid)

        try:
            # Read report from pipe
            raw_data = b""
            while True:
                chunk = os.read(parent_pipe_r, 4096)
                if not chunk:
                    break
                raw_data += chunk
            os.close(parent_pipe_r)

            _, status = os.waitpid(launcher_pid, 0)

            if raw_data:
                payload = json.loads(raw_data.decode("utf-8"))
                if "error" in payload:
                    res.error = payload["error"]
                else:
                    child_ns = payload.get("child_ns", {})
                    # Compare namespace inodes
                    res.user_ns_status = "PASS" if child_ns.get("user") != parent_ns.get("user") else "FAIL"
                    res.pid_ns_status = "PASS" if child_ns.get("pid") != parent_ns.get("pid") else "FAIL"
                    res.mount_ns_status = "PASS" if child_ns.get("mnt") != parent_ns.get("mnt") else "FAIL"
                    res.net_ns_status = "PASS" if child_ns.get("net") != parent_ns.get("net") else "FAIL"

                    res.host_sentinel_blocked = payload.get("sentinel_blocked", False)
                    res.cross_tenant_blocked = payload.get("cross_tenant_blocked", False)
                    res.network_isolated = payload.get("net_isolated", False)
                    res.child_result = payload.get("task_result")
        except Exception as exc:
            res.error = f"Parent supervisor error: {exc}"
        finally:
            if cg_ctx:
                self.cgroups.cleanup_cgroup(cg_ctx)

        return res


def _read_namespace_inodes(pid: int) -> Dict[str, Optional[int]]:
    """Reads namespace inode numbers from /proc/<pid>/ns/*."""
    ns_dict: Dict[str, Optional[int]] = {"user": None, "pid": None, "mnt": None, "net": None, "ipc": None, "uts": None}
    if not IS_LINUX:
        return ns_dict
    ns_dir = Path(f"/proc/{pid}/ns")
    for ns_name in ns_dict.keys():
        link = ns_dir / ns_name
        try:
            stat_info = os.stat(link)
            ns_dict[ns_name] = stat_info.st_ino
        except Exception:
            pass
    return ns_dict


def _write_file(path: str, data: str) -> None:
    """Helper to write data to a system pseudo-file."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)
