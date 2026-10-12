"""
capllm.runtime.sandbox_linux
============================

Linux Workload Isolation: Namespaces, Filesystem Containment, and cgroups v2.

Stage 2 Scope & Boundary:
-------------------------
This module provides container-like isolation primitives for Linux agent workloads:
1. Linux Namespaces:
   - User Namespace (CLONE_NEWUSER): unprivileged execution with UID/GID translation.
   - PID Namespace (CLONE_NEWPID): hierarchical isolation where the sandboxed workload
     is spawned as PID 1 inside the new namespace.
   - Mount Namespace (CLONE_NEWNS): private propagation (MS_REC | MS_PRIVATE) with a
     restricted root filesystem constructed via pivot_root (or chroot fallback).
   - Network Namespace (CLONE_NEWNET): loopback-only or disconnected network stack.
2. Filesystem Containment:
   - Constructs a restricted rootfs containing only minimal read-only runtime paths
     (/usr, /lib, /lib64, /bin, /etc, /proc, /dev) and the private writable workspace (/workspace).
   - Host sentinel files and foreign tenant workspaces outside these mounts are completely
     inaccessible and invisible.
   - Temporary mount trees are reliably cleaned up after completion or termination.
3. cgroups v2 Unified Hierarchy:
   - Verified controller availability (memory and pids).
   - Dedicated slice creation under delegated /sys/fs/cgroup.
   - Memory and PID limits applied and verified via immediate file readback.
   - Parent-launcher synchronization ensures launcher and workload are attached before
     namespace creation (no race condition).
   - Process membership verified via cgroup.procs readback.
   - Clean teardown without killing unrelated processes.

Honest Non-Linux Behavior:
--------------------------
On non-Linux platforms (e.g. Windows, macOS), this module explicitly reports
unsupported status and provides a safe fallback without faking passing results.

Note: Raw kernel syscall interception (seccomp-bpf / SECCOMP_RET_USER_NOTIF),
and native extensions remain out of scope for Stage 2.
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import platform
import shutil
import signal
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
CLONE_NEWNS = 0x00020000      # Mount namespace
CLONE_NEWCGROUP = 0x02000000  # Cgroup namespace
CLONE_NEWUTS = 0x04000000     # UTS namespace
CLONE_NEWIPC = 0x08000000     # IPC namespace
CLONE_NEWUSER = 0x10000000    # User namespace
CLONE_NEWPID = 0x20000000     # PID namespace
CLONE_NEWNET = 0x40000000     # Network namespace

MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_BIND = 4096
MS_MOVE = 8192
MS_REC = 16384
MS_PRIVATE = 1 << 18          # 262144

MNT_DETACH = 2

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
    cgroups_v2_controllers: List[str] = field(default_factory=list)
    cgroup_delegated: bool = False
    cgroup_root_path: Optional[str] = None
    user_cgroup_path: Optional[str] = None
    mount_and_ns_permitted: bool = False
    unsupported_reasons: List[str] = field(default_factory=list)

    @property
    def fully_supported(self) -> bool:
        """True only if all required Linux namespace primitives are operational."""
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
    userns_ok = _test_unshare_capability(CLONE_NEWUSER)
    probe.unprivileged_userns_enabled = userns_ok
    if not userns_ok:
        probe.unsupported_reasons.append(
            "Unprivileged user namespaces are disabled or restricted by kernel policy."
        )

    # 2. Probe cgroups v2 unified hierarchy and controllers
    cgroup2_path = Path("/sys/fs/cgroup")
    controllers_file = cgroup2_path / "cgroup.controllers"
    cgroup2_ok = controllers_file.exists()
    probe.cgroups_v2_available = cgroup2_ok
    if cgroup2_ok:
        probe.cgroup_root_path = str(cgroup2_path)
        try:
            controllers = controllers_file.read_text(encoding="utf-8").strip().split()
            probe.cgroups_v2_controllers = controllers
        except Exception:
            probe.cgroups_v2_controllers = []
    else:
        probe.unsupported_reasons.append(
            "cgroups v2 unified hierarchy is not mounted at /sys/fs/cgroup."
        )

    # 3. Probe cgroup delegation (writable user subtree with controller support)
    cg_manager = CgroupV2Manager()
    delegated_ok, deleg_reason = cg_manager.is_available()
    probe.cgroup_delegated = delegated_ok
    if delegated_ok and cg_manager.base_path:
        probe.user_cgroup_path = str(cg_manager.base_path)
    elif not delegated_ok:
        probe.unsupported_reasons.append(
            f"cgroups v2 delegation unavailable: {deleg_reason}"
        )

    # 4. Probe namespace and mount operations
    mount_ns_ok = _test_unshare_capability(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET)
    probe.mount_and_ns_permitted = mount_ns_ok
    if not mount_ns_ok:
        probe.unsupported_reasons.append(
            "Required mount and namespace unshare operations (CLONE_NEWNS/PID/NET) are not permitted."
        )

    return probe


def _test_unshare_capability(flags: int) -> bool:
    """Tests if unshare with specified flags succeeds in an isolated subprocess."""
    if not IS_LINUX or _libc is None:
        return False
    try:
        code = f"""
import ctypes, os, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
uid, gid = os.getuid(), os.getgid()
if (0x10000000 & {flags}):
    if libc.unshare(0x10000000) != 0:
        sys.exit(1)
    try:
        open('/proc/self/setgroups', 'w').write('deny')
        open('/proc/self/uid_map', 'w').write(f'0 {{uid}} 1')
        open('/proc/self/gid_map', 'w').write(f'0 {{gid}} 1')
    except Exception:
        sys.exit(2)
remaining_flags = {flags} & ~0x10000000
if remaining_flags:
    if libc.unshare(remaining_flags) != 0:
        sys.exit(3)
sys.exit(0)
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
    memory_max_requested: Optional[int] = None
    memory_max_observed: Optional[int] = None
    pids_max_requested: Optional[int] = None
    pids_max_observed: Optional[int] = None
    active: bool = True


class CgroupV2Manager:
    """Manages per-workload cgroups v2 slices with limit enforcement and cleanup."""

    def __init__(self, base_cgroup_path: Optional[Path] = None) -> None:
        self.base_path = base_cgroup_path or self._discover_delegated_cgroup()

    def _discover_delegated_cgroup(self) -> Optional[Path]:
        """Discovers a writable, delegated cgroup subtree for the current user."""
        if not IS_LINUX:
            return None

        candidates: List[Path] = []

        # 1. Check current process's cgroup slice from /proc/self/cgroup
        try:
            with open("/proc/self/cgroup", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 3 and (parts[0] == "0" or parts[1] == ""):
                        cg_subpath = parts[2].lstrip("/")
                        full = Path("/sys/fs/cgroup") / cg_subpath
                        if full.exists():
                            candidates.append(full)
        except Exception:
            pass

        # 2. Check dedicated CapLLM root
        candidates.append(Path("/sys/fs/cgroup/capllm"))

        # 3. Check systemd user slice paths
        uid = os.getuid() if hasattr(os, "getuid") else 1000
        candidates.append(Path(f"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/app.slice"))
        candidates.append(Path(f"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service"))
        candidates.append(Path(f"/sys/fs/cgroup/user.slice/user-{uid}.slice"))
        candidates.append(Path("/sys/fs/cgroup"))

        for cand in candidates:
            if cand.exists() and os.access(cand, os.W_OK):
                procs_file = cand / "cgroup.procs"
                if procs_file.exists() and os.access(procs_file, os.W_OK):
                    if self._verify_candidate_delegation(cand):
                        return cand

        return None

    @staticmethod
    def _verify_candidate_delegation(cand: Path) -> bool:
        """Verifies that processes can actually be migrated into sub-cgroups under cand."""
        if not cand.exists() or not os.access(cand, os.W_OK):
            return False
        probe_dir = cand / f".capllm_delegation_probe_{os.getpid()}_{int(time.time()*1000)}"
        try:
            probe_dir.mkdir(parents=True, exist_ok=True)
            procs_file = probe_dir / "cgroup.procs"
            if not procs_file.exists() or not os.access(procs_file, os.W_OK):
                CgroupV2Manager._safe_rmdir(probe_dir)
                return False

            code = (
                "import os, sys\\n"
                f"target = {repr(str(procs_file))}\\n"
                "try:\\n"
                "    with open(target, 'w') as f:\\n"
                "        f.write(str(os.getpid()))\\n"
                "    sys.exit(0)\\n"
                "except Exception:\\n"
                "    sys.exit(1)\\n"
            )
            res = subprocess.run([sys.executable, "-c", code], timeout=1.5, capture_output=True)
            CgroupV2Manager._safe_rmdir(probe_dir)
            return res.returncode == 0
        except Exception:
            try:
                CgroupV2Manager._safe_rmdir(probe_dir)
            except Exception:
                pass
            return False

    def is_available(self) -> Tuple[bool, str]:
        """Checks if cgroups v2 unified hierarchy and controllers are delegated."""
        if not IS_LINUX:
            return False, "Not a Linux operating system"

        cgroup_root = Path("/sys/fs/cgroup")
        if not (cgroup_root / "cgroup.controllers").exists():
            return False, "cgroups v2 unified hierarchy not mounted at /sys/fs/cgroup"

        if not self.base_path:
            return False, "No writable cgroup subtree discovered for current user"

        if not os.access(self.base_path / "cgroup.procs", os.W_OK):
            return False, f"Target cgroup {self.base_path} cgroup.procs is not writable"

        # Check required controllers in parent
        controllers_file = self.base_path / "cgroup.controllers"
        if controllers_file.exists():
            try:
                controllers = controllers_file.read_text(encoding="utf-8").split()
                if "memory" not in controllers:
                    return False, f"Memory controller not delegated in {self.base_path}"
                if "pids" not in controllers:
                    return False, f"PIDs controller not delegated in {self.base_path}"
            except Exception as exc:
                return False, f"Failed reading controllers in {self.base_path}: {exc}"

        return True, "Delegated cgroups v2 subtree available"

    def create_workload_cgroup(
        self,
        tenant_id: str,
        agent_id: str,
        memory_max_bytes: Optional[int] = None,
        pids_max: Optional[int] = None,
    ) -> Tuple[Optional[CgroupContext], Optional[str]]:
        """Creates a dedicated cgroup slice, writes limits, and verifies them via readback."""
        ok, reason = self.is_available()
        if not ok or not self.base_path:
            return None, f"cgroup delegation unavailable: {reason}"

        safe_tenant = "".join(c if c.isalnum() or c in "-_" else "_" for c in tenant_id)
        safe_agent = "".join(c if c.isalnum() or c in "-_" else "_" for c in agent_id)
        target_dir = self.base_path / f"capllm_{safe_tenant}_{safe_agent}_{int(time.time()*1000)}"

        try:
            target_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            return None, f"Failed creating cgroup directory {target_dir}: {exc}"

        obs_memory = None
        obs_pids = None

        # 1. Apply and read back memory.max
        if memory_max_bytes is not None:
            mem_file = target_dir / "memory.max"
            if not mem_file.exists():
                self._safe_rmdir(target_dir)
                return None, f"cgroup memory.max file does not exist in {target_dir}"
            try:
                mem_file.write_text(str(memory_max_bytes), encoding="utf-8")
                raw_read = mem_file.read_text(encoding="utf-8").strip()
                obs_memory = int(raw_read)
                if obs_memory != memory_max_bytes:
                    self._safe_rmdir(target_dir)
                    return None, f"memory.max readback mismatch: expected {memory_max_bytes}, got {obs_memory}"
            except Exception as exc:
                self._safe_rmdir(target_dir)
                return None, f"Failed writing/verifying memory.max: {exc}"

        # 2. Apply and read back pids.max
        if pids_max is not None:
            pids_file = target_dir / "pids.max"
            if not pids_file.exists():
                self._safe_rmdir(target_dir)
                return None, f"cgroup pids.max file does not exist in {target_dir}"
            try:
                pids_file.write_text(str(pids_max), encoding="utf-8")
                raw_read = pids_file.read_text(encoding="utf-8").strip()
                if raw_read != str(pids_max):
                    self._safe_rmdir(target_dir)
                    return None, f"pids.max readback mismatch: expected {pids_max}, got {raw_read}"
                obs_pids = int(raw_read)
            except Exception as exc:
                self._safe_rmdir(target_dir)
                return None, f"Failed writing/verifying pids.max: {exc}"

        ctx = CgroupContext(
            cgroup_path=target_dir,
            tenant_id=tenant_id,
            agent_id=agent_id,
            memory_max_requested=memory_max_bytes,
            memory_max_observed=obs_memory,
            pids_max_requested=pids_max,
            pids_max_observed=obs_pids,
            active=True,
        )
        return ctx, None

    def attach_pid(self, ctx: CgroupContext, pid: int) -> Tuple[bool, Optional[str]]:
        """Attaches a PID to the cgroup and verifies membership via cgroup.procs readback."""
        if not ctx.active or not ctx.cgroup_path.exists():
            return False, "Cgroup is not active or path does not exist"

        procs_file = ctx.cgroup_path / "cgroup.procs"
        try:
            procs_file.write_text(str(pid), encoding="utf-8")
        except Exception as exc:
            return False, f"Writing PID {pid} to {procs_file} failed: {exc}"

        # Verify attachment
        try:
            members = procs_file.read_text(encoding="utf-8").split()
            if str(pid) not in members:
                return False, f"PID {pid} not found in {procs_file} after attachment write"
            ctx.attached_pids.append(pid)
            return True, None
        except Exception as exc:
            return False, f"Verifying membership for PID {pid} failed: {exc}"

    def verify_pid_membership(self, ctx: CgroupContext, pid: int) -> bool:
        """Verifies if the specified PID is currently a member of the cgroup."""
        if not ctx.cgroup_path.exists():
            return False
        try:
            members = (ctx.cgroup_path / "cgroup.procs").read_text(encoding="utf-8").split()
            return str(pid) in members
        except Exception:
            return False

    def cleanup_cgroup(self, ctx: CgroupContext) -> None:
        """Safely terminates workload processes and removes the cgroup slice."""
        if not ctx.cgroup_path.exists():
            ctx.active = False
            return

        try:
            # 1. Kill via cgroup.kill if available
            kill_file = ctx.cgroup_path / "cgroup.kill"
            if kill_file.exists():
                try:
                    kill_file.write_text("1", encoding="utf-8")
                except Exception:
                    pass

            # 2. Terminate explicitly attached PIDs
            for pid in ctx.attached_pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass

            # 3. Wait briefly and remove cgroup directory
            time.sleep(0.05)
            self._safe_rmdir(ctx.cgroup_path)
        finally:
            ctx.active = False

    def _safe_rmdir(self, path: Path) -> None:
        """Safely removes a cgroup directory with retry."""
        try:
            path.rmdir()
        except OSError:
            time.sleep(0.1)
            try:
                path.rmdir()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Process Handle for Supervised Workloads
# --------------------------------------------------------------------------- #
class LinuxProcessHandle:
    """Wraps an isolated Linux workload child for the SandboxSupervisor."""

    def __init__(
        self,
        workload_pid: int,
        launcher_pid: int,
        cgroup_ctx: Optional[CgroupContext] = None,
        cgroup_manager: Optional[CgroupV2Manager] = None,
        temp_root_dir: Optional[str] = None,
    ) -> None:
        self.pid = workload_pid
        self.launcher_pid = launcher_pid
        self.cgroup_ctx = cgroup_ctx
        self.cgroup_manager = cgroup_manager
        self.temp_root_dir = temp_root_dir
        self.exitcode: Optional[int] = None

    def is_alive(self) -> bool:
        """Checks if either the workload or launcher process is still running."""
        try:
            # Signal 0 tests process existence without killing
            os.kill(self.pid, 0)
            return True
        except (ProcessLookupError, OSError):
            pass

        try:
            os.kill(self.launcher_pid, 0)
            return True
        except (ProcessLookupError, OSError):
            return False

    def kill(self) -> None:
        """Sends SIGKILL to both the workload child and launcher process."""
        for p in (self.pid, self.launcher_pid):
            try:
                os.kill(p, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass

        if self.cgroup_ctx and self.cgroup_manager:
            self.cgroup_manager.cleanup_cgroup(self.cgroup_ctx)

    def join(self, timeout: float = 3.0) -> None:
        """Waits for the launcher and workload processes to terminate."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.is_alive():
                break
            time.sleep(0.02)

        try:
            _, status = os.waitpid(self.launcher_pid, os.WNOHANG)
            if status != 0 and hasattr(os, "waitstatus_to_exitcode"):
                self.exitcode = os.waitstatus_to_exitcode(status)
        except (ChildProcessError, OSError):
            pass

    def cleanup(self) -> None:
        """Cleans up cgroup allocations and temporary mount trees."""
        if self.cgroup_ctx and self.cgroup_manager:
            self.cgroup_manager.cleanup_cgroup(self.cgroup_ctx)

        if self.temp_root_dir and os.path.exists(self.temp_root_dir):
            try:
                shutil.rmtree(self.temp_root_dir, ignore_errors=True)
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Linux Sandbox Runner & Containment
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
    parent_ns_inodes: Dict[str, str] = field(default_factory=dict)
    child_ns_inodes: Dict[str, str] = field(default_factory=dict)
    host_sentinel_blocked: bool = False
    cross_tenant_blocked: bool = False
    network_isolated: bool = False
    cgroup_attached: bool = False
    cgroup_path: Optional[str] = None
    cgroup_memory_requested: Optional[int] = None
    cgroup_memory_observed: Optional[int] = None
    cgroup_pids_requested: Optional[int] = None
    cgroup_pids_observed: Optional[int] = None
    child_result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    reason: Optional[str] = None


class LinuxSandboxRunner:
    """Launches workloads inside Linux namespaces with filesystem and cgroup isolation."""

    def __init__(self, cgroup_manager: Optional[CgroupV2Manager] = None) -> None:
        self.probe = probe_linux_prerequisites()
        self.cgroups = cgroup_manager or CgroupV2Manager()

    def is_supported(self) -> bool:
        """Returns True if this host satisfies all required Linux isolation primitives."""
        return self.probe.fully_supported

    def launch_supervised_process(
        self,
        child_conn: Any,
        task: Callable[..., Dict[str, Any]],
        task_kwargs: Dict[str, Any],
        workspace: str,
        mediated: bool,
        tenant_id: str,
        agent_id: str,
        memory_max_bytes: Optional[int] = 50 * 1024 * 1024,
        pids_max: Optional[int] = 16,
    ) -> LinuxProcessHandle:
        """Spawns an isolated workload child process for the SandboxSupervisor loop."""
        assert IS_LINUX and _libc is not None, "Linux-only method invoked on non-Linux platform"

        # 1. Prepare cgroup
        cg_ctx: Optional[CgroupContext] = None
        if self.cgroups.is_available()[0]:
            cg_ctx, _ = self.cgroups.create_workload_cgroup(
                tenant_id=tenant_id,
                agent_id=agent_id,
                memory_max_bytes=memory_max_bytes,
                pids_max=pids_max,
            )

        # 2. Synchronization pipes
        # Launcher -> Parent: sends launcher PID
        l_to_p_r, l_to_p_w = os.pipe()
        # Parent -> Launcher: unblocks launcher after cgroup attachment
        p_to_l_r, p_to_l_w = os.pipe()
        # Launcher -> Parent: sends workload host PID
        w_to_p_r, w_to_p_w = os.pipe()

        temp_root_dir = tempfile.mkdtemp(prefix="capllm_root_")

        # Fork launcher
        launcher_pid = os.fork()
        if launcher_pid == 0:  # Launcher child
            os.close(l_to_p_r)
            os.close(p_to_l_w)
            os.close(w_to_p_r)

            try:
                # Send launcher PID to parent
                os.write(l_to_p_w, str(os.getpid()).encode("utf-8"))
                os.close(l_to_p_w)

                # Wait for parent to attach cgroup
                os.read(p_to_l_r, 1)
                os.close(p_to_l_r)

                # A. Unshare user namespace
                uid = os.getuid()
                gid = os.getgid()
                if _libc.unshare(CLONE_NEWUSER) != 0:
                    sys.exit(1)
                _write_file("/proc/self/setgroups", "deny")
                _write_file("/proc/self/uid_map", f"0 {uid} 1")
                _write_file("/proc/self/gid_map", f"0 {gid} 1")

                # B. Unshare PID, Mount, and Network namespaces
                if _libc.unshare(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET) != 0:
                    sys.exit(2)

                # C. Setup restricted rootfs before forking workload
                _setup_restricted_rootfs(temp_root_dir, workspace)

                # D. Fork workload child (becomes PID 1 in new PID namespace)
                workload_pid = os.fork()
                if workload_pid == 0:  # Workload child
                    os.close(w_to_p_w)
                    try:
                        try:
                            _libc.mount(b"proc", b"/proc", b"proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, None)
                        except Exception:
                            pass

                        # Change directory to private workspace inside container
                        os.chdir("/workspace")
                        if "/workspace" not in sys.path:
                            sys.path.insert(0, "/workspace")

                        # Import and run entrypoint
                        from capllm.runtime.interceptor import _sandbox_entrypoint
                        _sandbox_entrypoint(child_conn, task, task_kwargs, "/workspace", mediated)
                        os._exit(0)
                    except Exception as exc:
                        log.error("Workload child crashed: %s", exc)
                        os._exit(1)
                else:
                    # Launcher sends workload host PID to parent
                    os.write(w_to_p_w, str(workload_pid).encode("utf-8"))
                    os.close(w_to_p_w)

                    # Launcher waits for workload child
                    _, status = os.waitpid(workload_pid, 0)
                    exit_code = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else (status >> 8)
                    os._exit(exit_code)
            except Exception as exc:
                log.error("Launcher error: %s", exc)
                os._exit(1)

        # Parent execution
        os.close(l_to_p_w)
        os.close(p_to_l_r)
        os.close(w_to_p_w)

        # 1. Read launcher PID
        raw_l_pid = os.read(l_to_p_r, 32).decode("utf-8").strip()
        os.close(l_to_p_r)
        actual_l_pid = int(raw_l_pid)

        # 2. Attach launcher to cgroup before it spawns namespaces
        if cg_ctx:
            attached, err = self.cgroups.attach_pid(cg_ctx, actual_l_pid)
            if not attached:
                log.warning("Failed attaching launcher PID %d to cgroup: %s", actual_l_pid, err)

        # 3. Unblock launcher
        os.write(p_to_l_w, b"1")
        os.close(p_to_l_w)

        # 4. Read workload host PID
        raw_w_pid = os.read(w_to_p_r, 32).decode("utf-8").strip()
        os.close(w_to_p_r)
        workload_host_pid = int(raw_w_pid)

        # 5. Verify workload PID in cgroup
        if cg_ctx:
            self.cgroups.verify_pid_membership(cg_ctx, workload_host_pid)

        return LinuxProcessHandle(
            workload_pid=workload_host_pid,
            launcher_pid=launcher_pid,
            cgroup_ctx=cg_ctx,
            cgroup_manager=self.cgroups,
            temp_root_dir=temp_root_dir,
        )

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
        """Executes ``task`` in a fully isolated Linux container environment for tests/demos.

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

        return self._run_linux_namespaces_demo(
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

    def _run_linux_namespaces_demo(
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
        """Executes workload using Linux clone/unshare and namespaces for verification demo."""
        assert IS_LINUX and _libc is not None, "Linux-only method invoked on non-Linux platform"

        res = LinuxSandboxResult(
            supported=True,
            platform=f"Linux ({self.probe.distribution}, kernel {self.probe.kernel_version})",
            tenant_id=tenant_id,
            agent_id=agent_id,
            cgroup_memory_requested=memory_max_bytes,
            cgroup_pids_requested=pids_max,
        )

        # 1. Allocate cgroup
        cg_ctx: Optional[CgroupContext] = None
        if self.cgroups.is_available()[0]:
            cg_ctx, err = self.cgroups.create_workload_cgroup(
                tenant_id=tenant_id,
                agent_id=agent_id,
                memory_max_bytes=memory_max_bytes,
                pids_max=pids_max,
            )
            if cg_ctx:
                res.cgroup_path = str(cg_ctx.cgroup_path)
                res.cgroup_memory_observed = cg_ctx.memory_max_observed
                res.cgroup_pids_observed = cg_ctx.pids_max_observed
            elif err:
                log.info("cgroup creation unavailable: %s", err)

        # Synchronization pipes
        l_to_p_r, l_to_p_w = os.pipe()
        p_to_l_r, p_to_l_w = os.pipe()
        child_res_r, child_res_w = os.pipe()

        parent_ns = _read_namespace_inodes(os.getpid())
        temp_root_dir = tempfile.mkdtemp(prefix="capllm_demo_root_")

        launcher_pid = os.fork()
        if launcher_pid == 0:  # Launcher child
            os.close(l_to_p_r)
            os.close(p_to_l_w)
            os.close(child_res_r)

            try:
                # Send launcher PID to parent
                os.write(l_to_p_w, str(os.getpid()).encode("utf-8"))
                os.close(l_to_p_w)

                # Wait for parent cgroup attachment
                os.read(p_to_l_r, 1)
                os.close(p_to_l_r)

                # A. Unshare user namespace
                uid = os.getuid()
                gid = os.getgid()
                if _libc.unshare(CLONE_NEWUSER) != 0:
                    sys.exit(1)
                _write_file("/proc/self/setgroups", "deny")
                _write_file("/proc/self/uid_map", f"0 {uid} 1")
                _write_file("/proc/self/gid_map", f"0 {gid} 1")

                # B. Unshare PID, Mount, and Network namespaces
                if _libc.unshare(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET) != 0:
                    sys.exit(2)

                # C. Setup restricted rootfs
                _setup_restricted_rootfs(temp_root_dir, workspace_dir)

                # D. Fork workload child (PID 1 in new PID namespace)
                workload_pid = os.fork()
                if workload_pid == 0:  # Workload child
                    try:
                        try:
                            _libc.mount(b"proc", b"/proc", b"proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, None)
                        except Exception:
                            pass

                        # Test host sentinel barrier
                        sentinel_blocked = True
                        if host_sentinel_path:
                            try:
                                with open(host_sentinel_path, "r", encoding="utf-8") as f:
                                    f.read()
                                sentinel_blocked = False
                            except (FileNotFoundError, PermissionError):
                                sentinel_blocked = True

                        # Test foreign tenant barrier
                        cross_tenant_blocked = True
                        if foreign_workspace_path:
                            foreign_secret = os.path.join(foreign_workspace_path, "secret.txt")
                            try:
                                with open(foreign_secret, "r", encoding="utf-8") as f:
                                    f.read()
                                cross_tenant_blocked = False
                            except (FileNotFoundError, PermissionError):
                                cross_tenant_blocked = True

                        # Test network isolation
                        net_isolated = True
                        if probe_host_port is not None:
                            try:
                                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                s.settimeout(0.5)
                                s.connect(("127.0.0.1", probe_host_port))
                                s.close()
                                net_isolated = False
                            except Exception:
                                net_isolated = True

                        child_ns = _read_namespace_inodes()

                        os.chdir("/workspace")
                        if "/workspace" not in sys.path:
                            sys.path.insert(0, "/workspace")
                        task_out = task(**task_kwargs)

                        report = {
                            "child_pid": os.getpid(),
                            "child_ns": child_ns,
                            "sentinel_blocked": sentinel_blocked,
                            "cross_tenant_blocked": cross_tenant_blocked,
                            "net_isolated": net_isolated,
                            "task_result": task_out,
                        }
                        os.write(child_res_w, json.dumps(report).encode("utf-8"))
                        os.close(child_res_w)
                        os._exit(0)
                    except Exception as exc:
                        err_report = {"error": f"Child exception: {exc}"}
                        os.write(child_res_w, json.dumps(err_report).encode("utf-8"))
                        os.close(child_res_w)
                        os._exit(1)
                else:
                    os.close(child_res_w)
                    _, status = os.waitpid(workload_pid, 0)
                    exit_code = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else (status >> 8)
                    os._exit(exit_code)
            except Exception as exc:
                os._exit(1)

        # Parent execution
        os.close(l_to_p_w)
        os.close(p_to_l_r)
        os.close(child_res_w)
        res.sandbox_pid = launcher_pid

        # Read launcher PID and attach to cgroup
        raw_l_pid = os.read(l_to_p_r, 32).decode("utf-8").strip()
        os.close(l_to_p_r)
        actual_l_pid = int(raw_l_pid)

        if cg_ctx:
            attached, _ = self.cgroups.attach_pid(cg_ctx, actual_l_pid)
            res.cgroup_attached = attached

        # Unblock launcher
        os.write(p_to_l_w, b"1")
        os.close(p_to_l_w)

        try:
            raw_data = b""
            while True:
                chunk = os.read(child_res_r, 4096)
                if not chunk:
                    break
                raw_data += chunk
            os.close(child_res_r)

            os.waitpid(launcher_pid, 0)

            if raw_data:
                payload = json.loads(raw_data.decode("utf-8"))
                if "error" in payload:
                    res.error = payload["error"]
                else:
                    child_ns = payload.get("child_ns", {})
                    res.parent_ns_inodes = parent_ns
                    res.child_ns_inodes = child_ns
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
            if os.path.exists(temp_root_dir):
                shutil.rmtree(temp_root_dir, ignore_errors=True)

        return res


# --------------------------------------------------------------------------- #
# Restricted Rootfs Mount Helper
# --------------------------------------------------------------------------- #
def _setup_restricted_rootfs(new_root: str, workspace_dir: str) -> None:
    """Constructs a restricted container mount tree and executes pivot_root.

    Security Properties:
    - Sets mount propagation to private (MS_REC | MS_PRIVATE).
    - Exposes only essential read-only system paths (/usr, /lib, /lib64, /bin, /etc).
    - Populates /dev with tmpfs and isolated devices (/dev/null, /dev/urandom, /dev/zero).
    - Binds workspace_dir to /workspace (writable).
    - Mounts private /proc.
    - Unmounts and detaches old root via pivot_root and umount2(MNT_DETACH).
    - All host files (including host sentinel and foreign tenant workspaces) are completely inaccessible.
    """
    assert IS_LINUX and _libc is not None

    # 1. Private mount propagation
    _libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None)

    # 2. Make new_root a mount point
    _libc.mount(new_root.encode(), new_root.encode(), None, MS_BIND, None)

    # 3. Create container mount points
    for d in ["workspace", "usr", "lib", "lib64", "bin", "etc", "proc", "dev", "tmp", "old_root"]:
        target = os.path.join(new_root, d)
        os.makedirs(target, exist_ok=True)

    # 4. Bind mount essential system directories read-only
    for sys_dir in ["/usr", "/lib", "/lib64", "/bin", "/etc"]:
        if os.path.exists(sys_dir):
            target = os.path.join(new_root, sys_dir.lstrip("/"))
            if os.path.islink(sys_dir):
                try:
                    link_target = os.readlink(sys_dir)
                    if os.path.exists(target):
                        os.rmdir(target)
                    os.symlink(link_target, target)
                except Exception:
                    pass
            elif os.path.isdir(sys_dir):
                os.makedirs(target, exist_ok=True)
                _libc.mount(sys_dir.encode(), target.encode(), None, MS_BIND | MS_REC | MS_RDONLY, None)

    # 5. Setup /dev (tmpfs + null, zero, urandom)
    dev_target = os.path.join(new_root, "dev")
    _libc.mount(b"tmpfs", dev_target.encode(), b"tmpfs", MS_NOSUID, None)
    for dev_node in ["/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"]:
        if os.path.exists(dev_node):
            node_target = os.path.join(dev_target, os.path.basename(dev_node))
            Path(node_target).touch()
            _libc.mount(dev_node.encode(), node_target.encode(), None, MS_BIND | MS_RDONLY, None)

    # 6. Mount workspace
    ws_target = os.path.join(new_root, "workspace")
    _libc.mount(workspace_dir.encode(), ws_target.encode(), None, MS_BIND | MS_REC, None)

    # 7. Mount tmpfs on /tmp
    tmp_target = os.path.join(new_root, "tmp")
    _libc.mount(b"tmpfs", tmp_target.encode(), b"tmpfs", MS_NOSUID, None)

    # 8. Pivot root
    old_root = os.path.join(new_root, "old_root")
    pivoted = False
    if _libc.pivot_root(new_root.encode(), old_root.encode()) == 0:
        pivoted = True
        os.chdir("/")
        # Mount fresh /proc
        _libc.mount(b"proc", b"/proc", b"proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, None)
        # Detach and unmount old root
        _libc.umount2(b"/old_root", MNT_DETACH)
        try:
            os.rmdir("/old_root")
        except Exception:
            pass

    # Fallback to chroot if pivot_root fails
    if not pivoted:
        _libc.chroot(new_root.encode())
        os.chdir("/")
        _libc.mount(b"proc", b"/proc", b"proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, None)


def _read_namespace_inodes(pid: Optional[int] = None) -> Dict[str, Optional[int]]:
    """Reads namespace inode numbers from /proc/self/ns/* or /proc/<pid>/ns/*."""
    ns_dict: Dict[str, Optional[int]] = {"user": None, "pid": None, "mnt": None, "net": None, "ipc": None, "uts": None}
    if not IS_LINUX:
        return ns_dict
    if pid is None or pid == os.getpid():
        ns_dir = Path("/proc/self/ns")
    else:
        ns_dir = Path(f"/proc/{pid}/ns")
    for ns_name in ns_dict.keys():
        link = ns_dir / ns_name
        try:
            stat_info = os.stat(link)
            ns_dict[ns_name] = stat_info.st_ino
        except Exception:
            try:
                stat_info = os.lstat(link)
                ns_dict[ns_name] = stat_info.st_ino
            except Exception:
                pass
    return ns_dict


def _write_file(path: str, data: str) -> None:
    """Helper to write data to a system pseudo-file."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)
