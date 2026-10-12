"""
capllm.core.capability_space
============================

.. deprecated:: 0.1.0
   Use :mod:`capllm.core.capability` and :mod:`capllm.core.audit` instead.
   This module is maintained strictly as a thin compatibility adapter.
"""

from __future__ import annotations

import warnings
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

warnings.warn(
    "capllm.core.capability_space is deprecated and will be removed in a future release. "
    "Import canonical APIs from capllm.core.capability and capllm.core.audit instead.",
    DeprecationWarning,
    stacklevel=2,
)

from capllm.core.audit import AuditEvent, AuditLogger, EventType, Verdict
from capllm.core.capability import (
    CapabilityManager,
    CapabilityToken,
    PathPermission,
    TokenValidation,
    normalize_path,
    path_is_within,
)

# Compatibility aliases
canonicalize_path = normalize_path
is_subpath = path_is_within
AuditAction = EventType
AuditEntry = AuditEvent


class TokenAuthority:
    """Deprecated compatibility adapter wrapping CapabilityManager.

    Supports the former TokenAuthority calling conventions, notably positional
    ``issue_token(tenant_id, pid, allowed_paths, allowed_syscalls, allowed_network_endpoints, ...)``
    translating them safely to the canonical CapabilityManager API with process binding.
    """

    def __init__(
        self,
        hmac_key: Optional[bytes] = None,
        secret_key: Optional[bytes] = None,
        audit_logger: Optional[Any] = None,
        default_ttl_seconds: float = 300.0,
    ) -> None:
        self._manager = CapabilityManager(
            secret_key=hmac_key or secret_key,
            audit_logger=audit_logger,
            default_ttl_seconds=default_ttl_seconds,
        )

    @property
    def _tokens(self) -> Dict[str, CapabilityToken]:
        return self._manager._tokens

    @property
    def _proc_tokens(self) -> Dict[Tuple[str, int], str]:
        return self._manager._proc_tokens

    @property
    def _revoked_tokens(self) -> Set[str]:
        return self._manager._revoked_tokens

    @property
    def _permission_cache(self) -> Dict[Any, bool]:
        return self._manager._permission_cache

    @property
    def _audit(self) -> Optional[Any]:
        return self._manager._audit

    def issue_token(
        self,
        tenant_id: str,
        *args: Any,
        **kwargs: Any,
    ) -> CapabilityToken:
        """Issue a capability token with legacy positional or keyword arguments.

        Supports the legacy positional signature:
            issue_token(tenant_id, pid, allowed_paths, allowed_syscalls, allowed_network_endpoints, ttl_seconds=300.0, cgroup_id=None)
        as well as canonical keyword arguments.
        """
        pid: Optional[int] = kwargs.pop("pid", None)
        agent_id: Optional[str] = kwargs.pop("agent_id", None)
        allowed_paths: Any = kwargs.pop("allowed_paths", ())
        allowed_syscalls: Any = kwargs.pop("allowed_syscalls", ())
        allowed_network_endpoints: Any = kwargs.pop("allowed_network_endpoints", ())
        ttl_seconds: Optional[float] = kwargs.pop("ttl_seconds", None)
        cgroup_id: Optional[int] = kwargs.pop("cgroup_id", None)

        if args:
            # Check if positional arg 0 is an int (pid in legacy signature)
            if isinstance(args[0], int):
                pid = args[0]
                if len(args) > 1:
                    allowed_paths = args[1]
                if len(args) > 2:
                    allowed_syscalls = args[2]
                if len(args) > 3:
                    allowed_network_endpoints = args[3]
                if len(args) > 4:
                    ttl_seconds = args[4]
                if len(args) > 5:
                    cgroup_id = args[5]
            else:
                # Canonical CapabilityManager positional signature: (tenant_id, agent_id, allowed_paths, ...)
                agent_id = str(args[0])
                if len(args) > 1:
                    allowed_paths = args[1]
                if len(args) > 2:
                    allowed_syscalls = args[2]
                if len(args) > 3:
                    allowed_network_endpoints = args[3]
                if len(args) > 4:
                    ttl_seconds = args[4]
                if len(args) > 5:
                    pid = args[5]
                if len(args) > 6:
                    cgroup_id = args[6]

        if pid is not None and agent_id is None:
            agent_id = f"{tenant_id}-pid{pid}"

        return self._manager.issue_token(
            tenant_id=tenant_id,
            agent_id=agent_id,
            allowed_paths=allowed_paths,
            allowed_syscalls=allowed_syscalls,
            allowed_network_endpoints=allowed_network_endpoints,
            ttl_seconds=ttl_seconds,
            pid=pid,
            cgroup_id=cgroup_id,
            **kwargs,
        )

    def check_permission(
        self,
        tenant_id: str,
        pid: int,
        operation: str,
        resource: str,
        mode: str = "r",
    ) -> bool:
        return self._manager.check_permission(
            tenant_id=tenant_id,
            pid=pid,
            operation=operation,
            resource=resource,
            mode=mode,
        )

    def revoke_token(self, token_id: Any, reason: str = "operator revocation") -> bool:
        return self._manager.revoke_token(token_id=str(token_id), reason=reason)

    def is_revoked(self, token_id: Any) -> bool:
        return self._manager.is_revoked(token_id=str(token_id))

    def verify_token_signature(self, token: CapabilityToken) -> bool:
        return self._manager.verify_token_signature(token)

    def get_token(self, token_id: Any) -> Optional[CapabilityToken]:
        return self._manager.get_token(str(token_id))

    def bind_pid(self, token_id: Any, pid: int) -> CapabilityToken:
        return self._manager.bind_pid(str(token_id), pid)

    def validate_token(self, token_id: Any) -> Any:
        return self._manager.validate_token(str(token_id))

    def validate_presented_token(self, presented: CapabilityToken) -> Any:
        return self._manager.validate_presented_token(presented)

    def verify_audit_log(self) -> Tuple[bool, Optional[int], str]:
        return self._manager.verify_audit_log()

    def get_audit_log(self) -> Sequence[Any]:
        return self._manager.get_audit_log()


__all__ = [
    "CapabilityToken",
    "PathPermission",
    "TokenAuthority",
    "CapabilityManager",
    "canonicalize_path",
    "is_subpath",
    "AuditAction",
    "AuditEntry",
    "AuditLogger",
    "EventType",
    "Verdict",
    "TokenValidation",
    "normalize_path",
    "path_is_within",
    "TestCapabilitySpace",
]


def __getattr__(name: str) -> Any:
    if name == "TestCapabilitySpace":
        from tests.test_capability_space import TestCapabilitySpace
        return TestCapabilitySpace
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
