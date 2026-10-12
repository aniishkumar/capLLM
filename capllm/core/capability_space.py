"""
capllm.core.capability_space
============================

.. deprecated:: 0.1.0
   Use :mod:`capllm.core.capability` and :mod:`capllm.core.audit` instead.
   This module is maintained strictly as a thin compatibility wrapper.
"""

from __future__ import annotations

import warnings
from typing import Any, Dict, List, Optional, Set, Tuple, Union

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
TokenAuthority = CapabilityManager

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

