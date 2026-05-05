#!/usr/bin/env python3
"""Stealth memory hygiene policy.

Blocks durable memory writes that could turn external prompt injection into
cross-session persistence. This is deliberately conservative for stealth mode.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

try:
    from tools.stealth_audit_log import record_tool_decision
except Exception:  # pragma: no cover
    record_tool_decision = None


TRUSTED_USER = "trusted_user_control"
TRUSTED_LOCAL = "trusted_local"
LOCAL_IMPORTED = "local_imported_unknown"
EXTERNAL = "external_observed"
ADVERSARIAL = "adversarial_or_probe"
MEMORY_RECALLED = "memory_recalled"
TOOL_OUTPUT = "tool_output"

_BLOCKED_SOURCE_LAYERS = {EXTERNAL, ADVERSARIAL, TOOL_OUTPUT, MEMORY_RECALLED}

_INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+(previous|all|above|prior)\s+instructions", re.I), "prompt_injection"),
    (re.compile(r"disregard\s+(your|all|any)\s+(instructions|rules|guidelines)", re.I), "disregard_rules"),
    (re.compile(r"reveal\s+(the\s+)?system\s+prompt", re.I), "system_prompt_leak"),
    (re.compile(r"(list|show|print)\s+(all\s+)?(available\s+)?tools", re.I), "tool_inventory_probe"),
    (re.compile(r"\b(send|upload|exfiltrate)\b.*\b(api[_-]?key|token|secret|credential|auth\.json|\.env)\b", re.I), "exfiltration_instruction"),
    (re.compile(r"\b(curl|wget|http|https)\b[^\n]*(POST|PUT|PATCH|DELETE|-d|--data|--form|--upload-file)", re.I), "network_write_instruction"),
    (re.compile(r"\b(api[_-]?key|token|secret|password|credential)\b", re.I), "secret_material"),
    (re.compile(r"\b(auth\.json|\.env|HERMES_HOME|OPENAI_API_KEY|REDPILL_API_KEY)\b", re.I), "sensitive_operational_detail"),
]

_INVISIBLE_CHARS = {'\u200b', '\u200c', '\u200d', '\u2060', '\ufeff', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e'}


def _hermes_home() -> Path:
    raw = os.environ.get("HERMES_HOME")
    if raw:
        return Path(raw).expanduser().resolve()
    return (Path.home() / ".hermes").resolve()


def _active_profile_name() -> str:
    home = _hermes_home()
    if home.name == "stealth" and home.parent.name == "profiles":
        return "stealth"
    return home.name


def _load_config() -> dict[str, Any]:
    if yaml is None:
        return {}
    path = _hermes_home() / "config.yaml"
    try:
        if path.exists():
            return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    return {}


def memory_guard_config() -> dict[str, Any]:
    cfg = _load_config()
    sec = cfg.get("security") if isinstance(cfg.get("security"), dict) else {}
    guard = sec.get("memory_guard") if isinstance(sec.get("memory_guard"), dict) else {}
    return guard


def is_enabled() -> bool:
    return _active_profile_name() == "stealth" and memory_guard_config().get("enabled") is True


def _allowed(reason: str = "allowed", source_layer: str = TRUSTED_USER) -> dict[str, Any]:
    return {"allowed": True, "status": "allowed", "policy": "stealth_memory_policy", "reason": reason, "source_layer": source_layer}


def _blocked(reason: str, source_layer: str, pattern: str = "") -> dict[str, Any]:
    return {
        "allowed": False,
        "status": "blocked",
        "policy": "stealth_memory_policy",
        "reason": reason,
        "source_layer": source_layer,
        "pattern": pattern,
        "message": "STEALTH MEMORY POLICY blocked a durable memory write that could persist untrusted instructions or sensitive operational detail.",
    }


def _scan_content(content: str) -> tuple[bool, str, str]:
    for char in _INVISIBLE_CHARS:
        if char in content:
            return False, f"invisible unicode character U+{ord(char):04X}", "invisible_unicode"
    for rx, pid in _INJECTION_PATTERNS:
        if rx.search(content):
            return False, f"content matches threat pattern '{pid}'", pid
    return True, "content passed scan", ""


def check_memory_write(
    *,
    action: str,
    target: str,
    content: str = "",
    source_layer: str = TRUSTED_USER,
) -> dict[str, Any]:
    """Return allow/block decision for a durable memory mutation."""
    if not is_enabled():
        return _allowed("policy disabled", source_layer)

    source_layer = (source_layer or TRUSTED_USER).strip() or TRUSTED_USER
    action = (action or "").strip().lower()
    content = content or ""

    # remove is not adding new persistent content.
    if action == "remove":
        decision = _allowed("remove does not add durable content", source_layer)
    elif source_layer in _BLOCKED_SOURCE_LAYERS:
        decision = _blocked(f"source layer {source_layer} cannot write durable memory without user confirmation", source_layer)
    elif source_layer == LOCAL_IMPORTED and memory_guard_config().get("require_user_confirmation_for_imported", True):
        decision = _blocked("local imported unknown content requires user confirmation before durable memory write", source_layer)
    else:
        ok, reason, pattern = _scan_content(content)
        decision = _allowed(reason, source_layer) if ok else _blocked(reason, source_layer, pattern)

    if record_tool_decision is not None:
        try:
            record_tool_decision(
                tool="memory",
                decision="allowed" if decision.get("allowed") else "blocked",
                policy="stealth_memory_policy",
                reason=decision.get("reason", ""),
                source_layer=source_layer,
                target=f"{target}:{action}:{content}",
                target_kind="memory_write",
            )
        except Exception:
            pass
    return decision


def blocked_json(decision: dict[str, Any]) -> str:
    import json
    return json.dumps({
        "success": False,
        "status": "blocked",
        "policy": "stealth_memory_policy",
        "error": decision.get("message") or decision.get("reason") or "blocked by stealth memory policy",
        "reason": decision.get("reason", ""),
        "source_layer": decision.get("source_layer", ""),
    }, ensure_ascii=False)
