#!/usr/bin/env python3
"""Stealth tool-decision audit log.

Records policy decisions without persisting raw sensitive values. This is an
observability layer, not an approval layer.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None


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


def _audit_config() -> dict[str, Any]:
    cfg = _load_config()
    sec = cfg.get("security") if isinstance(cfg.get("security"), dict) else {}
    audit = sec.get("tool_decision_audit") if isinstance(sec.get("tool_decision_audit"), dict) else {}
    return audit


def is_enabled() -> bool:
    return _active_profile_name() == "stealth" and _audit_config().get("enabled") is True


def _sha(value: Any) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        value = str(value)
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _log_path() -> Path:
    cfg = _audit_config()
    raw = cfg.get("log_path") or "security/tool_decisions.jsonl"
    path = Path(str(raw)).expanduser()
    if not path.is_absolute():
        path = _hermes_home() / path
    return path


def record_tool_decision(
    *,
    tool: str,
    decision: str,
    policy: str,
    reason: str = "",
    source_layer: str = "unknown",
    target: Any = None,
    target_kind: str = "unknown",
    session_id: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record a policy decision without raw target content."""
    if not is_enabled():
        return {"recorded": False, "reason": "disabled"}

    entry: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "profile": _active_profile_name(),
        "tool": str(tool or "unknown"),
        "decision": str(decision or "unknown"),
        "policy": str(policy or "unknown"),
        "reason": str(reason or ""),
        "source_layer": str(source_layer or "unknown"),
        "target_kind": str(target_kind or "unknown"),
        "target_sha256": _sha(target),
    }
    if session_id:
        entry["session_id_sha256"] = _sha(session_id)
    if extra:
        for key, value in extra.items():
            if key.endswith("_raw") or key in {"raw", "content", "command", "path", "query", "target"}:
                continue
            if isinstance(value, (str, int, float, bool)) or value is None:
                entry[key] = value

    try:
        path = _log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        return {"recorded": True, "path": str(path)}
    except Exception as exc:
        return {"recorded": False, "reason": str(exc)}
