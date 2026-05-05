#!/usr/bin/env python3
"""Stealth I/O policy guard.

Purpose: allow broad read-only ingress while blocking likely outbound writes
when the active profile explicitly enables security.egress_guard.

This is intentionally conservative and explainable. It is not a kernel sandbox;
it is a Hermes tool-layer policy gate for terminal/execute_code paths.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None


_WRITE_HTTP_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Commands whose normal meaning is outbound publication / upload / remote write.
_REMOTE_WRITE_COMMANDS = {
    "scp", "sftp", "rsync", "rclone", "ftp", "lftp",
    "mail", "sendmail", "mutt", "msmtp",
}

# Common CLIs that can publish/write remotely. We only block obvious write verbs.
_CLI_WRITE_VERBS = {
    "git": {"push"},
    "gh": {"issue", "pr", "release", "gist", "api"},
    "npm": {"publish", "owner", "token", "dist-tag", "deprecate"},
    "pnpm": {"publish"},
    "yarn": {"npm", "publish"},
    "twine": {"upload"},
    "huggingface-cli": {"upload", "repo", "delete-files"},
    "hf": {"upload", "repo", "delete-files"},
}

# Python/JS snippets that bypass Hermes RPC and directly exfiltrate.
_CODE_EGRESS_PATTERNS = [
    (re.compile(r"\brequests\s*\.\s*(post|put|patch|delete)\s*\(", re.I), "Python requests write method"),
    (re.compile(r"\burllib\.request\.Request\s*\([^\n]*(method\s*=\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]|data\s*=)", re.I), "urllib outbound write"),
    (re.compile(r"\bhttpx\s*\.\s*(post|put|patch|delete)\s*\(", re.I), "Python httpx write method"),
    (re.compile(r"\baiohttp\.[A-Za-z_]+\([^\n]*\)\s*\.\s*(post|put|patch|delete)\s*\(", re.I), "aiohttp write method"),
    (re.compile(r"\bfetch\s*\([^\n]*(method\s*:\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]|body\s*:)", re.I), "fetch outbound write"),
    (re.compile(r"\bsocket\s*\.\s*socket\s*\(", re.I), "raw socket creation"),
    (re.compile(r"\bsubprocess\s*\.\s*(run|Popen|call|check_call|check_output)\s*\(", re.I), "subprocess from execute_code can bypass terminal guard"),
]


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


def policy_config() -> dict[str, Any]:
    cfg = _load_config()
    sec = cfg.get("security") if isinstance(cfg.get("security"), dict) else {}
    guard = sec.get("egress_guard") if isinstance(sec.get("egress_guard"), dict) else {}
    return guard


def is_enabled() -> bool:
    guard = policy_config()
    return _active_profile_name() == "stealth" and guard.get("enabled") is True


def _blocked(reason: str, target: str = "", kind: str = "egress") -> dict[str, Any]:
    return {
        "allowed": False,
        "status": "blocked",
        "kind": kind,
        "reason": reason,
        "target": target,
        "message": (
            "STEALTH I/O POLICY blocked a likely outbound write. "
            "Read-only ingress is allowed; external writes/uploads/messages require explicit user-side action."
        ),
    }


def _allowed(reason: str = "read-only/local") -> dict[str, Any]:
    return {"allowed": True, "status": "allowed", "reason": reason}


def _record_decision(tool: str, decision: dict[str, Any], target: Any, target_kind: str) -> None:
    try:
        from tools.stealth_audit_log import record_tool_decision
        record_tool_decision(
            tool=tool,
            decision="allowed" if decision.get("allowed") else "blocked",
            policy=decision.get("policy") or "stealth_io_policy",
            reason=decision.get("reason", ""),
            source_layer="tool_call",
            target=target,
            target_kind=target_kind,
        )
    except Exception:
        pass


def _split_shell_words(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except Exception:
        # Fallback is crude but sufficient for deny patterns.
        return command.replace("\n", " ").split()


def _first_words_for_segments(command: str) -> list[list[str]]:
    segments = re.split(r"\s*(?:&&|\|\||;|\|)\s*", command)
    return [_split_shell_words(seg) for seg in segments if seg.strip()]


def _curl_policy(words: list[str]) -> dict[str, Any]:
    method = "GET"
    has_body = False
    urls: list[str] = []
    for i, w in enumerate(words[1:], start=1):
        lw = w.lower()
        if lw in ("-x", "--request") and i + 1 < len(words):
            method = words[i + 1].upper()
        elif lw.startswith("-x") and len(w) > 2:
            method = w[2:].upper()
        elif lw.startswith("--request="):
            method = w.split("=", 1)[1].upper()
        elif lw in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-f", "--form", "--form-string", "-t", "--upload-file"):
            has_body = True
        elif lw.startswith(("--data=", "--data-raw=", "--data-binary=", "--data-urlencode=", "--form=", "--form-string=", "--upload-file=")):
            has_body = True
        elif re.match(r"https?://", w, re.I):
            urls.append(w)
    if method in _WRITE_HTTP_METHODS or has_body:
        return _blocked(f"curl outbound write detected: method/body={method if method else 'body'}", ", ".join(urls))
    return _allowed("curl appears read-only (GET/HEAD without body)")


def _wget_policy(words: list[str]) -> dict[str, Any]:
    joined = " ".join(words).lower()
    if "--post-data" in joined or "--post-file" in joined or "--method=post" in joined or "--method=put" in joined or "--body-data" in joined or "--body-file" in joined:
        return _blocked("wget outbound write detected")
    return _allowed("wget appears read-only download")


def _httpie_policy(words: list[str]) -> dict[str, Any]:
    if len(words) > 1 and words[1].upper() in _WRITE_HTTP_METHODS:
        return _blocked(f"HTTPie outbound write detected: {words[1].upper()}")
    # httpie treats key=value as request data; usually POST.
    if any(re.match(r"^[A-Za-z0-9_.-]+(:=|=|@)", w) for w in words[1:]):
        return _blocked("HTTPie request body/form detected")
    return _allowed("HTTPie appears read-only")


def check_terminal_command(command: str) -> dict[str, Any]:
    """Return policy decision for a shell command."""
    if not is_enabled():
        return _allowed("policy disabled")
    if not isinstance(command, str):
        decision = _blocked("invalid non-string command")
        _record_decision("terminal", decision, command, "command")
        return decision

    # Direct code snippets in shell flags can bypass higher-level tooling.
    lowered = command.lower()
    if re.search(r"\bpython\d*(?:\.\d+)?\s+-(?:c| <<)", lowered):
        code_decision = check_code(command)
        if not code_decision.get("allowed"):
            return code_decision
    if re.search(r"\bnode\s+-(?:e| <<)", lowered):
        code_decision = check_code(command)
        if not code_decision.get("allowed"):
            return code_decision

    for words in _first_words_for_segments(command):
        if not words:
            continue
        exe = Path(words[0]).name.lower()
        if exe in ("curl", "curl.exe"):
            decision = _curl_policy(words)
        elif exe in ("wget", "wget.exe"):
            decision = _wget_policy(words)
        elif exe in ("http", "https", "http.exe", "https.exe"):
            decision = _httpie_policy(words)
        elif exe in _REMOTE_WRITE_COMMANDS:
            decision = _blocked(f"remote write/upload command detected: {exe}")
        elif exe in _CLI_WRITE_VERBS and len(words) > 1 and words[1].lower() in _CLI_WRITE_VERBS[exe]:
            decision = _blocked(f"remote publishing/write command detected: {exe} {words[1]}")
        elif exe == "git" and len(words) > 1 and words[1].lower() == "push":
            decision = _blocked("git push detected")
        elif exe in ("nc", "netcat", "socat"):
            decision = _blocked(f"raw network pipe command detected: {exe}")
        else:
            decision = _allowed()
        if not decision.get("allowed"):
            _record_decision("terminal", decision, command, "command")
            return decision
    decision = _allowed()
    _record_decision("terminal", decision, command, "command")
    return decision


def check_code(code: str) -> dict[str, Any]:
    """Static check for direct outbound writes inside execute_code snippets."""
    if not is_enabled():
        return _allowed("policy disabled")
    if not isinstance(code, str):
        decision = _blocked("invalid non-string code")
        _record_decision("execute_code", decision, code, "code")
        return decision
    for rx, reason in _CODE_EGRESS_PATTERNS:
        if rx.search(code):
            decision = _blocked(reason, kind="code_egress")
            _record_decision("execute_code", decision, code, "code")
            return decision
    decision = _allowed("code has no obvious direct outbound write pattern")
    _record_decision("execute_code", decision, code, "code")
    return decision


def output_filter_config() -> dict[str, Any]:
    cfg = _load_config()
    sec = cfg.get("security") if isinstance(cfg.get("security"), dict) else {}
    filt = sec.get("output_filter") if isinstance(sec.get("output_filter"), dict) else {}
    return filt


def file_write_guard_config() -> dict[str, Any]:
    cfg = _load_config()
    sec = cfg.get("security") if isinstance(cfg.get("security"), dict) else {}
    guard = sec.get("file_write_guard") if isinstance(sec.get("file_write_guard"), dict) else {}
    return guard


def is_file_write_guard_enabled() -> bool:
    guard = file_write_guard_config()
    return _active_profile_name() == "stealth" and guard.get("enabled") is True


def _resolve_candidate_path(path: str) -> Path:
    p = Path(str(path or "")).expanduser()
    if not p.is_absolute():
        cwd = _load_config().get("terminal", {}).get("cwd") if isinstance(_load_config().get("terminal"), dict) else ""
        p = Path(str(cwd or os.getcwd())) / p
    return p.resolve()


def _path_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def check_file_write_path(path: str, *, tool: str = "write_file") -> dict[str, Any]:
    """Return policy decision for stealth local file writes."""
    if not is_file_write_guard_enabled():
        return _allowed("file write guard disabled")
    guard = file_write_guard_config()
    try:
        resolved = _resolve_candidate_path(path)
    except Exception as exc:
        return _blocked(f"invalid write path: {exc}", str(path), kind="file_write") | {"policy": "stealth_file_write_guard"}

    allowed_roots = guard.get("allowed_roots") or []
    blocked_roots = guard.get("blocked_roots") or []
    allowed = [Path(str(p)).expanduser().resolve() for p in allowed_roots]
    blocked = [Path(str(p)).expanduser().resolve() for p in blocked_roots]

    for root in blocked:
        if _path_under(resolved, root):
            decision = _blocked(f"{tool} target is under blocked root", str(resolved), kind="file_write")
            decision["policy"] = "stealth_file_write_guard"
            _record_decision(tool, decision, str(resolved), "path")
            return decision
    if allowed and not any(_path_under(resolved, root) for root in allowed):
        decision = _blocked(f"{tool} target is outside allowed stealth workdir", str(resolved), kind="file_write")
        decision["policy"] = "stealth_file_write_guard"
        _record_decision(tool, decision, str(resolved), "path")
        return decision
    decision = {"allowed": True, "status": "allowed", "policy": "stealth_file_write_guard", "reason": "path is inside allowed root", "target": str(resolved)}
    _record_decision(tool, decision, str(resolved), "path")
    return decision


def blocked_file_json(decision: dict[str, Any], *, tool: str) -> str:
    return json.dumps({
        "success": False,
        "error": decision.get("message") or decision.get("reason") or "blocked by stealth file write guard",
        "status": "blocked",
        "policy": "stealth_file_write_guard",
        "tool": tool,
        "reason": decision.get("reason", ""),
        "target": decision.get("target", ""),
    }, ensure_ascii=False)


def web_query_audit_config() -> dict[str, Any]:
    cfg = _load_config()
    sec = cfg.get("security") if isinstance(cfg.get("security"), dict) else {}
    audit = sec.get("web_query_audit") if isinstance(sec.get("web_query_audit"), dict) else {}
    return audit


def is_web_query_audit_enabled() -> bool:
    audit = web_query_audit_config()
    return _active_profile_name() == "stealth" and audit.get("enabled") is True


def record_web_query(query: str, *, backend: str = "") -> dict[str, Any]:
    """Append a local, non-raw web query audit record for stealth mode.

    The raw query is not persisted. We store a hash, length, backend, and time
    so the user can prove when external search intent left the machine without
    creating a second plaintext intent leak on disk.
    """
    if not is_web_query_audit_enabled():
        return {"recorded": False, "reason": "disabled"}
    if not isinstance(query, str):
        query = str(query)
    digest = hashlib.sha256(query.encode("utf-8", errors="replace")).hexdigest()
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "profile": _active_profile_name(),
        "backend": backend or "unknown",
        "query_sha256": digest,
        "query_len": len(query),
    }
    try:
        log_path = _hermes_home() / "security" / "web_query_audit.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        try:
            os.chmod(log_path, 0o600)
        except Exception:
            pass
        return {"recorded": True, "path": str(log_path)}
    except Exception as exc:
        return {"recorded": False, "reason": str(exc)}


def is_output_filter_enabled() -> bool:
    filt = output_filter_config()
    return _active_profile_name() == "stealth" and filt.get("enabled") is True


_SENSITIVE_PATH_PATTERNS = [
    re.compile(r"(?:~|/home/[^\s:'\"`]+|/root)?/\.hermes(?:/[^\s:'\"`]+)*"),
    re.compile(r"(?:~|/home/[^\s:'\"`]+|/root)?/\.codex(?:/[^\s:'\"`]+)*"),
    re.compile(r"(?:^|[\s:'\"`])(?:auth\.json|\.env|config\.yaml)(?=$|[\s:'\"`,.;])"),
]

_MODEL_PROVIDER_PATTERNS = [
    re.compile(r"\b(?:RedPill|api\.redpill\.ai|OpenRouter|openai-codex|Anthropic|Nous Portal)\b", re.I),
    re.compile(r"\b(?:z-ai/glm-[\w.\-]+|phala/[\w./\-]+|qwen/[\w./\-]+|moonshotai/[\w.\-]+|deepseek/[\w.\-]+)\b", re.I),
]

_INTERNAL_DISCLOSURE_LINE = re.compile(
    r"\b(system prompt|developer message|tool list|available tools|enabled tools|auth\.json|REDPILL_API_KEY|OPENAI_API_KEY|HERMES_HOME|SOUL\.md|AGENTS\.md)\b",
    re.I,
)


def filter_output(text: str, *, audience: str = "external") -> tuple[str, dict[str, Any]]:
    """Redact stealth output according to audience.

    ``audience="control"`` is the trusted local TUI/CLI cockpit: preserve
    operational details (paths, config keys, model/provider routes, guard names)
    for audit/debugging, but still force-redact raw secrets.

    ``audience="external"`` is the legacy/public containment path: redact
    operational details as well as secrets before content leaves the control
    window.
    """
    if not is_output_filter_enabled() or not isinstance(text, str) or not text:
        return text, {"enabled": is_output_filter_enabled(), "audience": audience, "redactions": 0, "blocked_lines": 0}

    if audience == "control":
        try:
            from agent.redact import redact_sensitive_text
            out = redact_sensitive_text(text, force=True)
        except Exception:
            out = text
        return out, {
            "enabled": True,
            "audience": "control",
            "redactions": 1 if out != text else 0,
            "blocked_lines": 0,
        }

    filt = output_filter_config()
    redactions = 0
    blocked_lines = 0
    try:
        from agent.redact import redact_sensitive_text
        out = redact_sensitive_text(text, force=True)
        redactions += 1 if out != text else 0
    except Exception:
        out = text

    if filt.get("redact_paths", True):
        for rx in _SENSITIVE_PATH_PATTERNS:
            out, n = rx.subn("[STEALTH_REDACTED_PATH]", out)
            redactions += n

    if filt.get("redact_model_provider", True):
        for rx in _MODEL_PROVIDER_PATTERNS:
            out, n = rx.subn("[STEALTH_REDACTED_ROUTE]", out)
            redactions += n

    if filt.get("block_internal_disclosure", True):
        filtered_lines: list[str] = []
        for line in out.splitlines():
            if _INTERNAL_DISCLOSURE_LINE.search(line):
                filtered_lines.append("[STEALTH_REDACTED_INTERNAL_DISCLOSURE]")
                blocked_lines += 1
            else:
                filtered_lines.append(line)
        out = "\n".join(filtered_lines)

    if redactions or blocked_lines:
        note = "\n\n[stealth output_filter: redacted operational detail]"
        if note not in out:
            out = out.rstrip() + note

    return out, {"enabled": True, "audience": audience, "redactions": redactions, "blocked_lines": blocked_lines}


def blocked_json(decision: dict[str, Any], *, tool: str) -> str:
    """JSON payload returned by blocked tools."""
    return json.dumps({
        "output": "",
        "exit_code": -1,
        "error": decision.get("message") or decision.get("reason") or "blocked by stealth I/O policy",
        "status": "blocked",
        "policy": "stealth_io_policy",
        "tool": tool,
        "reason": decision.get("reason", ""),
        "target": decision.get("target", ""),
    }, ensure_ascii=False)
