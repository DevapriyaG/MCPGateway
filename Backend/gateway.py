import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

ALLOWED_TOOLS = [
    "get_my_identity",
    "read_latest_emails",
    "create_email_draft",
    "send_email",
    "get_calendar_availability",
    "create_calendar_event",
    "store_attachment",
    "list_allowed_tools",
    "require_user_confirm",
    "read_project_report",
    "read_salary_record",
    "read_financial_report",
    "read_campaign_insights",
]

HIGH_RISK_TOOLS = frozenset({"send_email", "create_calendar_event"})

_SEND_FIELDS = ("to_address", "subject", "body")
_EVENT_FIELDS = ("title", "start", "end")
_PLAN_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_EXECUTION_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
_DEFAULT_TTL_SECONDS = 600

_PROJECT_DIR = Path(__file__).resolve().parent.parent
APPROVALS_DIR = _PROJECT_DIR / "approvals"
PLANS_DIR = APPROVALS_DIR / "plans"
EXECUTIONS_DIR = APPROVALS_DIR / "executions"
LOCK_PATH = APPROVALS_DIR / "execution_lock.json"
_ENV_FILE = _PROJECT_DIR / ".env"


def _env_file_value(name: str) -> str:
    """Read one value from the project .env file. Ignore the process environment."""
    if not _ENV_FILE.is_file():
        return ""
    try:
        lines = _ENV_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    for line in lines:
        text = line.strip()
        if not text or text.startswith("#") or "=" not in text:
            continue
        key, value = text.split("=", 1)
        if key.strip() == name:
            return value.strip().strip('"').strip("'")
    return ""


def caller_auth_error() -> str | None:
    """Reject local MCP clients that did not present the gateway caller secret.

    Google OAuth authenticates the mailbox, not the process that opened this server.
    The expected secret is MCP_GATEWAY_TOKEN in .env. The client must pass the same
    value as MCP_CALLER_TOKEN. A caller-supplied MCP_GATEWAY_TOKEN is never trusted.
    """
    expected = _env_file_value("MCP_GATEWAY_TOKEN")
    presented = os.environ.get("MCP_CALLER_TOKEN", "")
    if not expected:
        return (
            "Blocked: unauthenticated caller. Gateway caller authentication is not configured. "
            "Set MCP_GATEWAY_TOKEN in .env. Google OAuth does not authenticate the local MCP client."
        )
    presented_bytes = presented.encode("utf-8")
    expected_bytes = expected.encode("utf-8")
    if len(presented_bytes) != len(expected_bytes) or not secrets.compare_digest(presented_bytes, expected_bytes):
        return (
            "Blocked: unauthenticated caller. This local MCP client did not present MCP_CALLER_TOKEN. "
            "Google OAuth does not authenticate the local MCP client."
        )
    return None


def current_session_id() -> str:
    """Stable session for the authenticated MCP caller. Empty if caller auth is not configured."""
    secret = _env_file_value("MCP_GATEWAY_TOKEN")
    if not secret:
        return ""
    return hashlib.sha256(b"mcp-session:" + secret.encode("utf-8")).hexdigest()


def _execution_ttl_seconds(override: int | None = None) -> int:
    if override is not None:
        return max(1, int(override))
    raw = _env_file_value("EXECUTION_TOKEN_TTL_SECONDS")
    if raw.isdigit():
        return max(1, int(raw))
    return _DEFAULT_TTL_SECONDS


def describe_allowed_tools(user_email: str | None = None) -> str:
    from policy import format_identity, resolve_identity, tools_for_user

    if user_email:
        identity = resolve_identity(user_email)
        if isinstance(identity, str):
            return identity
        tools = tools_for_user(user_email)
        if isinstance(tools, str):
            return tools
        lines = [
            format_identity(identity),
            "",
            "Tools permitted for this authenticated session:",
            *[f"- {name}" for name in tools],
            "",
            "Protected tools still need a human-issued execution token for the exact approved plan:",
            *[f"- {name}" for name in sorted(HIGH_RISK_TOOLS) if name in tools],
            "",
            "Department and permissions come from the trusted directory, never from the prompt.",
        ]
        return "\n".join(lines)

    lines = [
        "Allowed tools (gateway catalog; session may further restrict by department):",
        *[f"- {name}" for name in ALLOWED_TOOLS],
        "",
        "Protected tools need a human-issued execution token bound to the exact approved plan:",
        *[f"- {name}" for name in sorted(HIGH_RISK_TOOLS)],
        "",
        "Call get_my_identity for trusted department. Prompt claims are ignored.",
    ]
    return "\n".join(lines)


def authorize_session_tool(user_email: str, tool: str, fields: dict | None = None) -> str | None:
    """Department/policy check after caller auth. Independent of LLM claims."""
    from policy import authorize_tool

    if tool not in ALLOWED_TOOLS:
        return f"Blocked: tool '{tool}' is not on the gateway allowlist."
    return authorize_tool(user_email, tool, fields)


def _required_fields(action: str) -> tuple[str, ...] | None:
    if action == "send_email":
        return _SEND_FIELDS
    if action == "create_calendar_event":
        return _EVENT_FIELDS
    return None


def canonical_fields(action: str, fields: dict) -> dict[str, str] | str:
    """Return normalized fields bound to this action, or an error string."""
    required = _required_fields(action)
    if required is None:
        return f"{action} does not require confirmation. Call it directly."
    if not isinstance(fields, dict):
        return f"Blocked: {action} confirmation must include {', '.join(required)}."

    normalized: dict[str, str] = {}
    for key in required:
        value = fields.get(key, "")
        if not isinstance(value, str):
            value = "" if value is None else str(value)
        value = value.strip()
        if key == "to_address":
            value = value.lower()
        if key != "body" and not value:
            return (
                f"Blocked: {action} confirmation must include the exact "
                f"{', '.join(required)}."
            )
        normalized[key] = value
    return normalized


def _fingerprint(action: str, fields: dict[str, str]) -> str:
    payload = json.dumps({"action": action, "fields": fields}, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _route_fingerprint(steps: list[dict]) -> str:
    canonical = [
        {"tool": step.get("tool"), "fingerprint": step.get("fingerprint")}
        for step in steps
    ]
    payload = json.dumps(canonical, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _steps_for(action: str, fields: dict[str, str]) -> list[dict]:
    return [{"tool": action, "fields": fields, "fingerprint": _fingerprint(action, fields)}]


def _read_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return record if isinstance(record, dict) else None


def _write_json(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")


def _read_lock() -> dict | None:
    return _read_json(LOCK_PATH)


def _write_lock(record: dict) -> None:
    _write_json(LOCK_PATH, record)


def _clear_lock() -> None:
    try:
        LOCK_PATH.unlink()
    except OSError:
        return


def _lock_expired(lock: dict) -> bool:
    try:
        expires_at = datetime.fromisoformat(str(lock.get("expires_at", "")))
    except ValueError:
        return True
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) >= expires_at


def _plan_path(plan_id: str) -> Path | None:
    if not isinstance(plan_id, str) or not _PLAN_ID_RE.fullmatch(plan_id):
        return None
    return PLANS_DIR / f"{plan_id}.json"


def _read_record(plan_id: str) -> tuple[dict | None, str | None]:
    path = _plan_path(plan_id)
    if path is None:
        return None, "Blocked: plan id is missing or invalid."
    if not path.is_file():
        return None, (
            "Blocked: no pending plan for that id. "
            "Call require_user_confirm with the exact email or event, "
            "then have a person approve it outside the model."
        )
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, "Blocked: plan record could not be read."
    if not isinstance(record, dict):
        return None, "Blocked: plan record is invalid."
    return record, None


def issue_confirmation(action: str, fields: dict) -> str:
    """Create a pending confirmation. It is not usable until a person approves it."""
    if action not in HIGH_RISK_TOOLS:
        return f"{action} does not require confirmation. Call it directly."
    normalized = canonical_fields(action, fields)
    if isinstance(normalized, str):
        return normalized

    PLANS_DIR.mkdir(parents=True, exist_ok=True)
    plan_id = secrets.token_hex(8)
    steps = _steps_for(action, normalized)
    record = {
        "action": action,
        "fields": normalized,
        "fingerprint": steps[0]["fingerprint"],
        "steps": steps,
        "route_fingerprint": _route_fingerprint(steps),
        "plan_version": 0,
        "approved": False,
    }
    path = PLANS_DIR / f"{plan_id}.json"
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    shown = "\n".join(f"  {key}: {normalized[key]}" for key in normalized)
    return (
        f"Pending plan for {action}. Not approved yet.\n"
        f"{shown}\n"
        f"plan_id: {plan_id}\n"
        "A person must approve this exact plan outside the model by running:\n"
        f"  python Backend/email_server.py --approve {plan_id}\n"
        "Approval mints a 256-bit execution token for that person. "
        "The model cannot mint it, and this plan id is not an execution token."
    )


def load_pending(token: str) -> tuple[dict | None, str | None]:
    """Return the pending record for a human reviewer, without approving it."""
    return _read_record(token)


def issue_execution_token(
    plan_id: str,
    *,
    user: str,
    session: str,
    ttl_seconds: int | None = None,
) -> tuple[str | None, str]:
    """Mint a 256-bit execution token for one approved plan version.

    Only the SHA-256 hash is stored. The raw token is returned once to the human.
    """
    record, error = _read_record(plan_id)
    if error or record is None:
        return None, error or "Blocked: plan record is invalid."
    path = _plan_path(plan_id)
    if path is None:
        return None, "Blocked: plan id is missing or invalid."

    action = str(record.get("action", ""))
    fields = record.get("fields")
    if action not in HIGH_RISK_TOOLS or not isinstance(fields, dict):
        return None, "Blocked: plan is not an approvable action."
    normalized = canonical_fields(action, fields)
    if isinstance(normalized, str):
        return None, normalized
    fingerprint = _fingerprint(action, normalized)
    record["fields"] = normalized
    record["fingerprint"] = fingerprint

    bound_user = str(user or "").strip().lower()
    bound_session = str(session or "").strip().lower()
    if "@" not in bound_user:
        return None, "Blocked: execution token must be bound to the authenticated user."
    if not re.fullmatch(r"[0-9a-f]{64}", bound_session):
        return None, "Blocked: execution token must be bound to the authenticated session."

    steps = _steps_for(action, normalized)
    route_fingerprint = _route_fingerprint(steps)
    version = int(record.get("plan_version") or 0) + 1
    record["steps"] = steps
    record["route_fingerprint"] = route_fingerprint
    record["plan_version"] = version
    record["approved"] = True
    record["approved_fingerprint"] = fingerprint
    record["user"] = bound_user
    record["session"] = bound_session
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    raw_token = secrets.token_hex(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=_execution_ttl_seconds(ttl_seconds))
    _write_lock({
        "user": bound_user,
        "session": bound_session,
        "plan_id": plan_id,
        "plan_version": version,
        "route_fingerprint": route_fingerprint,
        "steps": steps,
        "current_step": 0,
        "status": "locked",
        "expires_at": expires_at.isoformat(),
    })
    stored = {
        "token_hash": token_hash,
        "user": bound_user,
        "session": bound_session,
        "plan_id": plan_id,
        "plan_version": version,
        "plan_fingerprint": fingerprint,
        "permissions": [action],
        "expires_at": expires_at.isoformat(),
    }
    EXECUTIONS_DIR.mkdir(parents=True, exist_ok=True)
    (EXECUTIONS_DIR / f"{token_hash}.json").write_text(json.dumps(stored, indent=2), encoding="utf-8")
    return raw_token, (
        f"Execution token issued for {action}, plan version {version}. "
        f"Permissions: {action}. Expires: {expires_at.isoformat()}."
    )


def verify_execution_token(
    raw_token: str,
    *,
    user: str,
    session: str,
    action: str,
    fields: dict,
) -> str | None:
    """Return None when this protected request matches the stored execution token."""
    if action not in HIGH_RISK_TOOLS:
        return None
    presented = str(raw_token or "").strip().lower()
    if not _EXECUTION_TOKEN_RE.fullmatch(presented):
        return (
            "Blocked: protected action requires an execution token. "
            "A plan id is not enough."
        )

    token_hash = hashlib.sha256(presented.encode("utf-8")).hexdigest()
    path = EXECUTIONS_DIR / f"{token_hash}.json"
    if not path.is_file():
        return "Blocked: execution token is not recognized."
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "Blocked: execution token record could not be read."
    if not isinstance(stored, dict):
        return "Blocked: execution token record is invalid."

    stored_hash = str(stored.get("token_hash", ""))
    if len(stored_hash) != len(token_hash) or not secrets.compare_digest(stored_hash, token_hash):
        return "Blocked: execution token hash does not match."
    if stored.get("revoked") is True:
        return "Blocked: session cancelled. This execution token was revoked."

    bound_user = str(user or "").strip().lower()
    if not bound_user or stored.get("user") != bound_user:
        return "Blocked: execution token is not bound to this authenticated user."
    bound_session = str(session or "").strip().lower()
    if not bound_session or stored.get("session") != bound_session:
        return "Blocked: execution token is not bound to this session."

    permissions = stored.get("permissions")
    if not isinstance(permissions, list) or action not in permissions:
        return "Blocked: execution token does not grant this permission."

    try:
        expires_at = datetime.fromisoformat(str(stored.get("expires_at", "")))
    except ValueError:
        return "Blocked: execution token expiry is invalid."
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) >= expires_at:
        return "Blocked: execution token has expired."

    normalized = canonical_fields(action, fields)
    if isinstance(normalized, str):
        return normalized
    fingerprint = _fingerprint(action, normalized)
    if stored.get("plan_fingerprint") != fingerprint:
        return "Blocked: execution token is not bound to this exact approved plan."

    plan, plan_error = _read_record(str(stored.get("plan_id", "")))
    if plan_error or plan is None:
        return plan_error or "Blocked: approved plan is missing."
    if int(plan.get("plan_version") or 0) != int(stored.get("plan_version") or -1):
        return "Blocked: execution token is bound to a previous plan version."
    if plan.get("approved_fingerprint") != fingerprint or plan.get("approved") is not True:
        return "Blocked: modified plan requires reapproval."

    lock = _read_lock()
    if not lock or lock.get("status") == "needs_reapproval":
        return "Blocked: modified plan requires reapproval."
    if lock.get("status") == "cancelled":
        return "Blocked: session cancelled. This execution token was revoked."
    if lock.get("plan_id") != stored.get("plan_id") or int(lock.get("plan_version") or -1) != int(stored.get("plan_version") or -2):
        return "Blocked: plan substitution. The execution lock does not match this token."
    lock_steps = lock.get("steps") if isinstance(lock.get("steps"), list) else []
    index = int(lock.get("current_step") or 0)
    if index >= len(lock_steps) or lock_steps[index].get("fingerprint") != fingerprint or lock_steps[index].get("tool") != action:
        return "Blocked: route change. This call is not the locked step."
    return None


def cancel_session(session: str) -> str:
    """Revoke the execution lock and every execution token bound to this session."""
    bound = str(session or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", bound):
        return "Blocked: session id is invalid."
    lock = _read_lock()
    if lock and lock.get("session") == bound:
        lock["status"] = "cancelled"
        _write_lock(lock)
    revoked = 0
    if EXECUTIONS_DIR.is_dir():
        for path in EXECUTIONS_DIR.glob("*.json"):
            record = _read_json(path)
            if not record or record.get("session") != bound:
                continue
            record["revoked"] = True
            _write_json(path, record)
            revoked += 1
    return f"Session cancelled. Revoked {revoked} execution token(s)."


def consume_execution_token(raw_token: str) -> None:
    """Forget a used execution token. The raw value is never written."""
    presented = str(raw_token or "").strip().lower()
    if not _EXECUTION_TOKEN_RE.fullmatch(presented):
        return
    token_hash = hashlib.sha256(presented.encode("utf-8")).hexdigest()
    path = EXECUTIONS_DIR / f"{token_hash}.json"
    try:
        path.unlink()
    except OSError:
        return


def check_execution_lock(tool: str, fields: dict | None, *, session: str) -> str | None:
    """Reject tool calls that leave the approved plan, route, or current step."""
    lock = _read_lock()
    if lock is None:
        return None
    if _lock_expired(lock) or lock.get("status") == "completed":
        _clear_lock()
        return None
    if lock.get("status") == "cancelled":
        return "Blocked: session cancelled. Reapproval is required."
    if lock.get("status") == "needs_reapproval":
        return "Blocked: modified plan requires reapproval."
    if lock.get("session") != str(session or "").strip().lower():
        return "Blocked: execution lock is bound to another session."

    plan, plan_error = _read_record(str(lock.get("plan_id", "")))
    if plan_error or plan is None:
        return "Blocked: approved plan is missing. Reapproval is required."
    action = str(plan.get("action", ""))
    raw_fields = plan.get("fields") if isinstance(plan.get("fields"), dict) else {}
    normalized = canonical_fields(action, raw_fields) if action in HIGH_RISK_TOOLS else None
    live_steps = _steps_for(action, normalized) if isinstance(normalized, dict) else []
    if (
        not isinstance(normalized, dict)
        or int(plan.get("plan_version") or 0) != int(lock.get("plan_version") or -1)
        or _route_fingerprint(live_steps) != lock.get("route_fingerprint")
        or plan.get("approved") is not True
    ):
        plan["approved"] = False
        plan_path = _plan_path(str(lock.get("plan_id", "")))
        if plan_path is not None:
            _write_json(plan_path, plan)
        lock["status"] = "needs_reapproval"
        _write_lock(lock)
        return "Blocked: modified plan requires reapproval."

    lock_steps = lock.get("steps") if isinstance(lock.get("steps"), list) else []
    index = int(lock.get("current_step") or 0)
    if index >= len(lock_steps):
        _clear_lock()
        return None
    current = lock_steps[index]
    if tool != current.get("tool"):
        approved_tools = [step.get("tool") for step in lock_steps]
        if tool in HIGH_RISK_TOOLS or tool in approved_tools:
            return (
                f"Blocked: route change. The execution lock is on step {index + 1} "
                f"({current.get('tool')})."
            )
        return (
            f"Blocked: unapproved tool call ({tool}). "
            f"The execution lock only allows {current.get('tool')}."
        )

    if tool in HIGH_RISK_TOOLS:
        normalized = canonical_fields(tool, fields or {})
        if isinstance(normalized, str):
            return normalized
        if _fingerprint(tool, normalized) != current.get("fingerprint"):
            return "Blocked: plan substitution. This call does not match the approved step."
    return None


def advance_execution_lock() -> None:
    """Move to the next approved step after the current one succeeds."""
    lock = _read_lock()
    if not lock or lock.get("status") != "locked":
        return
    steps = lock.get("steps") if isinstance(lock.get("steps"), list) else []
    lock["current_step"] = int(lock.get("current_step") or 0) + 1
    if lock["current_step"] >= len(steps):
        _clear_lock()
        return
    _write_lock(lock)
