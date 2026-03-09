"""Session-based authenticator with JWT-like local tokens."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from argus_ops.auth.models import AuthEvent, Role, Session
from argus_ops.auth.user_store import UserStore

_DEFAULT_TTL_HOURS = 24
_SECRET_FILE = "session_secret"
_SESSION_FILE = "session.json"
_AUTH_AUDIT_FILE = "auth-audit.jsonl"


class Authenticator:
    """Manage login, logout, and token validation for CLI and web."""

    def __init__(
        self,
        data_dir: str | Path | None = None,
        session_ttl_hours: int = _DEFAULT_TTL_HOURS,
    ) -> None:
        self._data_dir = Path(data_dir) if data_dir else Path.home() / ".argus-ops"
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._ttl = timedelta(hours=session_ttl_hours)
        self._store = UserStore(self._data_dir / "users.db")
        self._secret = self._load_or_create_secret()

    @property
    def user_store(self) -> UserStore:
        return self._store

    def _load_or_create_secret(self) -> str:
        secret_path = self._data_dir / _SECRET_FILE
        if secret_path.exists():
            return secret_path.read_text(encoding="utf-8").strip()
        secret = secrets.token_hex(32)
        secret_path.write_text(secret, encoding="utf-8")
        try:
            secret_path.chmod(0o600)
        except OSError:
            pass
        return secret

    def _make_token(self, username: str, role: str, issued: str, expires: str) -> str:
        payload = json.dumps(
            {"u": username, "r": role, "iat": issued, "exp": expires},
            separators=(",", ":"),
        )
        signature = hmac.new(self._secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        raw = payload.encode() + b"." + signature.encode()
        return base64.urlsafe_b64encode(raw).decode()

    def _verify_token(self, token: str) -> dict | None:
        try:
            raw = base64.urlsafe_b64decode(token.encode())
            payload_bytes, signature_hex = raw.rsplit(b".", 1)
            expected = hmac.new(self._secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature_hex.decode()):
                return None
            data = json.loads(payload_bytes)
            if datetime.now(timezone.utc) > datetime.fromisoformat(data["exp"]):
                return None
            return data
        except Exception:
            return None

    def login(
        self,
        username: str,
        password: str,
        *,
        persist: bool = True,
        ip_address: str = "",
        user_agent: str = "",
    ) -> Session | None:
        user = self._store.authenticate(username, password)
        if user is None:
            self.log_event(
                "login_failure",
                username,
                ip_address=ip_address,
                user_agent=user_agent,
                details="Invalid credentials",
            )
            return None

        now = datetime.now(timezone.utc)
        expires = now + self._ttl
        session = Session(
            username=username,
            role=user.role,
            issued_at=now,
            expires_at=expires,
            token=self._make_token(
                username,
                user.role.value,
                now.isoformat(),
                expires.isoformat(),
            ),
        )
        if persist:
            self._save_session(session)
        self.log_event("login_success", username, ip_address=ip_address, user_agent=user_agent)
        return session

    def logout(self) -> bool:
        session_path = self._data_dir / _SESSION_FILE
        if not session_path.exists():
            return False
        current = self.get_current_session()
        session_path.unlink()
        self.log_event("logout", current.username if current else "unknown")
        return True

    def session_from_token(self, token: str) -> Session | None:
        payload = self._verify_token(token)
        if payload is None:
            return None
        user = self._store.get_user(payload["u"])
        if user is None or not user.is_active:
            return None
        return Session(
            username=payload["u"],
            role=Role(payload["r"]),
            issued_at=datetime.fromisoformat(payload["iat"]),
            expires_at=datetime.fromisoformat(payload["exp"]),
            token=token,
        )

    def get_current_session(self) -> Session | None:
        session_path = self._data_dir / _SESSION_FILE
        if not session_path.exists():
            return None
        try:
            data = json.loads(session_path.read_text(encoding="utf-8"))
        except Exception:
            return None
        return self.session_from_token(data.get("token", ""))

    def whoami(self) -> Session | None:
        return self.get_current_session()

    def log_event(
        self,
        event_type: str,
        username: str,
        *,
        ip_address: str = "",
        user_agent: str = "",
        details: str = "",
    ) -> None:
        event = AuthEvent(
            event_type=event_type,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
        )
        audit_path = self._data_dir / _AUTH_AUDIT_FILE
        with open(audit_path, "a", encoding="utf-8") as handle:
            handle.write(event.model_dump_json() + "\n")

    def _save_session(self, session: Session) -> None:
        session_path = self._data_dir / _SESSION_FILE
        session_path.write_text(
            json.dumps(
                {
                    "username": session.username,
                    "role": session.role.value,
                    "issued_at": session.issued_at.isoformat(),
                    "expires_at": session.expires_at.isoformat(),
                    "token": session.token,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        try:
            session_path.chmod(0o600)
        except OSError:
            pass
