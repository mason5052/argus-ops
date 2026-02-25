"""Session-based authenticator with JWT-like local tokens."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from argus_ops.auth.models import AuthEvent, Role, Session, User
from argus_ops.auth.user_store import UserStore

logger = logging.getLogger(__name__)

_DEFAULT_TTL_HOURS = 24
_SECRET_FILE = "session_secret"
_SESSION_FILE = "session.json"
_AUTH_AUDIT_FILE = "auth-audit.jsonl"


class Authenticator:
    """Manages login, logout, and session validation.

    Args:
        data_dir: Base directory for Argus-Ops data (default ``~/.argus-ops``).
        session_ttl_hours: Session expiry in hours.
    """

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

    # ---- Secret management ----

    def _load_or_create_secret(self) -> str:
        secret_path = self._data_dir / _SECRET_FILE
        if secret_path.exists():
            return secret_path.read_text().strip()
        secret = secrets.token_hex(32)
        secret_path.write_text(secret)
        # Restrict permissions on Unix
        try:
            secret_path.chmod(0o600)
        except OSError:
            pass
        return secret

    # ---- Token generation / validation ----

    def _make_token(self, username: str, role: str, issued: str, expires: str) -> str:
        """Create an HMAC-signed token (base64-encoded JSON + signature)."""
        payload = json.dumps(
            {"u": username, "r": role, "iat": issued, "exp": expires},
            separators=(",", ":"),
        )
        sig = hmac.new(self._secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        raw = payload.encode() + b"." + sig.encode()
        return base64.urlsafe_b64encode(raw).decode()

    def _verify_token(self, token: str) -> dict | None:
        """Decode and verify a token. Returns payload dict or None."""
        try:
            raw = base64.urlsafe_b64decode(token.encode())
            payload_bytes, sig_hex = raw.rsplit(b".", 1)
            expected = hmac.new(
                self._secret.encode(), payload_bytes, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(expected, sig_hex.decode()):
                return None
            data = json.loads(payload_bytes)
            exp = datetime.fromisoformat(data["exp"])
            if datetime.now(timezone.utc) > exp:
                return None
            return data
        except Exception:
            return None

    # ---- Public API ----

    def login(self, username: str, password: str) -> Session | None:
        """Authenticate and create a session. Returns None on failure."""
        user = self._store.authenticate(username, password)
        if user is None:
            self._log_auth_event("login_failure", username, "Invalid credentials")
            return None

        now = datetime.now(timezone.utc)
        expires = now + self._ttl
        token = self._make_token(
            username, user.role.value, now.isoformat(), expires.isoformat()
        )
        session = Session(
            username=username,
            role=user.role,
            issued_at=now,
            expires_at=expires,
            token=token,
        )
        self._save_session(session)
        self._log_auth_event("login_success", username)
        logger.info("User '%s' logged in (role: %s)", username, user.role.value)
        return session

    def logout(self) -> bool:
        """Clear the current session. Returns True if a session existed."""
        session_path = self._data_dir / _SESSION_FILE
        if session_path.exists():
            current = self.get_current_session()
            username = current.username if current else "unknown"
            session_path.unlink()
            self._log_auth_event("logout", username)
            logger.info("User '%s' logged out", username)
            return True
        return False

    def get_current_session(self) -> Session | None:
        """Load and validate the current session from disk."""
        session_path = self._data_dir / _SESSION_FILE
        if not session_path.exists():
            return None
        try:
            data = json.loads(session_path.read_text())
            token = data.get("token", "")
            payload = self._verify_token(token)
            if payload is None:
                return None
            return Session(
                username=payload["u"],
                role=Role(payload["r"]),
                issued_at=datetime.fromisoformat(payload["iat"]),
                expires_at=datetime.fromisoformat(payload["exp"]),
                token=token,
            )
        except Exception:
            return None

    def whoami(self) -> Session | None:
        """Alias for get_current_session."""
        return self.get_current_session()

    # ---- Persistence ----

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
            )
        )
        try:
            session_path.chmod(0o600)
        except OSError:
            pass

    # ---- Auth audit ----

    def _log_auth_event(self, event_type: str, username: str, details: str = "") -> None:
        event = AuthEvent(
            event_type=event_type,
            username=username,
            details=details,
        )
        audit_path = self._data_dir / _AUTH_AUDIT_FILE
        with open(audit_path, "a", encoding="utf-8") as f:
            f.write(event.model_dump_json() + "\n")
