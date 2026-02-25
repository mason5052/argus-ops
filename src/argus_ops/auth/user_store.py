"""Local SQLite user database with bcrypt password hashing."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from argus_ops.auth.models import Role, User

logger = logging.getLogger(__name__)

# bcrypt is optional; fall back to PBKDF2-HMAC-SHA256 if unavailable
try:
    import bcrypt

    _HAS_BCRYPT = True
except ImportError:
    _HAS_BCRYPT = False

_PBKDF2_ITERATIONS = 600_000
_PBKDF2_PREFIX = "pbkdf2:"


def _hash_password(plain: str) -> str:
    """Hash a password using bcrypt (preferred) or PBKDF2 fallback."""
    if _HAS_BCRYPT:
        return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), _PBKDF2_ITERATIONS)
    return f"{_PBKDF2_PREFIX}{salt}${dk.hex()}"


def _verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against its hash."""
    if hashed.startswith(_PBKDF2_PREFIX):
        body = hashed[len(_PBKDF2_PREFIX) :]
        salt, dk_hex = body.split("$", 1)
        dk = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), _PBKDF2_ITERATIONS)
        return hmac.compare_digest(dk.hex(), dk_hex)
    if _HAS_BCRYPT:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    return False


class UserStore:
    """SQLite-backed local user database.

    Args:
        db_path: Path to SQLite file. Defaults to ``~/.argus-ops/users.db``.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            db_path = Path.home() / ".argus-ops" / "users.db"
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username   TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    role       TEXT NOT NULL DEFAULT 'viewer',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    is_active  INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            conn.commit()

    # ---- CRUD ----

    def create_user(self, username: str, password: str, role: Role = Role.viewer) -> User:
        """Create a new user. Raises ValueError if username already exists."""
        now = datetime.now(timezone.utc).isoformat()
        pw_hash = _hash_password(password)
        try:
            with self._conn() as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (username, pw_hash, role.value, now, now),
                )
                conn.commit()
        except sqlite3.IntegrityError:
            raise ValueError(f"User '{username}' already exists")

        logger.info("Created user '%s' with role '%s'", username, role.value)
        return User(
            username=username,
            password_hash=pw_hash,
            role=role,
            created_at=datetime.fromisoformat(now),
            updated_at=datetime.fromisoformat(now),
        )

    def get_user(self, username: str) -> User | None:
        """Return a User or None if not found."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
        if row is None:
            return None
        return User(
            username=row["username"],
            password_hash=row["password_hash"],
            role=Role(row["role"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            is_active=bool(row["is_active"]),
        )

    def authenticate(self, username: str, password: str) -> User | None:
        """Verify credentials. Returns User on success, None on failure."""
        user = self.get_user(username)
        if user is None or not user.is_active:
            return None
        if _verify_password(password, user.password_hash):
            return user
        return None

    def list_users(self) -> list[User]:
        """Return all users."""
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY created_at").fetchall()
        return [
            User(
                username=r["username"],
                password_hash=r["password_hash"],
                role=Role(r["role"]),
                created_at=datetime.fromisoformat(r["created_at"]),
                updated_at=datetime.fromisoformat(r["updated_at"]),
                is_active=bool(r["is_active"]),
            )
            for r in rows
        ]

    def update_role(self, username: str, new_role: Role) -> bool:
        """Change a user's role. Returns True if updated."""
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE users SET role = ?, updated_at = ? WHERE username = ?",
                (new_role.value, now, username),
            )
            conn.commit()
        if cur.rowcount > 0:
            logger.info("Updated role for '%s' to '%s'", username, new_role.value)
            return True
        return False

    def remove_user(self, username: str) -> bool:
        """Delete a user. Returns True if deleted."""
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()
        if cur.rowcount > 0:
            logger.info("Removed user '%s'", username)
            return True
        return False

    def change_password(self, username: str, new_password: str) -> bool:
        """Update password hash. Returns True if updated."""
        now = datetime.now(timezone.utc).isoformat()
        pw_hash = _hash_password(new_password)
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?",
                (pw_hash, now, username),
            )
            conn.commit()
        return cur.rowcount > 0

    def user_count(self) -> int:
        """Return total number of users."""
        with self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM users").fetchone()
        return row["cnt"]
