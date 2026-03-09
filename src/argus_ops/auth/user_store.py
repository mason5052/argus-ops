"""Local SQLite user database with bcrypt password hashing."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from argus_ops.auth.models import Role, User

try:
    import bcrypt

    _HAS_BCRYPT = True
except ImportError:
    _HAS_BCRYPT = False

_PBKDF2_ITERATIONS = 600_000
_PBKDF2_PREFIX = "pbkdf2:"


def _hash_password(plain: str) -> str:
    if _HAS_BCRYPT:
        return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), _PBKDF2_ITERATIONS)
    return f"{_PBKDF2_PREFIX}{salt}${digest.hex()}"


def _verify_password(plain: str, hashed: str) -> bool:
    if hashed.startswith(_PBKDF2_PREFIX):
        salt, digest_hex = hashed[len(_PBKDF2_PREFIX):].split("$", 1)
        digest = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), _PBKDF2_ITERATIONS)
        return hmac.compare_digest(digest.hex(), digest_hex)
    if _HAS_BCRYPT:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    return False


class UserStore:
    """SQLite-backed local user database."""

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
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            conn.commit()

    def create_user(self, username: str, password: str, role: Role = Role.viewer) -> User:
        now = datetime.now(timezone.utc).isoformat()
        password_hash = _hash_password(password)
        try:
            with self._conn() as conn:
                conn.execute(
                    (
                        "INSERT INTO users "
                        "(username, password_hash, role, created_at, updated_at) "
                        "VALUES (?, ?, ?, ?, ?)"
                    ),
                    (username, password_hash, role.value, now, now),
                )
                conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"User '{username}' already exists") from exc
        return User(
            username=username,
            password_hash=password_hash,
            role=role,
            created_at=datetime.fromisoformat(now),
            updated_at=datetime.fromisoformat(now),
        )

    def get_user(self, username: str) -> User | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
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
        user = self.get_user(username)
        if user is None or not user.is_active:
            return None
        return user if _verify_password(password, user.password_hash) else None

    def list_users(self) -> list[User]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY created_at").fetchall()
        return [
            User(
                username=row["username"],
                password_hash=row["password_hash"],
                role=Role(row["role"]),
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
                is_active=bool(row["is_active"]),
            )
            for row in rows
        ]

    def update_role(self, username: str, new_role: Role) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            cursor = conn.execute(
                "UPDATE users SET role = ?, updated_at = ? WHERE username = ?",
                (new_role.value, now, username),
            )
            conn.commit()
        return cursor.rowcount > 0

    def change_password(self, username: str, new_password: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        password_hash = _hash_password(new_password)
        with self._conn() as conn:
            cursor = conn.execute(
                "UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?",
                (password_hash, now, username),
            )
            conn.commit()
        return cursor.rowcount > 0

    def set_active(self, username: str, is_active: bool) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            cursor = conn.execute(
                "UPDATE users SET is_active = ?, updated_at = ? WHERE username = ?",
                (1 if is_active else 0, now, username),
            )
            conn.commit()
        return cursor.rowcount > 0

    def remove_user(self, username: str) -> bool:
        with self._conn() as conn:
            cursor = conn.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()
        return cursor.rowcount > 0

    def user_count(self) -> int:
        with self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()
        return row["cnt"]
