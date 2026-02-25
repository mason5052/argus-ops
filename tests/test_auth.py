"""Tests for the authentication and authorization system."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from argus_ops.auth.authenticator import Authenticator
from argus_ops.auth.models import Role, Session, User
from argus_ops.auth.user_store import UserStore, _hash_password, _verify_password


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

class TestPasswordHashing:
    def test_hash_and_verify(self):
        pw = "test-password-123"
        hashed = _hash_password(pw)
        assert _verify_password(pw, hashed)

    def test_wrong_password(self):
        pw = "correct-password"
        hashed = _hash_password(pw)
        assert not _verify_password("wrong-password", hashed)

    def test_different_hashes(self):
        pw = "same-password"
        h1 = _hash_password(pw)
        h2 = _hash_password(pw)
        # Hashes should differ due to random salt
        assert h1 != h2


# ---------------------------------------------------------------------------
# UserStore
# ---------------------------------------------------------------------------

class TestUserStore:
    @pytest.fixture
    def store(self, tmp_path):
        return UserStore(db_path=tmp_path / "test-users.db")

    def test_create_and_get_user(self, store):
        user = store.create_user("alice", "pass123", Role.viewer)
        assert user.username == "alice"
        assert user.role == Role.viewer

        fetched = store.get_user("alice")
        assert fetched is not None
        assert fetched.username == "alice"
        assert fetched.role == Role.viewer

    def test_create_duplicate_raises(self, store):
        store.create_user("bob", "pass123")
        with pytest.raises(ValueError, match="already exists"):
            store.create_user("bob", "pass456")

    def test_authenticate_success(self, store):
        store.create_user("carol", "secret")
        user = store.authenticate("carol", "secret")
        assert user is not None
        assert user.username == "carol"

    def test_authenticate_wrong_password(self, store):
        store.create_user("dave", "correct")
        assert store.authenticate("dave", "wrong") is None

    def test_authenticate_nonexistent_user(self, store):
        assert store.authenticate("nobody", "pass") is None

    def test_list_users(self, store):
        store.create_user("u1", "p1", Role.admin)
        store.create_user("u2", "p2", Role.operator)
        users = store.list_users()
        assert len(users) == 2
        assert {u.username for u in users} == {"u1", "u2"}

    def test_update_role(self, store):
        store.create_user("eve", "pass", Role.viewer)
        assert store.update_role("eve", Role.admin)
        user = store.get_user("eve")
        assert user.role == Role.admin

    def test_remove_user(self, store):
        store.create_user("frank", "pass")
        assert store.remove_user("frank")
        assert store.get_user("frank") is None

    def test_user_count(self, store):
        assert store.user_count() == 0
        store.create_user("x", "p")
        assert store.user_count() == 1


# ---------------------------------------------------------------------------
# Authenticator
# ---------------------------------------------------------------------------

class TestAuthenticator:
    @pytest.fixture
    def auth(self, tmp_path):
        return Authenticator(data_dir=tmp_path / "argus-test", session_ttl_hours=1)

    def test_login_success(self, auth):
        auth.user_store.create_user("admin", "admin123", Role.admin)
        session = auth.login("admin", "admin123")
        assert session is not None
        assert session.username == "admin"
        assert session.role == Role.admin
        assert session.token

    def test_login_failure(self, auth):
        auth.user_store.create_user("admin", "admin123")
        session = auth.login("admin", "wrongpass")
        assert session is None

    def test_whoami(self, auth):
        auth.user_store.create_user("test", "test123", Role.operator)
        auth.login("test", "test123")
        session = auth.whoami()
        assert session is not None
        assert session.username == "test"
        assert session.role == Role.operator

    def test_logout(self, auth):
        auth.user_store.create_user("user1", "pass")
        auth.login("user1", "pass")
        assert auth.logout()
        assert auth.whoami() is None

    def test_session_persistence(self, auth):
        auth.user_store.create_user("persist", "pass", Role.viewer)
        auth.login("persist", "pass")
        # Create a new Authenticator pointing to same data dir
        auth2 = Authenticator(
            data_dir=auth._data_dir, session_ttl_hours=1
        )
        session = auth2.whoami()
        assert session is not None
        assert session.username == "persist"


# ---------------------------------------------------------------------------
# Role model
# ---------------------------------------------------------------------------

class TestRole:
    def test_role_ordering(self):
        assert Role.viewer < Role.operator
        assert Role.operator < Role.admin
        assert Role.admin >= Role.operator
        assert Role.viewer <= Role.admin

    def test_role_level(self):
        assert Role.viewer.level == 0
        assert Role.operator.level == 1
        assert Role.admin.level == 2
