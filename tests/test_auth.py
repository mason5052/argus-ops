"""Tests for the authentication and authorization system."""

from __future__ import annotations

import pytest

from argus_ops.auth.authenticator import Authenticator
from argus_ops.auth.models import Role
from argus_ops.auth.user_store import UserStore, _hash_password, _verify_password


class TestPasswordHashing:
    def test_hash_and_verify(self):
        password = "test-password-123"
        hashed = _hash_password(password)
        assert _verify_password(password, hashed)

    def test_wrong_password(self):
        hashed = _hash_password("correct-password")
        assert not _verify_password("wrong-password", hashed)

    def test_different_hashes(self):
        hashed_one = _hash_password("same-password")
        hashed_two = _hash_password("same-password")
        assert hashed_one != hashed_two


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

    def test_authenticate_disabled_user(self, store):
        store.create_user("dave", "secret")
        assert store.set_active("dave", False)
        assert store.authenticate("dave", "secret") is None

    def test_list_users(self, store):
        store.create_user("u1", "p1", Role.admin)
        store.create_user("u2", "p2", Role.viewer)
        users = store.list_users()
        assert len(users) == 2
        assert {user.username for user in users} == {"u1", "u2"}

    def test_update_role(self, store):
        store.create_user("eve", "pass", Role.viewer)
        assert store.update_role("eve", Role.admin)
        user = store.get_user("eve")
        assert user is not None
        assert user.role == Role.admin

    def test_change_password(self, store):
        store.create_user("frank", "pass")
        assert store.change_password("frank", "new-pass")
        assert store.authenticate("frank", "new-pass") is not None

    def test_user_count(self, store):
        assert store.user_count() == 0
        store.create_user("x", "p")
        assert store.user_count() == 1


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
        assert auth.login("admin", "wrongpass") is None

    def test_whoami(self, auth):
        auth.user_store.create_user("viewer", "test123", Role.viewer)
        auth.login("viewer", "test123")
        session = auth.whoami()
        assert session is not None
        assert session.username == "viewer"
        assert session.role == Role.viewer

    def test_logout(self, auth):
        auth.user_store.create_user("user1", "pass")
        auth.login("user1", "pass")
        assert auth.logout()
        assert auth.whoami() is None

    def test_session_from_token(self, auth):
        auth.user_store.create_user("persist", "pass", Role.viewer)
        session = auth.login("persist", "pass", persist=False)
        restored = auth.session_from_token(session.token)
        assert restored is not None
        assert restored.username == "persist"
        assert restored.role == Role.viewer

    def test_session_persistence(self, auth):
        auth.user_store.create_user("persist", "pass", Role.viewer)
        auth.login("persist", "pass")
        auth_two = Authenticator(data_dir=auth._data_dir, session_ttl_hours=1)
        session = auth_two.whoami()
        assert session is not None
        assert session.username == "persist"


class TestRole:
    def test_role_ordering(self):
        assert Role.viewer < Role.admin
        assert Role.admin >= Role.viewer
        assert Role.viewer <= Role.admin

    def test_role_level(self):
        assert Role.viewer.level == 0
        assert Role.admin.level == 1
