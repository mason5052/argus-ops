"""Role-based access control decorators for CLI commands."""

from __future__ import annotations

import functools
import logging

import click

from argus_ops.auth.authenticator import Authenticator
from argus_ops.auth.models import Role

logger = logging.getLogger(__name__)


def _get_authenticator(ctx: click.Context) -> Authenticator:
    """Retrieve or create an Authenticator from the Click context."""
    auth = ctx.obj.get("authenticator") if ctx.obj else None
    if auth is None:
        auth = Authenticator()
        if ctx.obj is None:
            ctx.obj = {}
        ctx.obj["authenticator"] = auth
    return auth


def require_auth(func):
    """Ensure a valid session exists before running the command."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        ctx = click.get_current_context()
        auth = _get_authenticator(ctx)
        session = auth.get_current_session()
        if session is None:
            click.echo("Error: Not authenticated. Run 'argus-ops login' first.", err=True)
            ctx.exit(1)
        ctx.obj["session"] = session
        return func(*args, **kwargs)

    return wrapper


def require_role(minimum_role: Role):
    """Ensure the session has at least the required role."""

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            ctx = click.get_current_context()
            session = ctx.obj.get("session")
            if session is None:
                click.echo("Error: Not authenticated.", err=True)
                ctx.exit(1)
            if session.role < minimum_role:
                logger.warning(
                    "Role escalation attempt: user '%s' (role: %s) tried action requiring '%s'",
                    session.username,
                    session.role.value,
                    minimum_role.value,
                )
                auth = _get_authenticator(ctx)
                auth.log_event(
                    "role_escalation_attempt",
                    session.username,
                    details=f"Required: {minimum_role.value}, has: {session.role.value}",
                )
                click.echo(
                    f"Error: Insufficient permissions. Role '{minimum_role.value}' required, "
                    f"you have '{session.role.value}'.",
                    err=True,
                )
                ctx.exit(1)
            return func(*args, **kwargs)

        return wrapper

    return decorator
