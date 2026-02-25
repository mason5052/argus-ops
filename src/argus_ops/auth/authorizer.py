"""Role-based access control decorators for CLI commands."""

from __future__ import annotations

import functools
import logging
from pathlib import Path

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


def require_auth(f):
    """Decorator: ensures a valid session exists before running the command.

    Injects ``session`` into the Click context object.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ctx = click.get_current_context()
        auth = _get_authenticator(ctx)
        session = auth.get_current_session()
        if session is None:
            click.echo("Error: Not authenticated. Run 'argus-ops login' first.", err=True)
            ctx.exit(1)
        ctx.obj["session"] = session
        return f(*args, **kwargs)

    return wrapper


def require_role(minimum_role: Role):
    """Decorator factory: ensures the user has at least the given role.

    Must be used *after* ``@require_auth`` so the session is available.

    Usage::

        @cli.command()
        @require_auth
        @require_role(Role.operator)
        def heal(ctx):
            ...
    """

    def decorator(f):
        @functools.wraps(f)
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
                # Log the escalation attempt to auth audit
                auth = _get_authenticator(ctx)
                auth._log_auth_event(
                    "role_escalation_attempt",
                    session.username,
                    f"Required: {minimum_role.value}, has: {session.role.value}",
                )
                click.echo(
                    f"Error: Insufficient permissions. "
                    f"Role '{minimum_role.value}' required, you have '{session.role.value}'.",
                    err=True,
                )
                ctx.exit(1)
            return f(*args, **kwargs)

        return wrapper

    return decorator
