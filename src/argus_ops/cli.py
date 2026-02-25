"""CLI entry point for argus-ops."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import click

from argus_ops import __version__
from argus_ops.config import (
    DEFAULT_CONFIG_PATH,
    generate_default_yaml,
    load_config,
)
from argus_ops.logging_config import setup_logging


@click.group()
@click.version_option(__version__, prog_name="argus-ops")
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=False),
    default=None,
    help="Path to config file (default: ~/.argus-ops/config.yaml)",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default=None,
    help="Logging verbosity",
)
@click.pass_context
def cli(ctx: click.Context, config: str | None, log_level: str | None) -> None:
    """Argus-Ops: AI-powered infrastructure monitoring and diagnosis.

    Scans Kubernetes clusters for issues, provides AI root cause analysis,
    and (coming soon) executes remediation with human approval.

    Quick start:
      argus-ops config init
      argus-ops scan
      argus-ops diagnose
    """
    ctx.ensure_object(dict)
    cfg = load_config(config)
    if log_level:
        cfg["logging"]["level"] = log_level
    setup_logging(cfg["logging"]["level"])
    ctx.obj["config"] = cfg


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--output",
    "-o",
    type=click.Choice(["console", "json"], case_sensitive=False),
    default="console",
    help="Output format",
)
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["info", "low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Show only findings at or above this severity",
)
@click.option(
    "--namespace",
    "-n",
    multiple=True,
    help="Kubernetes namespace(s) to scan (repeatable)",
)
@click.pass_context
def scan(
    ctx: click.Context,
    output: str,
    severity: str | None,
    namespace: tuple[str, ...],
) -> None:
    """Scan infrastructure for issues (no AI, fast, free).

    Runs rule-based analyzers against your Kubernetes cluster
    to detect resource issues, unhealthy pods, and node problems.

    Examples:
      argus-ops scan
      argus-ops scan --output json
      argus-ops scan --severity high
      argus-ops scan --namespace rpa --namespace zrpa-demo
    """
    from argus_ops.analyzers import ALL_ANALYZERS
    from argus_ops.collectors.k8s import KubernetesCollector
    from argus_ops.engine.pipeline import Pipeline
    from argus_ops.reporters import findings_to_json, print_findings

    cfg = ctx.obj["config"]
    k8s_cfg = cfg["targets"]["kubernetes"]

    # Override namespaces if passed via CLI flag
    if namespace:
        k8s_cfg = {**k8s_cfg, "namespaces": list(namespace), "exclude_namespaces": []}

    if not k8s_cfg.get("enabled", True):
        click.echo("Kubernetes target is disabled in config.", err=True)
        sys.exit(1)

    click.echo("Scanning infrastructure...", err=True)

    collector = KubernetesCollector(config=k8s_cfg)
    analyzers = _build_analyzers(ALL_ANALYZERS, cfg)

    pipeline = Pipeline(collectors=[collector], analyzers=analyzers)

    try:
        findings = pipeline.scan()
    except Exception as e:
        click.echo(f"Scan failed: {e}", err=True)
        sys.exit(1)

    # Filter by severity
    if severity:
        sev_order = ["info", "low", "medium", "high", "critical"]
        min_idx = sev_order.index(severity.lower())
        findings = [f for f in findings if sev_order.index(f.severity.value) >= min_idx]

    if output == "json":
        click.echo(findings_to_json(findings))
    else:
        print_findings(findings, title="Scan Results")


# ---------------------------------------------------------------------------
# diagnose command
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--output",
    "-o",
    type=click.Choice(["console", "json"], case_sensitive=False),
    default="console",
    help="Output format",
)
@click.option(
    "--model",
    "-m",
    type=str,
    default=None,
    help="Override the AI model (e.g., gpt-4o, claude-sonnet-4-6, ollama/llama3.2)",
)
@click.option(
    "--namespace",
    "-n",
    multiple=True,
    help="Kubernetes namespace(s) to scan (repeatable)",
)
@click.pass_context
def diagnose(
    ctx: click.Context,
    output: str,
    model: str | None,
    namespace: tuple[str, ...],
) -> None:
    """Scan + AI-powered root cause diagnosis.

    Runs the full scan pipeline, then sends findings to your configured
    AI model for root cause analysis and recommendations.

    Requires an AI provider API key (e.g., OPENAI_API_KEY).

    Examples:
      argus-ops diagnose
      argus-ops diagnose --model gpt-4o
      argus-ops diagnose --model ollama/llama3.2
      argus-ops diagnose --output json
    """
    from argus_ops.ai.provider import LiteLLMProvider
    from argus_ops.analyzers import ALL_ANALYZERS
    from argus_ops.collectors.k8s import KubernetesCollector
    from argus_ops.engine.pipeline import Pipeline
    from argus_ops.reporters import print_diagnosis, print_findings
    from argus_ops.reporters.json_reporter import incident_to_json

    cfg = ctx.obj["config"]
    ai_cfg = cfg["ai"].copy()
    if model:
        ai_cfg["model"] = model

    k8s_cfg = cfg["targets"]["kubernetes"]
    if namespace:
        k8s_cfg = {**k8s_cfg, "namespaces": list(namespace), "exclude_namespaces": []}

    click.echo("Scanning infrastructure...", err=True)

    collector = KubernetesCollector(config=k8s_cfg)
    analyzers = _build_analyzers(ALL_ANALYZERS, cfg)
    ai_provider = LiteLLMProvider(config=ai_cfg)
    pipeline = Pipeline(collectors=[collector], analyzers=analyzers, ai_provider=ai_provider)

    try:
        findings = pipeline.scan()
    except Exception as e:
        click.echo(f"Scan failed: {e}", err=True)
        sys.exit(1)

    if not findings:
        click.echo("No findings detected. Infrastructure looks healthy.", err=True)
        return

    click.echo(
        f"Found {len(findings)} issue(s). Running AI diagnosis with {ai_cfg['model']}...",
        err=True,
    )

    try:
        incidents = pipeline.diagnose(findings)
    except Exception as e:
        click.echo(f"Diagnosis failed: {e}", err=True)
        sys.exit(1)

    if output == "json":
        import json
        click.echo(json.dumps([
            json.loads(incident_to_json(inc)) for inc in incidents
        ], indent=2))
    else:
        for incident in incidents:
            print_findings(incident.findings, title=f"Findings ({incident.incident_id})")
            if incident.diagnosis:
                print_diagnosis(incident.diagnosis)

        # Print cost summary
        if ai_provider.cost_tracker.calls:
            summary = ai_provider.cost_tracker.summary()
            click.echo(
                f"\n[AI] {summary['total_calls']} call(s), "
                f"{summary['total_tokens']} tokens, "
                f"${summary['total_cost_usd']:.4f}",
                err=True,
            )


# ---------------------------------------------------------------------------
# serve command
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--host",
    default=None,
    help="Bind host (default: from config, usually 127.0.0.1)",
)
@click.option(
    "--port",
    "-p",
    type=int,
    default=None,
    help="Bind port (default: from config, usually 8080)",
)
@click.option(
    "--watch-interval",
    type=int,
    default=None,
    help="Seconds between background cluster scans (default: from config)",
)
@click.option(
    "--reload-interval",
    type=int,
    default=None,
    help="Seconds between browser auto-refresh polls (default: from config)",
)
@click.option(
    "--no-browser",
    is_flag=True,
    default=False,
    help="Do not open browser automatically on startup",
)
@click.pass_context
def serve(
    ctx: click.Context,
    host: str | None,
    port: int | None,
    watch_interval: int | None,
    reload_interval: int | None,
    no_browser: bool,
) -> None:
    """Start the web dashboard server (watch mode).

    Launches a FastAPI server with a live dashboard that polls the cluster
    in the background and auto-refreshes in the browser every 30 seconds.

    Requires: pip install argus-ops[web]

    Examples:
      argus-ops serve
      argus-ops serve --port 9090
      argus-ops serve --watch-interval 60 --no-browser
      argus-ops serve --host 0.0.0.0 --port 8080
    """
    try:
        import uvicorn

        from argus_ops.web.api import create_app
        from argus_ops.web.watch_service import WatchService
    except ImportError:
        click.echo(
            "Web dependencies not installed. Run: pip install argus-ops[web]",
            err=True,
        )
        sys.exit(1)

    import threading
    import webbrowser

    from argus_ops.analyzers import ALL_ANALYZERS
    from argus_ops.collectors.k8s import KubernetesCollector
    from argus_ops.engine.pipeline import Pipeline

    cfg = ctx.obj["config"]
    serve_cfg = cfg.get("serve", {})

    # CLI flags take precedence over config values
    _host = host or serve_cfg.get("host", "127.0.0.1")
    _port = port or serve_cfg.get("port", 8080)
    _watch_interval = watch_interval or serve_cfg.get("watch_interval", 30)
    _reload_interval = reload_interval or serve_cfg.get("reload_interval", 30)
    _open_browser = (not no_browser) and serve_cfg.get("open_browser", True)

    # Propagate resolved reload_interval so Jinja2 template receives it
    cfg.setdefault("serve", {})["reload_interval"] = _reload_interval

    k8s_cfg = cfg["targets"]["kubernetes"]
    if not k8s_cfg.get("enabled", True):
        click.echo("Kubernetes target is disabled in config.", err=True)
        sys.exit(1)

    # Initialize AI provider if an API key is available.
    # ai_diagnosis flag in config controlled the old auto-mode; for on-demand diagnosis
    # via the dashboard button we only need the key to be present.
    ai_provider = None
    import os
    ai_key_env = cfg.get("ai", {}).get("api_key_env", "OPENAI_API_KEY")
    if os.environ.get(ai_key_env):
        from argus_ops.ai.provider import LiteLLMProvider
        ai_provider = LiteLLMProvider(config=cfg["ai"])

    def _make_pipeline() -> Pipeline:
        collector = KubernetesCollector(config=k8s_cfg)
        analyzers = _build_analyzers(ALL_ANALYZERS, cfg)
        return Pipeline(collectors=[collector], analyzers=analyzers)

    watch = WatchService(
        pipeline_factory=_make_pipeline,
        interval=_watch_interval,
        ai_provider=ai_provider,
    )
    watch.start()

    app = create_app(watch=watch, cfg=cfg)

    url = f"http://{_host}:{_port}"
    click.echo(f"Argus-Ops Dashboard: {url}")
    click.echo(f"API docs:            {url}/docs")
    click.echo(f"Watch interval:      {_watch_interval}s (background scan)")
    click.echo(f"Reload interval:     {_reload_interval}s (browser refresh)")
    if ai_provider:
        click.echo(f"AI diagnosis:        on-demand ({cfg['ai']['model']})")
    else:
        click.echo(f"AI diagnosis:        disabled (set {ai_key_env} to enable)")
    click.echo("Press Ctrl+C to stop.")

    if _open_browser:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    uvicorn.run(app, host=_host, port=_port, log_level="warning")


# ---------------------------------------------------------------------------
# login / logout / whoami commands
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--username", "-u", prompt="Username", help="Account username")
@click.option(
    "--password",
    "-p",
    prompt=True,
    hide_input=True,
    help="Account password",
)
@click.pass_context
def login(ctx: click.Context, username: str, password: str) -> None:
    """Authenticate and create a local session.

    Example:
      argus-ops login
      argus-ops login -u mason -p mypassword
    """
    from argus_ops.auth.authenticator import Authenticator

    auth = Authenticator()
    session = auth.login(username, password)
    if session is None:
        click.echo("Login failed: invalid username or password.", err=True)
        sys.exit(1)
    click.echo(f"Logged in as '{session.username}' (role: {session.role.value})")
    click.echo(f"Session expires: {session.expires_at.strftime('%Y-%m-%d %H:%M UTC')}")


@cli.command()
def logout() -> None:
    """End the current session."""
    from argus_ops.auth.authenticator import Authenticator

    auth = Authenticator()
    if auth.logout():
        click.echo("Logged out.")
    else:
        click.echo("No active session.", err=True)


@cli.command()
def whoami() -> None:
    """Show current authenticated user and role."""
    from argus_ops.auth.authenticator import Authenticator

    auth = Authenticator()
    session = auth.whoami()
    if session is None:
        click.echo("Not logged in. Run 'argus-ops login' first.", err=True)
        sys.exit(1)
    click.echo(f"Username: {session.username}")
    click.echo(f"Role:     {session.role.value}")
    click.echo(f"Expires:  {session.expires_at.strftime('%Y-%m-%d %H:%M UTC')}")


# ---------------------------------------------------------------------------
# user management commands (admin only)
# ---------------------------------------------------------------------------

@cli.group()
def user() -> None:
    """Manage user accounts (admin only)."""
    pass


@user.command("add")
@click.argument("username")
@click.option(
    "--role",
    type=click.Choice(["viewer", "operator", "admin"], case_sensitive=False),
    default="viewer",
    help="Role to assign",
)
@click.option("--password", "-p", prompt=True, hide_input=True, confirmation_prompt=True)
def user_add(username: str, role: str, password: str) -> None:
    """Create a new user account."""
    from argus_ops.auth.authenticator import Authenticator
    from argus_ops.auth.models import Role

    auth = Authenticator()
    session = auth.get_current_session()
    if session is None or session.role != Role.admin:
        click.echo("Error: Admin role required for user management.", err=True)
        sys.exit(1)

    try:
        new_user = auth.user_store.create_user(username, password, Role(role))
        click.echo(f"User '{new_user.username}' created with role '{new_user.role.value}'.")
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@user.command("list")
def user_list() -> None:
    """List all user accounts."""
    from argus_ops.auth.authenticator import Authenticator
    from argus_ops.auth.models import Role

    auth = Authenticator()
    session = auth.get_current_session()
    if session is None or session.role != Role.admin:
        click.echo("Error: Admin role required for user management.", err=True)
        sys.exit(1)

    users = auth.user_store.list_users()
    if not users:
        click.echo("No users found.")
        return
    for u in users:
        status = "active" if u.is_active else "disabled"
        click.echo(f"  {u.username:20s}  role={u.role.value:10s}  {status}")


@user.command("role")
@click.argument("username")
@click.option("--set", "new_role", required=True, type=click.Choice(["viewer", "operator", "admin"]))
def user_role(username: str, new_role: str) -> None:
    """Change a user's role."""
    from argus_ops.auth.authenticator import Authenticator
    from argus_ops.auth.models import Role

    auth = Authenticator()
    session = auth.get_current_session()
    if session is None or session.role != Role.admin:
        click.echo("Error: Admin role required.", err=True)
        sys.exit(1)

    if auth.user_store.update_role(username, Role(new_role)):
        click.echo(f"User '{username}' role updated to '{new_role}'.")
    else:
        click.echo(f"User '{username}' not found.", err=True)
        sys.exit(1)


@user.command("remove")
@click.argument("username")
@click.confirmation_option(prompt="Are you sure you want to remove this user?")
def user_remove(username: str) -> None:
    """Remove a user account."""
    from argus_ops.auth.authenticator import Authenticator
    from argus_ops.auth.models import Role

    auth = Authenticator()
    session = auth.get_current_session()
    if session is None or session.role != Role.admin:
        click.echo("Error: Admin role required.", err=True)
        sys.exit(1)

    if auth.user_store.remove_user(username):
        click.echo(f"User '{username}' removed.")
    else:
        click.echo(f"User '{username}' not found.", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# heal command
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--dry-run", is_flag=True, help="Show what would be done without executing")
@click.option("--auto", "auto_mode", is_flag=True, help="Auto-approve low-risk actions")
@click.option(
    "--namespace",
    "-n",
    multiple=True,
    help="Kubernetes namespace(s) to heal (repeatable)",
)
@click.pass_context
def heal(ctx: click.Context, dry_run: bool, auto_mode: bool, namespace: tuple[str, ...]) -> None:
    """AI-guided remediation with approval gates.

    Scans for issues, generates fix suggestions, and executes approved
    remediation actions. Every action is logged to the audit trail.

    Examples:
      argus-ops heal
      argus-ops heal --dry-run
      argus-ops heal --auto
      argus-ops heal -n zrpa
    """
    from argus_ops.analyzers import ALL_ANALYZERS
    from argus_ops.audit.logger import AuditLogger
    from argus_ops.auth.authenticator import Authenticator
    from argus_ops.auth.models import Role
    from argus_ops.collectors.k8s import KubernetesCollector
    from argus_ops.engine.pipeline import Pipeline
    from argus_ops.healers.approval import ApprovalGate
    from argus_ops.healers.k8s_healer import K8sHealer
    from argus_ops.reporters import print_findings

    cfg = ctx.obj["config"]

    # Auth check
    auth = Authenticator()
    session = auth.get_current_session()
    if session is None:
        click.echo("Error: Not authenticated. Run 'argus-ops login' first.", err=True)
        sys.exit(1)

    if session.role < Role.operator:
        click.echo(
            f"Error: Role 'operator' or higher required. You have '{session.role.value}'.",
            err=True,
        )
        sys.exit(1)

    if auto_mode and session.role != Role.admin:
        click.echo("Error: --auto mode requires admin role.", err=True)
        sys.exit(1)

    # Scan for issues
    k8s_cfg = cfg["targets"]["kubernetes"]
    if namespace:
        k8s_cfg = {**k8s_cfg, "namespaces": list(namespace), "exclude_namespaces": []}

    click.echo("Scanning for issues...", err=True)
    collector = KubernetesCollector(config=k8s_cfg)
    analyzers = _build_analyzers(ALL_ANALYZERS, cfg)
    pipeline = Pipeline(collectors=[collector], analyzers=analyzers)

    try:
        findings = pipeline.scan()
    except Exception as e:
        click.echo(f"Scan failed: {e}", err=True)
        sys.exit(1)

    if not findings:
        click.echo("No issues found. Cluster looks healthy.")
        return

    print_findings(findings, title="Issues Found")
    click.echo(f"\n{len(findings)} issue(s) detected. Generating remediation plan...\n", err=True)

    # Setup healer
    audit_logger = AuditLogger()
    approval_gate = ApprovalGate(actor=session.username, auto_mode=auto_mode)
    healer = K8sHealer(
        audit_logger=audit_logger,
        approval_gate=approval_gate,
        actor=session.username,
    )

    # Process findings and suggest remediation
    healed = 0
    for finding in findings:
        record = _suggest_and_heal(healer, finding, dry_run=dry_run)
        if record and record.result.get("status") == "success":
            healed += 1

    mode = "dry-run" if dry_run else "live"
    click.echo(f"\nHeal complete ({mode}): {healed}/{len(findings)} issues addressed.")


def _suggest_and_heal(healer, finding, dry_run: bool = False):
    """Map a finding to a heal action and execute it."""
    from argus_ops.models import FindingCategory

    category = finding.category
    target = finding.target

    # Extract namespace and resource name from target string
    parts = target.split("/")
    ns = parts[0] if len(parts) > 1 else ""
    name = parts[-1] if parts else ""

    if category == FindingCategory.POD_HEALTH:
        if "CrashLoopBackOff" in finding.title or "OOMKilled" in finding.title:
            return healer.restart_pod(name, ns, reason=finding.description, dry_run=dry_run)
    elif category == FindingCategory.STORAGE:
        if "Orphaned" in finding.title:
            click.echo(f"  [skip] {finding.title} -- manual cleanup recommended")
    elif category == FindingCategory.CRONJOB:
        if "Failed" in finding.title:
            click.echo(f"  [info] {finding.title} -- investigate root cause")
    else:
        click.echo(f"  [skip] {finding.title} -- no auto-remediation available")

    return None


# ---------------------------------------------------------------------------
# audit command
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--cluster", is_flag=True, help="Show cluster-wide K8s audit events (Layer 2)")
@click.option("--all", "show_all", is_flag=True, help="Show combined Layer 1 + Layer 2")
@click.option("--diff", "show_drift", is_flag=True, help="Show changes NOT made through Argus-Ops")
@click.option("--date", "date_str", default=None, help="Filter by date (YYYY-MM-DD)")
@click.option("--actor", default=None, help="Filter by actor username")
@click.option("--action", default=None, help="Filter by action type")
@click.option("--risk", default=None, type=click.Choice(["low", "medium", "high", "critical"]))
@click.option("--export", "export_path", default=None, help="Export to CSV file path")
@click.pass_context
def audit(
    ctx: click.Context,
    cluster: bool,
    show_all: bool,
    show_drift: bool,
    date_str: str | None,
    actor: str | None,
    action: str | None,
    risk: str | None,
    export_path: str | None,
) -> None:
    """View the audit trail of operations and cluster changes.

    Examples:
      argus-ops audit                         # Layer 1: Argus-Ops operations
      argus-ops audit --cluster               # Layer 2: All K8s changes
      argus-ops audit --all                   # Combined view
      argus-ops audit --diff                  # Drift detection
      argus-ops audit --date 2026-02-25
      argus-ops audit --actor mason --risk high
      argus-ops audit --export audit-report.csv
    """
    from datetime import date

    from argus_ops.audit.correlator import AuditCorrelator
    from argus_ops.audit.k8s_audit import K8sAuditCollector
    from argus_ops.audit.logger import AuditLogger
    from argus_ops.audit.models import RiskLevel
    from argus_ops.audit.viewer import (
        print_audit_records,
        print_combined_audit,
        print_drift_events,
        print_k8s_audit_events,
    )

    audit_logger = AuditLogger()
    k8s_collector = K8sAuditCollector()
    correlator = AuditCorrelator(audit_logger, k8s_collector)

    # Parse date filter
    start_date = end_date = None
    if date_str:
        try:
            start_date = end_date = date.fromisoformat(date_str)
        except ValueError:
            click.echo(f"Invalid date format: {date_str}. Use YYYY-MM-DD.", err=True)
            sys.exit(1)

    risk_level = RiskLevel(risk) if risk else None

    # CSV export
    if export_path:
        count = audit_logger.export_csv(export_path, start_date=start_date, end_date=end_date)
        click.echo(f"Exported {count} records to {export_path}")
        return

    # Drift detection
    if show_drift:
        drift = correlator.get_drift(start_date=start_date, end_date=end_date)
        print_drift_events(drift)
        return

    # Combined view
    if show_all:
        entries = correlator.get_combined(
            start_date=start_date, end_date=end_date, actor=actor
        )
        print_combined_audit(entries)
        return

    # Cluster-wide audit (Layer 2)
    if cluster:
        events = k8s_collector.query(
            start_date=start_date, end_date=end_date, user=actor
        )
        print_k8s_audit_events(events)
        return

    # Default: Argus-Ops operations (Layer 1)
    records = audit_logger.query(
        start_date=start_date,
        end_date=end_date,
        actor=actor,
        action=action,
        risk_level=risk_level,
    )
    print_audit_records(records)


# ---------------------------------------------------------------------------
# config command group
# ---------------------------------------------------------------------------

@cli.group()
def config() -> None:
    """Manage argus-ops configuration."""
    pass


@config.command("init")
@click.option(
    "--path",
    type=click.Path(),
    default=None,
    help=f"Where to create the config (default: {DEFAULT_CONFIG_PATH})",
)
@click.option("--force", is_flag=True, help="Overwrite existing config")
def config_init(path: str | None, force: bool) -> None:
    """Initialize Argus-Ops: create config, admin account, and probe cluster.

    Creates ~/.argus-ops/config.yaml, prompts for first admin account,
    and displays a cluster structure summary.

    Example:
      argus-ops config init
      argus-ops config init --path ./argus-ops.yaml
    """
    from argus_ops.auth.authenticator import Authenticator
    from argus_ops.auth.models import Role

    target = Path(path) if path else DEFAULT_CONFIG_PATH

    if target.exists() and not force:
        click.echo(
            f"Config already exists at {target}. Use --force to overwrite.", err=True
        )
        sys.exit(1)

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(generate_default_yaml())
    click.echo(f"  Config created at: {target}")

    # Create first admin account if no users exist
    auth = Authenticator()
    if auth.user_store.user_count() == 0:
        click.echo("\n  Creating admin account...")
        admin_user = click.prompt("  Username", default="admin")
        admin_pass = click.prompt("  Password", hide_input=True, confirmation_prompt=True)
        auth.user_store.create_user(admin_user, admin_pass, Role.admin)
        click.echo(f"  Admin account '{admin_user}' created.")
    else:
        click.echo(f"  Users already exist ({auth.user_store.user_count()} account(s)).")

    # Probe cluster and display summary
    click.echo("\n  Connecting to cluster...")
    try:
        from kubernetes import client, config as k8s_config

        try:
            k8s_config.load_incluster_config()
        except k8s_config.ConfigException:
            k8s_config.load_kube_config()

        v1 = client.CoreV1Api()
        apps_v1 = client.AppsV1Api()
        batch_v1 = client.BatchV1Api()

        # Version
        ver = client.VersionApi().get_code()
        click.echo(f"  Cluster: kubernetes (v{ver.major}.{ver.minor})")

        # Nodes
        nodes = v1.list_node(_request_timeout=15)
        masters = sum(
            1 for n in nodes.items
            if any(
                l.startswith("node-role.kubernetes.io/") and "master" in l or "control-plane" in l
                for l in (n.metadata.labels or {})
            )
        )
        workers = len(nodes.items) - masters
        click.echo(f"  Nodes: {len(nodes.items)} ({masters} master, {workers} worker)")

        # Namespaces
        ns_list = v1.list_namespace(_request_timeout=15)
        system_ns = {"kube-system", "kube-public", "kube-node-lease"}
        user_ns = [n for n in ns_list.items if n.metadata.name not in system_ns]
        click.echo(f"  Namespaces: {len(user_ns)} (excluding system)")

        # Pods
        pods = v1.list_pod_for_all_namespaces(_request_timeout=30)
        running = sum(1 for p in pods.items if p.status.phase == "Running")
        pending = sum(1 for p in pods.items if p.status.phase == "Pending")
        failed = sum(1 for p in pods.items if p.status.phase == "Failed")
        click.echo(f"  Pods: {running} running, {pending} pending, {failed} failed")

        # CronJobs
        cjs = batch_v1.list_cron_job_for_all_namespaces(_request_timeout=15)
        click.echo(f"  CronJobs: {len(cjs.items)}")

        # Deployments
        deps = apps_v1.list_deployment_for_all_namespaces(_request_timeout=15)
        click.echo(f"  Deployments: {len(deps.items)}")

        # Services
        svcs = v1.list_service_for_all_namespaces(_request_timeout=15)
        click.echo(f"  Services: {len(svcs.items)}")

        click.echo("  Ready.")

    except Exception as e:
        click.echo(f"  Could not connect to cluster: {e}")
        click.echo("  Config created. Connect to a cluster and run 'argus-ops scan' to start.")


@config.command("show")
@click.pass_context
def config_show(ctx: click.Context) -> None:
    """Show current effective configuration."""
    import yaml

    cfg = ctx.obj["config"]
    # Mask sensitive values
    display = _mask_secrets(cfg)
    click.echo(yaml.dump(display, default_flow_style=False, sort_keys=False))


@config.command("test")
@click.pass_context
def config_test(ctx: click.Context) -> None:
    """Test connections to configured targets."""
    from argus_ops.collectors.k8s import KubernetesCollector

    cfg = ctx.obj["config"]
    all_ok = True

    # Test K8s connection
    k8s_cfg = cfg["targets"]["kubernetes"]
    if k8s_cfg.get("enabled"):
        click.echo("Testing Kubernetes connection...", nl=False)
        collector = KubernetesCollector(config=k8s_cfg)
        if collector.is_available():
            click.echo(" [OK]")
        else:
            click.echo(" [FAILED]")
            all_ok = False
    else:
        click.echo("Kubernetes: disabled")

    sys.exit(0 if all_ok else 1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_analyzers(analyzer_classes: list, cfg: dict[str, Any]) -> list:
    """Instantiate analyzers with their config sections."""
    _key_map = {
        "ResourceAnalyzer": "resource",
        "PodHealthAnalyzer": "pod_health",
        "NodeHealthAnalyzer": "node_health",
        "StorageAnalyzer": "storage",
        "CronJobAnalyzer": "cronjob",
        "NetworkPolicyAnalyzer": "network_policy",
        "SecurityAnalyzer": "security",
        "ConfigurationAnalyzer": "configuration",
    }
    result = []
    for cls in analyzer_classes:
        config_key = _key_map.get(cls.__name__, cls.__name__.lower())
        analyzer_cfg = cfg.get("analyzers", {}).get(config_key, {})
        result.append(cls(config=analyzer_cfg))
    return result


def _mask_secrets(cfg: dict[str, Any]) -> dict[str, Any]:
    """Replace secret values with masked placeholders for display."""
    import copy
    display = copy.deepcopy(cfg)
    secret_keys = {"api_key", "password", "token", "secret"}
    def _mask(d: dict) -> None:
        for k, v in d.items():
            if any(s in k.lower() for s in secret_keys) and isinstance(v, str) and v:
                d[k] = "***"
            elif isinstance(v, dict):
                _mask(v)
    _mask(display)
    return display


def main() -> None:
    """Entry point for the argus-ops CLI."""
    cli(obj={})


if __name__ == "__main__":
    main()
