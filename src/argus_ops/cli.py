"""CLI entry point for argus-ops."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import click
import yaml

from argus_ops import __version__
from argus_ops.audit.models import RiskLevel
from argus_ops.config import DEFAULT_CONFIG_PATH, generate_default_yaml, load_config
from argus_ops.logging_config import setup_logging
from argus_ops.models import ActionIntent


@click.group()
@click.version_option(__version__, prog_name="argus-ops")
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=False),
    default=None,
    help="Path to config file (default: ~/.argus-ops/config.yaml or ARGUS_OPS_CONFIG)",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default=None,
    help="Logging verbosity",
)
@click.pass_context
def cli(ctx: click.Context, config: str | None, log_level: str | None) -> None:
    """Argus-Ops: AI-assisted infrastructure discovery and operations."""
    ctx.ensure_object(dict)
    config_path = config or os.environ.get("ARGUS_OPS_CONFIG")
    cfg = load_config(config_path)
    if log_level:
        cfg["logging"]["level"] = log_level
    setup_logging(cfg["logging"]["level"])
    ctx.obj["config"] = cfg
    ctx.obj["config_path"] = config_path or str(DEFAULT_CONFIG_PATH)


@cli.command()
@click.option(
    "--path",
    type=click.Path(),
    default=None,
    help=f"Where to create the config (default: {DEFAULT_CONFIG_PATH})",
)
@click.option("--force", is_flag=True, help="Overwrite existing config")
def bootstrap(path: str | None, force: bool) -> None:
    """Initialize config, create the first admin account, and run discovery."""
    _bootstrap(path=path, force=force)


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
    """Run rule-based analysis against the configured Kubernetes target."""
    from argus_ops.reporters import findings_to_json, print_findings

    cfg = ctx.obj["config"]
    collector = _build_kubernetes_collector(cfg, namespace)
    if collector is None:
        click.echo("Kubernetes target is disabled in config.", err=True)
        sys.exit(1)

    pipeline = _build_pipeline(cfg, collector)

    click.echo("Scanning infrastructure...", err=True)
    try:
        findings = pipeline.scan()
    except Exception as exc:
        click.echo(f"Scan failed: {exc}", err=True)
        _log_cli_action(cfg, "scan", result_status="error", metadata={"error": str(exc)})
        sys.exit(1)

    if severity:
        sev_order = ["info", "low", "medium", "high", "critical"]
        min_idx = sev_order.index(severity.lower())
        findings = [f for f in findings if sev_order.index(f.severity.value) >= min_idx]

    _log_cli_action(
        cfg,
        "scan",
        intent=ActionIntent.READ_ONLY,
        result_status="success",
        metadata={"finding_count": len(findings)},
    )

    if output == "json":
        click.echo(findings_to_json(findings))
    else:
        print_findings(findings, title="Scan Results")


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
    help="Override the AI model",
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
    """Run scan plus AI diagnosis. Admin only."""
    from argus_ops.reporters import print_diagnosis, print_findings
    from argus_ops.reporters.json_reporter import incident_to_json

    cfg = ctx.obj["config"]
    session = _require_session(cfg, minimum_role="admin")
    collector = _build_kubernetes_collector(cfg, namespace)
    if collector is None:
        click.echo("Kubernetes target is disabled in config.", err=True)
        sys.exit(1)

    ai_cfg = cfg["ai"].copy()
    if model:
        ai_cfg["model"] = model

    pipeline = _build_pipeline(cfg, collector, ai_cfg=ai_cfg)
    click.echo("Scanning infrastructure...", err=True)

    try:
        findings = pipeline.scan()
    except Exception as exc:
        click.echo(f"Scan failed: {exc}", err=True)
        _log_cli_action(
            cfg,
            "diagnose",
            session=session,
            result_status="error",
            risk_level=RiskLevel.medium,
            metadata={"error": str(exc)},
        )
        sys.exit(1)

    if not findings:
        click.echo("No findings detected. Infrastructure looks healthy.")
        _log_cli_action(
            cfg,
            "diagnose",
            session=session,
            result_status="success",
            risk_level=RiskLevel.medium,
            metadata={"finding_count": 0, "incident_count": 0},
        )
        return

    click.echo(
        f"Found {len(findings)} issue(s). Running AI diagnosis with {ai_cfg['model']}...",
        err=True,
    )

    try:
        incidents = pipeline.diagnose(findings)
    except Exception as exc:
        click.echo(f"Diagnosis failed: {exc}", err=True)
        _log_cli_action(
            cfg,
            "diagnose",
            session=session,
            result_status="error",
            risk_level=RiskLevel.medium,
            metadata={"error": str(exc), "finding_count": len(findings)},
        )
        sys.exit(1)

    _log_cli_action(
        cfg,
        "diagnose",
        session=session,
        result_status="success",
        risk_level=RiskLevel.medium,
        metadata={"finding_count": len(findings), "incident_count": len(incidents)},
    )

    if output == "json":
        click.echo(json.dumps([json.loads(incident_to_json(inc)) for inc in incidents], indent=2))
        return

    for incident in incidents:
        print_findings(incident.findings, title=f"Findings ({incident.incident_id})")
        if incident.diagnosis:
            print_diagnosis(incident.diagnosis)

    ai_provider = pipeline.ai_provider
    if (
        ai_provider
        and getattr(ai_provider, "cost_tracker", None)
        and ai_provider.cost_tracker.calls
    ):
        summary = ai_provider.cost_tracker.summary()
        click.echo(
            f"\n[AI] {summary['total_calls']} call(s), "
            f"{summary['total_tokens']} tokens, "
            f"${summary['total_cost_usd']:.4f}",
            err=True,
        )


@cli.command()
@click.option(
    "--output",
    "-o",
    type=click.Choice(["console", "json"], case_sensitive=False),
    default="console",
    help="Output format",
)
@click.pass_context
def inventory(ctx: click.Context, output: str) -> None:
    """Run discovery collectors and print the current inventory graph summary."""
    cfg = ctx.obj["config"]
    summary = _run_inventory(cfg)
    _log_cli_action(
        cfg,
        "inventory",
        intent=ActionIntent.READ_ONLY,
        result_status="success",
        metadata={
            "asset_count": len(summary.get("assets", [])),
            "snapshot_count": summary.get("snapshot_count", 0),
        },
    )

    if output == "json":
        click.echo(json.dumps(summary, indent=2))
        return

    click.echo("Inventory Summary")
    click.echo(f"  Snapshots:    {summary.get('snapshot_count', 0)}")
    click.echo(f"  Assets:       {len(summary.get('assets', []))}")
    click.echo(f"  Relations:    {len(summary.get('relations', []))}")
    click.echo(f"  Capabilities: {len(summary.get('capabilities', []))}")
    latest = summary.get("latest_snapshot")
    if latest:
        click.echo(f"  Last update:  {latest}")

    for asset in summary.get("assets", [])[:20]:
        click.echo(
            f"    - {asset['asset_type']}: {asset['name']} ({asset['infra_type']})"
        )


@cli.command()
@click.argument("goal")
@click.option(
    "--mode",
    type=click.Choice(["auto", "gitops", "direct"], case_sensitive=False),
    default="auto",
    help="Preferred execution path for mutating requests",
)
@click.option("--target", "targets", multiple=True, help="Asset id or asset name to scope the plan")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["console", "json"], case_sensitive=False),
    default="console",
    help="Output format",
)
@click.pass_context
def plan(ctx: click.Context, goal: str, mode: str, targets: tuple[str, ...], output: str) -> None:
    """Create a structured action plan from a natural-language goal."""
    from argus_ops.automation import classify_intent, prefers_direct_execution

    cfg = ctx.obj["config"]
    intent = classify_intent(goal)
    session = None
    actor = ""
    if intent == ActionIntent.MUTATING:
        session = _require_session(cfg, minimum_role="admin")
        actor = session.username
    else:
        session = _optional_session(cfg)
        actor = session.username if session else ""

    if intent == ActionIntent.READ_ONLY:
        execution_mode = "read-only"
    elif mode == "direct" or (mode == "auto" and prefers_direct_execution(goal)):
        execution_mode = "direct"
    else:
        execution_mode = "gitops"

    summary = _run_inventory(cfg)
    findings = []
    collector = _build_kubernetes_collector(cfg)
    if collector is not None:
        try:
            findings = _build_pipeline(cfg, collector).scan()
        except Exception:
            findings = []

    service = _get_automation_service(cfg)
    action_plan = service.build_plan(
        goal,
        inventory_summary=summary,
        findings=findings,
        actor=actor,
        execution_mode=execution_mode,
        target_assets=list(targets),
    )
    risk_level = _risk_level_from_name(
        action_plan.metadata.get("risk_level", RiskLevel.medium.value)
    )
    _log_cli_action(
        cfg,
        "plan",
        session=session,
        actor=actor,
        intent=action_plan.intent,
        result_status="success",
        risk_level=risk_level,
        metadata={
            "plan_id": action_plan.plan_id,
            "execution_mode": action_plan.metadata.get("execution_mode", execution_mode),
            "target_count": len(action_plan.target_assets),
        },
    )

    if output == "json":
        click.echo(json.dumps(action_plan.model_dump(mode="json"), indent=2))
        return

    click.echo(f"Plan ID:        {action_plan.plan_id}")
    click.echo(f"Intent:         {action_plan.intent.value}")
    click.echo(f"Risk:           {action_plan.metadata.get('risk_level', 'medium')}")
    click.echo(f"Execution mode: {action_plan.metadata.get('execution_mode', execution_mode)}")
    click.echo(f"Targets:        {len(action_plan.target_assets)}")
    click.echo(f"Summary:        {action_plan.summary}")
    click.echo(f"Impact:         {action_plan.impact_summary}")
    click.echo(f"Workflow:       {action_plan.metadata.get('workflow_export_path', '-')}")
    click.echo(f"Governance:     {action_plan.metadata.get('governance_summary', '-')}")
    click.echo("Steps:")
    for step in action_plan.steps:
        click.echo(f"  - {step.get('name')}: {step.get('action')}")


@cli.command("apply")
@click.option("--plan-id", required=True, help="Plan identifier returned by 'argus-ops plan'")
@click.option("--approve", is_flag=True, help="Approve and execute a mutating plan")
@click.option("--direct", is_flag=True, help="Allow direct execution when the policy permits it")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["console", "json"], case_sensitive=False),
    default="console",
    help="Output format",
)
@click.pass_context
def apply_cmd(ctx: click.Context, plan_id: str, approve: bool, direct: bool, output: str) -> None:
    """Apply a previously generated plan. Admin only for mutating plans."""
    cfg = ctx.obj["config"]
    session = _require_session(cfg, minimum_role="admin")
    service = _get_automation_service(cfg)

    try:
        result = service.apply_plan(plan_id, actor=session.username, approve=approve, direct=direct)
    except ValueError as exc:
        click.echo(f"Apply failed: {exc}", err=True)
        _log_cli_action(
            cfg,
            "apply",
            session=session,
            result_status="error",
            risk_level=RiskLevel.high,
        )
        sys.exit(1)

    risk_level = _risk_level_from_name(result.get("risk_level", RiskLevel.medium.value))
    _log_cli_action(
        cfg,
        "apply",
        session=session,
        intent=ActionIntent.MUTATING,
        result_status="success" if result.get("status") == "completed" else "error",
        risk_level=risk_level,
        metadata={
            "plan_id": plan_id,
            "status": result.get("status"),
            "execution_mode": result.get("execution_mode"),
        },
    )

    if output == "json":
        click.echo(json.dumps(result, indent=2))
        if result.get("status") != "completed":
            sys.exit(1)
        return

    click.echo(f"Plan ID:        {result['plan_id']}")
    click.echo(f"Status:         {result['status']}")
    click.echo(f"Execution mode: {result['execution_mode']}")
    click.echo(f"Risk:           {result['risk_level']}")
    click.echo(f"Workflow:       {result.get('workflow_export_path', '-')}")
    if result.get("status") != "completed":
        click.echo("Approval required before this plan can run.", err=True)
        sys.exit(1)
    click.echo(f"Artifacts:      {len(result.get('artifacts', []))}")
    click.echo(f"Verification:   {len(result.get('verification_results', []))} result(s)")
    for item in result.get("artifacts", []):
        click.echo(f"  - artifact[{item.get('type')}]: {item.get('path')}")
    for item in result.get("verification_results", []):
        click.echo(f"  - verify[{item.get('provider')}]: {item.get('status')}")


@cli.group()
def workflows() -> None:
    """Inspect built-in workflow specifications."""
    return None


@workflows.command("list")
@click.pass_context
def workflows_list(ctx: click.Context) -> None:
    """List built-in workflow specifications."""
    service = _get_automation_service(ctx.obj["config"])
    for workflow in service.list_workflows():
        click.echo(
            f"- {workflow.workflow_id:24s} kind={workflow.metadata.get('kind', 'workflow'):10s} "
            f"steps={len(workflow.steps):2d} triggers={', '.join(workflow.triggers)}"
        )


@workflows.command("export")
@click.option("--plan-id", required=True, help="Plan identifier to export as workflow YAML")
@click.pass_context
def workflows_export(ctx: click.Context, plan_id: str) -> None:
    """Show the exported workflow-as-code payload for a stored plan."""
    service = _get_automation_service(ctx.obj["config"])
    try:
        export = service.export_workflow(plan_id)
    except ValueError as exc:
        click.echo(f"Export failed: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Path: {export['path']}")
    click.echo(yaml.safe_dump(export["content"], sort_keys=False))


@cli.command("executions")
@click.option(
    "--limit",
    type=int,
    default=10,
    show_default=True,
    help="Number of recent executions to show",
)
@click.pass_context
def executions_list(ctx: click.Context, limit: int) -> None:
    """List recent plan execution records."""
    cfg = ctx.obj["config"]
    _require_session(cfg, minimum_role="admin")
    service = _get_automation_service(cfg)
    executions = service.list_execution_history(limit=limit)
    if not executions:
        click.echo("No execution records found.")
        return
    for record in executions:
        click.echo(
            f"- {record.execution_id:14s} plan={record.plan_id:14s} "
            f"mode={record.execution_mode:10s} status={record.status:24s} actor={record.actor}"
        )


@cli.group()
def plugins() -> None:
    """Inspect built-in plugin and pack metadata."""
    return None


@plugins.command("list")
@click.pass_context
def plugins_list(ctx: click.Context) -> None:
    """List built-in collectors, analyzers, executors, and packs."""
    service = _get_automation_service(ctx.obj["config"])
    for plugin in service.list_plugins():
        click.echo(
            (
                f"- {plugin['name']:20s} kind={plugin['kind']:14s} "
                f"builtin={str(plugin.get('builtin', True)).lower()}"
            )
        )


@cli.group()
def connectors() -> None:
    """Inspect built-in discovery connectors."""
    return None


@connectors.command("list")
@click.pass_context
def connectors_list(ctx: click.Context) -> None:
    """List built-in collectors, enablement, and capabilities."""
    cfg = ctx.obj["config"]
    for collector in _build_discovery_collectors(cfg):
        enabled = _is_target_enabled(cfg, collector.name)
        availability = "available" if collector.is_available() else "unavailable"
        click.echo(
            (
                f"- {collector.name:10s} enabled={str(enabled).lower():5s} "
                f"status={availability:11s} capabilities="
                f"{', '.join(collector.provided_capabilities) or '-'}"
            )
        )


@cli.command()
@click.option("--host", default=None, help="Bind host")
@click.option("--port", "-p", type=int, default=None, help="Bind port")
@click.option("--watch-interval", type=int, default=None, help="Background scan interval")
@click.option("--reload-interval", type=int, default=None, help="Browser reload fallback interval")
@click.option("--no-browser", is_flag=True, default=False, help="Do not open browser automatically")
@click.option(
    "--mcp",
    is_flag=True,
    default=False,
    help="Expose MCP-compatible tool manifest metadata",
)
@click.pass_context
def serve(
    ctx: click.Context,
    host: str | None,
    port: int | None,
    watch_interval: int | None,
    reload_interval: int | None,
    no_browser: bool,
    mcp: bool,
) -> None:
    """Start the web dashboard and background discovery service."""
    try:
        import threading
        import webbrowser

        import uvicorn

        from argus_ops.discovery import DiscoveryService
        from argus_ops.inventory_store import InventoryStore
        from argus_ops.web.api import create_app
        from argus_ops.web.watch_service import WatchService
    except ImportError:
        click.echo("Web dependencies not installed. Run: pip install argus-ops[web]", err=True)
        sys.exit(1)

    cfg = ctx.obj["config"]
    serve_cfg = cfg.get("serve", {})
    resolved_host = host or serve_cfg.get("host", "127.0.0.1")
    resolved_port = port or serve_cfg.get("port", 8080)
    resolved_watch = watch_interval or serve_cfg.get("watch_interval", 30)
    resolved_reload = reload_interval or serve_cfg.get("reload_interval", 30)
    resolved_mcp = mcp or serve_cfg.get("mcp", False)
    open_browser = (not no_browser) and serve_cfg.get("open_browser", True)

    cfg.setdefault("serve", {})["reload_interval"] = resolved_reload
    cfg["serve"]["mcp"] = resolved_mcp

    ai_provider = None
    ai_key_env = cfg.get("ai", {}).get("api_key_env", "OPENAI_API_KEY")
    if os.environ.get(ai_key_env):
        from argus_ops.ai.provider import LiteLLMProvider

        ai_provider = LiteLLMProvider(config=cfg["ai"])

    k8s_collector = _build_kubernetes_collector(cfg)

    def _make_pipeline():
        from argus_ops.engine.pipeline import Pipeline

        if k8s_collector is None:
            return Pipeline(collectors=[], analyzers=[])
        return _build_pipeline(cfg, k8s_collector)

    data_dir = _resolve_data_dir(cfg)
    inventory_store = InventoryStore(db_path=data_dir / "inventory.db")
    discovery = DiscoveryService(
        collectors=_build_discovery_collectors(cfg),
        store=inventory_store,
    )
    watch = WatchService(
        pipeline_factory=_make_pipeline,
        interval=resolved_watch,
        ai_provider=ai_provider,
        db_path=data_dir / "history.db",
        discovery_service=discovery,
        inventory_store=inventory_store,
    )
    watch.start()

    app = create_app(watch=watch, cfg=cfg)

    url = f"http://{resolved_host}:{resolved_port}"
    click.echo(f"Argus-Ops Dashboard: {url}")
    click.echo(f"API docs:            {url}/docs")
    click.echo(f"Health probe:        {url}/healthz")
    click.echo(f"Watch interval:      {resolved_watch}s")
    click.echo(f"Reload interval:     {resolved_reload}s")
    click.echo(f"MCP manifest:        {'enabled' if resolved_mcp else 'disabled'}")
    if ai_provider:
        click.echo(f"AI diagnosis:        on-demand ({cfg['ai']['model']})")
    else:
        click.echo(f"AI diagnosis:        disabled (set {ai_key_env} to enable)")

    if open_browser:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    uvicorn.run(app, host=resolved_host, port=resolved_port, log_level="warning")


@cli.command()
@click.option("--username", "-u", prompt="Username", help="Account username")
@click.option("--password", "-p", prompt=True, hide_input=True, help="Account password")
@click.pass_context
def login(ctx: click.Context, username: str, password: str) -> None:
    """Authenticate and create a local CLI session."""
    cfg = ctx.obj["config"]
    auth = _get_authenticator(cfg)
    session = auth.login(username, password)
    if session is None:
        click.echo("Login failed: invalid username or password.", err=True)
        _log_cli_action(
            cfg,
            "login",
            actor=username,
            intent=ActionIntent.MUTATING,
            result_status="error",
            risk_level=RiskLevel.low,
        )
        sys.exit(1)
    _log_cli_action(
        cfg,
        "login",
        session=session,
        intent=ActionIntent.MUTATING,
        result_status="success",
        risk_level=RiskLevel.low,
    )
    click.echo(f"Logged in as '{session.username}' (role: {session.role.value})")
    click.echo(f"Session expires: {session.expires_at.strftime('%Y-%m-%d %H:%M UTC')}")


@cli.command()
@click.pass_context
def logout(ctx: click.Context) -> None:
    """End the current session."""
    cfg = ctx.obj["config"]
    auth = _get_authenticator(cfg)
    session = auth.get_current_session()
    if auth.logout():
        _log_cli_action(
            cfg,
            "logout",
            session=session,
            intent=ActionIntent.MUTATING,
            result_status="success",
            risk_level=RiskLevel.low,
        )
        click.echo("Logged out.")
    else:
        click.echo("No active session.", err=True)


@cli.command()
@click.pass_context
def whoami(ctx: click.Context) -> None:
    """Show the current authenticated CLI user."""
    cfg = ctx.obj["config"]
    auth = _get_authenticator(cfg)
    session = auth.whoami()
    if session is None:
        click.echo("Not logged in. Run 'argus-ops login' first.", err=True)
        sys.exit(1)
    click.echo(f"Username: {session.username}")
    click.echo(f"Role:     {session.role.value}")
    click.echo(f"Expires:  {session.expires_at.strftime('%Y-%m-%d %H:%M UTC')}")


@cli.group()
def user() -> None:
    """Manage user accounts. Admin only."""
    return None


@user.command("add")
@click.argument("username")
@click.option(
    "--role",
    type=click.Choice(["viewer", "admin"], case_sensitive=False),
    default="viewer",
    help="Role to assign",
)
@click.option("--password", "-p", prompt=True, hide_input=True, confirmation_prompt=True)
@click.pass_context
def user_add(ctx: click.Context, username: str, role: str, password: str) -> None:
    """Create a new user account."""
    from argus_ops.auth.models import Role

    cfg = ctx.obj["config"]
    session = _require_session(cfg, minimum_role="admin")
    auth = _get_authenticator(cfg)
    try:
        new_user = auth.user_store.create_user(username, password, Role(role))
    except ValueError as exc:
        click.echo(f"Error: {exc}", err=True)
        _log_cli_action(
            cfg,
            "user.add",
            session=session,
            result_status="error",
            risk_level=RiskLevel.high,
        )
        sys.exit(1)
    _log_cli_action(
        cfg,
        "user.add",
        session=session,
        result_status="success",
        risk_level=RiskLevel.high,
        metadata={"target_user": new_user.username, "role": new_user.role.value},
    )
    click.echo(f"User '{new_user.username}' created with role '{new_user.role.value}'.")


@user.command("list")
@click.pass_context
def user_list(ctx: click.Context) -> None:
    """List all user accounts."""
    cfg = ctx.obj["config"]
    _require_session(cfg, minimum_role="admin")
    auth = _get_authenticator(cfg)
    users = auth.user_store.list_users()
    if not users:
        click.echo("No users found.")
        return
    for item in users:
        status_label = "active" if item.is_active else "disabled"
        click.echo(f"  {item.username:20s}  role={item.role.value:6s}  {status_label}")

@user.command("role")
@click.argument("username")
@click.option("--set", "new_role", required=True, type=click.Choice(["viewer", "admin"]))
@click.pass_context
def user_role(ctx: click.Context, username: str, new_role: str) -> None:
    """Change a user's role."""
    from argus_ops.auth.models import Role

    cfg = ctx.obj["config"]
    session = _require_session(cfg, minimum_role="admin")
    auth = _get_authenticator(cfg)
    if not auth.user_store.update_role(username, Role(new_role)):
        click.echo(f"User '{username}' not found.", err=True)
        _log_cli_action(
            cfg,
            "user.role",
            session=session,
            result_status="error",
            risk_level=RiskLevel.high,
        )
        sys.exit(1)
    _log_cli_action(
        cfg,
        "user.role",
        session=session,
        result_status="success",
        risk_level=RiskLevel.high,
        metadata={"target_user": username, "role": new_role},
    )
    click.echo(f"User '{username}' role updated to '{new_role}'.")


@user.command("disable")
@click.argument("username")
@click.pass_context
def user_disable(ctx: click.Context, username: str) -> None:
    """Disable a user account without deleting it."""
    cfg = ctx.obj["config"]
    session = _require_session(cfg, minimum_role="admin")
    auth = _get_authenticator(cfg)
    if not auth.user_store.set_active(username, False):
        click.echo(f"User '{username}' not found.", err=True)
        _log_cli_action(
            cfg,
            "user.disable",
            session=session,
            result_status="error",
            risk_level=RiskLevel.high,
        )
        sys.exit(1)
    _log_cli_action(
        cfg,
        "user.disable",
        session=session,
        result_status="success",
        risk_level=RiskLevel.high,
        metadata={"target_user": username},
    )
    click.echo(f"User '{username}' disabled.")


@user.command("enable")
@click.argument("username")
@click.pass_context
def user_enable(ctx: click.Context, username: str) -> None:
    """Re-enable a disabled user account."""
    cfg = ctx.obj["config"]
    session = _require_session(cfg, minimum_role="admin")
    auth = _get_authenticator(cfg)
    if not auth.user_store.set_active(username, True):
        click.echo(f"User '{username}' not found.", err=True)
        _log_cli_action(
            cfg,
            "user.enable",
            session=session,
            result_status="error",
            risk_level=RiskLevel.high,
        )
        sys.exit(1)
    _log_cli_action(
        cfg,
        "user.enable",
        session=session,
        result_status="success",
        risk_level=RiskLevel.high,
        metadata={"target_user": username},
    )
    click.echo(f"User '{username}' enabled.")


@user.command("remove")
@click.argument("username")
@click.confirmation_option(prompt="Are you sure you want to remove this user?")
@click.pass_context
def user_remove(ctx: click.Context, username: str) -> None:
    """Remove a user account."""
    cfg = ctx.obj["config"]
    session = _require_session(cfg, minimum_role="admin")
    auth = _get_authenticator(cfg)
    if not auth.user_store.remove_user(username):
        click.echo(f"User '{username}' not found.", err=True)
        _log_cli_action(
            cfg,
            "user.remove",
            session=session,
            result_status="error",
            risk_level=RiskLevel.critical,
        )
        sys.exit(1)
    _log_cli_action(
        cfg,
        "user.remove",
        session=session,
        result_status="success",
        risk_level=RiskLevel.critical,
        metadata={"target_user": username},
    )
    click.echo(f"User '{username}' removed.")


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
    """Run approved K8s remediation actions. Admin only."""
    from argus_ops.audit.logger import AuditLogger
    from argus_ops.healers.approval import ApprovalGate
    from argus_ops.healers.k8s_healer import K8sHealer
    from argus_ops.reporters import print_findings

    cfg = ctx.obj["config"]
    session = _require_session(cfg, minimum_role="admin")
    collector = _build_kubernetes_collector(cfg, namespace)
    if collector is None:
        click.echo("Kubernetes target is disabled in config.", err=True)
        sys.exit(1)

    pipeline = _build_pipeline(cfg, collector)
    click.echo("Scanning for issues...", err=True)
    try:
        findings = pipeline.scan()
    except Exception as exc:
        click.echo(f"Scan failed: {exc}", err=True)
        _log_cli_action(
            cfg,
            "heal",
            session=session,
            result_status="error",
            risk_level=RiskLevel.high,
        )
        sys.exit(1)

    if not findings:
        click.echo("No issues found. Cluster looks healthy.")
        return

    print_findings(findings, title="Issues Found")
    click.echo(f"\n{len(findings)} issue(s) detected. Generating remediation plan...\n", err=True)

    audit_logger = AuditLogger(audit_dir=cfg.get("audit", {}).get("log_dir"))
    approval_gate = ApprovalGate(actor=session.username, auto_mode=auto_mode)
    healer = K8sHealer(
        audit_logger=audit_logger,
        approval_gate=approval_gate,
        actor=session.username,
    )

    healed = 0
    for finding in findings:
        record = _suggest_and_heal(healer, finding, dry_run=dry_run)
        if record and record.result.get("status") == "success":
            healed += 1

    mode = "dry-run" if dry_run else "live"
    _log_cli_action(
        cfg,
        "heal",
        session=session,
        result_status="success",
        risk_level=RiskLevel.high,
        metadata={"finding_count": len(findings), "healed_count": healed, "mode": mode},
    )
    click.echo(f"\nHeal complete ({mode}): {healed}/{len(findings)} issues addressed.")


@cli.command()
@click.option("--cluster", is_flag=True, help="Show cluster-wide K8s audit events")
@click.option("--all", "show_all", is_flag=True, help="Show combined Layer 1 + Layer 2")
@click.option("--diff", "show_drift", is_flag=True, help="Show changes not made through Argus-Ops")
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
    """View the audit trail. Admin only."""
    from datetime import date

    from argus_ops.audit.correlator import AuditCorrelator
    from argus_ops.audit.k8s_audit import K8sAuditCollector
    from argus_ops.audit.logger import AuditLogger
    from argus_ops.audit.viewer import (
        print_audit_records,
        print_combined_audit,
        print_drift_events,
        print_k8s_audit_events,
    )

    cfg = ctx.obj["config"]
    _require_session(cfg, minimum_role="admin")
    audit_logger = AuditLogger(audit_dir=cfg.get("audit", {}).get("log_dir"))
    k8s_collector = K8sAuditCollector()
    correlator = AuditCorrelator(audit_logger, k8s_collector)

    start_date = end_date = None
    if date_str:
        try:
            start_date = end_date = date.fromisoformat(date_str)
        except ValueError:
            click.echo(f"Invalid date format: {date_str}. Use YYYY-MM-DD.", err=True)
            sys.exit(1)

    risk_level = RiskLevel(risk) if risk else None

    if export_path:
        count = audit_logger.export_csv(export_path, start_date=start_date, end_date=end_date)
        click.echo(f"Exported {count} records to {export_path}")
        return

    if show_drift:
        drift = correlator.get_drift(start_date=start_date, end_date=end_date)
        print_drift_events(drift)
        return

    if show_all:
        entries = correlator.get_combined(start_date=start_date, end_date=end_date, actor=actor)
        print_combined_audit(entries)
        return

    if cluster:
        events = k8s_collector.query(start_date=start_date, end_date=end_date, user=actor)
        print_k8s_audit_events(events)
        return

    records = audit_logger.query(
        start_date=start_date,
        end_date=end_date,
        actor=actor,
        action=action,
        risk_level=risk_level,
        limit=500,
    )
    print_audit_records(records)

@cli.group()
def config() -> None:
    """Manage argus-ops configuration."""
    return None


@config.command("init")
@click.option(
    "--path",
    type=click.Path(),
    default=None,
    help=f"Where to create the config (default: {DEFAULT_CONFIG_PATH})",
)
@click.option("--force", is_flag=True, help="Overwrite existing config")
def config_init(path: str | None, force: bool) -> None:
    """Initialize config, admin account, and initial discovery."""
    _bootstrap(path=path, force=force)


@config.command("show")
@click.pass_context
def config_show(ctx: click.Context) -> None:
    """Show the current effective configuration."""
    import yaml

    cfg = ctx.obj["config"]
    click.echo(yaml.dump(_mask_secrets(cfg), default_flow_style=False, sort_keys=False))


@config.command("test")
@click.pass_context
def config_test(ctx: click.Context) -> None:
    """Test connections to configured collectors."""
    cfg = ctx.obj["config"]
    collectors = []
    kubernetes_collector = _build_kubernetes_collector(cfg)
    if kubernetes_collector is not None:
        collectors.append(kubernetes_collector)
    collectors.extend(_build_discovery_collectors(cfg))

    any_failure = False
    seen: set[str] = set()
    for collector in collectors:
        if collector.name in seen:
            continue
        seen.add(collector.name)
        enabled = _is_target_enabled(cfg, collector.name)
        if not enabled:
            click.echo(f"{collector.name}: disabled")
            continue
        try:
            available = collector.is_available()
        except Exception as exc:
            click.echo(f"{collector.name}: failed ({exc})")
            any_failure = True
            continue
        status_label = "OK" if available else "FAILED"
        click.echo(f"{collector.name}: {status_label}")
        if not available:
            any_failure = True

    sys.exit(1 if any_failure else 0)


def _bootstrap(path: str | None, force: bool) -> None:
    from argus_ops.auth.models import Role

    target = Path(path) if path else DEFAULT_CONFIG_PATH
    if target.exists() and not force:
        click.echo(f"Config already exists at {target}. Use --force to overwrite.", err=True)
        sys.exit(1)

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(generate_default_yaml(), encoding="utf-8")
    click.echo(f"Config created at: {target}")

    cfg = load_config(target)
    auth = _get_authenticator(cfg)
    if auth.user_store.user_count() == 0:
        click.echo("\nCreating first admin account...")
        admin_user = click.prompt("Username", default="admin")
        admin_pass = click.prompt("Password", hide_input=True, confirmation_prompt=True)
        auth.user_store.create_user(admin_user, admin_pass, Role.admin)
        click.echo(f"Admin account '{admin_user}' created.")
    else:
        click.echo(f"Users already exist ({auth.user_store.user_count()} account(s)).")

    click.echo("\nRunning discovery bootstrap...")
    summary = _run_inventory(cfg)
    click.echo(
        f"Discovered {len(summary.get('assets', []))} asset(s) across "
        f"{summary.get('snapshot_count', 0)} snapshot(s)."
    )
    capabilities = summary.get("capabilities") or []
    if capabilities:
        click.echo(
            f"Capabilities: {', '.join(item['name'] for item in capabilities[:12])}"
        )


def _build_pipeline(cfg: dict[str, Any], collector: Any, ai_cfg: dict[str, Any] | None = None):
    from argus_ops.ai.provider import LiteLLMProvider
    from argus_ops.analyzers import ALL_ANALYZERS
    from argus_ops.engine.pipeline import Pipeline

    analyzers = _build_analyzers(ALL_ANALYZERS, cfg)
    ai_provider = LiteLLMProvider(config=ai_cfg or cfg["ai"]) if ai_cfg else None
    return Pipeline(collectors=[collector], analyzers=analyzers, ai_provider=ai_provider)


def _build_kubernetes_collector(cfg: dict[str, Any], namespace: tuple[str, ...] = ()):
    from argus_ops.collectors.k8s import KubernetesCollector

    k8s_cfg = cfg["targets"]["kubernetes"]
    if not k8s_cfg.get("enabled", True):
        return None
    if namespace:
        k8s_cfg = {**k8s_cfg, "namespaces": list(namespace), "exclude_namespaces": []}
    return KubernetesCollector(config=k8s_cfg)


def _build_discovery_collectors(cfg: dict[str, Any]) -> list[Any]:
    from argus_ops.collectors import (
        AWSCollector,
        DockerCollector,
        GitHubCollector,
        GitRepoCollector,
        HostCollector,
        TerraformCollector,
    )

    collectors: list[Any] = []
    targets = cfg.get("targets", {})
    inventory_cfg = cfg.get("inventory", {})

    def _merged(name: str) -> dict[str, Any]:
        merged = dict(targets.get(name, {}))
        if name in {"host", "git", "terraform"}:
            if inventory_cfg.get("paths") and not merged.get("paths"):
                merged["paths"] = list(inventory_cfg.get("paths", []))
            if inventory_cfg.get("max_depth") and not merged.get("max_depth"):
                merged["max_depth"] = inventory_cfg["max_depth"]
        return merged

    if targets.get("host", {}).get("enabled", True):
        collectors.append(HostCollector(config=_merged("host")))
    if targets.get("docker", {}).get("enabled", True):
        collectors.append(DockerCollector(config=_merged("docker")))
    if targets.get("git", {}).get("enabled", True):
        collectors.append(GitRepoCollector(config=_merged("git")))
    if targets.get("terraform", {}).get("enabled", True):
        collectors.append(TerraformCollector(config=_merged("terraform")))
    if targets.get("github", {}).get("enabled", True):
        collectors.append(GitHubCollector(config=_merged("github")))
    if targets.get("aws", {}).get("enabled", True):
        collectors.append(AWSCollector(config=_merged("aws")))
    kubernetes_collector = _build_kubernetes_collector(cfg)
    if kubernetes_collector is not None:
        collectors.append(kubernetes_collector)
    return collectors


def _run_inventory(cfg: dict[str, Any]) -> dict[str, Any]:
    from argus_ops.discovery import DiscoveryService
    from argus_ops.inventory_store import InventoryStore

    data_dir = _resolve_data_dir(cfg)
    store = InventoryStore(db_path=data_dir / "inventory.db")
    discovery = DiscoveryService(_build_discovery_collectors(cfg), store=store)
    discovery.discover()
    return store.load_inventory_summary()



def _resolve_data_dir(cfg: dict[str, Any]) -> Path:
    configured = cfg.get("auth", {}).get("data_dir")
    if configured:
        return Path(configured)
    return Path.home() / ".argus-ops"



def _get_authenticator(cfg: dict[str, Any]):
    from argus_ops.auth.authenticator import Authenticator

    auth_cfg = cfg.get("auth", {})
    return Authenticator(
        data_dir=auth_cfg.get("data_dir"),
        session_ttl_hours=auth_cfg.get("session_ttl_hours", 24),
    )


def _get_automation_service(cfg: dict[str, Any]):
    from argus_ops.automation import AutomationService

    return AutomationService(data_dir=_resolve_data_dir(cfg))


def _optional_session(cfg: dict[str, Any]):
    auth = _get_authenticator(cfg)
    return auth.get_current_session()



def _require_session(cfg: dict[str, Any], minimum_role: str = "viewer"):
    from argus_ops.auth.models import Role

    auth = _get_authenticator(cfg)
    session = auth.get_current_session()
    if session is None:
        click.echo("Error: Not authenticated. Run 'argus-ops login' first.", err=True)
        sys.exit(1)
    if session.role < Role(minimum_role):
        click.echo(
            f"Error: Role '{minimum_role}' required. You have '{session.role.value}'.",
            err=True,
        )
        sys.exit(1)
    return session



def _log_cli_action(
    cfg: dict[str, Any],
    action: str,
    *,
    session: Any | None = None,
    actor: str = "",
    intent: ActionIntent = ActionIntent.READ_ONLY,
    result_status: str = "success",
    risk_level: RiskLevel = RiskLevel.low,
    metadata: dict[str, Any] | None = None,
) -> None:
    from argus_ops.audit.logger import AuditLogger
    from argus_ops.audit.models import AuditRecord

    audit_logger = AuditLogger(audit_dir=cfg.get("audit", {}).get("log_dir"))
    audit_logger.log(
        AuditRecord(
            actor=session.username if session else actor,
            role=session.role.value if session else "",
            session_id=session.token[:12] if session and getattr(session, "token", "") else "",
            source="cli",
            action=action,
            intent=intent,
            target=action,
            resource=action,
            risk_level=risk_level,
            result={"status": result_status},
            metadata=metadata or {},
        )
    )



def _build_analyzers(analyzer_classes: list, cfg: dict[str, Any]) -> list[Any]:
    key_map = {
        "ResourceAnalyzer": "resource",
        "PodHealthAnalyzer": "pod_health",
        "NodeHealthAnalyzer": "node_health",
        "StorageAnalyzer": "storage",
        "CronJobAnalyzer": "cronjob",
        "NetworkPolicyAnalyzer": "network_policy",
        "SecurityAnalyzer": "security",
        "ConfigurationAnalyzer": "configuration",
    }
    analyzers = []
    for cls in analyzer_classes:
        config_key = key_map.get(cls.__name__, cls.__name__.lower())
        analyzers.append(cls(config=cfg.get("analyzers", {}).get(config_key, {})))
    return analyzers



def _is_target_enabled(cfg: dict[str, Any], collector_name: str) -> bool:
    key_map = {
        "host": "host",
        "docker": "docker",
        "git": "git",
        "terraform": "terraform",
        "github": "github",
        "aws": "aws",
        "kubernetes": "kubernetes",
    }
    target_name = key_map.get(collector_name, collector_name)
    return cfg.get("targets", {}).get(target_name, {}).get("enabled", True)



def _risk_level_from_name(value: str) -> RiskLevel:
    try:
        return RiskLevel(value)
    except ValueError:
        return RiskLevel.medium


def _suggest_and_heal(healer: Any, finding: Any, dry_run: bool = False):
    from argus_ops.models import FindingCategory

    target = finding.target
    parts = target.split("/")
    namespace = parts[0] if len(parts) > 1 else ""
    name = parts[-1] if parts else ""

    if finding.category == FindingCategory.POD_HEALTH:
        if "CrashLoopBackOff" in finding.title or "OOMKilled" in finding.title:
            return healer.restart_pod(name, namespace, reason=finding.description, dry_run=dry_run)
    elif finding.category == FindingCategory.STORAGE:
        if "Orphaned" in finding.title:
            click.echo(f"  [skip] {finding.title} -- manual cleanup recommended")
    elif finding.category == FindingCategory.CRONJOB:
        if "Failed" in finding.title:
            click.echo(f"  [info] {finding.title} -- investigate root cause")
    else:
        click.echo(f"  [skip] {finding.title} -- no auto-remediation available")
    return None



def _mask_secrets(cfg: dict[str, Any]) -> dict[str, Any]:
    import copy

    display = copy.deepcopy(cfg)
    secret_keys = {"api_key", "password", "token", "secret"}

    def _mask(target: dict[str, Any]) -> None:
        for key, value in target.items():
            if (
                any(secret in key.lower() for secret in secret_keys)
                and isinstance(value, str)
                and value
            ):
                target[key] = "***"
            elif isinstance(value, dict):
                _mask(value)

    _mask(display)
    return display



def main() -> None:
    """Entry point for the argus-ops CLI."""
    cli(obj={})


if __name__ == "__main__":
    main()










