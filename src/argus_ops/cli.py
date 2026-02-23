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
    """Create a default configuration file.

    Creates ~/.argus-ops/config.yaml with sensible defaults
    and inline documentation for all settings.

    Example:
      argus-ops config init
      argus-ops config init --path ./argus-ops.yaml
    """
    target = Path(path) if path else DEFAULT_CONFIG_PATH

    if target.exists() and not force:
        click.echo(
            f"Config already exists at {target}. Use --force to overwrite.", err=True
        )
        sys.exit(1)

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(generate_default_yaml())
    click.echo(f"Config created at: {target}")
    click.echo("Edit it to configure your AI provider and targets.")


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
