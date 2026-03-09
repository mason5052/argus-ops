"""Configuration loading from YAML files and environment variables."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

CONFIG_DIR = Path.home() / ".argus-ops"
DEFAULT_CONFIG_PATH = CONFIG_DIR / "config.yaml"

DEFAULT_CONFIG: dict[str, Any] = {
    "ai": {
        "provider": "openai",
        "model": "gpt-4o-mini",
        "api_key_env": "OPENAI_API_KEY",
        "base_url": None,
        "temperature": 0.3,
        "max_tokens": 4096,
        "cost_limit_per_run": 0.50,
    },
    "targets": {
        "kubernetes": {
            "enabled": True,
            "kubeconfig": None,
            "context": None,
            "namespaces": [],
            "exclude_namespaces": ["kube-system", "kube-public", "kube-node-lease"],
        },
        "host": {
            "enabled": True,
            "paths": [],
        },
        "docker": {
            "enabled": True,
        },
        "git": {
            "enabled": True,
            "paths": [],
            "max_depth": 4,
        },
        "terraform": {
            "enabled": True,
            "paths": [],
            "max_depth": 4,
        },
        "github": {
            "enabled": True,
            "token_env": "GITHUB_TOKEN",
        },
        "aws": {
            "enabled": True,
        },
        "ssh_hosts": [],
        "prometheus": {
            "enabled": False,
            "url": "http://localhost:9090",
        },
    },
    "inventory": {
        "enabled": True,
        "paths": [],
        "max_depth": 4,
    },
    "analyzers": {
        "resource": {
            "cpu_warning": 80,
            "cpu_critical": 95,
            "memory_warning": 85,
            "memory_critical": 95,
            "disk_warning": 80,
            "disk_critical": 90,
        },
        "pod_health": {
            "crashloop_restart_threshold": 5,
            "pending_timeout_minutes": 10,
        },
        "node_health": {
            "conditions_to_check": [
                "Ready",
                "MemoryPressure",
                "DiskPressure",
                "PIDPressure",
            ],
        },
        "security": {},
        "storage": {},
        "cronjob": {},
        "network_policy": {},
        "configuration": {},
    },
    "auth": {
        "session_ttl_hours": 24,
        "data_dir": None,
        "cookie_name": "argus_ops_session",
    },
    "audit": {
        "log_dir": None,
        "cluster_audit_dir": None,
        "retention_days": 90,
    },
    "logging": {
        "level": "INFO",
    },
    "serve": {
        "host": "127.0.0.1",
        "port": 8080,
        "reload_interval": 30,
        "watch_interval": 30,
        "open_browser": True,
        "ai_diagnosis": False,
        "mcp": False,
    },
}


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """Load configuration with priority: env vars > YAML file > defaults."""
    config = _deep_copy_dict(DEFAULT_CONFIG)

    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    if path.exists():
        with open(path, encoding="utf-8") as handle:
            file_config = yaml.safe_load(handle) or {}
        config = _deep_merge(config, file_config)

    _apply_env_overrides(config)
    _normalize_paths(config)
    return config


def create_default_config(path: Path | None = None) -> Path:
    """Create a default configuration file."""
    target = path or DEFAULT_CONFIG_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        yaml.dump(
            DEFAULT_CONFIG,
            handle,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )
    return target


def _apply_env_overrides(config: dict[str, Any]) -> None:
    """Apply ARGUS_OPS_* environment variable overrides."""
    env_mappings = {
        "ARGUS_OPS_AI_PROVIDER": ("ai", "provider"),
        "ARGUS_OPS_AI_MODEL": ("ai", "model"),
        "ARGUS_OPS_AI_BASE_URL": ("ai", "base_url"),
        "ARGUS_OPS_LOG_LEVEL": ("logging", "level"),
        "ARGUS_OPS_SERVE_HOST": ("serve", "host"),
        "ARGUS_OPS_SERVE_PORT": ("serve", "port"),
        "ARGUS_OPS_GITHUB_TOKEN_ENV": ("targets", "github", "token_env"),
    }
    for env_var, keys in env_mappings.items():
        value = os.environ.get(env_var)
        if not value:
            continue
        target = config
        for key in keys[:-1]:
            target = target.setdefault(key, {})
        target[keys[-1]] = value


def _normalize_paths(config: dict[str, Any]) -> None:
    """Ensure discovery path-based targets inherit inventory scan paths by default."""
    inventory_paths = config.get("inventory", {}).get("paths") or []
    if inventory_paths:
        for target_name in ("host", "git", "terraform"):
            target_cfg = config.get("targets", {}).get(target_name, {})
            if not target_cfg.get("paths"):
                target_cfg["paths"] = list(inventory_paths)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override dict into base dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _deep_copy_dict(data: dict) -> dict:
    """Deep copy a nested dict structure."""
    result = {}
    for key, value in data.items():
        if isinstance(value, dict):
            result[key] = _deep_copy_dict(value)
        elif isinstance(value, list):
            result[key] = value.copy()
        else:
            result[key] = value
    return result


def generate_default_yaml() -> str:
    """Return a commented default config.yaml as a string."""
    return """\
# Argus-Ops Configuration
# Generated by: argus-ops config init
# Docs: https://github.com/mason5052/argus-ops

ai:
  provider: openai
  model: gpt-4o-mini
  api_key_env: OPENAI_API_KEY
  base_url: null
  temperature: 0.3
  max_tokens: 4096
  cost_limit_per_run: 0.50

targets:
  kubernetes:
    enabled: true
    kubeconfig: null
    context: null
    namespaces: []
    exclude_namespaces:
      - kube-system
      - kube-public
      - kube-node-lease
  host:
    enabled: true
    paths: []
  docker:
    enabled: true
  git:
    enabled: true
    paths: []
    max_depth: 4
  terraform:
    enabled: true
    paths: []
    max_depth: 4
  github:
    enabled: true
    token_env: GITHUB_TOKEN
  aws:
    enabled: true

inventory:
  enabled: true
  paths: []
  max_depth: 4

analyzers:
  resource:
    cpu_warning: 80
    cpu_critical: 95
    memory_warning: 85
    memory_critical: 95
    disk_warning: 80
    disk_critical: 90
  pod_health:
    crashloop_restart_threshold: 5
    pending_timeout_minutes: 10
  node_health:
    conditions_to_check:
      - Ready
      - MemoryPressure
      - DiskPressure
      - PIDPressure
  security: {}
  storage: {}
  cronjob: {}
  network_policy: {}
  configuration: {}

auth:
  session_ttl_hours: 24
  data_dir: null
  cookie_name: argus_ops_session

audit:
  log_dir: null
  cluster_audit_dir: null
  retention_days: 90

logging:
  level: WARNING

serve:
  host: 127.0.0.1
  port: 8080
  reload_interval: 30
  watch_interval: 30
  open_browser: true
  ai_diagnosis: false
  mcp: false
"""

