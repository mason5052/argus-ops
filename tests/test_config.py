"""Tests for configuration loading."""

from __future__ import annotations

import yaml

from argus_ops.config import _deep_merge, generate_default_yaml, load_config


class TestLoadConfig:
    def test_defaults_returned_when_no_file(self, tmp_path):
        nonexistent = tmp_path / "nope.yaml"
        config = load_config(config_path=nonexistent)
        assert "ai" in config
        assert "targets" in config
        assert "analyzers" in config

    def test_default_ai_model(self):
        config = load_config(config_path=None)
        # Use a path that definitely does not exist
        assert config["ai"]["model"] in ("gpt-4o-mini", "gpt-4o-mini")

    def test_file_overrides_defaults(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml.dump({"ai": {"model": "gpt-4o"}}))
        config = load_config(config_path=cfg_file)
        assert config["ai"]["model"] == "gpt-4o"

    def test_env_var_overrides_file(self, tmp_path, monkeypatch):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml.dump({"ai": {"model": "gpt-4o"}}))
        monkeypatch.setenv("ARGUS_OPS_AI_MODEL", "claude-sonnet-4-6")
        config = load_config(config_path=cfg_file)
        assert config["ai"]["model"] == "claude-sonnet-4-6"

    def test_deep_merge_preserves_nested_defaults(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml.dump({"ai": {"model": "gpt-4o"}}))
        config = load_config(config_path=cfg_file)
        # Other ai keys from defaults should still be present
        assert "temperature" in config["ai"]
        assert "max_tokens" in config["ai"]


class TestDeepMerge:
    def test_simple_override(self):
        base = {"a": 1, "b": 2}
        override = {"b": 99}
        result = _deep_merge(base, override)
        assert result["a"] == 1
        assert result["b"] == 99

    def test_nested_merge(self):
        base = {"ai": {"model": "gpt-4o-mini", "temperature": 0.3}}
        override = {"ai": {"model": "gpt-4o"}}
        result = _deep_merge(base, override)
        assert result["ai"]["model"] == "gpt-4o"
        assert result["ai"]["temperature"] == 0.3  # preserved from base

    def test_adds_new_keys(self):
        base = {"a": 1}
        override = {"b": 2}
        result = _deep_merge(base, override)
        assert result["a"] == 1
        assert result["b"] == 2


class TestGenerateDefaultYaml:
    def test_generates_valid_yaml(self):
        content = generate_default_yaml()
        parsed = yaml.safe_load(content)
        assert isinstance(parsed, dict)
        assert "ai" in parsed
        assert "targets" in parsed

    def test_contains_model_field(self):
        content = generate_default_yaml()
        assert "model:" in content

    def test_contains_kubernetes_section(self):
        content = generate_default_yaml()
        assert "kubernetes:" in content
