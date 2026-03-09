"""Local discovery collectors for host, Docker, Git, Terraform, GitHub, and AWS."""

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
import uuid
from pathlib import Path

from argus_ops.collectors.base import BaseCollector
from argus_ops.models import (
    Asset,
    AssetType,
    Capability,
    HealthSnapshot,
    InfraType,
    InventorySnapshot,
    Relation,
)


def _scan_roots(config: dict) -> list[Path]:
    roots = config.get("paths") or [str(Path.cwd())]
    return [Path(root).resolve() for root in roots]


def _safe_run(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout.strip()


class HostCollector(BaseCollector):
    """Discover local host properties and exposed operational capabilities."""

    @property
    def name(self) -> str:
        return "host"

    @property
    def infra_type(self) -> InfraType:
        return InfraType.HOST

    @property
    def provided_capabilities(self) -> list[str]:
        return [
            "host.identity",
            "host.filesystem",
            "host.network",
            "host.process_runtime",
        ]

    def is_available(self) -> bool:
        return True

    def collect(self) -> list[HealthSnapshot]:
        host_data = {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cwd": str(Path.cwd()),
        }
        return [
            HealthSnapshot(
                collector_name=self.name,
                infra_type=self.infra_type,
                target=f"host://{socket.gethostname()}",
                data=host_data,
                capabilities=self.provided_capabilities,
            )
        ]

    def discover(self) -> InventorySnapshot:
        host_name = socket.gethostname()
        host_id = f"host:{host_name}"
        filesystem_id = f"fs:{host_name}:{Path.cwd().resolve()}"
        assets = [
            Asset(
                asset_id=host_id,
                asset_type=AssetType.HOST,
                name=host_name,
                infra_type=self.infra_type,
                properties={
                    "platform": platform.platform(),
                    "python_version": platform.python_version(),
                    "architecture": platform.machine(),
                },
            ),
            Asset(
                asset_id=filesystem_id,
                asset_type=AssetType.FILESYSTEM_ROOT,
                name=str(Path.cwd().resolve()),
                infra_type=self.infra_type,
                properties={"cwd": str(Path.cwd().resolve())},
            ),
        ]
        relations = [
            Relation(
                source_asset_id=host_id,
                target_asset_id=filesystem_id,
                relation_type="hosts",
            )
        ]
        capabilities = [
            Capability(
                name=capability,
                collector_name=self.name,
                description="Local host capability discovered at runtime.",
            )
            for capability in self.provided_capabilities
        ]
        return InventorySnapshot(
            snapshot_id=f"INV-{uuid.uuid4().hex[:8]}",
            collector_name=self.name,
            target=f"host://{host_name}",
            assets=assets,
            relations=relations,
            capabilities=capabilities,
            metadata={"scan_roots": [str(root) for root in _scan_roots(self.config)]},
        )


class DockerCollector(BaseCollector):
    """Discover Docker engine availability and running containers."""

    @property
    def name(self) -> str:
        return "docker"

    @property
    def infra_type(self) -> InfraType:
        return InfraType.DOCKER

    @property
    def provided_capabilities(self) -> list[str]:
        return ["docker.engine", "docker.containers"]

    def is_available(self) -> bool:
        return shutil.which("docker") is not None

    def collect(self) -> list[HealthSnapshot]:
        if not self.is_available():
            return []
        version = _safe_run(["docker", "version", "--format", "{{json .Server}}"])
        data = {"engine": json.loads(version) if version else {}}
        return [
            HealthSnapshot(
                collector_name=self.name,
                infra_type=self.infra_type,
                target="docker://local",
                data=data,
                capabilities=self.provided_capabilities,
            )
        ]

    def discover(self) -> InventorySnapshot | None:
        if not self.is_available():
            return None
        engine_id = "docker:engine:local"
        assets = [
            Asset(
                asset_id=engine_id,
                asset_type=AssetType.DOCKER_ENGINE,
                name="local-docker-engine",
                infra_type=self.infra_type,
                properties={
                    "version": _safe_run(["docker", "version", "--format", "{{.Server.Version}}"]),
                },
            )
        ]
        relations: list[Relation] = []
        raw_containers = _safe_run(["docker", "ps", "--format", "{{json .}}"])
        for line in raw_containers.splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            container_id = f"docker:container:{item.get('ID')}"
            assets.append(
                Asset(
                    asset_id=container_id,
                    asset_type=AssetType.DOCKER_CONTAINER,
                    name=item.get("Names", item.get("ID", "container")),
                    infra_type=self.infra_type,
                    properties=item,
                )
            )
            relations.append(
                Relation(
                    source_asset_id=engine_id,
                    target_asset_id=container_id,
                    relation_type="runs",
                )
            )
        return InventorySnapshot(
            snapshot_id=f"INV-{uuid.uuid4().hex[:8]}",
            collector_name=self.name,
            target="docker://local",
            assets=assets,
            relations=relations,
            capabilities=[
                Capability(name=name, collector_name=self.name)
                for name in self.provided_capabilities
            ],
        )


class GitRepoCollector(BaseCollector):
    """Discover Git repositories and GitHub remotes beneath configured paths."""

    @property
    def name(self) -> str:
        return "git"

    @property
    def infra_type(self) -> InfraType:
        return InfraType.GIT

    @property
    def provided_capabilities(self) -> list[str]:
        return ["git.repositories", "github.remotes"]

    def is_available(self) -> bool:
        return shutil.which("git") is not None

    def collect(self) -> list[HealthSnapshot]:
        repos = self._discover_repo_paths()
        return [
            HealthSnapshot(
                collector_name=self.name,
                infra_type=self.infra_type,
                target="filesystem://git",
                data={"repositories": [str(path) for path in repos]},
                capabilities=self.provided_capabilities,
            )
        ]

    def discover(self) -> InventorySnapshot:
        assets: list[Asset] = []
        relations: list[Relation] = []
        for repo_path in self._discover_repo_paths():
            repo_id = f"git:{repo_path}"
            remote_url = _safe_run(["git", "-C", str(repo_path), "remote", "get-url", "origin"])
            branch = _safe_run(["git", "-C", str(repo_path), "rev-parse", "--abbrev-ref", "HEAD"])
            dirty = bool(_safe_run(["git", "-C", str(repo_path), "status", "--short"]))
            assets.append(
                Asset(
                    asset_id=repo_id,
                    asset_type=AssetType.GIT_REPOSITORY,
                    name=repo_path.name,
                    infra_type=self.infra_type,
                    properties={
                        "path": str(repo_path),
                        "remote_url": remote_url,
                        "branch": branch,
                    },
                    tags=["dirty"] if dirty else [],
                )
            )
            if "github.com" in remote_url:
                repo_name = remote_url.split("github.com")[-1].strip(":/").rstrip(".git")
                github_id = f"github:{repo_name}"
                assets.append(
                    Asset(
                        asset_id=github_id,
                        asset_type=AssetType.GITHUB_REPOSITORY,
                        name=repo_name,
                        infra_type=InfraType.GITHUB,
                        properties={"remote_url": remote_url},
                    )
                )
                relations.append(
                    Relation(
                        source_asset_id=repo_id,
                        target_asset_id=github_id,
                        relation_type="mirrors_to",
                    )
                )
        return InventorySnapshot(
            snapshot_id=f"INV-{uuid.uuid4().hex[:8]}",
            collector_name=self.name,
            target="filesystem://git",
            assets=assets,
            relations=relations,
            capabilities=[
                Capability(name=name, collector_name=self.name)
                for name in self.provided_capabilities
            ],
        )

    def _discover_repo_paths(self) -> list[Path]:
        repos: list[Path] = []
        seen: set[Path] = set()
        max_depth = int(self.config.get("max_depth", 4))
        for root in _scan_roots(self.config):
            for git_dir in root.rglob(".git"):
                repo_path = git_dir.parent
                if repo_path in seen:
                    continue
                try:
                    depth = len(repo_path.relative_to(root).parts)
                except ValueError:
                    continue
                if depth > max_depth:
                    continue
                seen.add(repo_path)
                repos.append(repo_path)
        return sorted(repos)


class TerraformCollector(BaseCollector):
    """Discover Terraform roots beneath configured paths."""

    @property
    def name(self) -> str:
        return "terraform"

    @property
    def infra_type(self) -> InfraType:
        return InfraType.TERRAFORM

    @property
    def provided_capabilities(self) -> list[str]:
        return ["terraform.roots"]

    def is_available(self) -> bool:
        return True

    def collect(self) -> list[HealthSnapshot]:
        roots = self._discover_terraform_roots()
        return [
            HealthSnapshot(
                collector_name=self.name,
                infra_type=self.infra_type,
                target="filesystem://terraform",
                data={"roots": [str(path) for path in roots]},
                capabilities=self.provided_capabilities,
            )
        ]

    def discover(self) -> InventorySnapshot:
        assets = [
            Asset(
                asset_id=f"terraform:{root}",
                asset_type=AssetType.TERRAFORM_ROOT,
                name=root.name,
                infra_type=self.infra_type,
                properties={
                    "path": str(root),
                    "has_backend": (root / "backend.tf").exists(),
                    "has_lockfile": (root / ".terraform.lock.hcl").exists(),
                },
            )
            for root in self._discover_terraform_roots()
        ]
        return InventorySnapshot(
            snapshot_id=f"INV-{uuid.uuid4().hex[:8]}",
            collector_name=self.name,
            target="filesystem://terraform",
            assets=assets,
            capabilities=[
                Capability(name=name, collector_name=self.name)
                for name in self.provided_capabilities
            ],
        )

    def _discover_terraform_roots(self) -> list[Path]:
        roots: set[Path] = set()
        max_depth = int(self.config.get("max_depth", 4))
        for root in _scan_roots(self.config):
            for tf_file in root.rglob("*.tf"):
                candidate = tf_file.parent
                try:
                    depth = len(candidate.relative_to(root).parts)
                except ValueError:
                    continue
                if depth <= max_depth:
                    roots.add(candidate)
        return sorted(roots)


class GitHubCollector(BaseCollector):
    """Discover GitHub access configuration from local environment."""

    @property
    def name(self) -> str:
        return "github"

    @property
    def infra_type(self) -> InfraType:
        return InfraType.GITHUB

    @property
    def provided_capabilities(self) -> list[str]:
        return ["github.token", "github.repositories"]

    def is_available(self) -> bool:
        return bool(os.environ.get(self._token_env_name()) or os.environ.get("GH_TOKEN"))

    def collect(self) -> list[HealthSnapshot]:
        return [
            HealthSnapshot(
                collector_name=self.name,
                infra_type=self.infra_type,
                target="github://local",
                data={"token_env": self._token_env_name()},
                capabilities=self.provided_capabilities if self.is_available() else [],
            )
        ]

    def discover(self) -> InventorySnapshot:
        assets: list[Asset] = []
        if self.is_available():
            assets.append(
                Asset(
                    asset_id=f"github:token:{self._token_env_name()}",
                    asset_type=AssetType.GITHUB_REPOSITORY,
                    name="github-token-configured",
                    infra_type=self.infra_type,
                    properties={"token_env": self._token_env_name()},
                    tags=["credential"],
                )
            )
        return InventorySnapshot(
            snapshot_id=f"INV-{uuid.uuid4().hex[:8]}",
            collector_name=self.name,
            target="github://local",
            assets=assets,
            capabilities=(
                [
                    Capability(name=name, collector_name=self.name)
                    for name in self.provided_capabilities
                ]
                if assets
                else []
            ),
        )

    def _token_env_name(self) -> str:
        return self.config.get("token_env", "GITHUB_TOKEN")


class AWSCollector(BaseCollector):
    """Discover locally configured AWS profiles."""

    @property
    def name(self) -> str:
        return "aws"

    @property
    def infra_type(self) -> InfraType:
        return InfraType.AWS

    @property
    def provided_capabilities(self) -> list[str]:
        return ["aws.profiles"]

    def is_available(self) -> bool:
        return self._credentials_path().exists() or self._config_path().exists()

    def collect(self) -> list[HealthSnapshot]:
        profiles = self._discover_profiles()
        return [
            HealthSnapshot(
                collector_name=self.name,
                infra_type=self.infra_type,
                target="aws://local",
                data={"profiles": profiles},
                capabilities=self.provided_capabilities if profiles else [],
            )
        ]

    def discover(self) -> InventorySnapshot:
        assets = [
            Asset(
                asset_id=f"aws:profile:{profile}",
                asset_type=AssetType.AWS_PROFILE,
                name=profile,
                infra_type=self.infra_type,
                properties={"profile": profile},
            )
            for profile in self._discover_profiles()
        ]
        return InventorySnapshot(
            snapshot_id=f"INV-{uuid.uuid4().hex[:8]}",
            collector_name=self.name,
            target="aws://local",
            assets=assets,
            capabilities=(
                [
                    Capability(name=name, collector_name=self.name)
                    for name in self.provided_capabilities
                ]
                if assets
                else []
            ),
        )

    def _discover_profiles(self) -> list[str]:
        profiles: set[str] = set()
        for path in (self._credentials_path(), self._config_path()):
            if not path.exists():
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if stripped.startswith("[") and stripped.endswith("]"):
                    profiles.add(stripped.strip("[]").replace("profile ", ""))
        return sorted(profile for profile in profiles if profile)

    @staticmethod
    def _credentials_path() -> Path:
        return Path.home() / ".aws" / "credentials"

    @staticmethod
    def _config_path() -> Path:
        return Path.home() / ".aws" / "config"
