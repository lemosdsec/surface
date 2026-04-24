"""Orchestrate clone → trufflehog → ingest → cleanup.

Used by both the `scan_repo_secrets` management command and the
`POST /secretsmanager/v1/scan` API view so the behaviour is identical.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Optional
from urllib.parse import urlparse, urlunparse

from django.conf import settings

from secretsmanager.utils import (
    ImportStats,
    ingest_trufflehog_stream,
    strip_git_suffix,
    upsert_git_source,
)

logger = logging.getLogger(__name__)

# Path to the bundled extra-detectors config shipped with the app.
BUNDLED_TRUFFLEHOG_CONFIG = os.path.join(os.path.dirname(__file__), "trufflehog.config.yaml")


@dataclass
class ScanResult:
    stats: ImportStats
    repo: str
    branch: Optional[str]
    workdir: str
    kept: bool = False
    only_verified: bool = False
    config_path: Optional[str] = None


def _inject_token(repo_url: str) -> str:
    """Attach the right token to the repo URL when configured.

    Leaves the URL alone for public repos or when no matching token is set.
    """
    try:
        parsed = urlparse(repo_url)
    except ValueError:
        return repo_url
    if not parsed.scheme.startswith("http") or parsed.username:
        return repo_url

    token = None
    host = (parsed.hostname or "").lower()
    if "github.com" in host:
        token = getattr(settings, "SURFACE_GITHUB_TOKEN", None)
    elif "gitlab" in host:
        token = getattr(settings, "SURFACE_GITLAB_TOKEN", None)

    if not token:
        return repo_url

    netloc = f"oauth2:{token}@{parsed.hostname}"
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunparse(parsed._replace(netloc=netloc))


@contextmanager
def _workdir(keep: bool) -> Iterator[str]:
    path = tempfile.mkdtemp(prefix="surface-secrets-")
    try:
        yield path
    finally:
        if not keep:
            shutil.rmtree(path, ignore_errors=True)


def _git_clone(repo_url: str, branch: Optional[str], target: str, shallow: bool) -> None:
    cmd = ["git", "clone"]
    if shallow:
        cmd += ["--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [_inject_token(repo_url), target]
    logger.info("cloning %s (branch=%s, shallow=%s)", repo_url, branch or "default", shallow)
    subprocess.run(
        cmd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=getattr(settings, "SECRETSMANAGER_CLONE_TIMEOUT", 600),
    )


def _resolve_config_path(extra_detectors: bool, config_path: Optional[str]) -> Optional[str]:
    """Pick the trufflehog `--config` path to use, if any.

    Precedence: explicit `config_path` > `extra_detectors=True` (bundled yaml)
    > `SECRETSMANAGER_TRUFFLEHOG_CONFIG` setting when set to a non-empty value.
    """
    if config_path:
        return config_path
    if extra_detectors:
        return getattr(settings, "SECRETSMANAGER_TRUFFLEHOG_CONFIG", None) or BUNDLED_TRUFFLEHOG_CONFIG
    return None


def _trufflehog_cmd(
    workdir: str,
    only_verified: bool = False,
    config_path: Optional[str] = None,
) -> list[str]:
    docker = getattr(settings, "SECRETSMANAGER_TRUFFLEHOG_DOCKER", False)

    if docker:
        image = getattr(settings, "SECRETSMANAGER_TRUFFLEHOG_IMAGE", "trufflesecurity/trufflehog:latest")
        cmd = ["docker", "run", "--rm", "-v", f"{workdir}:/src:ro"]
        if config_path:
            cmd += ["-v", f"{os.path.abspath(config_path)}:/config.yaml:ro"]
        cmd += [image, "git", "file:///src", "--json", "--no-update"]
        if config_path:
            cmd += ["--config", "/config.yaml"]
        if only_verified:
            cmd += ["--only-verified"]
        return cmd

    binary = getattr(settings, "SECRETSMANAGER_TRUFFLEHOG_BIN", "trufflehog")
    cmd = [binary, "git", f"file://{workdir}", "--json", "--no-update"]
    if config_path:
        cmd += ["--config", config_path]
    if only_verified:
        cmd += ["--only-verified"]
    return cmd


def _run_trufflehog_stream(
    workdir: str,
    only_verified: bool = False,
    config_path: Optional[str] = None,
    repo_override: Optional[str] = None,
) -> ImportStats:
    cmd = _trufflehog_cmd(workdir, only_verified=only_verified, config_path=config_path)
    logger.info("running trufflehog: %s", " ".join(cmd))
    timeout = getattr(settings, "SECRETSMANAGER_SCAN_TIMEOUT", 900)

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None

    try:
        stats = ingest_trufflehog_stream(
            iter(proc.stdout.readline, ""),
            repo_override=repo_override,
        )
    finally:
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise
    stderr = (proc.stderr.read() if proc.stderr else "") or ""
    if proc.returncode not in (0, None):
        logger.warning("trufflehog exited with code %s; stderr: %s", proc.returncode, stderr[:500])
    return stats


def scan_repo(
    repo: str,
    branch: Optional[str] = None,
    shallow: bool = True,
    keep: bool = False,
    only_verified: bool = False,
    extra_detectors: bool = False,
    config_path: Optional[str] = None,
) -> ScanResult:
    """Clone `repo`, run trufflehog, ingest findings, then clean up.

    - `only_verified=True` passes `--only-verified` to trufflehog.
    - `extra_detectors=True` passes the bundled `trufflehog.config.yaml`.
    - `config_path=<path>` overrides the bundled config with a custom YAML.

    Returns stats plus metadata for callers (log / API response).
    """
    upsert_git_source(repo, branch=branch or "master")

    resolved_config = _resolve_config_path(extra_detectors, config_path)
    if resolved_config and not os.path.isfile(resolved_config):
        raise FileNotFoundError(f"trufflehog config not found: {resolved_config}")

    with _workdir(keep) as workdir:
        _git_clone(repo, branch, workdir, shallow)
        stats = _run_trufflehog_stream(
            workdir,
            only_verified=only_verified,
            config_path=resolved_config,
            repo_override=strip_git_suffix(repo),
        )
        kept = keep
        if keep:
            logger.info("clone kept for inspection at %s", workdir)
        return ScanResult(
            stats=stats,
            repo=repo,
            branch=branch,
            workdir=workdir,
            kept=kept,
            only_verified=only_verified,
            config_path=resolved_config,
        )
