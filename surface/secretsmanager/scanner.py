"""Orchestrate clone → trufflehog → ingest → cleanup.

Used by both the `scan_repo_secrets` management command and the
`POST /secretsmanager/v1/scan` API view so the behaviour is identical.

Pass either a remote `repo` URL to clone, or a `local_path` to an existing
git working tree to scan in place (no clone, directory is never deleted).
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional
from urllib.parse import urlparse, urlunparse

from django.conf import settings

from secretsmanager.utils import (
    ImportStats,
    ingest_git_history,
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
    sensitive_files: bool = False
    local_path: Optional[str] = None
    history_only: bool = False


def _git_output(repo_dir: str, *args: str, timeout: int = 30) -> Optional[str]:
    try:
        proc = subprocess.run(
            ["git", "-C", repo_dir, *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out = (proc.stdout or "").strip()
        return out if out else None
    except (subprocess.CalledProcessError, FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return None


def _git_remote_origin_url(repo_dir: str) -> Optional[str]:
    return _git_output(repo_dir, "remote", "get-url", "origin")


def _git_current_branch(repo_dir: str) -> str:
    ref = _git_output(repo_dir, "rev-parse", "--abbrev-ref", "HEAD")
    if not ref or ref == "HEAD":
        return "master"
    return ref


def _is_inside_git_worktree(path: str) -> bool:
    try:
        subprocess.run(
            ["git", "-C", path, "rev-parse", "--is-inside-work-tree"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return False


def _canonical_local_repo(path: str) -> str:
    """Resolve and validate `path` as an on-disk git working tree."""
    expanded = os.path.expanduser(path.strip())
    canonical = os.path.realpath(expanded)
    if not os.path.isdir(canonical):
        raise ValueError(f"not a directory: {path!r}")
    if not _is_inside_git_worktree(canonical):
        raise ValueError(f"not a git working tree: {path!r}")
    return canonical


def validate_local_scan_path_for_api(path: str, jail_root: str) -> str:
    """Resolve a POST `/scan` `path` and ensure it stays inside ``jail_root``.

    Raises ``ValueError`` with a short message suitable for HTTP 400 responses.
    """
    canonical = _canonical_local_repo(path)
    root_r = os.path.realpath(os.path.expanduser(jail_root.strip()))
    if not os.path.isdir(root_r):
        raise ValueError("SECRETSMANAGER_LOCAL_SCAN_ROOT is not a directory")
    if canonical != root_r and not canonical.startswith(root_r + os.sep):
        raise ValueError("path must resolve inside SECRETSMANAGER_LOCAL_SCAN_ROOT")
    return canonical


def _repo_label_for_local(canonical_dir: str) -> str:
    """Prefer `origin` for inventory/GitSource; else a file:// URI."""
    origin = _git_remote_origin_url(canonical_dir)
    if origin:
        return strip_git_suffix(origin.strip())
    return Path(canonical_dir).as_uri()


def _ingest_local_sensitive_history(canonical: str, repo_label: str, org: Optional[str]) -> ImportStats:
    """Use ``org`` for labeling when there is no ``origin`` remote."""
    origin = _git_remote_origin_url(canonical)
    org_clean = (org or "").strip() or None
    if org_clean and not origin:
        return ingest_git_history(canonical, org=org_clean)
    return ingest_git_history(canonical, repo_url=repo_label)


def scan_repo(
    repo: Optional[str] = None,
    local_path: Optional[str] = None,
    branch: Optional[str] = None,
    shallow: bool = False,
    keep: bool = False,
    only_verified: bool = False,
    extra_detectors: bool = False,
    config_path: Optional[str] = None,
    sensitive_files: bool = False,
    org: Optional[str] = None,
    history_only: bool = False,
) -> ScanResult:
    """Clone `repo` **or** scan an existing checkout at `local_path`.

    Exactly one of `repo` or `local_path` must be set.

    Remote mode: clone into a temp directory, run trufflehog, optionally
    sensitive-files ingest, delete temp dir unless ``keep=True``. The default
    is a **full clone** (full git history) so trufflehog and the
    sensitive-files walk can see every commit; pass ``shallow=True`` to opt
    into a single-commit `--depth 1` clone for speed (HEAD only — past commits
    will not be scanned).

    Local mode: run trufflehog against ``local_path`` directly (same pattern as
    ``trufflehog git file:///path/to/repo`` from the docs — Surface runs from
    outside the repo but points trufflehog at that directory). The directory is
    never deleted. ``branch``, ``shallow``, and ``keep`` are ignored for local
    scans (the tree is whatever is already on disk).

    - `only_verified=True` passes `--only-verified` to trufflehog.
    - `extra_detectors=True` passes the bundled `trufflehog.config.yaml`.
    - `config_path=<path>` overrides the bundled config with a custom YAML.
    - `sensitive_files=True` walks `git rev-list --all` after trufflehog and
      records any blob whose path matches a known-sensitive extension
      (`.env`, `.pem`, `.keystore`, …). In remote mode this forces a full clone.
    - `org` on a **local** checkout (with `sensitive_files` or `history_only`):
      when there is no ``origin`` remote, label the repo as
      ``https://github.com/<org>/<dirname>``. Ignored when ``origin`` exists
      (the remote URL wins).
    - `history_only=True` **local only**: skip trufflehog and run only the
      git-history sensitive-filename import (``--import-git-history``).

    Returns stats plus metadata for callers (log / API response).
    """
    has_repo = bool(repo and repo.strip())
    has_local = bool(local_path and local_path.strip())
    if has_repo == has_local:
        raise ValueError("Specify exactly one of `repo` or `local_path`")
    if history_only and not has_local:
        raise ValueError("`history_only` requires `local_path`")

    if has_local and history_only:
        canonical = _canonical_local_repo(local_path or "")
        repo_label = _repo_label_for_local(canonical)
        eff_branch = _git_current_branch(canonical)
        logger.info(
            "git-history-only scan at %s (label=%s branch=%s)",
            canonical,
            repo_label,
            eff_branch,
        )
        stats = _ingest_local_sensitive_history(canonical, repo_label, org)
        logger.info(
            "git-history scan: processed=%s new_secrets=%s new_locations=%s skipped=%s errors=%s",
            stats.processed,
            stats.new_secrets,
            stats.new_locations,
            stats.skipped,
            stats.errors,
        )
        return ScanResult(
            stats=stats,
            repo=repo_label,
            branch=eff_branch,
            workdir=canonical,
            kept=True,
            only_verified=False,
            config_path=None,
            sensitive_files=True,
            local_path=canonical,
            history_only=True,
        )

    resolved_config = _resolve_config_path(extra_detectors, config_path)
    if resolved_config and not os.path.isfile(resolved_config):
        raise FileNotFoundError(f"trufflehog config not found: {resolved_config}")

    if has_local:
        canonical = _canonical_local_repo(local_path or "")
        repo_label = _repo_label_for_local(canonical)
        eff_branch = _git_current_branch(canonical)
        upsert_git_source(repo_label, branch=eff_branch)
        logger.info("scanning existing checkout at %s (label=%s branch=%s)", canonical, repo_label, eff_branch)

        stats = _run_trufflehog_stream(
            canonical,
            only_verified=only_verified,
            config_path=resolved_config,
            repo_override=repo_label,
        )
        if sensitive_files:
            sensitive_stats = _ingest_local_sensitive_history(canonical, repo_label, org)
            logger.info(
                "sensitive-files scan: processed=%s new_secrets=%s new_locations=%s skipped=%s errors=%s",
                sensitive_stats.processed,
                sensitive_stats.new_secrets,
                sensitive_stats.new_locations,
                sensitive_stats.skipped,
                sensitive_stats.errors,
            )
            _merge_stats(stats, sensitive_stats)

        return ScanResult(
            stats=stats,
            repo=repo_label,
            branch=eff_branch,
            workdir=canonical,
            kept=True,
            only_verified=only_verified,
            config_path=resolved_config,
            sensitive_files=sensitive_files,
            local_path=canonical,
        )

    # --- Remote URL: clone into tempdir ---
    repo = (repo or "").strip()
    upsert_git_source(repo, branch=branch or "master")

    effective_shallow = shallow
    if sensitive_files and shallow:
        logger.info("sensitive-files scan requested -> forcing full clone (shallow disabled)")
        effective_shallow = False
    if not effective_shallow:
        logger.info("full clone requested -> trufflehog will see complete git history")

    with _workdir(keep) as workdir:
        _git_clone(repo, branch, workdir, effective_shallow)
        stats = _run_trufflehog_stream(
            workdir,
            only_verified=only_verified,
            config_path=resolved_config,
            repo_override=strip_git_suffix(repo),
        )
        if sensitive_files:
            sensitive_stats = ingest_git_history(workdir, repo_url=repo)
            logger.info(
                "sensitive-files scan: processed=%s new_secrets=%s new_locations=%s skipped=%s errors=%s",
                sensitive_stats.processed,
                sensitive_stats.new_secrets,
                sensitive_stats.new_locations,
                sensitive_stats.skipped,
                sensitive_stats.errors,
            )
            _merge_stats(stats, sensitive_stats)
        if keep:
            logger.info("clone kept for inspection at %s", workdir)
        return ScanResult(
            stats=stats,
            repo=repo,
            branch=branch,
            workdir=workdir,
            kept=keep,
            only_verified=only_verified,
            config_path=resolved_config,
            sensitive_files=sensitive_files,
            local_path=None,
        )


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


def _merge_stats(into: ImportStats, extra: ImportStats) -> None:
    """Roll `extra` into `into` so a single ScanResult can carry stats from
    multiple ingest passes (trufflehog + sensitive-files)."""
    into.processed += extra.processed
    into.new_secrets += extra.new_secrets
    into.updated_secrets += extra.updated_secrets
    into.new_locations += extra.new_locations
    into.skipped += extra.skipped
    into.errors += extra.errors
    into.error_samples.extend(extra.error_samples)
