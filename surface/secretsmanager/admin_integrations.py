"""Admin hooks injected into other apps' admins.

We keep these in the `secretsmanager` app so inventory doesn't need to know
anything about secret scanning. Side effects here run once at app-ready time
(see `apps.SecretsManagerConfig.ready`).
"""

from __future__ import annotations

import logging

from django.contrib import admin, messages

from inventory.admin import GitSourceAdmin
from inventory.models import GitSource
from secretsmanager.scanner import scan_repo

logger = logging.getLogger(__name__)

# Scans are synchronous and clone+scan each repo one at a time. Anything past
# this would likely time out the admin request. Users with larger batches
# should run `manage.py scan_repo_secrets` directly.
MAX_BATCH = 5

# `inventory.GitSource.branch` defaults to "master" — for most modern repos
# that's wrong (default is `main`). Treat any value matching the model default
# as "no explicit branch" so we fall back to the repo's actual default
# (mirroring `manage.py scan_repo_secrets` without `--branch`).
_GITSOURCE_BRANCH_DEFAULT = GitSource._meta.get_field("branch").default


def _resolve_branch(gs: GitSource):
    branch = (gs.branch or "").strip()
    if not branch or branch == _GITSOURCE_BRANCH_DEFAULT:
        return None
    return branch


def _run_scans(
    request,
    queryset,
    *,
    only_verified: bool = False,
    extra_detectors: bool = False,
    sensitive_files: bool = False,
) -> None:
    """Shared body for the admin actions below.

    ``sensitive_files=True`` walks the cloned repo's git history for
    known-sensitive filenames (`.env`, `.pem`, `.keystore`, …) on top of
    trufflehog. ``scan_repo`` automatically forces a full clone in that mode,
    so admin scans pick up secrets buried in old commits — the closest
    equivalent of the CLI's ``--sensitive-files`` / ``--import-git-history``
    flows for a remote repository (the ``--import-git-history`` "no
    trufflehog, history only" mode requires a local ``--path`` and so cannot
    be triggered from the admin).
    """
    total = queryset.count()
    if total == 0:
        messages.warning(request, "No Git sources selected.")
        return
    if total > MAX_BATCH:
        messages.error(
            request,
            f"Selected {total} repos — cap is {MAX_BATCH} per batch. "
            "Use `python manage.py scan_repo_secrets` for bulk scans.",
        )
        return

    mode_bits = []
    if only_verified:
        mode_bits.append("only-verified")
    if extra_detectors:
        mode_bits.append("extra-detectors")
    if sensitive_files:
        mode_bits.append("sensitive-files (git history)")
    mode_label = ", ".join(mode_bits) or "default detectors"

    successes: list[str] = []
    failures: list[str] = []

    for gs in queryset:
        if not gs.repo_url:
            failures.append(f"#{gs.pk}: missing repo_url")
            continue
        try:
            result = scan_repo(
                repo=gs.repo_url,
                branch=_resolve_branch(gs),
                only_verified=only_verified,
                extra_detectors=extra_detectors,
                sensitive_files=sensitive_files,
            )
            stats = result.stats
            successes.append(
                f"{gs.repo_url}: processed={stats.processed} "
                f"new_secrets={stats.new_secrets} new_locations={stats.new_locations} "
                f"skipped={stats.skipped} errors={stats.errors}"
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("admin-triggered scan failed for %s", gs.repo_url)
            failures.append(f"{gs.repo_url}: {exc}")

    if successes:
        messages.success(
            request,
            f"Scanned {len(successes)} repo(s) ({mode_label}): " + " | ".join(successes),
        )
    if failures:
        messages.error(request, f"{len(failures)} scan(s) failed: " + " | ".join(failures))


@admin.action(description="Scan for secrets — default detectors")
def scan_default(modeladmin, request, queryset):
    _run_scans(request, queryset)


@admin.action(description="Scan for secrets — verified only")
def scan_only_verified(modeladmin, request, queryset):
    _run_scans(request, queryset, only_verified=True)


@admin.action(description="Scan for secrets — extra detectors (bundled config.yaml)")
def scan_with_extra_detectors(modeladmin, request, queryset):
    _run_scans(request, queryset, extra_detectors=True)


@admin.action(description="Scan for secrets — git history (sensitive files, full clone)")
def scan_with_git_history(modeladmin, request, queryset):
    _run_scans(request, queryset, sensitive_files=True)


@admin.action(description="Scan for secrets — extra detectors + git history (full clone)")
def scan_with_extra_detectors_and_git_history(modeladmin, request, queryset):
    _run_scans(request, queryset, extra_detectors=True, sensitive_files=True)


def register_gitsource_actions() -> None:
    """Idempotently append our scan actions onto inventory's GitSourceAdmin."""
    existing = list(GitSourceAdmin.actions or [])
    for action in (
        scan_default,
        scan_only_verified,
        scan_with_extra_detectors,
        scan_with_git_history,
        scan_with_extra_detectors_and_git_history,
    ):
        if action not in existing:
            existing.append(action)
    GitSourceAdmin.actions = existing
