"""Shared ingestion pipeline for the secretsmanager app.

Everything that converts external scanner output (TruffleHog NDJSON, git-history
sensitive-file scans) into `Secret` / `SecretLocation` rows lives here so the
management commands and the HTTP API go through exactly the same code path.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from datetime import timezone as dt_timezone
from typing import Any, Iterable, Iterator, Optional

from django.db import transaction
from django.utils import timezone

from inventory.models import GitSource
from secretsmanager.models import Secret, SecretLocation, State, sha256_of

# States where auto-triage is allowed to upgrade the row on re-ingest.
# Anything outside this (TRIAGED, FIXED, FP, RA) reflects a human decision and
# must never be overridden by a scanner run.
_AUTO_TRIAGEABLE_STATES = frozenset({State.NEW, State.OPEN})

logger = logging.getLogger(__name__)


@dataclass
class ImportStats:
    processed: int = 0
    new_secrets: int = 0
    updated_secrets: int = 0
    new_locations: int = 0
    skipped: int = 0
    errors: int = 0
    error_samples: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "processed": self.processed,
            "new_secrets": self.new_secrets,
            "updated_secrets": self.updated_secrets,
            "new_locations": self.new_locations,
            "skipped": self.skipped,
            "errors": self.errors,
            "error_samples": self.error_samples[:5],
        }


def strip_git_suffix(url: str) -> str:
    if url and url.endswith(".git"):
        return url[:-4]
    return url


def upsert_git_source(repo_url: Optional[str], branch: str = "master") -> Optional[GitSource]:
    """Return an existing GitSource for the repo or create a thin one.

    Never blocks the import when `repo_url` is empty — returns None instead.
    """
    if not repo_url:
        return None
    repo_url = strip_git_suffix(repo_url.strip())

    existing = GitSource.objects.filter(repo_url=repo_url, active=True).first()
    if existing:
        return existing

    gs, _created = GitSource.objects.get_or_create(
        repo_url=repo_url,
        branch=branch or "master",
        defaults={"active": True, "manually_inserted": True},
    )
    return gs


def parse_trufflehog_timestamp(raw: Optional[str]) -> datetime:
    """Parse a trufflehog git timestamp such as `2024-11-05 11:12:45 +0000`."""
    if not raw:
        return timezone.now()
    for fmt in ("%Y-%m-%d %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        logger.debug("could not parse trufflehog timestamp %r; defaulting to now", raw)
        return timezone.now()


_EMAIL_IN_ANGLE_RE = re.compile(r"<([^>]+)>")


def normalise_author(raw: Optional[str]) -> str:
    """TruffleHog emits `Name <email@domain>`; keep only the email."""
    if not raw:
        return "unknown@example.com"
    m = _EMAIL_IN_ANGLE_RE.search(raw)
    if m:
        return m.group(1).strip()
    if "@" in raw:
        return raw.strip()
    return "unknown@example.com"


def parse_trufflehog_record(
    record: dict[str, Any],
    repo_override: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """Translate one raw trufflehog JSON record into our canonical schema.

    `repo_override` is used when the caller cloned the repo locally (so
    trufflehog reports a `file:///tmp/…` path) but we want every row to carry
    the original remote URL.

    Returns None when the record does not carry enough information to be stored
    (e.g. no git metadata and no raw value).
    """
    raw_value = record.get("Raw") or record.get("RawV2") or ""
    if not raw_value:
        return None

    metadata = (record.get("SourceMetadata") or {}).get("Data") or {}
    git = metadata.get("Git") or {}
    filesystem = metadata.get("Filesystem") or {}

    reported_repo = (git.get("repository") or filesystem.get("file") or "").strip()
    if repo_override and (not reported_repo or reported_repo.startswith("file://")):
        repository = repo_override
    else:
        repository = reported_repo
    file_path = git.get("file") or filesystem.get("file") or "unknown"
    commit = git.get("commit") or "unknown"
    line = str(git.get("line") or filesystem.get("line") or "N/A")
    author = normalise_author(git.get("email"))
    ts = parse_trufflehog_timestamp(git.get("timestamp"))

    # Preserve detector diagnostics trufflehog reports alongside each hit so
    # we can show "why wasn't this verified?" in the admin.
    verification_error = record.get("VerificationError") or ""
    extra_data = record.get("ExtraData") or None
    structured_data = record.get("StructuredData") or None
    # Merge both under a single column — most detectors fill at most one.
    combined_extra: Optional[dict[str, Any]] = None
    if extra_data or structured_data:
        combined_extra = {}
        if extra_data:
            combined_extra["extra_data"] = extra_data
        if structured_data:
            combined_extra["structured_data"] = structured_data

    return {
        "secret": raw_value,
        "secret_hash": sha256_of(raw_value),
        "source": record.get("SourceName") or "trufflehog",
        "kind": record.get("DetectorName") or "",
        "verified": bool(record.get("Verified")),
        "verification_error": verification_error,
        "extra_data": combined_extra,
        "repository": strip_git_suffix(repository),
        "file_path": file_path,
        "commit": commit,
        "line": line,
        "author": author,
        "timestamp": ts,
    }


def _upsert_secret_and_location(parsed: dict[str, Any], stats: ImportStats) -> None:
    repository = parsed.get("repository") or ""
    git_source = upsert_git_source(repository) if repository else None

    verified = bool(parsed.get("verified"))
    # Verified hits start as TRIAGED; unverified hits start as NEW. This
    # mirrors Dalek's "SECRETS: only verified secrets are auto-triaged" rule.
    initial_state = State.TRIAGED if verified else State.NEW

    with transaction.atomic():
        secret, created = Secret.objects.get_or_create(
            secret_hash=parsed["secret_hash"],
            source=parsed["source"],
            defaults={
                "secret": parsed["secret"],
                "kind": parsed.get("kind", ""),
                "verified": verified,
                "verification_error": parsed.get("verification_error", ""),
                "extra_data": parsed.get("extra_data"),
                "git_source": git_source,
                "last_seen": timezone.now(),
                "state": initial_state,
            },
        )
        if created:
            stats.new_secrets += 1
        else:
            secret.last_seen = timezone.now()
            verified_flipped = verified and not secret.verified
            if verified_flipped:
                secret.verified = True
            if git_source and not secret.git_source_id:
                secret.git_source = git_source
            if parsed.get("kind") and not secret.kind:
                secret.kind = parsed["kind"]
            if parsed.get("verification_error") and not secret.verification_error:
                secret.verification_error = parsed["verification_error"]
            if parsed.get("extra_data") and not secret.extra_data:
                secret.extra_data = parsed["extra_data"]

            # Auto-triage on verification upgrade, but ONLY if the row is
            # still in an auto-triageable state — never override a human's
            # TRIAGED / FP / RA / FIXED decision.
            if verified_flipped and secret.state in _AUTO_TRIAGEABLE_STATES:
                secret.state = State.TRIAGED

            secret.save(
                update_fields=[
                    "last_seen",
                    "verified",
                    "git_source",
                    "kind",
                    "verification_error",
                    "extra_data",
                    "state",
                    "active",
                ]
            )
            stats.updated_secrets += 1

        if not repository:
            return

        # Two-step upsert so we can auto-triage new locations without ever
        # overwriting an existing row's (possibly human-set) state.
        location_defaults = {
            "author": parsed["author"],
            "timestamp": parsed["timestamp"],
        }
        existing_loc = SecretLocation.objects.filter(
            secret=secret,
            repository=strip_git_suffix(repository),
            file_path=parsed["file_path"],
            commit=parsed["commit"],
            line=parsed["line"],
        ).first()

        if existing_loc is None:
            SecretLocation.objects.create(
                secret=secret,
                repository=strip_git_suffix(repository),
                file_path=parsed["file_path"],
                commit=parsed["commit"],
                line=parsed["line"],
                state=initial_state,
                **location_defaults,
            )
            stats.new_locations += 1
        else:
            # Refresh mutable metadata without touching state (user may have
            # already FP'd this location).
            existing_loc.author = parsed["author"]
            existing_loc.timestamp = parsed["timestamp"]
            if verified and existing_loc.state in _AUTO_TRIAGEABLE_STATES:
                existing_loc.state = State.TRIAGED
            existing_loc.save(update_fields=["author", "timestamp", "state", "active"])


def ingest_trufflehog_stream(
    lines: Iterable[str],
    repo_override: Optional[str] = None,
) -> ImportStats:
    """Consume a stream of trufflehog NDJSON lines and upsert rows.

    `repo_override` rewrites the `repository` field on every record when
    trufflehog reports a local `file://` path (typical when we cloned the repo
    into a tempdir before scanning).

    Invalid / non-JSON / unparseable records are counted under `errors` but do
    not abort the whole import.
    """
    stats = ImportStats()
    for raw_line in lines:
        if raw_line is None:
            continue
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            stats.errors += 1
            stats.error_samples.append(f"json: {exc}")
            continue

        parsed = parse_trufflehog_record(record, repo_override=repo_override)
        if parsed is None:
            stats.skipped += 1
            continue

        try:
            _upsert_secret_and_location(parsed, stats)
            stats.processed += 1
        except Exception as exc:  # pragma: no cover - safety net
            stats.errors += 1
            stats.error_samples.append(f"db: {exc}")
            logger.exception("failed to ingest trufflehog record")
    return stats


# -----------------------------------------------------------------------------
# Git-history sensitive-files scan (mirrors examples/import_git_secrets.py)
# -----------------------------------------------------------------------------

SENSITIVE_EXTENSIONS = [
    # Cryptographic & Certificate Files
    ".jks",
    ".p12",
    ".pfx",
    ".pem",
    ".crt",
    ".cer",
    ".key",
    ".keystore",
    ".csr",
    ".der",
    ".spc",
    # Mobile & App Signing
    ".mobileprovision",
    ".keychain",
    ".provisionprofile",
    ".apk.sign",
    ".aab.sign",
    # Configuration & Credentials
    ".env",
    ".conf",
    ".config",
    ".ini",
    ".properties",
    ".secret",
    ".secrets",
    ".credentials",
    ".creds",
    ".htpasswd",
    ".netrc",
    # Cloud & Infrastructure
    ".aws",
    ".npmrc",
    ".tfstate",
    ".tfvars",
]
SENSITIVE_EXTENSIONS += [
    f".env.{env}" for env in ("dev", "development", "prod", "production", "staging", "test", "local")
]


def _git(repo_path: str, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", repo_path, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    return result.stdout


def _detect_default_branch(repo_path: str) -> str:
    try:
        return _git(repo_path, "rev-parse", "--abbrev-ref", "HEAD").strip() or "main"
    except subprocess.CalledProcessError:
        return "main"


def _iter_sensitive_files(repo_path: str) -> Iterator[dict[str, str]]:
    try:
        commits = _git(repo_path, "rev-list", "--all").splitlines()
    except subprocess.CalledProcessError as exc:
        logger.error("git rev-list failed: %s", exc)
        return

    for commit in commits:
        try:
            tree = _git(repo_path, "ls-tree", "-r", commit)
        except subprocess.CalledProcessError:
            continue
        for entry in tree.splitlines():
            try:
                _mode, _type, _hash, path = entry.split(None, 3)
            except ValueError:
                continue
            if not any(path.lower().endswith(ext) for ext in SENSITIVE_EXTENSIONS):
                continue
            try:
                author = _git(repo_path, "log", "-1", "--format=%ae", commit, "--", path).strip()
                date = _git(repo_path, "log", "-1", "--format=%aI", commit, "--", path).strip()
            except subprocess.CalledProcessError:
                author, date = "", ""
            yield {"commit": commit, "file": path, "author": author, "date": date}


def _file_content_sha(repo_path: str, commit: str, path: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "-C", repo_path, "show", f"{commit}:{path}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except subprocess.CalledProcessError:
        return None
    return hashlib.sha256(result.stdout).hexdigest()


def ingest_git_history(repo_path: str, org: str = "your-org") -> ImportStats:
    """Scan a git repo checkout for known-sensitive filenames and record them.

    One `Secret` per unique file content (keyed by its sha256); one
    `SecretLocation` per (commit, path) it appeared in.
    """
    stats = ImportStats()

    repo_name = os.path.basename(os.path.normpath(repo_path))
    repo_url = f"https://github.com/{org}/{repo_name}"
    default_branch = _detect_default_branch(repo_path)
    git_source = upsert_git_source(repo_url, branch=default_branch)

    by_hash: dict[str, dict[str, Any]] = {}
    for entry in _iter_sensitive_files(repo_path):
        content_hash = _file_content_sha(repo_path, entry["commit"], entry["file"])
        if not content_hash:
            stats.skipped += 1
            continue
        extension = os.path.splitext(entry["file"])[1] or "unknown"
        bucket = by_hash.setdefault(content_hash, {"extension": extension, "locations": []})
        bucket["locations"].append(entry)

    for content_hash, data in by_hash.items():
        kind = f"SensitiveFile ({data['extension']})"
        with transaction.atomic():
            secret, created = Secret.objects.get_or_create(
                secret_hash=content_hash,
                source="git-history-scan",
                defaults={
                    "secret": content_hash,
                    "kind": kind,
                    "verified": False,
                    "git_source": git_source,
                    "last_seen": timezone.now(),
                },
            )
            if created:
                stats.new_secrets += 1
            else:
                secret.last_seen = timezone.now()
                secret.save(update_fields=["last_seen"])
                stats.updated_secrets += 1

            for entry in data["locations"]:
                ts = entry.get("date") or ""
                try:
                    parsed_ts = datetime.fromisoformat(ts) if ts else timezone.now()
                except ValueError:
                    parsed_ts = timezone.now()
                if parsed_ts.tzinfo is None:
                    parsed_ts = parsed_ts.replace(tzinfo=dt_timezone.utc)

                # `active` is recomputed from `state` inside save(), so we
                # never set it explicitly — see `SecretLocation.save()`.
                _loc, loc_created = SecretLocation.objects.update_or_create(
                    secret=secret,
                    repository=repo_url,
                    file_path=entry["file"],
                    commit=entry["commit"],
                    line="1",
                    defaults={
                        "author": entry.get("author") or "unknown@example.com",
                        "timestamp": parsed_ts,
                    },
                )
                if loc_created:
                    stats.new_locations += 1
        stats.processed += len(data["locations"])

    return stats
