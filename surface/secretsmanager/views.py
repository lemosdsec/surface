"""HTTP API for the secretsmanager app.

- `POST /secretsmanager/v1/trufflehog`  upload a trufflehog NDJSON file
- `POST /secretsmanager/v1/scan`        trigger a server-side clone + scan
- `GET  /secretsmanager/v1/secrets`     list known secrets (smoke-test helper)

All endpoints follow the same curl-friendly pattern already used by
`sbomrepo` in `demo/sca_demo.md`.
"""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Optional

from django.conf import settings
from django.db.models import Count
from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from secretsmanager.models import Secret
from secretsmanager.scanner import scan_repo, validate_local_scan_path_for_api
from secretsmanager.utils import ingest_trufflehog_stream

logger = logging.getLogger(__name__)


def _auth_required() -> bool:
    return bool(getattr(settings, "SECRETSMANAGER_REQUIRE_AUTH", False))


def _check_auth(request: HttpRequest) -> Optional[JsonResponse]:
    """Return None when allowed, else a 401 JsonResponse.

    Validates a `Authorization: Token <digest>` header against `knox` tokens
    (which underpins `django-apitokens`). When auth is disabled via setting,
    always allows the request.
    """
    if not _auth_required():
        return None

    header = request.headers.get("Authorization", "")
    try:
        prefix, token = header.split(None, 1)
    except ValueError:
        return JsonResponse({"error": "Missing Authorization header"}, status=401)
    if prefix.lower() != "token":
        return JsonResponse({"error": "Invalid Authorization scheme"}, status=401)

    try:
        from knox.crypto import hash_token
        from knox.models import AuthToken
        from knox.settings import CONSTANTS

        digest = hash_token(token)
        exists = AuthToken.objects.filter(
            token_key=token[: CONSTANTS.TOKEN_KEY_LENGTH],
            digest=digest,
        ).exists()
    except Exception:
        logger.exception("knox token validation failed")
        return JsonResponse({"error": "Auth backend unavailable"}, status=500)

    if not exists:
        return JsonResponse({"error": "Invalid token"}, status=401)
    return None


@csrf_exempt
@require_http_methods(["POST"])
def upload_trufflehog(request: HttpRequest) -> JsonResponse:
    """Import a trufflehog NDJSON file.

    Expects `multipart/form-data` with a `file` field, mirroring sbomrepo's
    `curl -F file=@…` style.
    """
    auth_error = _check_auth(request)
    if auth_error is not None:
        return auth_error

    uploaded = request.FILES.get("file")
    if uploaded is None:
        return JsonResponse({"error": "`file` form field is required"}, status=400)

    def _lines():
        for raw_chunk in uploaded:
            text = raw_chunk.decode("utf-8", errors="replace") if isinstance(raw_chunk, bytes) else raw_chunk
            yield from text.splitlines()

    stats = ingest_trufflehog_stream(_lines())
    return JsonResponse({"status": "ok", "stats": stats.as_dict()})


@csrf_exempt
@require_http_methods(["POST"])
def scan(request: HttpRequest) -> JsonResponse:
    """Run trufflehog: clone ``repo`` or scan an on-disk tree via ``path``."""
    auth_error = _check_auth(request)
    if auth_error is not None:
        return auth_error

    try:
        body = json.loads(request.body.decode("utf-8")) if request.body else {}
    except json.JSONDecodeError as exc:
        return JsonResponse({"error": f"Invalid JSON body: {exc}"}, status=400)

    repo = (body.get("repo") or "").strip()
    raw_local = body.get("path") or body.get("local_path") or ""
    local_path = raw_local.strip() if isinstance(raw_local, str) else ""

    if repo and local_path:
        return JsonResponse({"error": "Specify only one of `repo` or `path`, not both"}, status=400)
    if not repo and not local_path:
        return JsonResponse({"error": "Provide `repo` (URL to clone) or `path` (local checkout)"}, status=400)

    # Default is a full clone (full git history). Accept either `shallow=True`
    # for the new opt-in shallow behaviour, or the legacy `full=True` body
    # field which used to mean "opt out of the old shallow default".
    if "shallow" in body:
        shallow_flag = bool(body.get("shallow"))
    elif "full" in body:
        shallow_flag = not bool(body.get("full"))
    else:
        shallow_flag = False

    scan_kwargs = dict(
        branch=body.get("branch"),
        shallow=shallow_flag,
        keep=bool(body.get("keep")),
        only_verified=bool(body.get("only_verified")),
        extra_detectors=bool(body.get("extra_detectors")),
        config_path=body.get("config") or None,
        sensitive_files=bool(body.get("sensitive_files")),
        org=(body.get("org") or "").strip() or None,
        history_only=bool(body.get("history_only") or body.get("import_git_history")),
    )

    label = repo or local_path or "(unknown)"
    try:
        if local_path:
            jail = getattr(settings, "SECRETSMANAGER_LOCAL_SCAN_ROOT", None)
            if not jail:
                return JsonResponse(
                    {
                        "error": "Local `path` scans are disabled. "
                        "Set SECRETSMANAGER_LOCAL_SCAN_ROOT (env SURF_SECRETS_LOCAL_SCAN_ROOT) "
                        "to a directory prefix, or use `manage.py scan_repo_secrets --path` on the host.",
                    },
                    status=400,
                )
            try:
                validated_path = validate_local_scan_path_for_api(local_path, jail)
            except ValueError as exc:
                return JsonResponse({"error": str(exc)}, status=400)

            result = scan_repo(local_path=validated_path, **scan_kwargs)
        else:
            result = scan_repo(repo=repo, **scan_kwargs)
    except ValueError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    except FileNotFoundError as exc:
        return JsonResponse({"status": "error", "error": str(exc)}, status=400)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        logger.exception("scan_repo failed for %s", label)
        return JsonResponse({"status": "error", "error": str(exc), "stderr": stderr[:2000]}, status=502)
    except subprocess.TimeoutExpired as exc:
        logger.exception("scan_repo timed out for %s", label)
        return JsonResponse({"status": "error", "error": f"Timeout: {exc}"}, status=504)

    payload = {
        "status": "ok",
        "repo": result.repo,
        "branch": result.branch,
        "kept": result.kept,
        "only_verified": result.only_verified,
        "sensitive_files": result.sensitive_files,
        "history_only": result.history_only,
        "config": result.config_path,
        "stats": result.stats.as_dict(),
    }
    if result.local_path is not None:
        payload["local_path"] = result.local_path
    return JsonResponse(payload)


_DEFAULT_LIMIT = 50
_MAX_LIMIT = 500


@require_http_methods(["GET"])
def list_secrets(request: HttpRequest) -> JsonResponse:
    """Read-only smoke-test endpoint for quick curl checks."""
    auth_error = _check_auth(request)
    if auth_error is not None:
        return auth_error

    try:
        limit = max(1, min(int(request.GET.get("limit", _DEFAULT_LIMIT)), _MAX_LIMIT))
    except (TypeError, ValueError):
        return JsonResponse({"error": "`limit` must be an integer"}, status=400)

    qs = (
        Secret.objects.select_related("git_source").annotate(_locations_count=Count("locations")).order_by("-last_seen")
    )
    repo = request.GET.get("repo")
    if repo:
        qs = qs.filter(locations__repository__icontains=repo).distinct()
    source = request.GET.get("source")
    if source:
        qs = qs.filter(source=source)

    data = [
        {
            "id": s.id,
            "secret_hash": s.secret_hash,
            "source": s.source,
            "kind": s.kind,
            "verified": s.verified,
            "state": s.get_state_display(),
            "active": s.active,
            "redacted": s.redacted,
            "git_source": s.git_source.repo_url if s.git_source else None,
            "locations": s._locations_count,
            "last_seen": s.last_seen.isoformat() if s.last_seen else None,
        }
        for s in qs[:limit]
    ]
    return JsonResponse({"status": "ok", "count": len(data), "secrets": data})
