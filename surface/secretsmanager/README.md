# Secrets Manager

Surface app for storing secret-scanner findings (TruffleHog today, git-history
sensitive-file scans as a bonus). Findings flow through a single canonical
ingest pipeline regardless of whether they arrive via management command or
HTTP upload.

## Data model

- `Secret` — one row per unique secret (`(secret_hash, source)` unique). Stores
  the raw value, a SHA256 digest, scanner-reported metadata (`kind`,
  `verified`), and optional links to `inventory.GitSource` / `inventory.Person`.
- `SecretLocation` — one row per `(repository, file_path, commit, line)` where
  a secret was observed. The same `Secret` can have many locations across
  different repos / commits.

## Ingest surfaces

| Surface | When to use |
| ------- | ----------- |
| `python manage.py scan_repo_secrets --repo <url>` | Demo-style clone → scan → import → delete loop. |
| `python manage.py scan_repo_secrets --path <dir> …` | Scan an existing clone (`--sensitive-files`, `--import-git-history`, `--org`, …). |
| `python manage.py import_secrets <file.ndjson>` | You already have TruffleHog output on disk. |
| `POST /secretsmanager/v1/trufflehog` (`file=@…`) | Upload a TruffleHog NDJSON via `curl`. |
| `POST /secretsmanager/v1/scan` (JSON `{repo, branch}`) | Trigger a server-side clone+scan+import. |

All paths converge on `secretsmanager.utils.ingest_trufflehog_stream` (or its
`ingest_git_history` sibling), so the admin/data model behaviour is identical
regardless of entry point.

## Settings

See [demo/secrets_demo.md](../../demo/secrets_demo.md#5-settings-cheat-sheet)
for the env-var cheat-sheet.

## Source tree

```
secretsmanager/
  apps.py
  models.py              # Secret + SecretLocation
  admin.py               # Unfold-based admins + links
  urls.py / views.py     # v1 API (upload, scan, list)
  scanner.py             # clone + trufflehog + cleanup orchestrator
  utils.py               # shared parsers + upsert helpers
  management/commands/
    scan_repo_secrets.py
    import_secrets.py
  tests/
    fixtures.py
    test_import_trufflehog.py
    test_scan_repo_secrets.py
    test_api.py
```
