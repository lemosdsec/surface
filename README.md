![GitHub Workflow Status (with branch)](https://img.shields.io/github/actions/workflow/status/surface-security/surface/release.yml)
![Python](https://img.shields.io/badge/python-%3E%3D3.8%2C%3C=3.11-blue)
![Django](https://img.shields.io/badge/Django-%3E%3D4.2%2C%3C%3D5.2.8-blue)
![Codecov](https://img.shields.io/codecov/c/github/surface-security/surface)

# Surface

**Security Intelligence Automation Platform** — asset inventory, software composition analysis, secret scanning and scanner orchestration, all in one Django app.

> This is a fork of [surface-security/surface](https://github.com/surface-security/surface) with additional modules, including the `secretsmanager` app for TruffleHog-driven secret scanning.

## What's inside

The platform is a collection of cooperating Django apps. Everything is managed through the Django admin:

| App | Purpose | Admin URL |
| --- | ------- | --------- |
| `inventory` | People, Applications (TLAs), Git repositories (`GitSource`) | `/inventory/` |
| `dns_ips` | DNS records, IP addresses/ranges, sources, tags | `/dns_ips/` |
| `scanners` | Scanner orchestration (Docker-based runners + rootboxes) | `/scanners/` |
| `scanner_baseline` | Baseline scan results | `/scanner_baseline/` |
| `sca` | Software Composition Analysis: SBOMs, dependencies, EoL checks, vulnerability findings, Renovate | `/sca/` |
| `secretsmanager` | **Secret scanning**: TruffleHog clone-and-scan, NDJSON import, git-history sensitive-file scan, REST API | `/secretsmanager/` |
| `vulns` | Unified `Finding` model used by SCA (and future modules) | `/vulns/` |
| `surfapp` | Shared templates, UI glue | `/` |
| `core_utils` | Shared admin / query / model helpers | *(no admin)* |

### Feature highlights

- **Asset tracking** — track people, teams, applications, repositories, DNS/IPs in one place.
- **SCA** — import CycloneDX SBOMs, match against OSV.dev vulns, check End-of-Life status, and raise pull requests via Renovate. See [`demo/sca_demo.md`](demo/sca_demo.md).
- **Secret scanning** (`secretsmanager`):
  - `scan_repo_secrets --repo …` → clones the repo, runs TruffleHog, ingests results, deletes the clone.
  - `import_secrets <file.ndjson>` → load pre-generated TruffleHog output.
  - `import_git_secrets <path>` → scan git history for known-sensitive filenames (`.env`, `.pem`, `.pfx`, `.keystore`, …).
  - REST API at `/secretsmanager/v1/…` for `curl`-style uploads and remote-trigger scans.
  - `Secret` ↔ `SecretLocation` with automatic state cascading (FP / Risk Accepted / Fixed propagates both ways).
  - Verified secrets auto-triage to `TRIAGED`; human state changes are never overridden on re-scan.
  - See [`demo/secrets_demo.md`](demo/secrets_demo.md).
- **Scanner infrastructure** — pluggable Docker-based scanners (`httpx`, `nmap`, `example`, and your own) dispatched across one or more rootboxes.

## Quickstart

### Local dev (fastest, no Docker needed)

Works well for developing or trying out a single app (like `secretsmanager`).

```bash
# 1. Clone
git clone git@github.com:lemosdsec/surface.git
cd surface

# 2. Install deps into a venv
python3 -m venv .venv && source .venv/bin/activate
pip install -r surface/requirements.txt

# 3. Create a local MySQL database (nothing fancy — empty schema is enough)
mysql -u root -e "CREATE DATABASE surface CHARACTER SET utf8mb4;"

# 4. Point Surface at it via surface/local.env (gitignored)
cat > surface/local.env <<'EOF'
SURF_DATABASE_URL=mysql://root:@127.0.0.1:3306/surface
SURF_DATABASE_PASSWORD=""
SURF_DEBUG=True
EOF

# 5. Migrate + create an admin user
cd surface
python manage.py migrate
python manage.py createsuperuser

# 6. Run the dev server
python manage.py runserver
```

Open <http://127.0.0.1:8000/> and log in.

### Docker (full stack)

Use this when you want the full Surface experience — nginx, sbomrepo service, dkron, slackbot, etc. — without installing anything on the host.

```bash
git clone git@github.com:lemosdsec/surface.git
cd surface

# Optional custom settings
touch surface/local.env

# Launch the stack
docker compose -f dev/docker-compose-in-a-box.yml up

# Run the "quick start" script — prompts for the admin password
dev/box_setup.sh
```

Open <http://localhost:8080> and log in as `admin`.

`box_setup.sh` creates a `local` Rootbox and registers the `example`, `httpx`, and `nmap` scanner images ([source](https://github.com/surface-security/?q=scanner-)).

> If the stack is already running when the migrations land, reload nginx + Surface:
> ```bash
> docker container restart dev-nginx-1 dev-surface-1
> ```

### AWS deployment

See [`dev/aws-cdk/README.md`](dev/aws-cdk/README.md).

## Demos / playbooks

| Demo | What it shows |
| ---- | ------------- |
| [`demo/sca_demo.md`](demo/sca_demo.md) | End-to-end SCA flow: generate SBOMs, sync OSV.dev vulns + EoL data, import SBOMs, review findings. |
| [`demo/secrets_demo.md`](demo/secrets_demo.md) | Four ways to feed secrets into Surface: CLI clone-and-scan, NDJSON import, `curl` upload, API-triggered remote scan. |

## Running tests

```bash
cd surface
pip install -r requirements_test.txt
pytest
```

To only run one app's tests:

```bash
pytest secretsmanager/
pytest sca/
```

## Common management commands

```bash
# Inventory & SCA
python manage.py resync_endoflife
python manage.py resync_sbom_repo
python manage.py check_public_dependencies

# Secrets
python manage.py scan_repo_secrets --repo https://github.com/owner/repo
python manage.py scan_repo_secrets --repo …  --only-verified          # high-signal only
python manage.py scan_repo_secrets --repo …  --extra-detectors        # include bundled detectors
python manage.py import_secrets /path/to/trufflehog-output.ndjson
python manage.py import_git_secrets /path/to/local/checkout --org myorg

# Scanner orchestration
python manage.py run_scanner <name>
python manage.py resync_rootbox
```

## Project structure

```
surface/                             # Django project root
├── manage.py
├── local.env                        # local config (gitignored)
├── requirements*.txt
├── surface/                         # project settings/urls/sidebar/wsgi
├── inventory/                       # people, apps, git sources
├── dns_ips/                         # DNS & IP records
├── scanners/                        # scanner orchestration
├── scanner_baseline/                # baseline scanning
├── sca/                             # Software Composition Analysis
├── secretsmanager/                  # TruffleHog-driven secret scanning
├── vulns/                           # Unified Finding model
├── surfapp/                         # shared templates
└── core_utils/                      # shared helpers

demo/                                # runbooks for demos (this fork only)
dev/                                 # docker-compose stack + helpers
e2e/                                 # end-to-end tests
```

## Contributing

- Fork, branch, commit, open a PR.
- `pre-commit` is configured (`.pre-commit-config.yaml`) — install it with `pre-commit install` so your commits get linted automatically.
- Tests must pass (`pytest`) and coverage shouldn't drop.

## Documentation

- Upstream wiki: <https://github.com/surface-security/surface/wiki>
- App-specific READMEs:
  - [`surface/secretsmanager/README.md`](surface/secretsmanager/README.md)
  - [`surface/sca/README.md`](surface/sca/README.md)
  - [`surface/scanners/README.md`](surface/scanners/README.md)
  - [`surface/core_utils/README.md`](surface/core_utils/README.md)

## License

MIT — see [LICENSE](LICENSE).
