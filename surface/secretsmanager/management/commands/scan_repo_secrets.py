from django.core.management.base import CommandError

from logbasecommand.base import LogBaseCommand
from secretsmanager.scanner import scan_repo


class Command(LogBaseCommand):
    help = (
        "Clone a remote repo (or scan an existing checkout on disk), run trufflehog, "
        "import results, then delete only temporary clones."
    )

    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--repo", help="Repository URL to clone and scan")
        group.add_argument(
            "--path",
            metavar="DIR",
            dest="local_path",
            help=(
                "Path to an existing git working tree — trufflehog runs as "
                "`trufflehog git file:///DIR` (same idea as the upstream docs). "
                "The directory is scanned in place and is never deleted."
            ),
        )
        parser.add_argument(
            "--branch", default=None, help="Branch to clone (defaults to repo default); ignored with --path"
        )
        parser.add_argument(
            "--shallow",
            action="store_true",
            help=(
                "Opt into a `git clone --depth 1` clone (HEAD only — much faster but "
                "trufflehog will NOT see past commits). Default is a full clone so the "
                "scan covers complete git history. Ignored with --path."
            ),
        )
        parser.add_argument(
            "--keep",
            action="store_true",
            help="Do NOT delete the temporary clone directory after scanning (debug); ignored with --path",
        )
        parser.add_argument(
            "--only-verified",
            action="store_true",
            help="Only record secrets trufflehog was able to verify (`trufflehog --only-verified`)",
        )
        parser.add_argument(
            "--extra-detectors",
            action="store_true",
            help="Enable the bundled extra-detectors trufflehog config (more, noisier results)",
        )
        parser.add_argument(
            "--config",
            dest="config_path",
            default=None,
            help="Path to a custom trufflehog YAML config; overrides the bundled one",
        )
        parser.add_argument(
            "--sensitive-files",
            action="store_true",
            help=(
                "After trufflehog, also walk git history for known-sensitive filenames "
                "(.env, .pem, .keystore, …). Forces a full clone when cloning from --repo."
            ),
        )
        parser.add_argument(
            "--org",
            default=None,
            help=(
                "For --path: when the checkout has no 'origin' remote, label the git-history import "
                "as https://github.com/<org>/<directory>. "
                "Ignored when origin exists. Use with --sensitive-files or --import-git-history."
            ),
        )
        parser.add_argument(
            "--import-git-history",
            action="store_true",
            dest="history_only",
            help=(
                "Skip trufflehog; only run the git-history sensitive-filename import. "
                "Requires --path. Combine with --org when there is no origin."
            ),
        )

    def handle(self, *args, **options):
        if options["history_only"] and not options.get("local_path"):
            raise CommandError("--import-git-history requires --path")
        result = scan_repo(
            repo=options.get("repo"),
            local_path=options.get("local_path"),
            branch=options["branch"],
            shallow=options["shallow"],
            keep=options["keep"],
            only_verified=options["only_verified"],
            extra_detectors=options["extra_detectors"],
            config_path=options["config_path"],
            sensitive_files=options["sensitive_files"],
            org=options["org"],
            history_only=options["history_only"],
        )
        stats = result.stats
        if result.local_path:
            extra = f" (in-place at {result.workdir})"
        elif result.kept:
            extra = f" (clone kept at {result.workdir})"
        else:
            extra = ""
        target = result.local_path or result.repo
        self.log(
            "scan complete for %s (only_verified=%s, sensitive_files=%s, import_git_history_only=%s, config=%s): "
            "processed=%s new_secrets=%s updated_secrets=%s new_locations=%s skipped=%s errors=%s%s",
            target,
            result.only_verified,
            result.sensitive_files,
            result.history_only,
            result.config_path or "—",
            stats.processed,
            stats.new_secrets,
            stats.updated_secrets,
            stats.new_locations,
            stats.skipped,
            stats.errors,
            extra,
        )
