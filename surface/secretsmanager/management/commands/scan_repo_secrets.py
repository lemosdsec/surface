from logbasecommand.base import LogBaseCommand
from secretsmanager.scanner import scan_repo


class Command(LogBaseCommand):
    help = "Clone a repo, run trufflehog against it, import results, then delete the clone."

    def add_arguments(self, parser):
        parser.add_argument("--repo", required=True, help="Repository URL to clone and scan")
        parser.add_argument("--branch", default=None, help="Branch to clone (defaults to repo default)")
        parser.add_argument(
            "--full",
            action="store_true",
            help="Clone the full history instead of a shallow clone (slower)",
        )
        parser.add_argument(
            "--keep",
            action="store_true",
            help="Do NOT delete the temporary clone directory after scanning (debug)",
        )
        parser.add_argument(
            "--only-verified",
            action="store_true",
            help="Only record secrets that trufflehog was able to verify (`--only-verified`)",
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

    def handle(self, *args, **options):
        result = scan_repo(
            repo=options["repo"],
            branch=options["branch"],
            shallow=not options["full"],
            keep=options["keep"],
            only_verified=options["only_verified"],
            extra_detectors=options["extra_detectors"],
            config_path=options["config_path"],
        )
        stats = result.stats
        self.log(
            "scan complete for %s (only_verified=%s, config=%s): "
            "processed=%s new_secrets=%s updated_secrets=%s new_locations=%s skipped=%s errors=%s%s",
            result.repo,
            result.only_verified,
            result.config_path or "—",
            stats.processed,
            stats.new_secrets,
            stats.updated_secrets,
            stats.new_locations,
            stats.skipped,
            stats.errors,
            f" (clone kept at {result.workdir})" if result.kept else "",
        )
