from logbasecommand.base import LogBaseCommand
from secretsmanager.utils import ingest_git_history


class Command(LogBaseCommand):
    help = "Scan a local git checkout for known-sensitive filenames across history."

    def add_arguments(self, parser):
        parser.add_argument("repo_path", type=str, help="Path to a local git checkout")
        parser.add_argument(
            "--org",
            type=str,
            default="your-org",
            help="GitHub organisation to derive a repo URL (used as GitSource link)",
        )

    def handle(self, *args, **options):
        stats = ingest_git_history(options["repo_path"], org=options["org"])
        self.log(
            "git-history scan complete: processed=%s new_secrets=%s updated_secrets=%s "
            "new_locations=%s skipped=%s errors=%s",
            stats.processed,
            stats.new_secrets,
            stats.updated_secrets,
            stats.new_locations,
            stats.skipped,
            stats.errors,
        )
