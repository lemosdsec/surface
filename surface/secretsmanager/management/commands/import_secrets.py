from logbasecommand.base import LogBaseCommand
from secretsmanager.utils import ingest_trufflehog_stream


class Command(LogBaseCommand):
    help = "Import secrets from a trufflehog NDJSON file into the secretsmanager app."

    def add_arguments(self, parser):
        parser.add_argument(
            "json_file",
            type=str,
            help="Path to the JSON/NDJSON file containing trufflehog findings",
        )

    def handle(self, *args, **options):
        path = options["json_file"]
        self.log("importing trufflehog findings from %s", path)
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            stats = ingest_trufflehog_stream(fh)
        self.log(
            "import complete: processed=%s new_secrets=%s updated_secrets=%s new_locations=%s skipped=%s errors=%s",
            stats.processed,
            stats.new_secrets,
            stats.updated_secrets,
            stats.new_locations,
            stats.skipped,
            stats.errors,
        )
