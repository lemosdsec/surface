import json

from django.test import TestCase

from inventory.models import GitSource
from secretsmanager.models import Secret, SecretLocation
from secretsmanager.tests.fixtures import TRUFFLEHOG_LINES
from secretsmanager.utils import (
    ingest_trufflehog_stream,
    normalise_author,
    parse_trufflehog_record,
    parse_trufflehog_timestamp,
    strip_git_suffix,
)


class ParserTests(TestCase):
    def test_normalise_author_extracts_email_from_angles(self):
        self.assertEqual(
            normalise_author("Diogo Lemos <diogo.lemos@olx.com>"),
            "diogo.lemos@olx.com",
        )
        self.assertEqual(normalise_author("someone@example.com"), "someone@example.com")
        self.assertEqual(normalise_author(""), "unknown@example.com")
        self.assertEqual(normalise_author(None), "unknown@example.com")

    def test_strip_git_suffix(self):
        self.assertEqual(strip_git_suffix("https://x/y.git"), "https://x/y")
        self.assertEqual(strip_git_suffix("https://x/y"), "https://x/y")

    def test_parse_timestamp_accepts_trufflehog_format(self):
        parsed = parse_trufflehog_timestamp("2024-11-05 11:12:45 +0000")
        self.assertEqual(parsed.year, 2024)
        self.assertEqual(parsed.minute, 12)

    def test_parse_record_extracts_expected_fields(self):
        record = json.loads(TRUFFLEHOG_LINES[0])
        parsed = parse_trufflehog_record(record)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["source"], "trufflehog - git")
        self.assertEqual(parsed["kind"], "CustomRegex")
        self.assertEqual(parsed["file_path"], "simple.py")
        self.assertEqual(parsed["line"], "11")
        self.assertEqual(parsed["author"], "diogo.lemos@olx.com")
        self.assertEqual(parsed["repository"], "https://github.com/lemosdsec/wmata-trains")
        self.assertFalse(parsed["verified"])
        self.assertEqual(len(parsed["secret_hash"]), 64)

    def test_parse_record_drops_empty_raw(self):
        parsed = parse_trufflehog_record({"SourceMetadata": {"Data": {"Git": {}}}, "Raw": "", "RawV2": ""})
        self.assertIsNone(parsed)

    def test_parse_record_overrides_file_uri_repository(self):
        record = {
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "commit": "deadbeef" * 5,
                        "file": "config.py",
                        "email": "x <x@y.z>",
                        "repository": "file:///tmp/surface-secrets-xyz",
                        "timestamp": "2024-11-05 10:52:35 +0000",
                        "line": 3,
                    }
                }
            },
            "SourceName": "trufflehog - git",
            "DetectorName": "CustomRegex",
            "Verified": False,
            "Raw": "CLIENT_SECRET=abcdef",
        }
        parsed = parse_trufflehog_record(record, repo_override="https://github.com/example/repo")
        self.assertEqual(parsed["repository"], "https://github.com/example/repo")

    def test_parse_record_captures_verification_error_and_extra_data(self):
        record = {
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "commit": "deadbeef" * 5,
                        "file": "config.py",
                        "email": "x <x@y.z>",
                        "repository": "https://github.com/example/repo",
                        "timestamp": "2024-11-05 10:52:35 +0000",
                        "line": 3,
                    }
                }
            },
            "SourceName": "trufflehog - git",
            "DetectorName": "AzureSearchAdminKey",
            "Verified": False,
            "VerificationError": "More than one detector has found this result.",
            "ExtraData": {"account": "demo"},
            "StructuredData": None,
            "Raw": "abcd1234",
        }
        parsed = parse_trufflehog_record(record)
        self.assertEqual(parsed["verification_error"], "More than one detector has found this result.")
        self.assertEqual(parsed["extra_data"], {"extra_data": {"account": "demo"}})

    def test_parse_record_keeps_real_repository_even_with_override(self):
        record = {
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "commit": "deadbeef" * 5,
                        "file": "config.py",
                        "email": "x <x@y.z>",
                        "repository": "https://github.com/real/repo",
                        "timestamp": "2024-11-05 10:52:35 +0000",
                        "line": 3,
                    }
                }
            },
            "SourceName": "trufflehog - git",
            "DetectorName": "CustomRegex",
            "Verified": False,
            "Raw": "CLIENT_SECRET=abcdef",
        }
        parsed = parse_trufflehog_record(record, repo_override="https://github.com/example/wrong")
        self.assertEqual(parsed["repository"], "https://github.com/real/repo")


class IngestPipelineTests(TestCase):
    def test_ingest_creates_secrets_and_locations(self):
        stats = ingest_trufflehog_stream(TRUFFLEHOG_LINES)

        self.assertEqual(stats.processed, 5)
        self.assertEqual(stats.errors, 0)
        self.assertGreater(stats.new_secrets, 0)
        self.assertGreater(stats.new_locations, 0)

        self.assertEqual(Secret.objects.count(), stats.new_secrets)
        self.assertEqual(SecretLocation.objects.count(), stats.new_locations)

    def test_ingest_is_idempotent(self):
        ingest_trufflehog_stream(TRUFFLEHOG_LINES)
        secrets_after_first = Secret.objects.count()
        locations_after_first = SecretLocation.objects.count()

        stats = ingest_trufflehog_stream(TRUFFLEHOG_LINES)

        self.assertEqual(Secret.objects.count(), secrets_after_first)
        self.assertEqual(SecretLocation.objects.count(), locations_after_first)
        self.assertEqual(stats.new_secrets, 0)
        self.assertEqual(stats.new_locations, 0)
        self.assertEqual(stats.updated_secrets, secrets_after_first)

    def test_ingest_upserts_gitsource(self):
        ingest_trufflehog_stream(TRUFFLEHOG_LINES)

        self.assertTrue(GitSource.objects.filter(repo_url="https://github.com/lemosdsec/wmata-trains").exists())
        secret = Secret.objects.first()
        self.assertIsNotNone(secret.git_source)
        self.assertEqual(secret.git_source.repo_url, "https://github.com/lemosdsec/wmata-trains")

    def test_ingest_counts_malformed_lines_as_errors(self):
        stats = ingest_trufflehog_stream(["not-json", "", "   ", *TRUFFLEHOG_LINES[:1]])
        self.assertEqual(stats.errors, 1)
        self.assertEqual(stats.processed, 1)

    def test_verified_flag_propagates(self):
        ingest_trufflehog_stream(TRUFFLEHOG_LINES)
        # Fixture line 3 is verified=true
        self.assertTrue(Secret.objects.filter(verified=True).exists())

    def test_verified_secret_is_auto_triaged_on_create(self):
        from secretsmanager.models import State

        ingest_trufflehog_stream(TRUFFLEHOG_LINES)

        verified = Secret.objects.filter(verified=True).first()
        self.assertIsNotNone(verified)
        self.assertEqual(verified.state, State.TRIAGED)
        self.assertTrue(verified.active)
        # All locations for a verified secret start TRIAGED too.
        self.assertTrue(all(loc.state == State.TRIAGED for loc in verified.locations.all()))

        unverified = Secret.objects.filter(verified=False).first()
        self.assertIsNotNone(unverified)
        self.assertEqual(unverified.state, State.NEW)

    def test_reingest_does_not_override_manual_triage(self):
        from secretsmanager.models import State

        ingest_trufflehog_stream(TRUFFLEHOG_LINES)
        unverified = Secret.objects.filter(verified=False).first()
        self.assertIsNotNone(unverified)

        # Operator manually marks it as False Positive.
        unverified.state = State.FALSE_POSITIVE
        unverified.save()
        unverified.refresh_from_db()
        self.assertFalse(unverified.active)

        # Another scan run — identical lines.
        ingest_trufflehog_stream(TRUFFLEHOG_LINES)

        unverified.refresh_from_db()
        self.assertEqual(unverified.state, State.FALSE_POSITIVE)
        self.assertFalse(unverified.active)

    def test_verification_upgrade_bumps_new_to_triaged(self):
        import json

        from secretsmanager.models import State

        # First ingest with verified=false.
        original = json.loads(TRUFFLEHOG_LINES[0])
        ingest_trufflehog_stream([json.dumps(original)])
        self.assertEqual(Secret.objects.count(), 1)
        created = Secret.objects.get()
        self.assertEqual(created.state, State.NEW)

        # Second ingest of the same secret but now verified=true.
        upgraded = dict(original)
        upgraded["Verified"] = True
        ingest_trufflehog_stream([json.dumps(upgraded)])

        created.refresh_from_db()
        self.assertTrue(created.verified)
        self.assertEqual(created.state, State.TRIAGED)
