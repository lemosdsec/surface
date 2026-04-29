import io
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

from django.test import TestCase, override_settings

from secretsmanager import scanner
from secretsmanager.models import Secret, SecretLocation
from secretsmanager.tests.fixtures import TRUFFLEHOG_NDJSON


class FakeProc:
    """Minimal stand-in for subprocess.Popen used by trufflehog streaming."""

    def __init__(self, stdout: str, returncode: int = 0, stderr: str = ""):
        self.stdout = io.StringIO(stdout)
        self.stderr = io.StringIO(stderr)
        self.returncode = returncode

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


class ScanRepoTests(TestCase):
    def test_scan_repo_clones_then_runs_trufflehog_then_cleans_up(self):
        with (
            mock.patch("secretsmanager.scanner.subprocess.run") as mocked_run,
            mock.patch("secretsmanager.scanner.subprocess.Popen") as mocked_popen,
            mock.patch("secretsmanager.scanner.shutil.rmtree") as mocked_rmtree,
            mock.patch("secretsmanager.scanner.tempfile.mkdtemp", return_value="/tmp/fake-scan-dir"),
        ):
            mocked_run.return_value = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            mocked_popen.return_value = FakeProc(TRUFFLEHOG_NDJSON)

            result = scanner.scan_repo(repo="https://github.com/lemosdsec/wmata-trains")

        self.assertEqual(mocked_run.call_count, 1)
        clone_cmd = mocked_run.call_args.args[0]
        self.assertIn("clone", clone_cmd)
        self.assertIn("--depth", clone_cmd)

        trufflehog_cmd = mocked_popen.call_args.args[0]
        self.assertEqual(trufflehog_cmd[0], "trufflehog")
        self.assertIn("git", trufflehog_cmd)

        mocked_rmtree.assert_called_once_with("/tmp/fake-scan-dir", ignore_errors=True)
        self.assertFalse(result.kept)
        self.assertEqual(result.repo, "https://github.com/lemosdsec/wmata-trains")
        self.assertGreater(result.stats.processed, 0)
        self.assertGreater(Secret.objects.count(), 0)
        self.assertGreater(SecretLocation.objects.count(), 0)

    def test_scan_repo_always_cleans_up_on_error(self):
        with (
            mock.patch("secretsmanager.scanner.subprocess.run") as mocked_run,
            mock.patch("secretsmanager.scanner.shutil.rmtree") as mocked_rmtree,
            mock.patch("secretsmanager.scanner.tempfile.mkdtemp", return_value="/tmp/fake-scan-dir"),
        ):
            mocked_run.side_effect = RuntimeError("clone boom")
            with self.assertRaises(RuntimeError):
                scanner.scan_repo(repo="https://github.com/fake/repo")

        mocked_rmtree.assert_called_once_with("/tmp/fake-scan-dir", ignore_errors=True)

    def test_keep_flag_skips_cleanup(self):
        with (
            mock.patch("secretsmanager.scanner.subprocess.run") as mocked_run,
            mock.patch("secretsmanager.scanner.subprocess.Popen") as mocked_popen,
            mock.patch("secretsmanager.scanner.shutil.rmtree") as mocked_rmtree,
            mock.patch("secretsmanager.scanner.tempfile.mkdtemp", return_value="/tmp/fake-scan-dir"),
        ):
            mocked_run.return_value = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            mocked_popen.return_value = FakeProc("")

            result = scanner.scan_repo(repo="https://github.com/fake/repo", keep=True)

        mocked_rmtree.assert_not_called()
        self.assertTrue(result.kept)

    @override_settings(SECRETSMANAGER_TRUFFLEHOG_DOCKER=True)
    def test_docker_mode_builds_docker_cmd(self):
        with (
            mock.patch("secretsmanager.scanner.subprocess.run") as mocked_run,
            mock.patch("secretsmanager.scanner.subprocess.Popen") as mocked_popen,
            mock.patch("secretsmanager.scanner.shutil.rmtree"),
            mock.patch("secretsmanager.scanner.tempfile.mkdtemp", return_value="/tmp/fake-scan-dir"),
        ):
            mocked_run.return_value = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            mocked_popen.return_value = FakeProc("")
            scanner.scan_repo(repo="https://github.com/fake/repo")

        cmd = mocked_popen.call_args.args[0]
        self.assertEqual(cmd[0], "docker")
        self.assertIn("run", cmd)
        self.assertIn("--rm", cmd)

    def test_only_verified_flag_is_forwarded(self):
        with (
            mock.patch("secretsmanager.scanner.subprocess.run") as mocked_run,
            mock.patch("secretsmanager.scanner.subprocess.Popen") as mocked_popen,
            mock.patch("secretsmanager.scanner.shutil.rmtree"),
            mock.patch("secretsmanager.scanner.tempfile.mkdtemp", return_value="/tmp/fake-scan-dir"),
        ):
            mocked_run.return_value = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            mocked_popen.return_value = FakeProc("")
            scanner.scan_repo(repo="https://github.com/fake/repo", only_verified=True)

        cmd = mocked_popen.call_args.args[0]
        self.assertIn("--only-verified", cmd)

    def test_extra_detectors_enables_bundled_config(self):
        with (
            mock.patch("secretsmanager.scanner.subprocess.run") as mocked_run,
            mock.patch("secretsmanager.scanner.subprocess.Popen") as mocked_popen,
            mock.patch("secretsmanager.scanner.shutil.rmtree"),
            mock.patch("secretsmanager.scanner.tempfile.mkdtemp", return_value="/tmp/fake-scan-dir"),
        ):
            mocked_run.return_value = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            mocked_popen.return_value = FakeProc("")
            result = scanner.scan_repo(repo="https://github.com/fake/repo", extra_detectors=True)

        cmd = mocked_popen.call_args.args[0]
        self.assertIn("--config", cmd)
        self.assertEqual(result.config_path, scanner.BUNDLED_TRUFFLEHOG_CONFIG)
        # The real bundled file must actually exist and be a YAML we can reach.
        import os

        self.assertTrue(os.path.isfile(scanner.BUNDLED_TRUFFLEHOG_CONFIG))

    def test_config_override_path_wins_over_extra_detectors(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
            fh.write("detectors: []\n")
            custom = fh.name

        with (
            mock.patch("secretsmanager.scanner.subprocess.run") as mocked_run,
            mock.patch("secretsmanager.scanner.subprocess.Popen") as mocked_popen,
            mock.patch("secretsmanager.scanner.shutil.rmtree"),
            mock.patch("secretsmanager.scanner.tempfile.mkdtemp", return_value="/tmp/fake-scan-dir"),
        ):
            mocked_run.return_value = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            mocked_popen.return_value = FakeProc("")
            result = scanner.scan_repo(
                repo="https://github.com/fake/repo",
                extra_detectors=True,
                config_path=custom,
            )

        cmd = mocked_popen.call_args.args[0]
        self.assertIn("--config", cmd)
        # explicit wins over extra_detectors
        self.assertEqual(result.config_path, custom)
        self.assertIn(custom, cmd)

    def test_missing_config_raises_before_clone(self):
        with (
            mock.patch("secretsmanager.scanner.subprocess.run") as mocked_run,
            mock.patch("secretsmanager.scanner.subprocess.Popen") as mocked_popen,
        ):
            with self.assertRaises(FileNotFoundError):
                scanner.scan_repo(repo="https://x/y", config_path="/does/not/exist.yaml")

        mocked_run.assert_not_called()
        mocked_popen.assert_not_called()

    def test_scan_repo_local_path_skips_clone_and_keeps_tree(self):
        """Local checkout: trufflehog + optional ingest only; no temp clone."""
        from secretsmanager.utils import ImportStats

        tmp = tempfile.mkdtemp(
            prefix="local_scan_",
            dir=str(Path(__file__).resolve().parents[3]),
        )
        try:
            subprocess.run(["git", "init"], cwd=tmp, check=True, capture_output=True)
            subprocess.run(["git", "-C", tmp, "config", "user.email", "a@b.c"], check=True)
            subprocess.run(["git", "-C", tmp, "config", "user.name", "x"], check=True)
            with open(os.path.join(tmp, "a.py"), "w", encoding="utf-8") as fh:
                fh.write("# noop")
            subprocess.run(["git", "-C", tmp, "add", "."], check=True, capture_output=True)
            subprocess.run(["git", "-C", tmp, "commit", "-m", "m"], check=True, capture_output=True)

            canonical = os.path.realpath(tmp)
            fake_history = ImportStats()
            with (
                mock.patch("secretsmanager.scanner._run_trufflehog_stream", return_value=ImportStats()) as mocked_th,
                mock.patch(
                    "secretsmanager.scanner._git_clone",
                    side_effect=AssertionError("_git_clone must not run for local_path"),
                ) as mock_clone,
                mock.patch("secretsmanager.scanner.ingest_git_history", return_value=fake_history) as mocked_ingest,
                mock.patch("secretsmanager.scanner.tempfile.mkdtemp") as mocked_mkdtemp,
            ):
                result = scanner.scan_repo(local_path=tmp, sensitive_files=True)

            mock_clone.assert_not_called()
            mocked_mkdtemp.assert_not_called()
            mocked_th.assert_called_once()
            mocked_ingest.assert_called_once()
            self.assertEqual(mocked_ingest.call_args[0][0], canonical)
            self.assertEqual(mocked_ingest.call_args.kwargs["repo_url"], Path(canonical).as_uri())
            self.assertTrue(result.kept)
            self.assertEqual(result.local_path, canonical)
            self.assertTrue(result.sensitive_files)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_scan_repo_history_only_skips_trufflehog(self):
        from secretsmanager.utils import ImportStats

        tmp = tempfile.mkdtemp(
            prefix="histonly_",
            dir=str(Path(__file__).resolve().parents[3]),
        )
        try:
            subprocess.run(["git", "init"], cwd=tmp, check=True, capture_output=True)
            subprocess.run(["git", "-C", tmp, "config", "user.email", "a@b.c"], check=True)
            subprocess.run(["git", "-C", tmp, "config", "user.name", "x"], check=True)
            with open(os.path.join(tmp, "a.py"), "w", encoding="utf-8") as fh:
                fh.write("# noop")
            subprocess.run(["git", "-C", tmp, "add", "."], check=True, capture_output=True)
            subprocess.run(["git", "-C", tmp, "commit", "-m", "m"], check=True, capture_output=True)

            with (
                mock.patch("secretsmanager.scanner._run_trufflehog_stream") as th,
                mock.patch("secretsmanager.scanner.ingest_git_history", return_value=ImportStats(processed=4)) as ig,
            ):
                result = scanner.scan_repo(local_path=tmp, history_only=True, org="acme")

            th.assert_not_called()
            ig.assert_called_once()
            self.assertEqual(ig.call_args.kwargs.get("org"), "acme")
            self.assertTrue(result.history_only)
            self.assertTrue(result.sensitive_files)
            self.assertEqual(result.stats.processed, 4)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_local_sensitive_files_passes_org_when_no_origin(self):
        from secretsmanager.utils import ImportStats

        tmp = tempfile.mkdtemp(
            prefix="org_",
            dir=str(Path(__file__).resolve().parents[3]),
        )
        try:
            subprocess.run(["git", "init"], cwd=tmp, check=True, capture_output=True)
            subprocess.run(["git", "-C", tmp, "config", "user.email", "a@b.c"], check=True)
            subprocess.run(["git", "-C", tmp, "config", "user.name", "x"], check=True)
            with open(os.path.join(tmp, "x.py"), "w", encoding="utf-8") as fh:
                fh.write("x")
            subprocess.run(["git", "-C", tmp, "add", "."], check=True, capture_output=True)
            subprocess.run(["git", "-C", tmp, "commit", "-m", "m"], check=True, capture_output=True)

            with (
                mock.patch("secretsmanager.scanner._run_trufflehog_stream", return_value=ImportStats()),
                mock.patch("secretsmanager.scanner.ingest_git_history", return_value=ImportStats()) as ig,
            ):
                scanner.scan_repo(local_path=tmp, sensitive_files=True, org="acme")

            self.assertEqual(ig.call_args.kwargs.get("org"), "acme")
            self.assertIsNone(ig.call_args.kwargs.get("repo_url"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class SensitiveFilesScanTests(TestCase):
    """Cover the `sensitive_files=True` branch of `scan_repo`."""

    def test_sensitive_files_flag_triggers_history_walk_and_forces_full_clone(self):
        from secretsmanager.utils import ImportStats

        fake_history_stats = ImportStats(processed=2, new_secrets=2, new_locations=2)

        with (
            mock.patch("secretsmanager.scanner.subprocess.run") as mocked_run,
            mock.patch("secretsmanager.scanner.subprocess.Popen") as mocked_popen,
            mock.patch("secretsmanager.scanner.shutil.rmtree"),
            mock.patch("secretsmanager.scanner.tempfile.mkdtemp", return_value="/tmp/fake-scan-dir"),
            mock.patch(
                "secretsmanager.scanner.ingest_git_history",
                return_value=fake_history_stats,
            ) as mocked_ingest,
        ):
            mocked_run.return_value = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            mocked_popen.return_value = FakeProc("")

            result = scanner.scan_repo(
                repo="https://github.com/fake/repo.git",
                sensitive_files=True,
            )

        # Sensitive-files scan walks `git rev-list --all`, so a shallow
        # clone would defeat the point — `scan_repo` has to override.
        clone_cmd = mocked_run.call_args.args[0]
        self.assertNotIn("--depth", clone_cmd)

        # `ingest_git_history` runs on the same workdir and sees the
        # canonical repo URL (not a guess derived from /tmp/fake-scan-dir).
        mocked_ingest.assert_called_once()
        kwargs = mocked_ingest.call_args.kwargs
        self.assertEqual(mocked_ingest.call_args.args[0], "/tmp/fake-scan-dir")
        self.assertEqual(kwargs["repo_url"], "https://github.com/fake/repo.git")

        # Stats from both passes are merged into a single ScanResult.
        self.assertTrue(result.sensitive_files)
        self.assertEqual(result.stats.processed, 2)
        self.assertEqual(result.stats.new_secrets, 2)
        self.assertEqual(result.stats.new_locations, 2)

    def test_sensitive_files_default_off(self):
        with (
            mock.patch("secretsmanager.scanner.subprocess.run") as mocked_run,
            mock.patch("secretsmanager.scanner.subprocess.Popen") as mocked_popen,
            mock.patch("secretsmanager.scanner.shutil.rmtree"),
            mock.patch("secretsmanager.scanner.tempfile.mkdtemp", return_value="/tmp/fake-scan-dir"),
            mock.patch("secretsmanager.scanner.ingest_git_history") as mocked_ingest,
        ):
            mocked_run.return_value = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            mocked_popen.return_value = FakeProc("")

            result = scanner.scan_repo(repo="https://github.com/fake/repo")

        mocked_ingest.assert_not_called()
        self.assertFalse(result.sensitive_files)
        # Default clone is still shallow when sensitive_files is off.
        clone_cmd = mocked_run.call_args.args[0]
        self.assertIn("--depth", clone_cmd)

    def test_stats_from_both_passes_are_merged(self):
        from secretsmanager.utils import ImportStats

        history_stats = ImportStats(
            processed=3,
            new_secrets=1,
            updated_secrets=2,
            new_locations=4,
            skipped=1,
            errors=1,
            error_samples=["history-error"],
        )

        with (
            mock.patch("secretsmanager.scanner.subprocess.run") as mocked_run,
            mock.patch("secretsmanager.scanner.subprocess.Popen") as mocked_popen,
            mock.patch("secretsmanager.scanner.shutil.rmtree"),
            mock.patch("secretsmanager.scanner.tempfile.mkdtemp", return_value="/tmp/fake-scan-dir"),
            mock.patch("secretsmanager.scanner.ingest_git_history", return_value=history_stats),
        ):
            mocked_run.return_value = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            # Trufflehog produces 5 valid records (the fixture).
            mocked_popen.return_value = FakeProc(TRUFFLEHOG_NDJSON)

            result = scanner.scan_repo(
                repo="https://github.com/lemosdsec/wmata-trains",
                sensitive_files=True,
            )

        # 5 trufflehog + 3 history.
        self.assertEqual(result.stats.processed, 5 + 3)
        # Skipped/errors carry through.
        self.assertEqual(result.stats.errors, 1)
        self.assertIn("history-error", result.stats.error_samples)
