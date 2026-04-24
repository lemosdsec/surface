import io
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
