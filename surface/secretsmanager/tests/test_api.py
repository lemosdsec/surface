import io
import json
from unittest import mock

from django.test import Client, TestCase, override_settings
from django.urls import reverse

from secretsmanager.models import Secret, SecretLocation
from secretsmanager.tests.fixtures import TRUFFLEHOG_NDJSON


class UploadTrufflehogApiTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse("secretsmanager:upload_trufflehog")

    def test_upload_creates_secrets(self):
        upload = io.BytesIO(TRUFFLEHOG_NDJSON.encode("utf-8"))
        upload.name = "secrets.ndjson"

        response = self.client.post(self.url, {"file": upload})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "ok")
        self.assertGreater(body["stats"]["processed"], 0)
        self.assertGreater(body["stats"]["new_secrets"], 0)
        self.assertGreater(Secret.objects.count(), 0)
        self.assertGreater(SecretLocation.objects.count(), 0)

    def test_upload_requires_file(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 400)

    def test_requires_post(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)


class ScanApiTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse("secretsmanager:scan")

    def test_scan_requires_repo_or_path(self):
        response = self.client.post(self.url, data=json.dumps({}), content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertIn("repo", response.json()["error"].lower())
        self.assertIn("path", response.json()["error"].lower())

    def test_scan_invokes_scan_repo(self):
        fake_result = mock.Mock()
        fake_result.repo = "https://github.com/fake/repo"
        fake_result.branch = "main"
        fake_result.kept = False
        fake_result.only_verified = False
        fake_result.sensitive_files = False
        fake_result.config_path = None
        fake_result.local_path = None
        fake_result.history_only = False
        fake_result.stats.as_dict.return_value = {"processed": 2}

        with mock.patch("secretsmanager.views.scan_repo", return_value=fake_result) as mocked:
            response = self.client.post(
                self.url,
                data=json.dumps({"repo": "https://github.com/fake/repo", "branch": "main"}),
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200)
        mocked.assert_called_once()
        kwargs = mocked.call_args.kwargs
        self.assertEqual(kwargs["repo"], "https://github.com/fake/repo")
        self.assertEqual(kwargs["branch"], "main")
        # Default is now a full clone (full git history); callers must
        # explicitly request shallow with `{"shallow": true}`.
        self.assertFalse(kwargs["shallow"])
        self.assertFalse(kwargs["only_verified"])
        self.assertFalse(kwargs["extra_detectors"])
        self.assertFalse(kwargs["sensitive_files"])
        self.assertIsNone(kwargs["config_path"])
        self.assertIsNone(kwargs["org"])
        self.assertFalse(kwargs["history_only"])

    def test_scan_forwards_sensitive_files_flag(self):
        fake_result = mock.Mock()
        fake_result.repo = "https://github.com/fake/repo"
        fake_result.branch = None
        fake_result.kept = False
        fake_result.only_verified = False
        fake_result.sensitive_files = True
        fake_result.config_path = None
        fake_result.local_path = None
        fake_result.history_only = False
        fake_result.stats.as_dict.return_value = {"processed": 7}

        with mock.patch("secretsmanager.views.scan_repo", return_value=fake_result) as mocked:
            response = self.client.post(
                self.url,
                data=json.dumps({"repo": "https://github.com/fake/repo", "sensitive_files": True}),
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200)
        kwargs = mocked.call_args.kwargs
        self.assertTrue(kwargs["sensitive_files"])
        body = response.json()
        self.assertTrue(body["sensitive_files"])

    def test_scan_forwards_only_verified_and_extra_detectors(self):
        fake_result = mock.Mock()
        fake_result.repo = "https://github.com/fake/repo"
        fake_result.branch = None
        fake_result.kept = False
        fake_result.only_verified = True
        fake_result.sensitive_files = False
        fake_result.config_path = "/app/secretsmanager/trufflehog.config.yaml"
        fake_result.local_path = None
        fake_result.history_only = False
        fake_result.stats.as_dict.return_value = {"processed": 1}

        with mock.patch("secretsmanager.views.scan_repo", return_value=fake_result) as mocked:
            response = self.client.post(
                self.url,
                data=json.dumps(
                    {
                        "repo": "https://github.com/fake/repo",
                        "only_verified": True,
                        "extra_detectors": True,
                    }
                ),
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200)
        kwargs = mocked.call_args.kwargs
        self.assertTrue(kwargs["only_verified"])
        self.assertTrue(kwargs["extra_detectors"])
        body = response.json()
        self.assertTrue(body["only_verified"])
        self.assertIn("trufflehog.config.yaml", body["config"])

    def test_scan_returns_400_for_missing_config_file(self):
        with mock.patch(
            "secretsmanager.views.scan_repo",
            side_effect=FileNotFoundError("trufflehog config not found: /nope"),
        ):
            response = self.client.post(
                self.url,
                data=json.dumps({"repo": "https://x/y", "config": "/nope"}),
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 400)

    def test_scan_local_path_disabled_without_jail(self):
        response = self.client.post(
            self.url,
            data=json.dumps({"path": "/tmp/should-not-be-used"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("disabled", response.json()["error"])

    def test_scan_local_path_works_when_jail_configured(self):
        import os
        import shutil
        import subprocess
        import tempfile

        root = tempfile.mkdtemp()
        try:
            repo_dir = os.path.join(root, "myrepo")
            os.makedirs(repo_dir)
            subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
            subprocess.run(["git", "-C", repo_dir, "config", "user.email", "t@t.t"], check=True)
            subprocess.run(["git", "-C", repo_dir, "config", "user.name", "t"], check=True)
            with open(os.path.join(repo_dir, "f.txt"), "w", encoding="utf-8") as fh:
                fh.write("x")
            subprocess.run(["git", "-C", repo_dir, "add", "."], check=True, capture_output=True)
            subprocess.run(["git", "-C", repo_dir, "commit", "-m", "m"], check=True, capture_output=True)

            canonical = os.path.realpath(repo_dir)
            fake_result = mock.Mock()
            fake_result.repo = "https://github.com/x/y"
            fake_result.branch = "master"
            fake_result.kept = True
            fake_result.only_verified = False
            fake_result.sensitive_files = False
            fake_result.config_path = None
            fake_result.local_path = canonical
            fake_result.history_only = False
            fake_result.stats.as_dict.return_value = {"processed": 0}

            with (
                override_settings(SECRETSMANAGER_LOCAL_SCAN_ROOT=root),
                mock.patch("secretsmanager.views.scan_repo", return_value=fake_result) as mocked,
            ):
                response = self.client.post(
                    self.url,
                    data=json.dumps({"path": repo_dir}),
                    content_type="application/json",
                )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["local_path"], canonical)
            self.assertEqual(mocked.call_args.kwargs["local_path"], canonical)
            self.assertEqual(mocked.call_args.kwargs["org"], None)
            self.assertFalse(mocked.call_args.kwargs["history_only"])
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_scan_forwards_org_and_import_git_history_alias(self):
        import os
        import shutil
        import subprocess
        import tempfile

        root = tempfile.mkdtemp()
        try:
            repo_dir = os.path.join(root, "r")
            os.makedirs(repo_dir)
            subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)

            fake_result = mock.Mock()
            fake_result.repo = "file:///x"
            fake_result.branch = "master"
            fake_result.kept = True
            fake_result.only_verified = False
            fake_result.sensitive_files = True
            fake_result.config_path = None
            fake_result.local_path = os.path.realpath(repo_dir)
            fake_result.history_only = True
            fake_result.stats.as_dict.return_value = {"processed": 1}

            with (
                override_settings(SECRETSMANAGER_LOCAL_SCAN_ROOT=root),
                mock.patch("secretsmanager.views.scan_repo", return_value=fake_result) as mocked,
            ):
                response = self.client.post(
                    self.url,
                    data=json.dumps({"path": repo_dir, "org": "acme", "import_git_history": True}),
                    content_type="application/json",
                )
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json()["history_only"])
            self.assertEqual(mocked.call_args.kwargs["org"], "acme")
            self.assertTrue(mocked.call_args.kwargs["history_only"])
        finally:
            shutil.rmtree(root, ignore_errors=True)


class AuthTests(TestCase):
    def setUp(self):
        self.client = Client()

    @override_settings(SECRETSMANAGER_REQUIRE_AUTH=True)
    def test_upload_rejects_missing_token_when_auth_required(self):
        upload = io.BytesIO(b"")
        upload.name = "x.ndjson"
        response = self.client.post(reverse("secretsmanager:upload_trufflehog"), {"file": upload})
        self.assertEqual(response.status_code, 401)

    @override_settings(SECRETSMANAGER_REQUIRE_AUTH=True)
    def test_scan_rejects_missing_token_when_auth_required(self):
        response = self.client.post(
            reverse("secretsmanager:scan"),
            data=json.dumps({"repo": "x"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)
