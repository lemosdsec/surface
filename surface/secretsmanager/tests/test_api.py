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

    def test_scan_requires_repo(self):
        response = self.client.post(self.url, data=json.dumps({}), content_type="application/json")
        self.assertEqual(response.status_code, 400)

    def test_scan_invokes_scan_repo(self):
        fake_result = mock.Mock()
        fake_result.repo = "https://github.com/fake/repo"
        fake_result.branch = "main"
        fake_result.kept = False
        fake_result.only_verified = False
        fake_result.config_path = None
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
        self.assertTrue(kwargs["shallow"])
        self.assertFalse(kwargs["only_verified"])
        self.assertFalse(kwargs["extra_detectors"])
        self.assertIsNone(kwargs["config_path"])

    def test_scan_forwards_only_verified_and_extra_detectors(self):
        fake_result = mock.Mock()
        fake_result.repo = "https://github.com/fake/repo"
        fake_result.branch = None
        fake_result.kept = False
        fake_result.only_verified = True
        fake_result.config_path = "/app/secretsmanager/trufflehog.config.yaml"
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
