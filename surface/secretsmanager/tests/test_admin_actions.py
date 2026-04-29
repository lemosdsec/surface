"""Smoke tests for the admin bulk actions and the list_secrets API endpoint."""

from unittest import mock

from django.contrib.admin.sites import AdminSite
from django.test import Client, RequestFactory, TestCase
from django.urls import reverse

from secretsmanager import admin as admin_module
from secretsmanager.admin import SecretAdmin, SecretLocationAdmin
from secretsmanager.models import Secret, SecretLocation, State


def _request():
    """Build a request object suitable for passing to admin actions."""
    req = RequestFactory().post("/")
    req._messages = mock.Mock()
    return req


class BulkActionsTests(TestCase):
    def setUp(self):
        self.secret_a = Secret.objects.create(
            secret="secret-a",
            secret_hash="a" * 64,
            source="trufflehog - git",
            state=State.OPEN,
        )
        self.secret_b = Secret.objects.create(
            secret="secret-b",
            secret_hash="b" * 64,
            source="trufflehog - git",
            state=State.OPEN,
        )
        self.loc = SecretLocation.objects.create(
            secret=self.secret_a,
            repository="https://github.com/example/repo",
            file_path="src/a.py",
            commit="a" * 40,
            line="1",
            state=State.OPEN,
        )

    def test_mark_false_positive_cascades(self):
        admin_instance = SecretAdmin(Secret, AdminSite())
        qs = Secret.objects.filter(pk__in=[self.secret_a.pk, self.secret_b.pk])

        admin_module.mark_false_positive(admin_instance, _request(), qs)

        self.secret_a.refresh_from_db()
        self.secret_b.refresh_from_db()
        self.loc.refresh_from_db()
        self.assertEqual(self.secret_a.state, State.FALSE_POSITIVE)
        self.assertEqual(self.secret_b.state, State.FALSE_POSITIVE)
        self.assertFalse(self.secret_a.active)
        self.assertFalse(self.secret_b.active)
        # Cascaded to the single location of secret_a.
        self.assertEqual(self.loc.state, State.FALSE_POSITIVE)
        self.assertFalse(self.loc.active)

    def test_reopen_action_restores_to_open(self):
        self.secret_a.state = State.FALSE_POSITIVE
        self.secret_a.save()
        self.assertFalse(self.secret_a.active)

        admin_instance = SecretAdmin(Secret, AdminSite())
        admin_module.reopen(admin_instance, _request(), Secret.objects.filter(pk=self.secret_a.pk))

        self.secret_a.refresh_from_db()
        self.assertEqual(self.secret_a.state, State.OPEN)
        self.assertTrue(self.secret_a.active)

    def test_mark_fp_on_single_location_closes_parent_secret(self):
        admin_instance = SecretLocationAdmin(SecretLocation, AdminSite())
        admin_module.mark_false_positive(admin_instance, _request(), SecretLocation.objects.filter(pk=self.loc.pk))

        self.loc.refresh_from_db()
        self.secret_a.refresh_from_db()
        self.assertEqual(self.loc.state, State.FALSE_POSITIVE)
        # Parent has only one location, so it cascades up.
        self.assertEqual(self.secret_a.state, State.FALSE_POSITIVE)
        self.assertFalse(self.secret_a.active)

    def test_mark_risk_accepted_and_fixed_work(self):
        admin_instance = SecretAdmin(Secret, AdminSite())

        admin_module.mark_risk_accepted(admin_instance, _request(), Secret.objects.filter(pk=self.secret_a.pk))
        self.secret_a.refresh_from_db()
        self.assertEqual(self.secret_a.state, State.RISK_ACCEPTED)
        self.assertFalse(self.secret_a.active)

        admin_module.mark_fixed(admin_instance, _request(), Secret.objects.filter(pk=self.secret_b.pk))
        self.secret_b.refresh_from_db()
        self.assertEqual(self.secret_b.state, State.FIXED)
        self.assertFalse(self.secret_b.active)


class ListSecretsEndpointTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse("secretsmanager:list_secrets")
        self.secret = Secret.objects.create(
            secret="abcd",
            secret_hash="c" * 64,
            source="trufflehog - git",
            state=State.OPEN,
            verified=True,
        )
        SecretLocation.objects.create(
            secret=self.secret,
            repository="https://github.com/example/repo",
            file_path="src/a.py",
            commit="a" * 40,
            line="1",
            state=State.OPEN,
        )
        SecretLocation.objects.create(
            secret=self.secret,
            repository="https://github.com/example/repo",
            file_path="src/b.py",
            commit="a" * 40,
            line="2",
            state=State.OPEN,
        )

    def test_list_secrets_returns_stats(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["count"], 1)
        row = body["secrets"][0]
        self.assertEqual(row["secret_hash"], "c" * 64)
        self.assertEqual(row["locations"], 2)
        self.assertEqual(row["state"], "Open")
        self.assertTrue(row["active"])

    def test_list_secrets_rejects_non_integer_limit(self):
        response = self.client.get(self.url, {"limit": "abc"})
        self.assertEqual(response.status_code, 400)

    def test_list_secrets_clamps_limit_to_max(self):
        response = self.client.get(self.url, {"limit": "99999"})
        self.assertEqual(response.status_code, 200)

    def test_list_secrets_filters_by_source(self):
        response = self.client.get(self.url, {"source": "not-a-real-source"})
        body = response.json()
        self.assertEqual(body["count"], 0)


class GitSourceScanActionTests(TestCase):
    """Smoke tests for the admin actions injected onto `inventory.GitSourceAdmin`."""

    def setUp(self):
        from inventory.models import GitSource

        self.gs = GitSource.objects.create(
            repo_url="https://github.com/example/repo",
            branch="main",
            active=True,
        )
        self.gs2 = GitSource.objects.create(
            repo_url="https://github.com/example/other",
            branch="main",
            active=True,
        )

    def _fake_result(self, processed=3, new_secrets=2, new_locations=3):
        result = mock.Mock()
        result.stats.processed = processed
        result.stats.new_secrets = new_secrets
        result.stats.new_locations = new_locations
        return result

    def test_default_action_calls_scan_repo_without_flags(self):
        from inventory.models import GitSource
        from secretsmanager.admin_integrations import scan_default

        with mock.patch(
            "secretsmanager.admin_integrations.scan_repo",
            return_value=self._fake_result(),
        ) as mocked:
            scan_default(None, _request(), GitSource.objects.filter(pk=self.gs.pk))

        mocked.assert_called_once()
        kwargs = mocked.call_args.kwargs
        self.assertEqual(kwargs["repo"], self.gs.repo_url)
        # gs.branch=="main" (custom, not the model default "master") → forwarded.
        self.assertEqual(kwargs["branch"], "main")
        self.assertFalse(kwargs["only_verified"])
        self.assertFalse(kwargs["extra_detectors"])

    def test_default_branch_placeholder_is_treated_as_no_branch(self):
        """If GitSource.branch == model default ("master"), pass branch=None
        so git uses the repo's actual default (mirrors CLI behaviour)."""
        from inventory.models import GitSource
        from secretsmanager.admin_integrations import scan_default

        master_gs = GitSource.objects.create(
            repo_url="https://github.com/trufflesecurity/test_keys",
            branch="master",  # i.e. the placeholder default
        )
        with mock.patch(
            "secretsmanager.admin_integrations.scan_repo",
            return_value=self._fake_result(),
        ) as mocked:
            scan_default(None, _request(), GitSource.objects.filter(pk=master_gs.pk))

        self.assertIsNone(mocked.call_args.kwargs["branch"])

    def test_only_verified_action_sets_flag(self):
        from inventory.models import GitSource
        from secretsmanager.admin_integrations import scan_only_verified

        with mock.patch(
            "secretsmanager.admin_integrations.scan_repo",
            return_value=self._fake_result(),
        ) as mocked:
            scan_only_verified(None, _request(), GitSource.objects.filter(pk=self.gs.pk))

        self.assertTrue(mocked.call_args.kwargs["only_verified"])

    def test_extra_detectors_action_sets_flag(self):
        from inventory.models import GitSource
        from secretsmanager.admin_integrations import scan_with_extra_detectors

        with mock.patch(
            "secretsmanager.admin_integrations.scan_repo",
            return_value=self._fake_result(),
        ) as mocked:
            scan_with_extra_detectors(None, _request(), GitSource.objects.filter(pk=self.gs.pk))

        self.assertTrue(mocked.call_args.kwargs["extra_detectors"])

    def test_batch_cap_blocks_too_many(self):
        from inventory.models import GitSource
        from secretsmanager.admin_integrations import MAX_BATCH, scan_default

        # Create enough rows to exceed the cap.
        for i in range(MAX_BATCH + 2):
            GitSource.objects.create(repo_url=f"https://github.com/x/r{i}", branch="main")

        with mock.patch("secretsmanager.admin_integrations.scan_repo") as mocked:
            scan_default(None, _request(), GitSource.objects.all())

        mocked.assert_not_called()

    def test_per_repo_errors_do_not_abort_batch(self):
        from inventory.models import GitSource
        from secretsmanager.admin_integrations import scan_default

        call_count = {"n": 0}

        def side_effect(**kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("clone boom")
            return self._fake_result()

        with mock.patch("secretsmanager.admin_integrations.scan_repo", side_effect=side_effect):
            scan_default(
                None,
                _request(),
                GitSource.objects.filter(pk__in=[self.gs.pk, self.gs2.pk]),
            )

        # Both repos were attempted (one failed, one succeeded).
        self.assertEqual(call_count["n"], 2)

    def test_gitsource_missing_repo_url_is_reported(self):
        from inventory.models import GitSource
        from secretsmanager.admin_integrations import scan_default

        broken = GitSource.objects.create(repo_url="", branch="main")
        with mock.patch("secretsmanager.admin_integrations.scan_repo") as mocked:
            scan_default(None, _request(), GitSource.objects.filter(pk=broken.pk))

        mocked.assert_not_called()

    def test_actions_are_registered_on_gitsource_admin(self):
        from inventory.admin import GitSourceAdmin
        from secretsmanager.admin_integrations import (
            scan_default,
            scan_only_verified,
            scan_with_extra_detectors,
        )

        actions = GitSourceAdmin.actions or []
        for action in (scan_default, scan_only_verified, scan_with_extra_detectors):
            self.assertIn(action, actions)


class SkipCascadeFlagIsNotStickyTests(TestCase):
    """Regression test — `_skip_cascade` must not leak across saves."""

    def test_skip_flag_is_consumed_once(self):
        secret = Secret.objects.create(
            secret="x",
            secret_hash="d" * 64,
            source="trufflehog - git",
            state=State.OPEN,
        )
        loc = SecretLocation.objects.create(
            secret=secret,
            repository="https://github.com/example/repo",
            file_path="x.py",
            commit="a" * 40,
            line="1",
            state=State.OPEN,
        )

        # First save with the flag skips the cascade.
        secret.state = State.FALSE_POSITIVE
        secret._skip_cascade = True
        secret.save()
        loc.refresh_from_db()
        self.assertEqual(loc.state, State.OPEN)  # cascade was skipped

        # Second save WITHOUT touching the flag must re-enable cascade.
        secret.state = State.RISK_ACCEPTED
        secret.save()
        loc.refresh_from_db()
        self.assertEqual(loc.state, State.RISK_ACCEPTED)
