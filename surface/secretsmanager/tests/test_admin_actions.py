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
        admin_module.mark_false_positive(
            admin_instance, _request(), SecretLocation.objects.filter(pk=self.loc.pk)
        )

        self.loc.refresh_from_db()
        self.secret_a.refresh_from_db()
        self.assertEqual(self.loc.state, State.FALSE_POSITIVE)
        # Parent has only one location, so it cascades up.
        self.assertEqual(self.secret_a.state, State.FALSE_POSITIVE)
        self.assertFalse(self.secret_a.active)

    def test_mark_risk_accepted_and_fixed_work(self):
        admin_instance = SecretAdmin(Secret, AdminSite())

        admin_module.mark_risk_accepted(
            admin_instance, _request(), Secret.objects.filter(pk=self.secret_a.pk)
        )
        self.secret_a.refresh_from_db()
        self.assertEqual(self.secret_a.state, State.RISK_ACCEPTED)
        self.assertFalse(self.secret_a.active)

        admin_module.mark_fixed(
            admin_instance, _request(), Secret.objects.filter(pk=self.secret_b.pk)
        )
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
            state=State.TRIAGED,
            verified=True,
        )
        SecretLocation.objects.create(
            secret=self.secret,
            repository="https://github.com/example/repo",
            file_path="src/a.py",
            commit="a" * 40,
            line="1",
            state=State.TRIAGED,
        )
        SecretLocation.objects.create(
            secret=self.secret,
            repository="https://github.com/example/repo",
            file_path="src/b.py",
            commit="a" * 40,
            line="2",
            state=State.TRIAGED,
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
        self.assertEqual(row["state"], "Triaged")
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
