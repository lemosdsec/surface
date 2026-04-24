"""Tests for the Secret ↔ SecretLocation state cascade."""

from django.test import TestCase

from secretsmanager.models import Secret, SecretLocation, State


class CascadeTests(TestCase):
    def _make_secret(self, hash_suffix="a") -> Secret:
        return Secret.objects.create(
            secret=f"raw-value-{hash_suffix}",
            secret_hash=f"{hash_suffix}" * 64,
            source="trufflehog - git",
            kind="CustomRegex",
            verified=False,
        )

    def _add_location(self, secret: Secret, file_path: str, line: str = "1") -> SecretLocation:
        return SecretLocation.objects.create(
            secret=secret,
            repository="https://github.com/example/repo",
            file_path=file_path,
            commit="a" * 40,
            line=line,
            author="dev@example.com",
            state=State.OPEN,
        )

    # -------- Secret → Locations ---------------------------------------------

    def test_secret_false_positive_cascades_to_all_locations(self):
        secret = self._make_secret()
        loc_a = self._add_location(secret, "src/a.py")
        loc_b = self._add_location(secret, "src/b.py")
        self.assertTrue(loc_a.active)
        self.assertTrue(loc_b.active)

        secret.state = State.FALSE_POSITIVE
        secret.save()

        loc_a.refresh_from_db()
        loc_b.refresh_from_db()
        self.assertEqual(loc_a.state, State.FALSE_POSITIVE)
        self.assertEqual(loc_b.state, State.FALSE_POSITIVE)
        self.assertFalse(loc_a.active)
        self.assertFalse(loc_b.active)

    def test_reopening_secret_does_not_blanket_reopen_locations(self):
        secret = self._make_secret("b")
        loc = self._add_location(secret, "src/a.py")

        secret.state = State.FALSE_POSITIVE
        secret.save()
        loc.refresh_from_db()
        self.assertFalse(loc.active)

        # Reopen the Secret directly — locations stay closed unless explicitly touched.
        secret.state = State.OPEN
        secret.save()
        loc.refresh_from_db()
        self.assertEqual(loc.state, State.FALSE_POSITIVE)
        self.assertFalse(loc.active)

    # -------- Location → Secret ---------------------------------------------

    def test_single_location_false_positive_closes_secret(self):
        secret = self._make_secret("c")
        loc = self._add_location(secret, "only-one.py")

        loc.state = State.FALSE_POSITIVE
        loc.save()

        secret.refresh_from_db()
        self.assertEqual(secret.state, State.FALSE_POSITIVE)
        self.assertFalse(secret.active)

    def test_partial_closure_keeps_secret_open(self):
        secret = self._make_secret("d")
        loc_a = self._add_location(secret, "src/a.py")
        loc_b = self._add_location(secret, "src/b.py")

        loc_a.state = State.FALSE_POSITIVE
        loc_a.save()

        secret.refresh_from_db()
        self.assertTrue(secret.active)
        self.assertNotEqual(secret.state, State.FALSE_POSITIVE)
        loc_b.refresh_from_db()
        self.assertTrue(loc_b.active)

    def test_closing_last_open_location_closes_secret(self):
        secret = self._make_secret("e")
        loc_a = self._add_location(secret, "src/a.py")
        loc_b = self._add_location(secret, "src/b.py")

        loc_a.state = State.FALSE_POSITIVE
        loc_a.save()
        secret.refresh_from_db()
        self.assertTrue(secret.active)

        loc_b.state = State.RISK_ACCEPTED
        loc_b.save()
        secret.refresh_from_db()
        self.assertFalse(secret.active)
        # Triggering row's state wins (most recent action).
        self.assertEqual(secret.state, State.RISK_ACCEPTED)

    def test_reopening_location_reopens_closed_secret(self):
        secret = self._make_secret("f")
        loc_a = self._add_location(secret, "src/a.py")
        loc_b = self._add_location(secret, "src/b.py")

        loc_a.state = State.FALSE_POSITIVE
        loc_a.save()
        loc_b.state = State.FALSE_POSITIVE
        loc_b.save()

        secret.refresh_from_db()
        self.assertFalse(secret.active)

        loc_a.state = State.OPEN
        loc_a.save()

        secret.refresh_from_db()
        self.assertTrue(secret.active)
        self.assertEqual(secret.state, State.OPEN)

    # -------- active auto-derive from state ---------------------------------

    def test_active_is_always_derived_from_state(self):
        secret = self._make_secret("g")
        secret.state = State.FIXED
        # Even if caller tries to force active=True, save() recomputes from state.
        secret.active = True
        secret.save()
        self.assertFalse(secret.active)

        loc = self._add_location(secret, "src/a.py")
        loc.state = State.RISK_ACCEPTED
        loc.active = True
        loc.save()
        self.assertFalse(loc.active)
