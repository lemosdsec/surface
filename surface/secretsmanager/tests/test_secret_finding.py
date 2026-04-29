"""Tests for the SecretLocation -> vulns.Finding link.

Covers the contract laid out in `_sync_finding`:

- A SecretLocation in `NEW` does NOT create a `SecretFinding` (raw scanner
  noise stays off the global Finding view).
- The first transition to a finding-worthy state (OPEN/TRIAGED/FIXED/FP/RA)
  materialises a SecretFinding with the mapped state and severity.
- Sibling SecretFindings of the same Secret are linked via the inherited
  `Finding.related_to` M2M (mirrors Dalek's `link_related_vulns`).
- Bulk-cascading from `Secret.save()` keeps every per-location SecretFinding
  in sync, even though that path bypasses `SecretLocation.save()`.
- The trufflehog ingest pipeline auto-creates SecretFindings for verified
  hits (state TRIAGED -> Finding.OPEN) and skips them for unverified ones.
"""

import json

from django.test import TestCase

from secretsmanager.models import (
    SECRET_STATE_TO_FINDING_STATE,
    Secret,
    SecretFinding,
    SecretLocation,
    State,
)
from secretsmanager.tests.fixtures import TRUFFLEHOG_LINES
from secretsmanager.utils import ingest_trufflehog_stream
from vulns import models as vuln_models


def _make_secret(hash_suffix: str = "a", *, verified: bool = False) -> Secret:
    return Secret.objects.create(
        secret=f"raw-value-{hash_suffix}",
        secret_hash=hash_suffix * 64,
        source="trufflehog - git",
        kind="CustomRegex",
        verified=verified,
    )


def _make_location(
    secret: Secret, file_path: str = "src/a.py", line: str = "1", state: int = State.NEW
) -> SecretLocation:
    return SecretLocation.objects.create(
        secret=secret,
        repository="https://github.com/example/repo",
        file_path=file_path,
        commit="a" * 40,
        line=line,
        author="dev@example.com",
        state=state,
    )


class StateMappingTests(TestCase):
    def test_mapping_matches_finding_state_docstring(self):
        F = vuln_models.Finding.State
        # Source of truth: docstring on `vulns.Finding.State`.
        self.assertEqual(SECRET_STATE_TO_FINDING_STATE[State.NEW.value], F.NEW.value)
        self.assertEqual(SECRET_STATE_TO_FINDING_STATE[State.OPEN.value], F.OPEN.value)
        self.assertEqual(SECRET_STATE_TO_FINDING_STATE[State.FIXED.value], F.RESOLVED.value)
        self.assertEqual(SECRET_STATE_TO_FINDING_STATE[State.FALSE_POSITIVE.value], F.CLOSED.value)
        self.assertEqual(SECRET_STATE_TO_FINDING_STATE[State.RISK_ACCEPTED.value], F.CLOSED.value)

    def test_state_enum_does_not_expose_triaged(self):
        # TRIAGED was redundant with `verified` and got dropped — a verified
        # secret skips NEW and lands in OPEN directly.
        self.assertFalse(hasattr(State, "TRIAGED"))


class FindingCreationTests(TestCase):
    def test_new_state_does_not_create_finding(self):
        secret = _make_secret("a")
        loc = _make_location(secret, state=State.NEW)
        self.assertFalse(SecretFinding.objects.filter(secret_location=loc).exists())

    def test_open_state_with_verified_secret_creates_high_severity_finding(self):
        secret = _make_secret("b", verified=True)
        loc = _make_location(secret, state=State.OPEN)
        finding = SecretFinding.objects.get(secret_location=loc)
        self.assertEqual(finding.state, vuln_models.Finding.State.OPEN)
        # Verified secret -> HIGH severity by default.
        self.assertEqual(finding.severity, vuln_models.Finding.Severity.HIGH)
        # The base Finding row carries our content_source pointer to SecretFinding.
        self.assertEqual(
            finding.cached_content_source.app_label,
            "secretsmanager",
        )

    def test_open_state_with_unverified_secret_creates_medium_severity_finding(self):
        secret = _make_secret("c")
        loc = _make_location(secret, state=State.OPEN)
        finding = SecretFinding.objects.get(secret_location=loc)
        self.assertEqual(finding.state, vuln_models.Finding.State.OPEN)
        # Unverified -> MEDIUM severity by default.
        self.assertEqual(finding.severity, vuln_models.Finding.Severity.MEDIUM)

    def test_fixed_maps_to_resolved(self):
        secret = _make_secret("d")
        loc = _make_location(secret, state=State.OPEN)
        loc.state = State.FIXED
        loc.save()
        finding = SecretFinding.objects.get(secret_location=loc)
        self.assertEqual(finding.state, vuln_models.Finding.State.RESOLVED)

    def test_fp_and_ra_both_map_to_closed(self):
        secret_a = _make_secret("e")
        secret_b = _make_secret("f")
        loc_fp = _make_location(secret_a, state=State.FALSE_POSITIVE)
        loc_ra = _make_location(secret_b, state=State.RISK_ACCEPTED)

        self.assertEqual(
            SecretFinding.objects.get(secret_location=loc_fp).state,
            vuln_models.Finding.State.CLOSED,
        )
        self.assertEqual(
            SecretFinding.objects.get(secret_location=loc_ra).state,
            vuln_models.Finding.State.CLOSED,
        )

    def test_promoting_from_new_to_open_creates_finding(self):
        secret = _make_secret("g")
        loc = _make_location(secret, state=State.NEW)
        self.assertFalse(SecretFinding.objects.filter(secret_location=loc).exists())

        loc.state = State.OPEN
        loc.save()
        self.assertTrue(SecretFinding.objects.filter(secret_location=loc).exists())

    def test_finding_not_recreated_on_subsequent_saves(self):
        secret = _make_secret("h")
        loc = _make_location(secret, state=State.OPEN)
        finding_pk = SecretFinding.objects.get(secret_location=loc).pk

        loc.state = State.FIXED
        loc.save()
        loc.state = State.FALSE_POSITIVE
        loc.save()

        same = SecretFinding.objects.get(secret_location=loc)
        self.assertEqual(same.pk, finding_pk)
        self.assertEqual(same.state, vuln_models.Finding.State.CLOSED)


class RelatedToTests(TestCase):
    def test_siblings_are_linked_via_related_to(self):
        secret = _make_secret("a")
        loc_a = _make_location(secret, file_path="src/a.py", state=State.OPEN)
        loc_b = _make_location(secret, file_path="src/b.py", state=State.OPEN)
        loc_c = _make_location(secret, file_path="src/c.py", state=State.OPEN)

        f_a = SecretFinding.objects.get(secret_location=loc_a)
        f_b = SecretFinding.objects.get(secret_location=loc_b)
        f_c = SecretFinding.objects.get(secret_location=loc_c)

        # `Finding.related_to` is a symmetrical M2M, so once all three exist
        # each finding sees the other two.
        self.assertSetEqual(set(f_a.related_to.values_list("pk", flat=True)), {f_b.pk, f_c.pk})
        self.assertSetEqual(set(f_b.related_to.values_list("pk", flat=True)), {f_a.pk, f_c.pk})
        self.assertSetEqual(set(f_c.related_to.values_list("pk", flat=True)), {f_a.pk, f_b.pk})

    def test_findings_of_different_secrets_are_not_linked(self):
        secret_a = _make_secret("a")
        secret_b = _make_secret("b")
        loc_a = _make_location(secret_a, state=State.OPEN)
        loc_b = _make_location(secret_b, state=State.OPEN)

        f_a = SecretFinding.objects.get(secret_location=loc_a)
        f_b = SecretFinding.objects.get(secret_location=loc_b)
        self.assertNotIn(f_b, f_a.related_to.all())


class CascadeKeepsFindingsInSyncTests(TestCase):
    """`Secret._cascade_state_to_locations` uses .update() to bulk-flip every
    sibling location's state. That bypasses `SecretLocation.save()`, so the
    cascade has to bring SecretFinding rows in line on its own."""

    def test_secret_fp_cascades_to_findings(self):
        secret = _make_secret("a")
        loc_a = _make_location(secret, file_path="src/a.py", state=State.OPEN)
        loc_b = _make_location(secret, file_path="src/b.py", state=State.OPEN)
        # Sanity: both have findings already in OPEN.
        self.assertEqual(
            SecretFinding.objects.get(secret_location=loc_a).state,
            vuln_models.Finding.State.OPEN,
        )

        secret.state = State.FALSE_POSITIVE
        secret.save()

        for loc in (loc_a, loc_b):
            self.assertEqual(
                SecretFinding.objects.get(secret_location=loc).state,
                vuln_models.Finding.State.CLOSED,
            )

    def test_secret_fp_cascade_creates_missing_findings_for_new_locations(self):
        """If a secret has a NEW location that never had a Finding and the
        parent gets closed, the cascade should both flip the location's state
        AND materialise a SecretFinding for it."""
        secret = _make_secret("b")
        loc_new = _make_location(secret, file_path="src/n.py", state=State.NEW)
        self.assertFalse(SecretFinding.objects.filter(secret_location=loc_new).exists())

        secret.state = State.RISK_ACCEPTED
        secret.save()

        finding = SecretFinding.objects.get(secret_location=loc_new)
        self.assertEqual(finding.state, vuln_models.Finding.State.CLOSED)


class TrufflehogIngestCreatesFindingsTests(TestCase):
    def test_only_verified_hits_create_findings_on_first_ingest(self):
        ingest_trufflehog_stream(TRUFFLEHOG_LINES)

        verified_locations = SecretLocation.objects.filter(secret__verified=True)
        unverified_locations = SecretLocation.objects.filter(secret__verified=False)
        self.assertGreater(verified_locations.count(), 0)
        self.assertGreater(unverified_locations.count(), 0)

        # Verified hits land in OPEN -> Finding row exists in OPEN.
        for loc in verified_locations:
            finding = SecretFinding.objects.get(secret_location=loc)
            self.assertEqual(finding.state, vuln_models.Finding.State.OPEN)
            self.assertEqual(finding.severity, vuln_models.Finding.Severity.HIGH)

        # Unverified hits stay NEW -> no Finding row.
        for loc in unverified_locations:
            self.assertFalse(SecretFinding.objects.filter(secret_location=loc).exists())

    def test_verification_upgrade_promotes_unverified_secret_to_finding(self):
        original = json.loads(TRUFFLEHOG_LINES[0])
        ingest_trufflehog_stream([json.dumps(original)])
        loc = SecretLocation.objects.get()
        self.assertEqual(loc.state, State.NEW)
        self.assertFalse(SecretFinding.objects.filter(secret_location=loc).exists())

        upgraded = dict(original)
        upgraded["Verified"] = True
        ingest_trufflehog_stream([json.dumps(upgraded)])

        loc.refresh_from_db()
        self.assertEqual(loc.state, State.OPEN)
        finding = SecretFinding.objects.get(secret_location=loc)
        self.assertEqual(finding.state, vuln_models.Finding.State.OPEN)
        self.assertEqual(finding.severity, vuln_models.Finding.Severity.HIGH)

    def test_reingest_is_idempotent_for_findings(self):
        ingest_trufflehog_stream(TRUFFLEHOG_LINES)
        before = SecretFinding.objects.count()

        ingest_trufflehog_stream(TRUFFLEHOG_LINES)

        self.assertEqual(SecretFinding.objects.count(), before)
