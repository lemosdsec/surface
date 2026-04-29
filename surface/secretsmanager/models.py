import hashlib

from django.db import models
from django.utils import timezone

from vulns import models as vuln_models


def sha256_of(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8", errors="replace")).hexdigest()


class State(models.IntegerChoices):
    """Workflow states shared between `Secret` and `SecretLocation`.

    Five states that line up almost 1:1 with `vulns.Finding.State`, with FP
    and Risk-Accepted both collapsing onto Finding.CLOSED. See the mapping in
    `SECRET_STATE_TO_FINDING_STATE`.

    `verified` (a separate boolean on `Secret`) is the *identity* signal —
    "the scanner cryptographically confirmed this credential" — and is kept
    decoupled from `state`, the *workflow* signal. Verified secrets simply
    skip NEW and start in OPEN.
    """

    NEW = 1, "New"
    OPEN = 2, "Open"
    FIXED = 4, "Fixed"
    FALSE_POSITIVE = 5, "False Positive"
    RISK_ACCEPTED = 6, "Risk Accepted"


CLOSED_STATES = frozenset({State.FIXED, State.FALSE_POSITIVE, State.RISK_ACCEPTED})


def is_closed(state_value) -> bool:
    try:
        return State(state_value) in CLOSED_STATES
    except (ValueError, TypeError):
        return False


# Mapping from this app's 5-state workflow to `vulns.Finding.State`. The
# target meanings come from the docstring on `Finding.State` itself:
#
#   NEW            -> NEW       (not yet evaluated)
#   OPEN           -> OPEN      ("valid, assigned for resolution")
#   FIXED          -> RESOLVED  ("OPEN -> resolved")
#   FALSE_POSITIVE -> CLOSED    ("invalid, false positive")
#   RISK_ACCEPTED  -> CLOSED    ("known accepted risk")
SECRET_STATE_TO_FINDING_STATE: dict[int, int] = {
    State.NEW.value: vuln_models.Finding.State.NEW.value,
    State.OPEN.value: vuln_models.Finding.State.OPEN.value,
    State.FIXED.value: vuln_models.Finding.State.RESOLVED.value,
    State.FALSE_POSITIVE.value: vuln_models.Finding.State.CLOSED.value,
    State.RISK_ACCEPTED.value: vuln_models.Finding.State.CLOSED.value,
}

# A SecretLocation in NEW is "raw scanner noise, nobody has looked at it" —
# we keep those off the global Finding view. The moment the row leaves NEW
# (verified scanner upgrade, or any human verdict via the admin) we
# materialise a SecretFinding.
FINDING_WORTHY_STATES = frozenset(
    {
        State.OPEN.value,
        State.FIXED.value,
        State.FALSE_POSITIVE.value,
        State.RISK_ACCEPTED.value,
    }
)


class Secret(models.Model):
    # Re-exposed for backward-compatible imports (`Secret.State.OPEN`).
    State = State

    secret = models.TextField(help_text="Raw secret value as reported by the scanner")
    secret_hash = models.CharField(
        max_length=64,
        db_index=True,
        help_text="SHA256 of `secret` for safe lookups and dedup",
    )
    source = models.CharField(
        max_length=64,
        help_text="Scanner name, e.g. 'trufflehog', 'git-history-scan'",
    )
    kind = models.CharField(
        max_length=128,
        blank=True,
        help_text="Detector / file type, e.g. 'CustomRegex', 'AWS', 'SensitiveFile(.env)'",
    )
    verified = models.BooleanField(default=False, db_index=True)
    verification_error = models.TextField(
        blank=True,
        default="",
        help_text="Optional message explaining why trufflehog could not verify this finding",
    )
    extra_data = models.JSONField(
        null=True,
        blank=True,
        help_text="Detector-specific extra data (trufflehog `ExtraData` / `StructuredData`)",
    )
    environment = models.CharField(max_length=64, default="Unknown", blank=True)
    team = models.ForeignKey(
        "inventory.Person",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
        help_text="Person responsible for the secret (Surface has no Team model)",
    )
    git_source = models.ForeignKey(
        "inventory.GitSource",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="secrets",
        help_text="Primary repository this secret was first seen in",
    )
    state = models.IntegerField(choices=State.choices, default=State.NEW, db_index=True)
    active = models.BooleanField(default=True, db_index=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = [("secret_hash", "source")]
        verbose_name = "Secret"
        verbose_name_plural = "Secrets"

    def save(self, *args, **kwargs):
        if self.secret and not self.secret_hash:
            self.secret_hash = sha256_of(self.secret)
        # active is always derived from state so the two never drift.
        self.active = not is_closed(self.state)
        # Consume the cascade-skip flag exactly once so a stale attribute on
        # the instance can't accidentally disable cascades on later saves.
        skip_cascade = kwargs.pop("_skip_cascade", False) or getattr(self, "_skip_cascade", False)
        if hasattr(self, "_skip_cascade"):
            delattr(self, "_skip_cascade")
        super().save(*args, **kwargs)
        if not skip_cascade:
            self._cascade_state_to_locations()

    def _cascade_state_to_locations(self) -> None:
        """Mirror this Secret's state onto every owned `SecretLocation`.

        Only applies when the Secret is in a closed state — reopening the
        Secret does NOT automatically reopen every location (the user may have
        marked individual locations as FP for different reasons).
        """
        if not self.pk or not is_closed(self.state):
            return
        SecretLocation.objects.filter(secret=self).exclude(state=self.state).update(
            state=self.state,
            active=False,
        )
        # The bulk update above bypasses SecretLocation.save(), so we have to
        # bring the per-location SecretFinding rows in line by hand. Two
        # passes: existing findings get a state UPDATE; locations that didn't
        # have one yet (was in NEW) get one created via the per-row hook.
        target_finding_state = SECRET_STATE_TO_FINDING_STATE[self.state]
        SecretFinding.objects.filter(secret_location__secret=self).update(state=target_finding_state)
        for loc in SecretLocation.objects.filter(secret=self).select_related("secret"):
            if not SecretFinding.objects.filter(secret_location_id=loc.pk).exists():
                loc._sync_finding()

    @property
    def redacted(self) -> str:
        if not self.secret:
            return ""
        preview = self.secret[:16]
        return f"{preview}..." if len(self.secret) > 16 else preview

    def __str__(self) -> str:
        digest = (self.secret_hash or "")[:12] or "unsaved"
        return f"[{self.source}] {self.kind or 'Secret'} {digest}"


class SecretLocation(models.Model):
    State = State

    secret = models.ForeignKey(Secret, on_delete=models.CASCADE, related_name="locations")
    repository = models.CharField(max_length=500)
    file_path = models.CharField(max_length=500)
    commit = models.CharField(max_length=40)
    line = models.CharField(max_length=10, default="N/A")
    author = models.EmailField(max_length=255, default="unknown@example.com")
    timestamp = models.DateTimeField(default=timezone.now)
    state = models.IntegerField(choices=State.choices, default=State.NEW, db_index=True)
    active = models.BooleanField(default=True, db_index=True)
    # MySQL can't index a composite over five long varchars (utf8mb4 4-bytes
    # per char blows past 3072). We collapse the natural key into a short
    # sha256 hash stored in its own column and enforce uniqueness there.
    location_hash = models.CharField(max_length=64, unique=True, editable=False)

    class Meta:
        ordering = ["-timestamp", "file_path"]
        verbose_name = "Secret Location"
        verbose_name_plural = "Secret Locations"

    @staticmethod
    def compute_location_hash(secret_id, repository: str, file_path: str, commit: str, line: str) -> str:
        payload = "|".join(
            [
                str(secret_id or ""),
                repository or "",
                file_path or "",
                commit or "",
                str(line or ""),
            ]
        )
        return sha256_of(payload)

    def save(self, *args, **kwargs):
        if self.repository and self.repository.endswith(".git"):
            self.repository = self.repository[:-4]
        self.active = not is_closed(self.state)
        self.location_hash = self.compute_location_hash(
            self.secret_id, self.repository, self.file_path, self.commit, self.line
        )
        skip_cascade = kwargs.pop("_skip_cascade", False) or getattr(self, "_skip_cascade", False)
        if hasattr(self, "_skip_cascade"):
            delattr(self, "_skip_cascade")
        super().save(*args, **kwargs)
        # Sync the per-location SecretFinding regardless of the cascade flag:
        # `_skip_cascade` is meant to break Secret<->Location feedback loops,
        # not to silence the Finding view, which must always reflect the row
        # we just persisted.
        if self.secret_id:
            self._sync_finding()
        if not skip_cascade and self.secret_id:
            self._cascade_state_to_secret()

    def _cascade_state_to_secret(self) -> None:
        """Reconcile the parent Secret's state with its locations.

        Rules:
        - If **all** siblings are in closed states → close the Secret with
          this row's state (preserves user intent: FP stays FP, RA stays RA).
        - If any sibling is still open **and** the Secret is currently
          closed → reopen the Secret (return it to OPEN).
        - Otherwise: leave the Secret alone.
        """
        secret = self.secret
        sibling_states = list(SecretLocation.objects.filter(secret=secret).values_list("state", flat=True))
        if not sibling_states:
            return

        all_closed = all(is_closed(s) for s in sibling_states)
        any_open = any(not is_closed(s) for s in sibling_states)

        if all_closed and secret.active:
            secret.state = self.state
            secret._skip_cascade = True
            secret.save(update_fields=["state", "active"])
            return

        if any_open and not secret.active:
            secret.state = State.OPEN
            secret._skip_cascade = True
            secret.save(update_fields=["state", "active"])

    @property
    def blob_url(self) -> str:
        if not self.repository or not self.commit:
            return ""
        return f"{self.repository}/blob/{self.commit}/{self.file_path}#L{self.line}"

    def _finding_title(self) -> str:
        kind = (self.secret.kind or "Secret") if self.secret_id else "Secret"
        return f"{kind} in {self.file_path}:{self.line}"

    def _finding_summary(self) -> str:
        secret = self.secret
        parts = [f"Secret detected by {secret.source}."]
        if secret.kind:
            parts.append(f"Detector: {secret.kind}.")
        if secret.verified:
            parts.append("Verified by scanner.")
        else:
            parts.append("Unverified.")
        blob = self.blob_url
        if blob:
            parts.append(f"Location: {blob}")
        return " ".join(parts)

    def _sync_finding(self) -> "SecretFinding | None":
        """Create / update / silently skip the per-location `SecretFinding`.

        Contract:
        - State is `NEW` (un-evaluated): no Finding row, return None. Any
          previously-existing Finding gets its state updated to NEW too so
          regressions stay consistent.
        - State is anything else: upsert a SecretFinding with the mapped
          state, then link it to every sibling Finding of the same `Secret`
          via the inherited `Finding.related_to` M2M (mirrors Dalek's
          `link_related_vulns`).
        """
        target_state = SECRET_STATE_TO_FINDING_STATE[self.state]

        if self.state not in FINDING_WORTHY_STATES:
            # Don't materialise a Finding for raw scanner noise. If one
            # already exists (state regressed back to NEW) keep it but
            # mirror the state so it's still in sync.
            SecretFinding.objects.filter(secret_location_id=self.pk).update(state=target_state)
            return None

        secret = self.secret
        defaults = {
            "state": target_state,
            "title": self._finding_title(),
            "summary": self._finding_summary(),
            "severity": SecretFinding.severity_for(secret),
            "last_seen_date": timezone.now(),
        }
        finding, created = SecretFinding.objects.update_or_create(
            secret_location=self,
            defaults=defaults,
        )
        if created:
            siblings = list(SecretFinding.objects.filter(secret_location__secret_id=secret.pk).exclude(pk=finding.pk))
            if siblings:
                finding.related_to.add(*siblings)
        return finding

    def __str__(self) -> str:
        short_commit = self.commit[:8] if self.commit else ""
        return f"{self.file_path} @ {short_commit}"


class SecretFinding(vuln_models.Finding):
    """Per-location `vulns.Finding` for a Secret hit.

    One SecretFinding per `SecretLocation`. Created lazily the first time the
    location reaches a finding-worthy state (anything other than `NEW`) and
    kept in sync with the SecretLocation's state thereafter via the mapping
    in `SECRET_STATE_TO_FINDING_STATE`. Sibling SecretFindings of the same
    `Secret` are linked through the inherited `Finding.related_to` M2M, so
    the global Finding view sees one row per location with the natural
    cross-references between them.

    Severity is HIGH for verified secrets and MEDIUM for unverified-but-
    triaged ones; humans can override it from the admin like any other
    Finding.
    """

    secret_location = models.OneToOneField(
        "secretsmanager.SecretLocation",
        on_delete=models.CASCADE,
        related_name="finding",
    )

    class Meta:
        verbose_name = "Secret Finding"
        verbose_name_plural = "Secret Findings"

    @staticmethod
    def severity_for(secret: "Secret") -> int:
        return vuln_models.Finding.Severity.HIGH if secret.verified else vuln_models.Finding.Severity.MEDIUM

    def __str__(self) -> str:
        return f"SecretFinding(loc={self.secret_location_id}, state={self.get_state_display()})"
