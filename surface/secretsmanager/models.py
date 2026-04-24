import hashlib

from django.db import models
from django.utils import timezone


def sha256_of(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8", errors="replace")).hexdigest()


class State(models.IntegerChoices):
    """Workflow states shared between `Secret` and `SecretLocation`.

    Mirrors Dalek's Vuln.State so the admin UX and bulk actions read the same.
    """

    NEW = 1, "New"
    OPEN = 2, "Open"
    TRIAGED = 3, "Triaged"
    FIXED = 4, "Fixed"
    FALSE_POSITIVE = 5, "False Positive"
    RISK_ACCEPTED = 6, "Risk Accepted"


CLOSED_STATES = frozenset({State.FIXED, State.FALSE_POSITIVE, State.RISK_ACCEPTED})


def is_closed(state_value) -> bool:
    try:
        return State(state_value) in CLOSED_STATES
    except (ValueError, TypeError):
        return False


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

    def __str__(self) -> str:
        short_commit = self.commit[:8] if self.commit else ""
        return f"{self.file_path} @ {short_commit}"
