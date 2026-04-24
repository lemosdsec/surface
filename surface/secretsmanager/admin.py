from django.contrib import admin, messages
from django.db.models import Count
from django.urls import reverse
from django.utils.html import format_html
from django.utils.safestring import mark_safe

from core_utils.admin import DefaultModelAdmin
from secretsmanager.models import Secret, SecretLocation, State


class ActiveFilter(admin.SimpleListFilter):
    """Default-to-active filter used on both Secret and SecretLocation admins.

    URL contract: `?active_status=yes|no|all`. When the param is missing we
    behave as if `yes` were selected, matching Dalek's UX.
    """

    title = "Active"
    parameter_name = "active_status"
    # Unfold's admin template renders filters by reading `lookup_kwarg`, which
    # only `FieldListFilter` subclasses expose. Aliasing here keeps our
    # SimpleListFilter compatible.
    lookup_kwarg = "active_status"
    default_value = "yes"

    def lookups(self, request, model_admin):
        return (
            ("yes", "Active only"),
            ("no", "Inactive only"),
            ("all", "All"),
        )

    def queryset(self, request, queryset):
        value = self.value() or self.default_value
        if value == "yes":
            return queryset.filter(active=True)
        if value == "no":
            return queryset.filter(active=False)
        return queryset

    def choices(self, changelist):
        # Highlight "Active only" when the param is absent so users can see
        # what's being filtered without having to click through.
        value = self.value()
        for lookup, title in self.lookup_choices:
            yield {
                "selected": value == str(lookup) or (value is None and lookup == self.default_value),
                "query_string": changelist.get_query_string({self.parameter_name: lookup}),
                "display": title,
            }


def _short(text: str, limit: int) -> str:
    text = (text or "").replace("\n", " ").replace("\r", " ").strip()
    return text[:limit] + ("…" if len(text) > limit else "") if text else ""


@admin.action(description="Mark selected as False Positive")
def mark_false_positive(modeladmin, request, queryset):
    updated = 0
    for obj in queryset:
        obj.state = State.FALSE_POSITIVE
        obj.save()
        updated += 1
    messages.success(request, f"Marked {updated} as False Positive (cascading).")


@admin.action(description="Mark selected as Risk Accepted")
def mark_risk_accepted(modeladmin, request, queryset):
    updated = 0
    for obj in queryset:
        obj.state = State.RISK_ACCEPTED
        obj.save()
        updated += 1
    messages.success(request, f"Marked {updated} as Risk Accepted (cascading).")


@admin.action(description="Mark selected as Fixed")
def mark_fixed(modeladmin, request, queryset):
    updated = 0
    for obj in queryset:
        obj.state = State.FIXED
        obj.save()
        updated += 1
    messages.success(request, f"Marked {updated} as Fixed (cascading).")


@admin.action(description="Reopen selected (back to Open)")
def reopen(modeladmin, request, queryset):
    updated = 0
    for obj in queryset:
        obj.state = State.OPEN
        obj.save()
        updated += 1
    messages.success(request, f"Reopened {updated}.")


@admin.register(Secret)
class SecretAdmin(DefaultModelAdmin):
    list_display = [
        "secret_preview",
        "source",
        "kind",
        "verified",
        "state",
        "active",
        "repository_link",
        "locations_count",
        "repository_links",
        "last_seen",
    ]
    list_filter = [ActiveFilter, "source", "verified", "state", "git_source__repo_url"]
    search_fields = ["secret_hash", "kind", "git_source__repo_url", "environment", "secret"]
    readonly_fields = [
        "secret_hash",
        "first_seen",
        "last_seen",
        "redacted_preview",
        "full_secret_display",
    ]
    actions = [mark_false_positive, mark_risk_accepted, mark_fixed, reopen]
    fieldsets = (
        (
            "Secret",
            {
                "fields": (
                    "full_secret_display",
                    "secret_hash",
                    "source",
                    "kind",
                    "verified",
                    "verification_error",
                    "state",
                    "active",
                    "environment",
                )
            },
        ),
        (
            "Ownership & Tracking",
            {
                "fields": ("git_source", "team", "first_seen", "last_seen"),
            },
        ),
        (
            "Extra Data",
            {
                "classes": ("collapse",),
                "fields": ("extra_data",),
                "description": "Detector-specific payload (trufflehog ExtraData / StructuredData)",
            },
        ),
    )

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .select_related("git_source")
            .prefetch_related("locations")
            .annotate(_locations_count=Count("locations"))
        )

    @admin.display(description="Secret Preview", ordering="secret")
    def secret_preview(self, obj: Secret) -> str:
        raw = _short(obj.secret, 20) or "-"
        digest = (obj.secret_hash or "")[:12] + ("…" if obj.secret_hash else "")
        return format_html(
            '<div style="line-height: 1.2; white-space: nowrap;">'
            '<div><strong>Secret:</strong> <code title="{}">{}</code></div>'
            '<div style="opacity: 0.7; font-size: 90%;"><strong>Hash:</strong> <code>{}</code></div>'
            "</div>",
            obj.secret or "",
            raw,
            digest,
        )

    @admin.display(description="Repository")
    def repository_link(self, obj: Secret) -> str:
        if not obj.git_source:
            return "-"
        url = reverse("admin:inventory_gitsource_change", args=[obj.git_source.pk])
        return format_html('<a href="{}">{}</a>', url, obj.git_source.repo_url)

    @admin.display(description="Locations Count", ordering="_locations_count")
    def locations_count(self, obj: Secret) -> str:
        count = getattr(obj, "_locations_count", None)
        if count is None:
            count = obj.locations.count()
        url = reverse("admin:secretsmanager_secretlocation_changelist")
        # Include active_status=all so click-through shows inactive siblings too.
        return format_html(
            '<a href="{}?secret__id__exact={}&active_status=all" '
            'title="View all locations (incl. inactive) for this secret">'
            '&#128269; {} locations</a>',
            url,
            obj.pk,
            count,
        )

    @admin.display(description="Repository Links")
    def repository_links(self, obj: Secret) -> str:
        locations = list(obj.locations.all()[:8])
        if not locations:
            return "-"
        parts = []
        for loc in locations:
            label = f"{loc.file_path}:{loc.line}"
            if loc.blob_url:
                parts.append(
                    format_html(
                        '<div><span style="color:#c0392b;">&#128205;</span> '
                        '<a href="{}" target="_blank" rel="noopener">{}</a></div>',
                        loc.blob_url,
                        label,
                    )
                )
            else:
                parts.append(
                    format_html(
                        '<div><span style="color:#c0392b;">&#128205;</span> {}</div>',
                        label,
                    )
                )
        total = obj.locations.count()
        if total > len(locations):
            parts.append(format_html('<div style="opacity:0.7;">&hellip; +{} more</div>', total - len(locations)))
        return mark_safe("".join(parts))

    @admin.display(description="Redacted preview")
    def redacted_preview(self, obj: Secret) -> str:
        return obj.redacted or "-"

    @admin.display(description="Full secret")
    def full_secret_display(self, obj: Secret) -> str:
        """Full raw value in a copy-friendly block at the top of the change view."""
        raw = obj.secret or ""
        if not raw:
            return "-"
        return format_html(
            '<div style="display:flex; align-items:flex-start; gap:8px;">'
            '<pre style="'
            "margin:0; padding:8px 12px; background:#f6f8fa; border:1px solid #d0d7de; "
            "border-radius:6px; max-width:900px; max-height:220px; overflow:auto; "
            'white-space:pre-wrap; word-break:break-all; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; '
            'font-size:12px; flex:1;">{}</pre>'
            "</div>",
            raw,
        )


@admin.register(SecretLocation)
class SecretLocationAdmin(DefaultModelAdmin):
    list_display = [
        "secret_preview",
        "file_path_with_icon",
        "commit_link",
        "line",
        "repository",
        "author",
        "state",
        "active",
        "timestamp",
    ]
    list_filter = [ActiveFilter, "state", "repository", "secret__source", "secret__verified"]
    search_fields = [
        "file_path",
        "commit",
        "repository",
        "author",
        "secret__secret_hash",
        "secret__secret",
    ]
    readonly_fields = ["secret", "repository", "file_path", "commit", "line", "author", "timestamp"]
    actions = [mark_false_positive, mark_risk_accepted, mark_fixed, reopen]

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("secret")

    @admin.display(description="Secret", ordering="secret__secret")
    def secret_preview(self, obj: SecretLocation) -> str:
        url = reverse("admin:secretsmanager_secret_change", args=[obj.secret_id])
        raw = _short(obj.secret.secret, 16)
        shown = raw or ((obj.secret.secret_hash or "")[:12] + "…")
        return format_html(
            '<a href="{}" title="{}"><code style="white-space: nowrap;">{}</code></a>',
            url,
            obj.secret.secret or obj.secret.secret_hash,
            shown,
        )

    @admin.display(description="File", ordering="file_path")
    def file_path_with_icon(self, obj: SecretLocation) -> str:
        label = f"{obj.file_path}:{obj.line}"
        if obj.blob_url:
            return format_html(
                '<span style="color:#c0392b;">&#128205;</span> <a href="{}" target="_blank" rel="noopener">{}</a>',
                obj.blob_url,
                label,
            )
        return format_html('<span style="color:#c0392b;">&#128205;</span> {}', label)

    @admin.display(description="Commit")
    def commit_link(self, obj: SecretLocation) -> str:
        if not obj.blob_url:
            return obj.commit[:8] if obj.commit else "-"
        return format_html(
            '<a href="{}" target="_blank" rel="noopener">{}</a>',
            obj.blob_url,
            obj.commit[:8],
        )
