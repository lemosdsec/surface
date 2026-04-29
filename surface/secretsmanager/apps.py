from django.apps import AppConfig


class SecretsManagerConfig(AppConfig):
    name = "secretsmanager"
    verbose_name = "Secrets Manager"
    default_auto_field = "django.db.models.AutoField"

    def ready(self):
        # Attach scan-from-GitSource admin actions. Done here (not in
        # inventory.admin) so secretsmanager is the only app that knows about
        # secret scanning.
        from secretsmanager.admin_integrations import register_gitsource_actions

        register_gitsource_actions()
