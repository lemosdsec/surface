from django.urls import path

from secretsmanager import views

urlpatterns = [
    path("v1/trufflehog", views.upload_trufflehog, name="upload_trufflehog"),
    path("v1/scan", views.scan, name="scan"),
    path("v1/secrets", views.list_secrets, name="list_secrets"),
]
