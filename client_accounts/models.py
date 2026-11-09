import uuid

from django.conf import settings
from django.db import models


class ClientAccountModule(models.Model):
    admin = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    societe = models.ForeignKey("accounts.Societe", on_delete=models.CASCADE)
    enabled = models.BooleanField(default=False)
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=("admin", "societe"), name="unique_client_module_admin_societe")
        ]


class CreatedClientAccount(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    module = models.ForeignKey(ClientAccountModule, on_delete=models.SET_NULL, null=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True,
        related_name="automatically_created_clients",
    )
    matricule = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
