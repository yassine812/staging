from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def create_shared_module(apps, schema_editor):
    Module = apps.get_model("client_accounts", "ClientAccountModule")
    alias = schema_editor.connection.alias
    # Preserve account history, but never widen access through previously shared links.
    Module.objects.using(alias).filter(is_shared=False).update(enabled=False)
    Module.objects.using(alias).get_or_create(is_shared=True, defaults={"enabled": False})


def remove_shared_module(apps, schema_editor):
    # Created accounts remain; their optional module reference is cleared by SET_NULL.
    Module = apps.get_model("client_accounts", "ClientAccountModule")
    Module.objects.using(schema_editor.connection.alias).filter(is_shared=True).delete()


class Migration(migrations.Migration):
    dependencies = [("client_accounts", "0002_createdclientaccount")]

    operations = [
        migrations.AlterField(
            model_name="clientaccountmodule", name="admin",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                    to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name="clientaccountmodule", name="societe",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE,
                                    to="accounts.societe"),
        ),
        migrations.AddField(
            model_name="clientaccountmodule", name="is_shared",
            field=models.BooleanField(default=False),
        ),
        migrations.AddConstraint(
            model_name="clientaccountmodule",
            constraint=models.UniqueConstraint(fields=("is_shared",), condition=models.Q(is_shared=True),
                                               name="unique_shared_client_module"),
        ),
        migrations.RunPython(create_shared_module, remove_shared_module),
    ]
