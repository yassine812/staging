import uuid

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("accounts", "0007_remove_section_responsable_n1_and_more"),
    ]
    operations = [
        migrations.CreateModel(
            name="ClientAccountModule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("enabled", models.BooleanField(default=False)),
                ("token", models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ("admin", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ("societe", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="accounts.societe")),
            ],
        ),
        migrations.AddConstraint(
            model_name="clientaccountmodule",
            constraint=models.UniqueConstraint(fields=("admin", "societe"), name="unique_client_module_admin_societe"),
        ),
    ]
