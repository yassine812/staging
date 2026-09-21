from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("reclamation_client", "0003_alter_reclamationclient_options_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="analysecausesdoubleaxed4",
            name="pourquoi_non_detection",
            field=models.JSONField(
                blank=True,
                default=dict,
                verbose_name="5 Pourquoi Non-Détection (D4.1)",
            ),
        ),
        migrations.AlterField(
            model_name="analysecausesdoubleaxed4",
            name="pourquoi_technique",
            field=models.JSONField(
                blank=True,
                default=dict,
                verbose_name="5 Pourquoi Cause Technique (D4.2)",
            ),
        ),
    ]
