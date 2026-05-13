from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("threat_app", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="UploadJob",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("status", models.CharField(choices=[("queued", "Queued"), ("running", "Running"), ("completed", "Completed"), ("failed", "Failed")], default="queued", max_length=20)),
                ("file_name", models.CharField(max_length=255)),
                ("owner", models.CharField(blank=True, default="", max_length=150)),
                ("total_rows", models.IntegerField(default=0)),
                ("processed_rows", models.IntegerField(default=0)),
                ("attacks", models.IntegerField(default=0)),
                ("error_message", models.TextField(blank=True, default="")),
                ("result_data", models.JSONField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
