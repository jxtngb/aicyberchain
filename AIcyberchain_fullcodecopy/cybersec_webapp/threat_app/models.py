from django.db import models

class Threat(models.Model):
    id = models.AutoField(primary_key=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.CharField(max_length=50)
    destination_ip = models.CharField(max_length=50)
    protocol = models.IntegerField()
    packet_size = models.FloatField()
    attack_type = models.CharField(max_length=50)
    detected = models.BooleanField(default=False)
    blockchain_tx = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return f"{self.source_ip} -> {self.destination_ip} | Detected: {self.detected}"
    
class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=255)
    blocked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=50, default="User")
    phone = models.CharField(max_length=20, blank=True, null=True)

    def __str__(self):
        return self.user.username


class UploadJob(models.Model):
    STATUS_CHOICES = [
        ("queued", "Queued"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="queued")
    file_name = models.CharField(max_length=255)
    owner = models.CharField(max_length=150, blank=True, default="")
    total_rows = models.IntegerField(default=0)
    processed_rows = models.IntegerField(default=0)
    attacks = models.IntegerField(default=0)
    error_message = models.TextField(blank=True, default="")
    result_data = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.file_name} [{self.status}]"


# Create your models here.
