from django.db import models

from scanner import fields


STATUSES = sorted([(item, item) for item in ["pending","in_progress", "completed", "failed"]])
PROVIDERS = sorted([(item, item) for item in ["aws", "azure", "gcp", "m365"]])
SEVERITIES = ["critical", "high", "medium", "low", "informational"]
SEVERITIES_CHOICES = sorted([(item, item) for item in SEVERITIES])

# Create your models here.
class Scan(models.Model):
    status = models.CharField(choices=STATUSES, max_length=100)
    provider = models.CharField(choices=PROVIDERS, max_length=100)
    severities = fields.MultiSelectField(choices=SEVERITIES_CHOICES, max_length=200)
    start = models.DateTimeField(null=True)
    end = models.DateTimeField(null=True)

    class Meta:
        ordering = ['start']

class Check(models.Model):
    scan = models.ForeignKey("Scan", related_name="checks", on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    service_name = models.CharField(max_length=50)
    severity = models.CharField(max_length=50)

    class Meta:
        ordering = ['-pk']

class Finding(models.Model):
    scan_check = models.ForeignKey("Check", related_name="findings", on_delete=models.CASCADE)
    message = models.TextField()
    title = models.TextField()
    resource_name = models.CharField(max_length=255)
    resource_type = models.CharField(max_length=255)
    risk = models.TextField()
    remediation = models.TextField()

    class Meta:
        ordering = ['-pk']