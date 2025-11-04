from django.contrib.auth.models import User
from django.db import models

class ScanHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    scan_date = models.DateTimeField(auto_now_add=True)
    system_info = models.JSONField(default=dict)
    installed_software = models.JSONField(default=list)
    open_ports = models.JSONField(default=list)
    firewall_rules = models.JSONField(default=list)
    vulnerabilities = models.JSONField(default=list)
    report_path = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return f"{self.user.username} - {self.scan_date}"
