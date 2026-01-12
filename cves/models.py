# cves/models.py
from django.db import models

class CVE(models.Model):
    identifiant_cve = models.CharField(max_length=50, unique=True)
    titre_bulletin = models.CharField(max_length=500)
    date_publication = models.DateField()
    lien_bulletin = models.URLField(max_length=500)
    base_severity = models.CharField(max_length=50, blank=True, null=True)
    score_cvss = models.FloatField(blank=True, null=True)
    description = models.TextField(blank=True, default='')
    
    def __str__(self):
        return self.identifiant_cve
    
    class Meta:
        ordering = ['-date_publication']


class EmailGroup(models.Model):
    name = models.CharField(max_length=100)
    emails = models.TextField()  # comma-separated list of emails

    def __str__(self):
        return self.name