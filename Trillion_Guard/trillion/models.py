from django.conf import settings
from django.db import models

class ORIGINAL_URL(models.Model):
    objects = models.Manager()
    URL = models.TextField(blank=True)
    DATE = models.DateTimeField(auto_now=True)
    HITS = models.IntegerField(null=True, blank=True, default=0)
    DAILY_HITS = models.IntegerField(null=True, blank=True, default=0)
    LABEL = models.CharField(max_length=20, blank=True)

    def __str__(self):
        return self.URL


class NEW_URL(models.Model):
    objects = models.Manager()
    URL = models.TextField(blank=True)
    HITS = models.IntegerField(null=True, blank=True, default=0)
    DAILY_HITS = models.IntegerField(null=True, blank=True, default=0)
    DATE = models.DateTimeField(auto_now=True)
    LABEL = models.CharField(max_length=20, blank=True)

    def __str__(self):
        return self.URL


class DAILY_HIT(models.Model):
    objects = models.Manager()
    PHISHING = models.IntegerField(null=True, blank=True)
    DAY_HITS = models.IntegerField(null=True, blank=True, default=0)



        
class POST(models.Model):
    objects = models.Manager()
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    content = models.TextField()
    created_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title
