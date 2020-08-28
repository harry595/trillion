from django.contrib import admin
from .models import POST ,ORIGINAL_URL ,NEW_URL

# Register your models here.

admin.site.register(POST)
admin.site.register(NEW_URL)
admin.site.register(ORIGINAL_URL)
