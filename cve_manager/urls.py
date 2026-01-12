"""
URL configuration for cve_manager project.
"""
from django.urls import path, include

urlpatterns = [
    path('api/', include('cves.urls')),
]
