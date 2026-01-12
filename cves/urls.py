from django.urls import path
from .views import (
    CVEListView, CVEDetailView,
    EmailGroupListCreateView, EmailGroupDetailView,
    SendCVEEmailView
)

urlpatterns = [
    path('cves/', CVEListView.as_view(), name='cve-list'),
    path('cves/<int:pk>/', CVEDetailView.as_view(), name='cve-detail'),
    path('email-groups/', EmailGroupListCreateView.as_view(), name='email-group-list-create'),
    path('email-groups/<int:pk>/', EmailGroupDetailView.as_view(), name='email-group-detail'),
    path('send-cve-email/', SendCVEEmailView.as_view(), name='send-cve-email'),
]