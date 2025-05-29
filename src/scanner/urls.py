from django.urls import path, include
from rest_framework.routers import DefaultRouter

from scanner import views

router = DefaultRouter()
router.register(r'scans', views.ScanViewSet, basename='scan')
router.register(r'checks', views.CheckViewSet, basename='check')
router.register(r'findings',  views.FindingViewSet, basename='finding')

urlpatterns = [
    path('', include(router.urls))
]