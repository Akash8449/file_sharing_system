from django.conf import settings
from django.conf.urls.static import static

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import UserViewSet, FileViewSet

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'files', FileViewSet, basename='file')

urlpatterns = [
    path('', include(router.urls)),   
    path('login/',UserViewSet.as_view({'post':'login'}),name='login'),
    path('verify-email/<str:uidb64>/<str:token>/', UserViewSet.as_view({'get': 'verify_email'}), name='verify-email'),
    path('download-file/<int:pk>/<str:token>/', FileViewSet.as_view({'get': 'download'}), name='download-file'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)