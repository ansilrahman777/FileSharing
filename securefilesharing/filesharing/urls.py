from django.urls import path
from .views import DownloadFileView, RegisterView, UploadFileView, VerifyEmailView, LoginView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('login/', LoginView.as_view(), name='login'),
    path('upload/', UploadFileView.as_view(), name='upload'),
    path('download-file/<int:assignment_id>/', DownloadFileView.as_view(), name='download_file'),
]
