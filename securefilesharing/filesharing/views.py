from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from django.contrib.auth import get_user_model
from .serializers import RegisterSerializer, LoginSerializer,AssignmentSerializer
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.core.files.storage import default_storage
from django.conf import settings
from django.utils.crypto import get_random_string
from .models import Assignment
from cryptography.fernet import Fernet

User = get_user_model()

def is_superuser(user):
    return user.is_superuser

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User registered successfully. Verify your email.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        token = request.GET.get('token')
        if not token:
            return Response({'error': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            access_token = AccessToken(token)
            user_id = access_token['user_id']
            user = User.objects.get(id=user_id)

            user.email_verified = True
            user.save()

            return Response({'message': 'Email verified successfully.'}, status=status.HTTP_200_OK)

        except AccessToken.ExpiredTokenError:
            return Response({'error': 'Token has expired. Please request a new one.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            return Response({'error': 'Invalid token or user does not exist'}, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = User.objects.get(email=request.data['email'])

            if not user.email_verified:
                return Response({'error': 'Email is not verified.'}, status=status.HTTP_400_BAD_REQUEST)

            refresh = RefreshToken.for_user(user)

            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
class UploadFileView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if not request.user.is_superuser:
            return Response({'error': 'Only Ops User is allowed to upload files'}, status=status.HTTP_403_FORBIDDEN)

        file = request.FILES.get('file')
        title = request.data.get('title', 'Untitled')
        allowed_extensions = ['pptx', 'docx', 'xlsx']
        if file.name.split('.')[-1].lower() not in allowed_extensions:
            return Response({'error': 'Invalid file type. Only pptx, docx, and xlsx are allowed.'}, status=status.HTTP_400_BAD_REQUEST)

        assignment = Assignment.objects.create(user=request.user, file=file, title=title)
        return Response({
            'message': 'File uploaded successfully',
            'assignment_id': assignment.id,
            'title': assignment.title,
        }, status=status.HTTP_201_CREATED)
class DownloadFileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, assignment_id):
        try:
            assignment = Assignment.objects.get(id=assignment_id)

            cipher = Fernet(settings.FERNET_KEY.encode())
            file_path = assignment.file.name
            encrypted_file_name = cipher.encrypt(file_path.encode()).decode()

            download_url = request.build_absolute_uri(f"/api/actual-download/{encrypted_file_name}/")

            return Response({
                'download-link': download_url,
                'message': 'Success',
            })
        except Assignment.DoesNotExist:
            return Response({'error': 'Assignment not found'}, status=status.HTTP_404_NOT_FOUND)

