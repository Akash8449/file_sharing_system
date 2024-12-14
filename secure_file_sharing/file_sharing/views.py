# views.py
from rest_framework import viewsets, permissions
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from .models import User, File
from .serializers import RegisterSerializer, LoginSerializer, FileSerializer
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from rest_framework_simplejwt.tokens import RefreshToken
import secrets
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import NotFound


class UserViewSet(viewsets.ModelViewSet):

    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    
    # Register a new user (signup)
    @action(detail=False, methods=['post'])
    def signup(self, request):
        print("Inside the signup method")  # Log to ensure this is being called
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            print(f"User created with type: {user.user_type}")
            if user.user_type == 'client':
                self.send_verification_email(user)
            return Response({'message': 'User created successfully', 'user': user.username})
        return Response(serializer.errors, status=400)
    
    # Send email verification
    def send_verification_email(self, user):
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        verification_link = f"http://127.0.0.1:8000/verify-email/{uid}/{token}/"
        send_mail(
            'Verify your email',
            f'Click the link to verify your email: {verification_link}',
            'akashtest121@gmail.com',  # This can be an environment variable
            [user.email],
            fail_silently=False,
        )

    # Verify email for the user
    @action(detail=False, methods=['get'])
    def verify_email(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise NotFound("User not found")

        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({'message': 'Email verified successfully!'})
        return Response({'message': 'Invalid token'}, status=400)
    
    # Login user
    @action(detail=False, methods=['post'])
    def login(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            refresh = RefreshToken.for_user(user)
            return Response({
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
            })
        return Response(serializer.errors, status=400)

    @action(detail=True, methods=['delete'])
    def delete_user(self, request, pk=None):
        try:
            user = User.objects.get(pk=pk)
            user.delete()
            return Response({'message': 'User deleted successfully'})
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=404)

class FileViewSet(viewsets.ModelViewSet):
    queryset = File.objects.all()
    serializer_class = FileSerializer
    authentication_classes=[JWTAuthentication]

    permission_classes = [permissions.IsAuthenticated]
    
    def perform_create(self, serializer):
        file = serializer.save(uploaded_by=self.request.user)
        print(self.request.user.user_type)
        if self.request.user.user_type != 'ops':
            file.delete()
            raise PermissionDenied('Only ops users can upload files.')
        
        # Validate file type
        if not self.is_valid_file_type(file.file.name):
            file.delete()
            raise PermissionDenied("Invalid file type. Only pptx, docx, and xlsx are allowed.")

    def is_valid_file_type(self, filename):
        allowed_extensions = ['.pptx', '.docx', '.xlsx']
        return any(filename.endswith(ext) for ext in allowed_extensions)

     
    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        file = self.get_object()
        if request.user.user_type != 'client':
            raise PermissionDenied('Only client users can download files.')
        
 
        secure_url = self.generate_secure_url(file)
        return Response({
            'download-link': secure_url,
            'message': 'success'
        })

    def generate_secure_url(self, file):
        
        token = secrets.token_urlsafe(32)
        secure_url = f"http://127.0.0.1:8000/download-file/{file.pk}/{token}/"
        return secure_url

    # List files uploaded by the current user
    @action(detail=False, methods=['get'])
    def list_files(self, request):
        files = File.objects.filter(uploaded_by=request.user)
        serializer = FileSerializer(files, many=True)
        return Response(serializer.data)  