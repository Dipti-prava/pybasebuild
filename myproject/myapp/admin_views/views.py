import base64

from django.contrib.auth import authenticate
from django.core.paginator import Paginator
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from ..admin_serializers.serializers import RoleSerializer, ResourceSerializer, \
    RoleResourceMappingSerializer
from ..models import User, Document
from ..utils.decoraters import AdminOnly
from ..utils.forms import LoginForm

user_dto = {}


@api_view(['POST'])
def admin_login(request):
    captcha_challenge = request.session.get('captcha')
    form = LoginForm(initial={'captcha': captcha_challenge}, data=request.data)

    if form.is_valid():
        email = form.cleaned_data.get('email')
        password = request.data.get('password')
        captcha_response = form.cleaned_data.get('captcha')

        user = User.objects.filter(email=email).first()

        print("User Data", user)

        if captcha_response != captcha_challenge:
            return Response({'error': 'Invalid CAPTCHA. Please try again.'}, status=400)
        if user is None:
            return Response({'error': 'Email does not exist'}, status=400)

        if user is None or not user.check_password(password):
            return Response({'error': 'Invalid email or password'}, status=400)
        if not user.is_active:
            return Response({'error': 'User is not Active'}, status=400)

        # Check if the user is authenticated and is an admin
        if user and user.is_admin:
            refresh = RefreshToken.for_user(user)  # Generate JWT refresh token
            access_token = str(refresh.access_token)  # Extract the access token

            user_data = {
                'user_id': user.user_id,
                'username': user.username,
                'email': user.email,
                # Add other fields as needed
            }

            return Response({
                'message': 'Logged in successfully',
                'user_data': user_data,
                'access_token': access_token  # Return the JWT access token
            }, status=200)
        else:
            return Response({'error': 'Invalid credentials or not an admin'}, status=401)
    else:
        # If the form is invalid, construct an error response
        errors = dict(form.errors.items())
        return Response({'error': errors}, status=400)


@api_view(['POST'])
@permission_classes([AdminOnly])
def create_role(request):
    serializer = RoleSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({
            'statusCode': '1',
            'data': serializer.data,
            'message': 'Role created successfully.',
        }, status=201)
    return Response({
        'statusCode': '0',
        'message': 'Role creation failed.',
    }, status=400)


@api_view(['POST'])
@permission_classes([AdminOnly])
def create_resource(request):
    serializer = ResourceSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({
            'statusCode': '1',
            'data': serializer.data,
            'message': 'Resource created successfully.',
        }, status=201)
    return Response({
        'statusCode': '0',
        'message': 'Resource creation failed.',
    }, status=400)


@api_view(['POST'])
@permission_classes([AdminOnly])
def create_role_resource_mapping(request):
    serializer = RoleResourceMappingSerializer(data=request.data)
    print(serializer)
    if serializer.is_valid():
        serializer.save()
        return Response({
            'statusCode': '1',
            'data': serializer.data,
            'message': 'Role Resource mapped successfully.',
        }, status=201)
    return Response({
        'statusCode': '0',
        'message': 'Role-Resource mapping failed.',
    }, status=400)


@api_view(['GET'])
@permission_classes([AdminOnly])
def list_documents_admin(request):
    try:
        # Fetch all documents from the database
        documents = Document.objects.all()

        # Pagination
        paginator = Paginator(documents, 10)  # Change '10' to desired items per page
        page_number = request.GET.get('page', 1)
        page_obj = paginator.get_page(page_number)

        # List to store document information with base64 content
        documents_data = []

        for document in page_obj:
            with open(document.doc.path, 'rb') as file:
                # Encode document content in base64
                encoded_data = base64.b64encode(file.read()).decode('utf-8')

            # Determine the file type and append the appropriate prefix

            file_extension = document.doc.path.split('.')[-1].lower()
            if file_extension in ['pdf', 'ppt', 'pptx', 'doc', 'docx', 'xls', 'xlsx']:
                encoded_file = f"data:application/{file_extension};base64,{encoded_data}"
            elif file_extension in ['jpg', 'jpeg', 'png']:
                encoded_file = f"data:image/{file_extension};base64,{encoded_data}"
            else:
                encoded_file = None
            # Create a dictionary containing document information and base64 content
            doc_info = {
                'id': document.id,
                'name': document.name,
                'doc_type': document.doc_type,
                'size': document.size,
                'doc': encoded_file
            }

            documents_data.append(doc_info)

        # Return all documents with their information and base64 content
        return Response({
            'documents': documents_data,
            'current_page': page_obj.number,
            'total_pages': paginator.num_pages
        }, status=200)

    except Exception as e:
        return Response({'error': str(e)}, status=500)
