import base64
import os

import pyotp
from django.core.files.base import ContentFile
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.http import HttpResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, Grievance, Document
from .serializers import UserSerializer, GrievanceSerializer, DocumentSerializer
from .utils.decoraters import IsAuthenticated
from .utils.forms import LoginForm, generate_captcha, generate_captcha_image
from rest_framework_simplejwt.tokens import AccessToken

user_dto = {}


@api_view(['POST'])
def send_otp(request):
    email = request.data.get('email')

    # Generate a unique secret (you can use user's email as a secret in this example)
    secret = email  # You might want to use a more secure secret in production

    # Generate OTP using the same secret
    totp = pyotp.TOTP(secret)
    otp = totp.now()

    # Send OTP via email
    subject = 'Verification OTP'
    message = f'Your OTP for signup: {otp}'

    try:
        send_mail(subject, message, None, [email])
        return Response({'message': 'OTP sent to your email'}, status=200)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['POST'])
def signup(request):
    email = request.data.get('email')
    username = request.data.get('username')
    password = request.data.get('password')
    is_active = request.data.get('is_active')
    is_admin = request.data.get('is_admin')

    if User.objects.filter(email=email).exists():
        return Response({'error': 'Email already Exists'}, status=200)

    # user = request.data
    user = User.objects.create_user(email=email, username=username, password=password, is_active=is_active,
                                    is_admin=is_admin)
    serializer = UserSerializer(user)
    # serializer.save()
    # if serializer.is_valid():
    #     serializer.save()
    #     return Response({'message': 'User created successfully', 'user': serializer.data}, status=201)
    # return Response({'message': 'Something went Wrong'}, serializer.errors, status= 400)
    return Response({'message': 'User created successfully', 'user': serializer.data}, status=201)


@api_view(['GET'])
def captcha_image(request):
    captcha_challenge = generate_captcha()
    request.session['captcha'] = captcha_challenge
    image_buffer = generate_captcha_image(captcha_challenge)

    response = HttpResponse(image_buffer, content_type='image/png')
    return response


@api_view(['POST'])
def signin(request):
    captcha_challenge = request.session.get('captcha')
    form = LoginForm(initial={'captcha': captcha_challenge}, data=request.data)

    if form.is_valid():

        email = form.cleaned_data.get('email')
        password = form.cleaned_data.get('password')
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

        user_data = {
            'user_id': user.user_id,
            'username': user.username,
            'email': user.email,
            # Add other fields as needed
        }

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # Return user data and token
        return Response({
            'message': 'Logged in successfully',
            'user_data': user_data,  # Example: Return the user's ID
            'access_token': access_token
        }, status=200)
    else:
        # If the form is invalid, construct an error response
        errors = dict(form.errors.items())
        return Response({'error': errors}, status=400)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    refresh_token = request.data.get('refresh')
    try:
        # Add refresh token to the blacklist
        TokenBlacklist.objects.create(token=refresh_token)
    except:
        pass
    return Response({'message': 'Logged out successfully'}, status=200)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_grievance(request):
    serializer_data = request.data.copy()  # Create a copy of the request data

    try:
        print("Request User::::::::", request.user)
        print("Request UserName::::::::", request.user.username)
        print("User ID:", request.user.user_id)
        print("Email:", request.user.email)
        serializer_data['user'] = request.user.user_id
        serializer = GrievanceSerializer(data=serializer_data)

        if serializer.is_valid():
            # Save the Grievance instance with user_id set
            serializer.save()  # Assuming Grievance model has user_id field
            return Response({'message': 'Grievance created successfully'}, status=201)

        return Response(serializer.errors, status=400)

    except IndexError:
        # Handle cases where the token is not found or not in the expected format
        return Response({'error': 'Invalid token format'}, status=400)
    except KeyError as e:
        # Handle cases where the expected claims are not present in the token payload
        return Response({'error': f'Missing claim in token: {e}'}, status=400)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def view_grievance(request):
    grievances = Grievance.objects.filter(user=request.user)
    serializer = GrievanceSerializer(grievances, many=True)
    return Response(serializer.data, status=200)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def view_grievance_by_userid(request, user_id):
    grievances = Grievance.objects.filter(user_id=user_id, user=request.user)
    serializer = GrievanceSerializer(grievances, many=True)
    if grievances is None:
        return Response({'error': 'No data found'}, status=404)

    return Response(serializer.data, status=200)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_grievances_by_userorgkid(request):
    type_of_id = request.data.get('type_of_id')
    id = request.data.get('value')

    if id and not (id.startswith('G') or id.startswith('U')):
        return Response({
            'statusCode': '0',
            'messege': 'Please enter a valid id'
        })
    if type_of_id == 'user_id':
        grievances = Grievance.objects.filter(user_id=id, user=request.user)
    elif type_of_id == 'gk_id':
        grievances = Grievance.objects.filter(gk_id=id, user=request.user)
    else:
        return Response({'statusCode': '0',
                         'messege': 'Please enter a valid id type'})

    serializer = GrievanceSerializer(grievances, many=True)

    return Response(serializer.data, status=200)


@api_view(['PUT', 'PATCH'])
@permission_classes([IsAuthenticated])
def update_grievance(request, gk_id):
    try:
        grievance = Grievance.objects.get(pk=gk_id, user=request.user)

        serializer = GrievanceSerializer(grievance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'statusCode': '1', 'message': 'Grievance Updated Successfully'}, serializer.data,
                            status=200)

        return Response({'statusCode': '0'}, serializer.errors, status=400)

    except Grievance.DoesNotExist:
        return Response({'statusCode': '0', 'error': 'Grievance not found'}, status=404)
    except Exception as e:
        return Response({'statusCode': '0', 'error': str(e)}, status=500)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_grievance(request, gk_id):
    grievance = Grievance.objects.filter(gk_id=gk_id, user=request.user).first()

    if grievance is None:
        return Response({'statusCode': '0', 'error': 'Grievance not found'}, status=404)

    grievance.delete()

    return Response({'statusCode': '1', 'message': 'Grievance deleted successfully'}, status=200)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def upload_document(request):
    allowed_extensions = ['pdf', 'ppt', 'pptx', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpeg', 'png']
    doc_category = request.data.get('category')
    doc_type = request.data.get('doc_type')
    document_name = request.data.get('name')
    doc_data = request.data.get('doc')

    if not all([document_name, doc_data]):
        return Response({'statusCode': '0', 'error': 'Missing required data'}, status=400)

    try:
        # Get the file extension
        extension = document_name.split('.')[-1].lower()
        if extension not in allowed_extensions:
            return Response({'error': 'File type not allowed'}, status=400)

        format, docstr = doc_data.split(';base64,')  # Extract format and data
        image_data = base64.b64decode(docstr)
        size = len(image_data)
        size = size / (1024 * 1024)  # convert to mb
        document = ContentFile(image_data, name=document_name)

        # Save document details in the database
        document_object = Document.objects.create(
            user_id=request.user.user_id,
            name=document_name,
            doc_type=extension,
            size=size,
            doc=document  # Save the ContentFile in the 'doc' field of Document model
        )

        serializer = DocumentSerializer(document_object)
        return Response({'status': '1', 'message': 'Document Uploaded Successfully'}, status=201)

    except Exception as e:
        return Response({'statusCode': '0', 'error': str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_documents(request):
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
            if file_extension == 'pdf':
                encoded_file = f"data:application/{file_extension};base64,{encoded_data}"
            elif file_extension == 'ppt':
                encoded_file = f"data:application/vnd.ms-powerpoint;base64,{encoded_data}"
            elif file_extension == 'pptx':
                encoded_file = f"data:application/vnd.openxmlformats-officedocument.presentationml.presentation;base64,{encoded_data}"
            elif file_extension == 'xls':
                encoded_file = f"data:application/vnd.ms-excel;base64,{encoded_data}"
            elif file_extension == 'xlsx':
                encoded_file = f"data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,{encoded_data}"
            elif file_extension == 'doc':
                encoded_file = f"data:application/msword;base64,{encoded_data}"
            elif file_extension == 'docx':
                encoded_file = f"data:application/vnd.openxmlformats-officedocument.wordprocessingml.document;base64,{encoded_data}"
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
        return Response({'statusCode': '1', 'documents': documents_data, 'current_page': page_obj.number,
                         'total_pages': paginator.num_pages}, status=200)

    except Exception as e:
        return Response({'statusCode': '0', 'error': str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_document_by_id(request):
    try:
        user_id = request.user.user_id
        documents = Document.objects.filter(user_id=user_id, user=request.user)

        if documents is None:
            return Response({'error': 'No document found'}, status=404)

        # List to store document information with base64 content
        documents_data = []
        for document in documents:
            with open(document.doc.path, 'rb') as file:
                # Encode document content in base64
                encoded_data = base64.b64encode(file.read()).decode('utf-8')
                # Determine the file type and append the appropriate prefix

                file_extension = document.doc.path.split('.')[-1].lower()
                if file_extension == 'pdf':
                    encoded_file = f"data:application/{file_extension};base64,{encoded_data}"
                elif file_extension == 'ppt':
                    encoded_file = f"data:application/vnd.ms-powerpoint;base64,{encoded_data}"
                elif file_extension == 'pptx':
                    encoded_file = f"data:application/vnd.openxmlformats-officedocument.presentationml.presentation;base64,{encoded_data}"
                elif file_extension == 'xls':
                    encoded_file = f"data:application/vnd.ms-excel;base64,{encoded_data}"
                elif file_extension == 'xlsx':
                    encoded_file = f"data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,{encoded_data}"
                elif file_extension == 'doc':
                    encoded_file = f"data:application/msword;base64,{encoded_data}"
                elif file_extension == 'docx':
                    encoded_file = f"data:application/vnd.openxmlformats-officedocument.wordprocessingml.document;base64,{encoded_data}"
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
        return Response({'statusCode': '1', 'documents': documents_data}, status=200)

    except Exception as e:
        return Response({'statusCode': '0', 'error': str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_documentby_doc_id(request):
    doc_id = request.data.get('doc_id')  # Use GET to retrieve the doc_id parameter
    try:
        document = Document.objects.get(pk=doc_id, user=request.user)
        print("documentssss", document)
    except Document.DoesNotExist:
        return Response({'statusCode': '0', 'error': 'Document not found'}, status=404)

    try:
        with open(document.doc.path, 'rb') as file:
            # Encode document content in base64
            encoded_data = base64.b64encode(file.read()).decode('utf-8')

        file_extension = document.doc.path.split('.')[-1].lower()
        print("file_Ext", file_extension)
        if file_extension == 'pdf':
            encoded_file = f"data:application/{file_extension};base64,{encoded_data}"
        elif file_extension == 'ppt':
            encoded_file = f"data:application/vnd.ms-powerpoint;base64,{encoded_data}"
        elif file_extension == 'pptx':
            encoded_file = f"data:application/vnd.openxmlformats-officedocument.presentationml.presentation;base64,{encoded_data}"
        elif file_extension == 'xls':
            encoded_file = f"data:application/vnd.ms-excel;base64,{encoded_data}"
        elif file_extension == 'xlsx':
            print("entered....")
            encoded_file = f"data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,{encoded_data}"
        elif file_extension == 'doc':
            encoded_file = f"data:application/msword;base64,{encoded_data}"
        elif file_extension == 'docx':
            encoded_file = f"data:application/vnd.openxmlformats-officedocument.wordprocessingml.document;base64,{encoded_data}"
        elif file_extension in ['jpg', 'jpeg', 'png']:
            encoded_file = f"data:image/{file_extension};base64,{encoded_data}"
        else:
            encoded_file = None

        doc_info = {
            'id': document.id,
            'name': document.name,
            'doc_type': document.doc_type,
            'size': document.size,
            'doc': encoded_file
        }

        return Response({'statusCode': '1', 'data': doc_info}, status=200)
    except Exception as e:
        return Response({'statusCode': '0', 'error': str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def update_document(request):
    # doc_id, doc
    doc_id = request.data.get('doc_id')
    category = request.data.get('category')
    doc_name = request.data.get('name')
    doc = request.data.get('doc')

    if not all([doc_name, doc]):
        return Response({'statusCode': '0', 'error': 'Missing required data'}, status=400)

    try:
        document = Document.objects.get(pk=doc_id, user=request.user)
    except Document.DoesNotExist:
        return Response({'statusCode': '0', 'error': 'Document not found'}, status=404)

    try:
        if doc:
            format, docstr = doc.split(';base64,')
            decoded_doc = base64.b64decode(docstr.encode())

            file_extension = document.doc.path.split('.')[-1].lower()

            new_filename = f'{doc_name}.{file_extension}'
            new_path = os.path.join(os.path.dirname(document.doc.path), doc_name)

            if os.path.exists(document.doc.path):
                os.remove(document.doc.path)

            with open(new_path, 'wb') as file:
                file.write(decoded_doc)

            if file_extension == 'pdf':
                encoded_file = f"data:application/{file_extension};base64,{docstr}"
            elif file_extension == 'ppt':
                encoded_file = f"data:application/vnd.ms-powerpoint;base64,{docstr}"
            elif file_extension == 'pptx':
                encoded_file = f"data:application/vnd.openxmlformats-officedocument.presentationml.presentation;base64,{docstr}"
            elif file_extension == 'xls':
                encoded_file = f"data:application/vnd.ms-excel;base64,{docstr}"
            elif file_extension == 'xlsx':
                encoded_file = f"data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,{docstr}"
            elif file_extension == 'doc':
                encoded_file = f"data:application/msword;base64,{docstr}"
            elif file_extension == 'docx':
                encoded_file = f"data:application/vnd.openxmlformats-officedocument.wordprocessingml.document;base64,{docstr}"
            elif file_extension in ['jpg', 'jpeg', 'png']:
                encoded_file = f"data:image/{file_extension};base64,{docstr}"
            else:
                encoded_file = None

            # Update document metadata
            document.doc_type = file_extension
            document.name = doc_name
            document.category = category
            document.doc = new_path
            document.size = len(decoded_doc) / (1024 * 1024)  # Size in MB
            document.save()

            doc_info = {
                'id': document.id,
                'name': document.name,
                'doc_type': document.doc_type,
                'size': document.size,
                'doc': encoded_file
            }
            return Response({'statusCode': '1', 'data': doc_info, 'message': 'Document updated successfully'},
                            status=200)
        else:
            return Response({'statusCode': '0', 'error': 'No document data provided for update'}, status=400)
    except Exception as e:
        return Response({'statusCode': '0', 'error': str(e)}, status=500)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_document(request, doc_id):
    try:
        document = Document.objects.get(pk=doc_id, user=request.user)
        print(document)
        # Get the path of the document file
        document_path = document.doc.path
        print("%%%%%%%%%%%%%%%%", os.path.dirname(document.doc.path))
        document.delete()

        # Check if the file exists and delete it from the storage folder
        if os.path.exists(document_path):
            os.remove(document_path)

        return Response({'statusCode': '1', 'message': 'Document deleted successfully'}, status=200)
    except Document.DoesNotExist:
        return Response({'statusCode': '0', 'error': 'Document not found'}, status=404)

    except Exception as e:
        return Response({'statusCode': '0', 'error': str(e)}, status=500)
