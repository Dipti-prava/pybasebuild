from django.http import HttpResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, Grievance
from .serializers import UserSerializer, GrievanceSerializer
from .utils.decoraters import IsAuthenticated
from .utils.forms import LoginForm, generate_captcha, generate_captcha_image
from rest_framework_simplejwt.tokens import AccessToken


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
            return Response(serializer.data, status=200)

        return Response(serializer.errors, status=400)

    except Grievance.DoesNotExist:
        return Response({'error': 'Grievance not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_grievance(request, gk_id):
    grievance = Grievance.objects.filter(gk_id=gk_id, user=request.user).first()

    if grievance is None:
        return Response({'error': 'Grievance not found'}, status=404)

    grievance.delete()

    return Response({'message': 'Grievance deleted successfully'}, status=200)
