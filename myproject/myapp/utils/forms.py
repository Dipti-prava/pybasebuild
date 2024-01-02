import hashlib

from django import forms
import random
import string
from PIL import Image, ImageDraw, ImageFont
import io
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.utils import timezone


class CaptchaField(forms.CharField):
    def __init__(self, *args, **kwargs):
        super(CaptchaField, self).__init__(*args, **kwargs)
        self.label = "Please Enter the characters shown below:"
        self.required = True
        self.widget = forms.TextInput(attrs={'placeholder': 'Enter CAPTCHA'})


def generate_captcha():
    # Generate a random 6-character string with letters and digits
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))


# Function to store captcha challenge with an identifier in the session
def store_captcha_with_identifier(request, captcha_key, captcha_challenge):
    if not request.session.session_key:
        request.session.save()  # Create a session if it doesn't exist yet
    print("store_captcha_with_identifier", request.session.session_key)
    request.session.setdefault('captcha_challenges', {})[captcha_key] = captcha_challenge
    request.session.modified = True  # Mark the session as modified to ensure it's saved
    request.session.save()  # Save the session after modifications


# Function to retrieve captcha from the session using the identifier
def get_captcha_from_storage(session_key, identifier):
    try:
        # Get the session object based on the session key
        session = Session.objects.get(session_key=session_key)
        # Check if the session is not expired
        if session.expire_date > timezone.now():
            # Access the session data dictionary
            session_data = session.get_decoded()
            # Get the captcha challenges from the session data using the identifier
            captcha_challenges = session_data.get('captcha_challenges', {})
            captcha = captcha_challenges.get(identifier)
            return captcha
    except Session.DoesNotExist:
        pass

    return None


def generate_captcha_image(captcha_challenge):
    font_path = 'arial.ttf'  # Path to the font file
    font_size = 28
    image_width = 120  # Increased width to include space for border
    image_height = 40  # Increased height to include space for border
    border_color = (197, 223, 248)  # Black border color (RGB)
    background_color = (197, 223, 248)  # White background color (RGB)
    text_color = (0, 0, 0)

    # Generate a new image with border and background
    image = Image.new('RGB', (image_width, image_height), color=background_color)
    d = ImageDraw.Draw(image)
    font = ImageFont.truetype(font_path, font_size)

    # Calculate the position to center the CAPTCHA text within the image
    text_width, text_height = d.textsize(captcha_challenge, font=font)
    x = (image_width - text_width) // 2
    y = (image_height - text_height) // 2

    # Draw the border around the image
    d.rectangle([0, 0, image_width - 1, image_height - 1], outline=border_color)

    # Draw the CAPTCHA challenge on the image
    d.text((x, y), captcha_challenge, fill=text_color, font=font)

    # Save the image to a bytes buffer
    image_buffer = io.BytesIO()
    image.save(image_buffer, format='PNG')
    image_buffer.seek(0)
    return image_buffer


class LoginForm(forms.Form):
    email = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)
    captcha = CaptchaField(max_length=6)


def encode_password(data, no_of_times):
    # password = data
    # for _ in range(no_of_times):
    #     # Perform SHA512 hashing
    #     password = hashlib.sha512(password.encode()).hexdigest()
    # return password
    decoded_password = data.encode('utf-8')
    for _ in range(no_of_times):
        decoded_password = hashlib.sha512(decoded_password).hexdigest().encode('utf-8')
    return decoded_password.decode('utf-8')
