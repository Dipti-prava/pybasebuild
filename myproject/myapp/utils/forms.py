from django import forms
import random
import string
from PIL import Image, ImageDraw, ImageFont
import io


class CaptchaField(forms.CharField):
    def __init__(self, *args, **kwargs):
        super(CaptchaField, self).__init__(*args, **kwargs)
        self.label = "Please Enter the characters shown below:"
        self.required = True
        self.widget = forms.TextInput(attrs={'placeholder': 'Enter CAPTCHA'})


def generate_captcha():
    # Generate a random 6-character string with letters and digits
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))


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
