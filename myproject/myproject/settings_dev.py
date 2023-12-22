import os
from dotenv import load_dotenv
from .settings import *

ROOT_URLCONF = 'myproject.urls'
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load .env file
load_dotenv()
print("fjdghgdddddd####################")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'mydatabase',
        'USER': 'postgres',
        'PASSWORD': 'techlab',
        'HOST': 'localhost',
        'PORT': '5433'
    }
}

# Configure your email backend settings
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')

print("################", os.getenv('EMAIL_HOST_USER'))
print(BASE_DIR)

# uploaded document folder path
MEDIA_ROOT = 'F:\\py\\documents'
MEDIA_URL = '/media/'
