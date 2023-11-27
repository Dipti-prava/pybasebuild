from django.urls import path
from .views import signup, signin, logout, create_grievance, view_grievance, update_grievance, delete_grievance,captcha_image

urlpatterns = [
    path('signup/', signup, name='signup'),
    path('captcha/', captcha_image, name='captcha_image'),
    path('signin/', signin, name='signin'),
    path('logout/', logout, name='logout'),
    path('grievances/', create_grievance, name='create_grievance'),
    path('grievances/<int:grievance_id>/', update_grievance, name='update_grievance'),
    path('grievances/<int:grievance_id>/', delete_grievance, name='delete_grievance'),
    path('grievances/', view_grievance, name='view_grievance'),
]