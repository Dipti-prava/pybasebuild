from django.urls import path

from .admin_views.views import create_role, create_resource, create_role_resource_mapping, admin_login
from .views import signup, signin, logout, create_grievance, view_grievance, update_grievance, delete_grievance, \
    captcha_image, view_grievance_by_userid, get_grievances_by_userorgkid

urlpatterns = [
    path('signup/', signup, name='signup'),
    path('captcha/', captcha_image, name='captcha_image'),
    path('signin/', signin, name='signin'),
    path('logout/', logout, name='logout'),
    path('grievances/', create_grievance, name='create_grievance'),
    path('grievances/<str:gk_id>/', update_grievance, name='update_grievance'),
    path('delete_grievance/<str:gk_id>/', delete_grievance, name='delete_grievance'),
    path('view/', view_grievance, name='view_grievance'),
    path('viewByUserId/<str:user_id>', view_grievance_by_userid, name='view_grievance_by_userid'),
    path('getDataById/', get_grievances_by_userorgkid, name='get_grievances_by_userorgkid'),

    # =====================Urls for Admin=============================
    path('admin/signin/', admin_login, name='admin_login'),
    path('admin/create_role/', create_role, name='create_role'),
    path('admin/create_resource/', create_resource, name='create_resource'),
    path('admin/role_resource_mapping/', create_role_resource_mapping, name='create_role_resource_mapping')
]
