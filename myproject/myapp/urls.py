from django.urls import path

from .admin_views.views import create_role, create_resource, create_role_resource_mapping, admin_login, list_documents_admin
from .views import signup, signin, logout, create_grievance, view_grievance, update_grievance, delete_grievance, \
    captcha_image, view_grievance_by_userid, get_grievances_by_userorgkid, upload_document, list_documents, \
    get_document_by_id, get_documentby_doc_id, update_document, delete_document

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
    path('admin/role_resource_mapping/', create_role_resource_mapping, name='create_role_resource_mapping'),
    path('admin/list_document/', list_documents_admin, name='list_documents'),

    # ==================== document upload ============================
    path('department/upload_document/', upload_document, name='upload_document'),
    path('department/getAllDocument/', list_documents, name='list_documents'),
    path('department/delete_document/', delete_document, name='delete_document'),
    path('department/get_document_by_id/', get_document_by_id, name='get_document_by_id'),
    path('department/get_documentby_doc_id/', get_documentby_doc_id, name='get_documentby_doc_id'),
    path('department/update_document/', update_document, name='update_document'),

]
