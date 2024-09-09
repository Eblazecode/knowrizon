from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='home'),
    path('admin_dashboard/', views.admin_dasahboard, name='admin_dashboard'),
    path('admin_register/', views.admin_register, name='admin_register'),
    path('admin_login/', views.admin_login, name='admin_login'),
   # path('student_registration/', views.student_register, name='student_register'),
    path('add_users/', views.add_user, name='add_users'),
    path('add_students/', views.add_student, name='add_students'),
    path('approve_requests/', views.approve_requests, name='approve_requests'),
    path('manage_user_roles/', views.manage_user_roles, name='manage_user_roles'),
    path('handle_password_resets/', views.handle_password_resets, name='handle_password_resets'),
    path('monitor_user_activity/', views.monitor_user_activity, name='monitor_user_activity'),
    path('oversee_user_permissions/', views.oversee_user_permissions, name='oversee_user_permissions'),
    path('add_academic_staff/', views.add_academic_staff, name='add_academic_staff'),
    path('add_content_manager/', views.add_content_manager, name='add_content_manager'),
    path('library_materials_category/', views.library_materials_category, name='library_materials_category'),
]