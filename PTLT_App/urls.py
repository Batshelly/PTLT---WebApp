from django.urls import path
from . import views


urlpatterns = [
    path('', views.login_view, name='login'),
    path('verify-otp/', views.verify_login_otp, name='verify_login_otp'),
    path('resend-otp/', views.resend_login_otp, name='resend_login_otp'),
    path('logout/', views.logout_view, name='logout'),
    path('forgot_password', views.forgot_password, name='forgot_password'),
    path('reset-password/<str:encoded_email>/<str:token>/', views.reset_password, name='reset_password'),
    path('student_attendance_records', views.student_attendance_records, name='student_attendance_records'),
    path('schedule', views.instructor_schedule, name='schedule'),
    path('update-class-schedule_instructor/', views.update_class_schedule_instructor, name='update_class_schedule_instructor'),
    path('account_management/', views.account_management, name='account_management'),
    path('delete_account/<int:account_id>/', views.delete_account, name='delete_account'),
    path('update_account/<int:account_id>/', views.update_account, name='update_account'),
    path("import_class_schedule/", views.import_class_schedule, name="import_class_schedule"),
    path('class_management', views.class_management, name='class_management'),
    path('add_course_section/', views.add_course_section, name='add_course_section'),
    path('update_class_schedule/<int:pk>/', views.update_class_schedule, name='update_class_schedule'),
    path('delete_class_schedule/<int:pk>/', views.delete_class_schedule, name='delete_class_schedule'),
    path('attendance_report_template', views.attendance_report_template, name='attendance_report_template'),
    path('create_instructor', views.create_instructor, name='create_instructor'),
    path("set_semester", views.set_semester, name="set_semester"),  # Keep this one
    path('auth/mobile/', views.mobile_auth, name='mobile_auth'), 
    path('force-password-change/', views.force_password_change, name='force_password_change'),
    path('attendance/docx/<int:class_id>/', views.generate_attendance_docx_view, name='generate_attendance_docx'),
    path('import_class_pdf/', views.import_class_from_pdf, name='import_class_pdf'),
    path('api/trigger-mobile-sync/', views.trigger_mobile_sync, name='trigger_mobile_sync'),
    path('api/mobile-account-sync/', views.mobile_account_sync, name='mobile_account_sync'),
    path('attendance/docx/<int:schedule_id>/', download_attendance_docx, name='attendance_docx'),
    path('attendance/pdf/<int:schedule_id>/', download_attendance_pdf, name='attendance_pdf'),


]