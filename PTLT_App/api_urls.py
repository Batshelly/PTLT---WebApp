from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'accounts', views.AccountViewSet, basename='account')
router.register(r'class-schedules', views.ClassScheduleViewSet, basename='class-schedule')
router.register(r'attendance-records', views.AttendanceRecordViewSet, basename='attendance-record')
router.register(r'course-sections', views.CourseSectionViewSet, basename='course-section')

urlpatterns = [
    path('auth/login/', views.mobile_login, name='mobile_login'),
    path('auth/mobile/', views.mobile_auth, name='mobile_auth'),
    path('mobile-account-sync/', views.mobile_account_sync, name='api_mobile_account_sync'),
    path('mobile-update-account/<str:user_id>/', views.mobile_update_account, name='mobile_update_account'), 
] + router.urls