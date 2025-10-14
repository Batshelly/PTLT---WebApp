from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.views.decorators.csrf import csrf_protect
import json
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.template.loader import render_to_string
from django.db.models import Q
from django.core.paginator import Paginator
from django.views.decorators.http import require_http_methods   
import json
from django.contrib.auth.models import User
from django.utils.crypto import get_random_string
from django.db import transaction
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.contrib.auth import logout
from django.utils.safestring import mark_safe
from django.core.serializers.json import DjangoJSONEncoder
from datetime import time, timedelta
from django.views.decorators.http import require_POST
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.hashers import check_password
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
import datetime
import csv
import io
import traceback
from django.core.mail import send_mail
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from datetime import datetime, date
from functools import wraps
import PyPDF2
import re
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token
from rest_framework import serializers
from django.contrib.auth.hashers import make_password
# Authentication endpoint for mobile
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from .serializers import MobileClassScheduleSerializer

from .models import Account
from .models import CourseSection
from .models import ClassSchedule
from .models import AttendanceRecord
from .models import Semester
from .models import AccountUploadNotification

from collections import defaultdict
from django.utils.dateparse import parse_date


from .serializers import (
    AccountSerializer, ClassScheduleSerializer, AttendanceRecordSerializer,
    MobileAccountSerializer, MobileAttendanceSerializer
)

# for docx file
from docxtpl import DocxTemplate
from io import BytesIO
import os
from django.conf import settings

from django.core.mail import EmailMessage
from django.conf import settings
import random
from datetime import datetime, timedelta, date
from .models import Account, CourseSection, ClassSchedule

# for pdf preview
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER

# Custom authentication decorators
def admin_required(view_func):
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        try:
            account = Account.objects.get(email=request.user.email, role='Admin')
        except Account.DoesNotExist:
            messages.error(request, "Access denied: Admin privileges required.")
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper

def instructor_or_admin_required(view_func):
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        try:
            account = Account.objects.get(email=request.user.email, role__in=['Instructor', 'Admin'])
        except Account.DoesNotExist:
            messages.error(request, "Access denied: Instructor or Admin role required.")
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper

def instructor_required(view_func):
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        try:
            account = Account.objects.get(email=request.user.email, role='Instructor')
        except Account.DoesNotExist:
            messages.error(request, "Access denied: Instructor role required.")
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper

#para to sa schedule ni instructor
PERIODS = [
    (time(9, 30), time(10, 20), "I"),
    (time(10, 20), time(11, 10), "II"),
    (time(11, 10), time(12, 0), "III"),
    (time(12, 0), time(12, 40), "Break"),  # Lunch
    (time(12, 40), time(13, 30), "IV"),
    (time(13, 30), time(14, 20), "V"),
    (time(14, 20), time(15, 10), "VI"),
    (time(15, 10), time(16, 0), "VII"),
]

@transaction.atomic 
def login_view(request):
    
    # Check if any accounts exist - keep your existing default account creation
    if not Account.objects.exists():
        default_accounts = [
            {
                'user_id': '000000',
                'email': 'tupcptlt@gmail.com',
                'first_name': 'Super Admin',
                'last_name': 'Account 0',
                'role': 'Admin',
                'password': None,  # No password needed
                'sex': 'Other',
                'status': 'Active'
            },
            {
                'user_id': '000001',
                'email': 'shelwinjay.buenaventura@gsfe.tupcavite.edu.ph',
                'first_name': 'Dummy',
                'last_name': 'Account 1',
                'role': 'Instructor',
                'password': None,
                'sex': 'Other',
                'status': 'Active'
            },
            {
                'user_id': '000002',
                'email': 'marktrieste.milan@gsfe.tupcavite.edu.ph',
                'first_name': 'Dummy',
                'last_name': 'Account 2',
                'role': 'Instructor',
                'password': None,
                'sex': 'Other',
                'status': 'Active'
            },
            {
                'user_id': '000003',
                'email': 'markjoshua.salinas@gsfe.tupcavite.edu.ph',
                'first_name': 'Dummy',
                'last_name': 'Account 3',
                'role': 'Instructor',
                'password': None,
                'sex': 'Other',
                'status': 'Active'
            },
            {
                'user_id': '000004',
                'email': 'janxander.yangco@gsfe.tupcavite.edu.ph',
                'first_name': 'Dummy',
                'last_name': 'Account 4',
                'role': 'Instructor',
                'password': None,
                'sex': 'Other',
                'status': 'Active'
            }
        ]

        for acc in default_accounts:
            # Create Django User for session management
            user = User.objects.create_user(
                username=acc['user_id'],
                email=acc['email'],
                password=get_random_string(12),  # Random password (won't be used)
                first_name=acc['first_name'],
                last_name=acc['last_name']
            )

            # Create Account entry
            Account.objects.create(
                user_id=acc['user_id'],
                email=acc['email'],
                first_name=acc['first_name'],
                last_name=acc['last_name'],
                role=acc['role'],
                password=None,
                sex=acc['sex'],
                status=acc['status'],
                course_section=None
            )
    
    if request.method == 'POST':
        email = request.POST.get('email')

        try:
            # Check if account exists and is Instructor or Admin
            account = Account.objects.get(email=email, role__in=['Instructor', 'Admin'])
            
            # Check if account is active
            if account.status != 'Active':
                messages.error(request, 'Your account is not active. Please contact administrator.')
                return redirect('login')
            
            # Generate 6-digit OTP
            otp = random.randint(100000, 999999)
            
            # Store OTP in session with timestamp
            request.session['login_otp'] = otp
            request.session['login_email'] = email
            request.session['otp_timestamp'] = datetime.now().isoformat()
            
            # Design the email
            email_subject = "PTLT - Login OTP Verification"
            email_body = f"""
            <html>
                <body style="font-family: Arial, sans-serif;">
                    <h2 style="color: #661e1e;">PTLT Login Verification</h2>
                    <p>Hello {account.first_name},</p>
                    <p>You have requested to log in to the PTLT system. Please use the OTP below:</p>
                    <div style="background-color: #f5f5f5; padding: 20px; text-align: center; margin: 20px 0;">
                        <h1 style="color: #661e1e; font-size: 36px; margin: 0; letter-spacing: 5px;">{otp}</h1>
                    </div>
                    <p style="color: #666;">This OTP is valid for <strong>5 minutes</strong>. Please do not share it with anyone.</p>
                    <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
                    <p style="font-size: 12px; color: #999;">
                        If you did not attempt to log in, please ignore this email or contact the administrator.
                    </p>
                </body>
            </html>
            """

            # Send OTP email
            try:
                email_message = EmailMessage(
                    email_subject,
                    email_body,
                    settings.EMAIL_HOST_USER,
                    [email],
                )
                email_message.content_subtype = 'html'
                email_message.send()
                
                messages.success(request, f'OTP has been sent to {email}. Please check your inbox.')
                return redirect('verify_login_otp')
                
            except Exception as e:
                messages.error(request, 'Failed to send OTP. Please try again later.')
                return redirect('login')

        except Account.DoesNotExist:
            messages.error(request, 'No account found with that email, or you do not have access to this system.')
            return redirect('login')
        
    return render(request, 'login.html')


# NEW VIEW: OTP Verification for Login
def verify_login_otp(request):
    # Check if user came from login page with OTP
    if 'login_otp' not in request.session or 'login_email' not in request.session:
        messages.error(request, "Session expired. Please request a new OTP.")
        return redirect('login')
    
    if request.method == 'POST':
        user_otp = request.POST.get('otp')
        stored_otp = request.session.get('login_otp')
        email = request.session.get('login_email')
        otp_timestamp = request.session.get('otp_timestamp')
        
        # Check OTP expiration (5 minutes)
        otp_time = datetime.fromisoformat(otp_timestamp)
        current_time = datetime.now()
        time_diff = (current_time - otp_time).total_seconds() / 60
        
        if time_diff > 5:
            # OTP expired
            del request.session['login_otp']
            del request.session['login_email']
            del request.session['otp_timestamp']
            messages.error(request, "OTP has expired. Please request a new one.")
            return redirect('login')
        
        # Validate OTP
        if str(stored_otp) == user_otp:
            try:
                # Get the account
                account = Account.objects.get(email=email)
                
                # Get or create Django User for session
                try:
                    user_obj = User.objects.get(email=email)
                except User.DoesNotExist:
                    # Create Django User if doesn't exist
                    user_obj = User.objects.create_user(
                        username=account.user_id,
                        email=account.email,
                        password=get_random_string(12),
                        first_name=account.first_name,
                        last_name=account.last_name
                    )
                
                # Log the user in (backend bypasses password check)
                from django.contrib.auth import login as auth_login
                auth_login(request, user_obj, backend='django.contrib.auth.backends.ModelBackend')
                
                # Set session variables
                request.session['user_id'] = account.user_id
                request.session['role'] = account.role
                
                # Clear OTP data from session
                del request.session['login_otp']
                del request.session['login_email']
                del request.session['otp_timestamp']
                
                messages.success(request, f"Welcome back, {account.first_name}!")
                
                # Redirect based on role
                if account.role == 'Admin':
                    return redirect('account_management')
                elif account.role == 'Instructor':
                    return redirect('schedule')
                else:
                    messages.error(request, "Unknown user role.")
                    return redirect('login')
                    
            except Account.DoesNotExist:
                messages.error(request, "Account not found.")
                return redirect('login')
        else:
            # Invalid OTP - but don't clear session, allow retry
            messages.error(request, "Invalid OTP. Please try again.")
            return render(request, 'verify_login_otp.html', {'email': email})
    
    # GET request - show OTP entry form
    email = request.session.get('login_email')
    return render(request, 'verify_login_otp.html', {'email': email})


# NEW VIEW: Resend OTP
def resend_login_otp(request):
    if 'login_email' not in request.session:
        messages.error(request, "Session expired. Please start login process again.")
        return redirect('login')
    
    email = request.session.get('login_email')
    
    try:
        account = Account.objects.get(email=email, role__in=['Instructor', 'Admin'])
        
        # Generate new OTP
        otp = random.randint(100000, 999999)
        
        # Update session
        request.session['login_otp'] = otp
        request.session['otp_timestamp'] = datetime.now().isoformat()
        
        # Send email
        email_subject = "PTLT - New Login OTP"
        email_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <h2 style="color: #661e1e;">PTLT Login Verification</h2>
                <p>Hello {account.first_name},</p>
                <p>You have requested a new OTP. Please use the code below:</p>
                <div style="background-color: #f5f5f5; padding: 20px; text-align: center; margin: 20px 0;">
                    <h1 style="color: #661e1e; font-size: 36px; margin: 0; letter-spacing: 5px;">{otp}</h1>
                </div>
                <p style="color: #666;">This OTP is valid for <strong>5 minutes</strong>.</p>
            </body>
        </html>
        """
        
        email_message = EmailMessage(
            email_subject,
            email_body,
            settings.EMAIL_HOST_USER,
            [email],
        )
        email_message.content_subtype = 'html'
        email_message.send()
        
        messages.success(request, 'A new OTP has been sent to your email.')
        return redirect('verify_login_otp')
        
    except Exception as e:
        messages.error(request, 'Failed to resend OTP. Please try again.')
        return redirect('verify_login_otp')


def force_password_change(request):
    # Check if user came from login with temp password
    if 'temp_user_id' not in request.session:
        messages.error(request, "Unauthorized access.")
        return redirect('login')
    
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password == '000000':
            messages.error(request, "Please try a different password.")
            return render(request, 'force_password_change.html')
        
        if new_password == 'secret':
            messages.error(request, "Uy bat mo alam?")
            return render(request, 'force_password_change.html')
        
        if new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'force_password_change.html')
        
        if len(new_password) < 6:  # Add your password requirements
            messages.error(request, "Password must be at least 6 characters long.")
            return render(request, 'force_password_change.html')
        
        try:
            user_id = request.session['temp_user_id']
            email = request.session['temp_email']
            account = Account.objects.get(user_id=user_id, email=email)
            
            # Create or update Django User
            try:
                user_obj = User.objects.get(email=email)
                # Update existing user password
                user_obj.set_password(new_password)
                user_obj.save()
            except User.DoesNotExist:
                # Create new Django User
                user_obj = User.objects.create_user(
                    username=account.user_id,
                    email=account.email,
                    password=new_password,
                    first_name=account.first_name,
                    last_name=account.last_name
                )
            
            # Clear temporary session data
            del request.session['temp_user_id']
            del request.session['temp_email']
            
            # Auto-login the user
            user = authenticate(request, username=user_obj.username, password=new_password)
            if user:
                login(request, user)
                request.session['user_id'] = account.user_id
                request.session['role'] = account.role
                
                messages.success(request, "Password updated successfully!")
                
                # Redirect based on role
                if account.role == 'Admin':
                    return redirect('account_management')
                elif account.role == 'Instructor':
                    return redirect('schedule')
                else:
                    return redirect('login')
            
        except Account.DoesNotExist:
            messages.error(request, "Account not found.")
            return redirect('login')
    
    return render(request, 'force_password_change.html')

def logout_view(request):
    logout(request)  # Destroys session and logs out user
    return redirect('login') 

@admin_required
def create_instructor(request):
    if request.method == 'POST':
        form_type = request.POST.get('form_type')

        if form_type == 'instructor_form':
            # Instructor form submitted
            user_id = request.POST.get('user_id')
            email = request.POST.get('email')
            first_name = request.POST.get('first_name')
            last_name = request.POST.get('last_name')
            role = request.POST.get('role')
            password = request.POST.get('password')
            sex = request.POST.get('sex')

            if Account.objects.filter(user_id=user_id).exists():
                messages.error(request, 'User ID already exists.')
            elif Account.objects.filter(email=email).exists():
                messages.error(request, 'Email already exists.')
            else:
                Account.objects.create(
                    user_id=user_id,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    role=role,
                    password=password,
                    sex=sex
                )
                messages.success(request, 'Instructor account created successfully!')
                return redirect('create_instructor')

        elif form_type == 'course_section_form':
            # Course & section form submitted
            course_name = request.POST.get('course_name')
            section_name = request.POST.get('section_name')

            try:
                course_section = CourseSection.objects.create(
                    course_name=course_name,
                    section_name=section_name
                )
                messages.success(request, f'Course Section "{course_section.course_section}" created successfully!')
                return redirect('create_instructor')
            except Exception as e:
                messages.error(request, f'Error: {str(e)}')

    return render(request, 'create_instructor.html')

def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get('email')

        try:
            # Fetch the user using the default User model
            user = User.objects.get(email=email)

            # Generate the password reset token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            current_site = get_current_site(request).domain
            # Generate the reset password URL
            reset_link = f"http://{current_site}/reset-password/{uid}/{token}/"

            # HTML email content - using triple quotes without f-string for CSS, then formatting
            email_subject = 'Password Reset Request'
            
            # Create the email body using format() method instead of f-string
            email_body = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Password Reset</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        margin: 0;
                        padding: 0;
                        background-color: #f5f5f5;
                    }}
                    .container {{
                        width: 100%;
                        max-width: 600px;
                        margin: 0 auto;
                        background-color: #ffffff;
                        padding: 20px;
                        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    }}
                    h1 {{
                        color: #333;
                        text-align: center;
                    }}
                    p {{
                        font-size: 1rem;
                        line-height: 1.5;
                        color: #555;
                    }}
                    .button {{
                        display: inline-block;
                        padding: 12px 24px;
                        background-color: #661e1e;
                        color: white !important;
                        text-decoration: none;
                        border-radius: 4px;
                        font-size: 1rem;
                        margin-top: 20px;
                        text-align: center;
                        transition: background-color 0.3s ease;
                    }}
                    .button:hover {{
                        background-color: #a74545;
                    }}
                    .footer {{
                        margin-top: 30px;
                        padding-top: 20px;
                        border-top: 1px solid #eee;
                        font-size: 0.9rem;
                        color: #777;
                    }}
                    .warning {{
                        background-color: #fff3cd;
                        border: 1px solid #ffeaa7;
                        border-radius: 4px;
                        padding: 15px;
                        margin: 20px 0;
                        color: #856404;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header-accent"></div>
                    <h1>Password Reset Request</h1>
                    <p>Hello {first_name},</p>
                    <p>We received a request to reset your password for your account. To proceed with resetting your password, please click the button below:</p>
                    <p><a href="{reset_link}" class="button">Reset Password</a></p>
                    
                    <div class="warning">
                        <strong>Security Notice:</strong> This link will expire in 24 hours for your security. If you didn't request this password reset, please ignore this email and your password will remain unchanged.
                    </div>
                    
                    <div class="footer">
                        <p>If the button above doesn't work, you can copy and paste this link into your browser:</p>
                        <p style="word-break: break-all; color: #dc2626 !important; font-weight: 600; text-decoration: none !important;">{reset_link}</p>
                        <p style="margin-top: 20px;">
                            <span style="color: #6b7280;">Best regards,</span><br>
                            <strong style="color: #dc2626;">PTLT TUP-CAVITE</strong>
                        </p>
                    </div>
                </div>
            </body>
            </html>
            """.format(first_name=user.first_name, reset_link=reset_link)

            # Send the HTML email
            send_mail(
                email_subject,
                '',  # Plain text version of the email (empty since we are sending HTML)
                'from@example.com',  # Set your sender email
                [email],
                fail_silently=False,
                html_message=email_body  # HTML version of the email
            )

            # Show success message to the user
            messages.success(request, 'Password reset link has been sent to your email address.')
            return redirect('login')

        except User.DoesNotExist:
            # Handle the case where the user doesn't exist
            messages.error(request, 'No account found with this email address.')
    return render(request, 'forgot_password.html')

def reset_password(request, encoded_email, token):
    try:
        # Decode the user ID from the encoded email
        try:
            uid = urlsafe_base64_decode(encoded_email).decode('utf-8')
            print(f"Decoded user ID: {uid}")
        except Exception as e:
            print(f"Error decoding email: {e}")
            messages.error(request, 'Invalid or expired reset link.')
            return redirect('login')
        
        # Fetch the user based on the decoded ID
        try:
            user = User.objects.get(pk=uid)
        except User.DoesNotExist:
            print(f"User does not exist for ID: {uid}")
            messages.error(request, 'User not found.')
            return redirect('login')
        
        # Check if the token matches the user's reset token
        if default_token_generator.check_token(user, token):
            if request.method == 'POST':
                new_password = request.POST.get('password')
                confirm_password = request.POST.get('confirm_password')
                print(f"new_password: {new_password}, confirm_password: {confirm_password}")

                # Ensure the passwords match
                if new_password == confirm_password:
                    user.set_password(new_password)  # Set the new password
                    user.save()  # Save the user object
                    print("Password reset successfully!")
                    messages.success(request, 'Your password has been reset successfully!')
                    update_session_auth_hash(request, user)  # Keep the user logged in
                    return redirect('login')  # Redirect to login page
                else:
                    messages.error(request, 'Passwords do not match. Please try again.')

            return render(request, 'reset_password.html', {'uid': encoded_email, 'token': token})

        else:
            print(f"Invalid token for user: {uid}")
            messages.error(request, 'Invalid or expired reset link.')
            return redirect('login')

    except Exception as e:
        print(f"Error occurred: {e}")
        messages.error(request, 'An error occurred during password reset. Please try again later.')
        return redirect('login')
    

@instructor_required
def student_attendance_records(request):
    # Get logged-in instructor's Account entry
    try:
        instructor_account = Account.objects.get(email=request.user.email, role='Instructor')
    except Account.DoesNotExist:
        return render(request, "error.html", {"message": "Instructor account not found"})

    # Subjects/Courses taught by this instructor
    schedules = ClassSchedule.objects.filter(professor=instructor_account)

    selected_schedule_id = request.GET.get("schedule")
    selected_date_range = request.GET.get("date_range")
    date_ranges = []
    attendance_table = []

    if selected_schedule_id:
        # Fetch unique attendance dates for selected class schedule
        attendance_dates = AttendanceRecord.objects.filter(
            class_schedule_id=selected_schedule_id
        ).values_list("date", flat=True).distinct().order_by("date")

        attendance_dates = list(attendance_dates)

        # Group into 8-day ranges for the filter dropdown
        for i in range(0, len(attendance_dates), 8):
            start_date = attendance_dates[i]
            end_date = attendance_dates[min(i + 7, len(attendance_dates) - 1)]
            date_ranges.append({
                "value": f"{start_date}_to_{end_date}",
                "label": f"{start_date.strftime('%B %d, %Y')} - {end_date.strftime('%B %d, %Y')}"
            })

        if selected_date_range:
            try:
                start_str, end_str = selected_date_range.split("_to_")
                start_date = parse_date(start_str)
                end_date = parse_date(end_str)
            except (ValueError, TypeError):
                start_date = end_date = None

            if start_date and end_date:
                # Get all attendance records within the date range
                attendance_qs = AttendanceRecord.objects.filter(
                    class_schedule_id=selected_schedule_id,
                    date__range=(start_date, end_date)
                ).select_related('student')

                # Get schedule object once
                schedule_obj = ClassSchedule.objects.get(id=selected_schedule_id)

                # Get students in the same course_section as the schedule
                students_in_schedule = Account.objects.filter(
                    course_section_id=schedule_obj.course_section_id
                ).order_by('last_name', 'first_name')

                # Map attendance data: {student_id: {date: {'status': status, 'time_in': time_in, 'time_out': time_out}}}
                attendance_data = defaultdict(lambda: defaultdict(dict))
                for record in attendance_qs:
                    attendance_data[record.student.id][record.date] = {
                        'status': record.status,
                        'time_in': record.time_in,
                        'time_out': record.time_out
                    }

                # Build date headers (max 8 dates)
                date_headers = [d for d in attendance_dates if start_date <= d <= end_date][:8]
                num_empty_date_column = 8 - len(date_headers)
                #create a pseudo list just for the for loop in html to work
                num_empty_date_columns = []
                for i in range(num_empty_date_column):
                    num_empty_date_columns.append("")


                attendance_table = []
                for student in students_in_schedule:
                    course_section_for_student = student.course_section
                    # Build dates_statuses as a list of dicts containing all attendance info
                    dates_statuses = []
                    for date in date_headers:
                        attendance_info = attendance_data[student.id].get(date, {})
                        dates_statuses.append({
                            'status': attendance_info.get('status', ''),
                            'time_in': attendance_info.get('time_in', ''),
                            'time_out': attendance_info.get('time_out', '')
                        })
                    
                    # Pad with empty dicts to always have 8 items
                    while len(dates_statuses) < 8:
                        dates_statuses.append({
                            'status': '',
                            'time_in': '',
                            'time_out': ''
                        })

                    # DEBUG: Check the length
                    print(f"Student {student.user_id}: dates_statuses length = {len(dates_statuses)}")

                    row = {
                        "student_id": student.user_id, 
                        "name": f"{student.first_name} {student.last_name}",
                        "sex": student.sex,
                        "course": course_section_for_student,
                        "subject": schedule_obj.course_code,
                        "room": schedule_obj.room_assignment,
                        "dates": dates_statuses,  # Always 8 items now
                    }
                    attendance_table.append(row)

                context = {
                    "schedules": schedules,
                    "date_ranges": date_ranges,
                    "selected_schedule_id": selected_schedule_id,
                    "selected_date_range": selected_date_range,
                    "attendance_table": attendance_table,
                    "date_headers": date_headers,
                    "num_empty_date_columns": num_empty_date_columns,
                }
                return render(request, "student_attendance_records.html", context)

        # If no valid date range selected or dates invalid, still render with schedules & date ranges
        context = {
            "schedules": schedules,
            "date_ranges": date_ranges,
            "selected_schedule_id": selected_schedule_id,
            "attendance_table": [],
            "date_headers": [],
            "num_empty_date_columns": ["", "", "", "", "", "", "", "", ],
        }
        return render(request, "student_attendance_records.html", context)

    # If no schedule selected at all, render with just schedules and empty date ranges
    context = {
        "schedules": schedules,
        "date_ranges": date_ranges,
        "selected_schedule_id": selected_schedule_id,
        "attendance_table": [],
        "date_headers": [],
        "num_empty_date_columns": ["", "", "", "", "", "", "", "", ],
    }
    return render(request, "student_attendance_records.html", context)



@require_POST
@instructor_required
def update_class_schedule_instructor(request):
    try:
        data = json.loads(request.body)

        # Validate required fields
        required_fields = ['course_code', 'time_in', 'time_out', 'room_assignment', 'grace_period']
        for field in required_fields:
            if field not in data:
                return JsonResponse({'success': False, 'error': f'Missing field: {field}'}, status=400)

        # Match instructor via user_id
        instructor = Account.objects.get(user_id=request.user.username, role='Instructor')

        # Get the specific schedule (only one per instructor + course_code assumed)
        schedule = ClassSchedule.objects.get(course_code=data['course_code'], professor=instructor)

        # Apply updates
        schedule.time_in = data['time_in']
        schedule.time_out = data['time_out']
        schedule.room_assignment = data['room_assignment']
        schedule.grace_period = int(data['grace_period'])
        schedule.save()

        return JsonResponse({'success': True})

    except ClassSchedule.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Class schedule not found.'}, status=404)

    except Account.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Instructor account not found.'}, status=403)

    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON data.'}, status=400)

    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@instructor_required    
def instructor_schedule(request):
    user = request.user
    try:
        instructor = Account.objects.get(user_id=user.username, role='Instructor')
    except Account.DoesNotExist:
        return render(request, 'error.html', {'message': 'Instructor not found.'})

    schedules = ClassSchedule.objects.filter(professor=instructor)

    for schedule in schedules:
        student_acc = Account.objects.filter(course_section_id=schedule.course_section_id)
        student_count = len(student_acc)
        schedule.student_count = int(student_count)
        schedule.save()

    return render(request, 'schedule.html', {
        'class_schedules': schedules,
    })


@admin_required
def account_management(request):
    role_filter = request.GET.get('role', '')
    status_filter = request.GET.get('status', '')
    search_query = request.GET.get('search', '')

    accounts = Account.objects.all()

    if role_filter:
        accounts = accounts.filter(role__iexact=role_filter)
    if status_filter:
        accounts = accounts.filter(status__iexact=status_filter)
    if search_query:
        accounts = accounts.filter(
            Q(first_name__icontains=search_query) | Q(last_name__icontains=search_query)
        )
    
    # Order the accounts
    accounts = accounts.order_by('user_id')

    # Add pagination - 10 accounts per page
    paginator = Paginator(accounts, 10)
    page_number = request.GET.get('page')
    accounts_page = paginator.get_page(page_number)

    update_notifications = AccountUploadNotification.objects.filter(is_read=False, notification_type='update')
    update_count = update_notifications.count()
    recent_updates = update_notifications[:5]
    
    # Mark updates as read if requested
    if request.GET.get('mark_updates_read') == 'true':
        AccountUploadNotification.objects.filter(is_read=False, notification_type='update').update(is_read=True)
        messages.success(request, f'Marked {update_count} notifications as read.')
        return redirect('account_management')
    
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        html = render_to_string('partials/account_table_body.html', {'accounts': accounts_page})
        return JsonResponse({'html': html})

    # Build query string for pagination links
    query_params = request.GET.copy()
    if 'page' in query_params:
        query_params.pop('page')
    query_string = query_params.urlencode()

    context = {
        'accounts': accounts_page,
        'update_count': update_count,
        'query_string': query_string,
    }

    return render(request, 'account_management.html', context)


@csrf_exempt
@admin_required
def delete_account(request, account_id):
    if request.method == 'POST':
        acc = get_object_or_404(Account, id=account_id)
        acc.delete()
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=400)

@csrf_exempt
@admin_required
def update_account(request, account_id):
    print("1")
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            print("Received data:", data)  # 👈 Debug
            
            account = get_object_or_404(Account, id=account_id)

            # Direct assignment from data
            account.user_id = data.get('user_id', account.user_id)
            account.first_name = data.get('first_name', account.first_name)
            account.last_name = data.get('last_name', account.last_name)
            account.role = data.get('role', account.role)
            account.email = data.get('email', account.email)

            account.save()

            return JsonResponse({'status': 'success'})
        except Exception as e:
            print("Error updating account:", str(e))
            return JsonResponse({'status': 'error', 'message': str(e)})

    return JsonResponse({'status': 'invalid_request'})

import csv
import io
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Account, ClassSchedule, CourseSection

@csrf_exempt
@instructor_or_admin_required
def import_class_schedule(request):
    """Import class schedules from CSV file"""
    
    print(f"Request method: {request.method}")
    print(f"Files: {list(request.FILES.keys())}")
    
    if request.method != 'POST':
        return JsonResponse({
            'status': 'error',
            'message': 'Only POST method allowed',
            'imported': 0,
            'skipped': 0,
            'errors': ['Only POST method allowed']
        }, status=405)
    
    # ✅ FIXED: Changed 'csvfile' to 'csv_file'
    if 'csv_file' not in request.FILES:
        return JsonResponse({
            'status': 'error',
            'message': 'No CSV file uploaded',
            'imported': 0,
            'skipped': 0,
            'errors': [f'No CSV file found. Received files: {list(request.FILES.keys())}']
        }, status=400)
    
    try:
        # ✅ FIXED: Changed to 'csv_file'
        csv_file = request.FILES['csv_file']
        print(f"Processing file: {csv_file.name}, size: {csv_file.size} bytes")
        
        # Read CSV file
        decoded_file = csv_file.read().decode('utf-8')
        io_string = io.StringIO(decoded_file)
        reader = csv.DictReader(io_string)
        
        results = {
            'imported': 0,
            'skipped': 0,
            'errors': []
        }
        
        for line_num, row in enumerate(reader, start=2):
            try:
                # Get data from CSV
                professor_user_id = row.get('professor_user_id', '').strip()
                course_title = row.get('course_title', '').strip()
                course_code = row.get('course_code', '').strip()
                course_section_id = row.get('course_section_id', '').strip()
                time_in_str = row.get('time_in', '').strip()
                time_out_str = row.get('time_out', '').strip()
                days = row.get('days', '').strip()
                grace_period = row.get('grace_period', '15').strip()
                student_count = row.get('student_count', '0').strip()
                remote_device = row.get('remote_device', '').strip()
                room_assignment = row.get('room_assignment', '').strip()
                
                print(f"Line {line_num}: Processing {course_code}")
                
                # Validate required fields
                if not all([professor_user_id, course_code, course_section_id, time_in_str, time_out_str]):
                    results['errors'].append(f"Line {line_num}: Missing required fields")
                    results['skipped'] += 1
                    continue
                
                # Get professor
                try:
                    professor = Account.objects.get(user_id=professor_user_id, role='Instructor')
                    print(f"Found professor: {professor.first_name} {professor.last_name}")
                except Account.DoesNotExist:
                    results['errors'].append(f"Line {line_num}: Instructor with user_id '{professor_user_id}' not found")
                    results['skipped'] += 1
                    continue
                
                # Get course section
                try:
                    course_section = CourseSection.objects.get(id=int(course_section_id))
                    print(f"Found course section: {course_section.course_section}")
                except CourseSection.DoesNotExist:
                    results['errors'].append(f"Line {line_num}: CourseSection with ID '{course_section_id}' not found")
                    results['skipped'] += 1
                    continue
                except ValueError:
                    results['errors'].append(f"Line {line_num}: Invalid course_section_id '{course_section_id}'")
                    results['skipped'] += 1
                    continue
                
                # Parse times
                try:
                    time_in = datetime.strptime(time_in_str, '%H:%M').time()
                    time_out = datetime.strptime(time_out_str, '%H:%M').time()
                except ValueError:
                    results['errors'].append(f"Line {line_num}: Invalid time format (use HH:MM)")
                    results['skipped'] += 1
                    continue
                
                # Create or update class schedule
                class_schedule, created = ClassSchedule.objects.update_or_create(
                    course_code=course_code,
                    course_section=course_section,
                    defaults={
                        'course_title': course_title or course_code,
                        'professor': professor,
                        'time_in': time_in,
                        'time_out': time_out,
                        'days': days,
                        'grace_period': int(grace_period) if grace_period.isdigit() else 15,
                        'student_count': int(student_count) if student_count.isdigit() else 0,
                        'remote_device': remote_device,
                        'room_assignment': room_assignment,
                    }
                )
                
                action = "Created" if created else "Updated"
                results['imported'] += 1
                print(f"{action} class schedule: {course_code}")
                
            except Exception as e:
                error_msg = f"Line {line_num}: {str(e)}"
                results['errors'].append(error_msg)
                results['skipped'] += 1
                print(f"Error: {error_msg}")
                import traceback
                traceback.print_exc()
        
        # Determine status
        if results['imported'] == 0 and results['skipped'] > 0:
            status_code = 'failed'
        elif results['skipped'] > 0:
            status_code = 'partial'
        else:
            status_code = 'ok'
        
        response_data = {
            'status': status_code,
            'imported': results['imported'],
            'skipped': results['skipped'],
            'errors': results['errors'][:10]  # Limit to first 10 errors
        }
        
        print(f"Import complete. Returning: {response_data}")
        return JsonResponse(response_data)
        
    except Exception as e:
        error_message = str(e)
        print(f"Fatal error in CSV import: {error_message}")
        import traceback
        traceback.print_exc()
        
        return JsonResponse({
            'status': 'error',
            'message': error_message,
            'imported': 0,
            'skipped': 0,
            'errors': [f'Server error: {error_message}']
        }, status=500)

#try pdf import

@require_http_methods(["POST"])
def import_class_from_pdf(request):
    if 'pdf_file' not in request.FILES:
        return JsonResponse({'status': 'error', 'message': 'No PDF file provided'}, status=400)
    
    pdf_file = request.FILES['pdf_file']
    
    try:
        # Read PDF content
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        full_text = ""
        
        # Extract text from all pages
        for page in pdf_reader.pages:
            full_text += page.extract_text() + "\n"
        
        # Initialize data containers
        schedule_data = {}
        all_students = []
        
        # Extract Schedule ID
        schedule_id_match = re.search(r'Schedule ID\s*:\s*([A-Z0-9]+)', full_text)
        if schedule_id_match:
            schedule_data['schedule_id'] = schedule_id_match.group(1).strip()
        
        # Extract Subject (Course Code - Course Title)
        subject_match = re.search(r'Subject\s*:\s*([A-Z0-9-]+)\s*-\s*(.+?)(?:\s*Venue|\n)', full_text)
        if subject_match:
            schedule_data['course_code'] = subject_match.group(1).strip()
            schedule_data['course_title'] = subject_match.group(2).strip()
        
        # Extract Day/Time
        day_time_match = re.search(r'Day/Time\s*:\s*([MTWRFSU])\s+(\d{1,2}:\d{2}[AP]M)-(\d{1,2}:\d{2}[AP]M)', full_text)
        if day_time_match:
            day_map = {
                'M': 'Monday', 'T': 'Tuesday', 'W': 'Wednesday',
                'R': 'Thursday', 'F': 'Friday', 'S': 'Saturday', 'U': 'Sunday'
            }
            schedule_data['day'] = day_map.get(day_time_match.group(1), 'Monday')
            
            time_in_str = day_time_match.group(2)
            time_out_str = day_time_match.group(3)
            
            schedule_data['time_in'] = datetime.strptime(time_in_str, '%I:%M%p').time()
            schedule_data['time_out'] = datetime.strptime(time_out_str, '%I:%M%p').time()
        
        # Extract Course/Section
        section_match = re.search(r'Course/Section\s*:\s*(.+?)(?:\s*\n|1st Semester)', full_text)
        if section_match:
            section_str = section_match.group(1).strip()
            # Handle format like "BET-COET-C-BET-COET-C-4A-C"
            parts = section_str.split('-')
            if len(parts) >= 3:
                # Extract course and section
                # For "BET-COET-C-BET-COET-C-4A-C", we want "BET-COET-C" and "4A-C"
                mid_point = len(parts) // 2
                schedule_data['course_name'] = '-'.join(parts[:mid_point])
                schedule_data['section_name'] = '-'.join(parts[-2:])
        
        # Extract student information
        # Pattern: number. TUPC-XX-XXXX LASTNAME, FIRSTNAME MIDDLENAME
        student_pattern = r'\d+\.\s*(TUPC-\d{2}-\d{4})\s+([A-Z\s,]+?)(?:\s+BET-COET|$)'
        student_matches = re.finditer(student_pattern, full_text)

        for match in student_matches:
            student_no = match.group(1).strip()
            name = match.group(2).strip()
            
            # Extract ID (TUPC-22-0352 → 220352)
            id_match = re.match(r'TUPC-(\d{2})-(\d{4})', student_no)
            if not id_match:
                continue
            
            short_id = id_match.group(1) + id_match.group(2)  # e.g., "220352"
            
            # Parse name (LASTNAME, FIRSTNAME SECONDNAME MIDDLENAME)
            name_parts = name.split(',')

            if len(name_parts) >= 2:
                last_name = name_parts[0].strip().title()
                
                # Split the part after comma and take only first 2 names
                name_after_comma = name_parts[1].strip().split()
                
                # Take first two words (first name + second name), skip third (middle name)
                if len(name_after_comma) >= 2:
                    first_name = f"{name_after_comma[0]} {name_after_comma[1]}".title()
                elif len(name_after_comma) == 1:
                    first_name = name_after_comma[0].title()
                else:
                    first_name = name_parts[1].strip().title()
                
                all_students.append({
                    'user_id': short_id,
                    'first_name': first_name,
                    'last_name': last_name
                })
        
        # Validate we got the required schedule data
        required_fields = ['course_code', 'course_title', 'day', 'time_in', 'time_out', 'course_name', 'section_name']
        missing_fields = [f for f in required_fields if f not in schedule_data]
        
        if missing_fields:
            return JsonResponse({
                'status': 'error',
                'message': f'Could not parse schedule information. Missing: {", ".join(missing_fields)}'
            }, status=400)
        
        if not all_students:
            return JsonResponse({
                'status': 'error',
                'message': 'Could not find any students in the PDF file'
            }, status=400)
        
        # Create or get CourseSection
        course_section, created = CourseSection.objects.get_or_create(
            course_name=schedule_data['course_name'],
            section_name=schedule_data['section_name']
        )
        
        # Create ClassSchedule
        class_schedule = ClassSchedule.objects.create(
            course_code=schedule_data['course_code'],
            course_title=schedule_data['course_title'],
            time_in=schedule_data['time_in'],
            time_out=schedule_data['time_out'],
            days=schedule_data['day'],
            course_section=course_section,
            professor=None,
            student_count=0,
            grace_period=15,
            remote_device='',
            room_assignment='-'
        )
        
        # Create student accounts
        created_students = 0
        skipped_students = 0
        
        for student_info in all_students:
            if not Account.objects.filter(user_id=student_info['user_id']).exists():
                
                print(f"DEBUG: Saving student - ID: {student_info['user_id']}, First: '{student_info['first_name']}', Last: '{student_info['last_name']}'")
                Account.objects.create(
                    user_id=student_info['user_id'],
                    email='',  # Empty - will be filled via mobile app
                    first_name=student_info['first_name'],
                    last_name=student_info['last_name'],
                    role='Student',
                    password='00000',
                    sex='',
                    status='Pending',
                    course_section=course_section,
                    fingerprint_template=None
                )
                created_students += 1
            else:
                skipped_students += 1
        
        # Update student count
        class_schedule.student_count = len(all_students)
        class_schedule.save()
        
        return JsonResponse({
            'status': 'success',
            'message': 'Successfully imported class schedule',
            'details': {
                'course_code': schedule_data['course_code'],
                'course_title': schedule_data['course_title'],
                'course_section': course_section.course_section,
                'day': schedule_data['day'],
                'time': f"{schedule_data['time_in']} - {schedule_data['time_out']}",
                'students_created': created_students,
                'students_skipped': skipped_students,
                'total_students': len(all_students)
            }
        })
        
    except Exception as e:
        print(f"Error importing PDF: {str(e)}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'status': 'error',
            'message': f'Failed to parse PDF: {str(e)}'
        }, status=500)
        
@admin_required
def class_management(request):
    
    today = timezone.now().date()
    
    current_semester = Semester.objects.filter(
        start_date__lte=today,
        end_date__gte=today
    ).first()
    active_semester = current_semester
    
    # Get unread notifications count
    new_accounts_count = AccountUploadNotification.objects.filter(is_read=False).count()
    recent_uploads = AccountUploadNotification.objects.filter(is_read=False)[:5]  # Last 5
    
    #update student count

    schedules = ClassSchedule.objects.all()
    for schedule in schedules:
        student_acc = Account.objects.filter(course_section_id=schedule.course_section_id)
        student_count = len(student_acc)
        schedule.student_count = int(student_count)
        schedule.save()

    # Mark as read if user clicks "Mark as Read"
    if request.GET.get('mark_read') == 'true':
        AccountUploadNotification.objects.filter(is_read=False).update(is_read=True)
        messages.success(request, f'Marked {new_accounts_count} notifications as read.')
        return redirect('class_management')
    
    course_sections = CourseSection.objects.all()

    if request.method == 'POST':
        course_code = request.POST.get('course_code')
        course_name = request.POST.get('course_name')
        time_in = request.POST.get('time_in')
        time_out = request.POST.get('time_out')
        day = request.POST.get('day')
        course_section_str = request.POST.get('course_section')
        remote_device = request.POST.get('remote_device')

        try:
            section_obj = CourseSection.objects.get(course_section=course_section_str)
        except CourseSection.DoesNotExist:
            section_obj = None

        ClassSchedule.objects.create(
            course_code=course_code,
            course_title=course_name,
            time_in=time_in,
            time_out=time_out,
            days=day,
            course_section=section_obj,
            professor=None,
            student_count=0,
            grace_period=0,
            remote_device=remote_device,
            room_assignment='-',
        )

    classes = ClassSchedule.objects.all()

    # Get instructors only
    instructors = Account.objects.filter(role="Instructor").values("first_name", "last_name")
    instructors_json = json.dumps(list(instructors), cls=DjangoJSONEncoder)

    return render(request, 'class_management.html', {
        "active_semester": active_semester,
        'course_sections': course_sections,
        'classes': classes,
        'instructors_json': instructors_json,
        'new_accounts_count': new_accounts_count,  # NEW
        'recent_uploads': recent_uploads,  # NEW
        'current_semester': current_semester
    })

@require_http_methods(["POST"])
@admin_required
def add_course_section(request):
    try:
        data = json.loads(request.body)
        course_name = data.get('course_name', '').strip()
        section_name = data.get('section_name', '').strip()

        if not course_name or not section_name:
            return JsonResponse({
                'status': 'error',
                'message': 'Course name and section name are required.'
            }, status=400)

        # Check if already exists
        course_section_str = f"{course_name} {section_name}"
        if CourseSection.objects.filter(course_section=course_section_str).exists():
            return JsonResponse({
                'status': 'error',
                'message': f'Section "{course_section_str}" already exists.'
            }, status=400)

        # Create new course section
        new_section = CourseSection.objects.create(
            course_name=course_name,
            section_name=section_name
        )

        return JsonResponse({
            'status': 'success',
            'message': 'Course section added successfully.',
            'course_section': new_section.course_section
        })

    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)    

@csrf_exempt
@admin_required
def update_class_schedule(request, pk):
    if request.method == "POST":
        try:
            cls = ClassSchedule.objects.get(id=pk)
            data = json.loads(request.body)

            prof_name = data.get("professor_name", "").strip()
            if prof_name:
                try:
                    first, last = prof_name.split(" ", 1)
                    professor = Account.objects.get(first_name=first, last_name=last)
                    cls.professor = professor
                except Account.DoesNotExist:
                    cls.professor = None

            cls.time_in = data.get("time_in")
            cls.time_out = data.get("time_out")
            cls.days = data.get("day")
            cls.remote_device = data.get("remote_device") 
            cls.save()
            

            return JsonResponse({"status": "success"})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)})

@csrf_exempt
@admin_required
def delete_class_schedule(request, pk):
    if request.method == "POST":
        try:
            cls = ClassSchedule.objects.get(id=pk)
            cls.delete()
            return JsonResponse({"status": "deleted"})
        except:
            return JsonResponse({"status": "error"}, status=400)

@instructor_or_admin_required
def attendance_report_template(request):
    # Get logged-in instructor's Account entry
    try:
        instructor_account = Account.objects.get(email=request.user.email, role='Instructor')
    except Account.DoesNotExist:
        return render(request, "error.html", {"message": "Instructor account not found"})
    
    # Get class schedules for the dropdown
    schedules = ClassSchedule.objects.filter(professor=instructor_account)
    
    selected_schedule_id = request.GET.get("schedule")
    selected_date_range = request.GET.get("date_range")
    date_ranges = []
    attendance_table = []
    attendance_data = {}
    students_list = []
    
    if selected_schedule_id:
        try:
            # Get the selected schedule
            schedule_obj = ClassSchedule.objects.get(id=selected_schedule_id)
            
            # Class details for the form
            attendance_data_attendance_report = {
                'subject': schedule_obj.course_title,
                'faculty_name': f"{schedule_obj.professor.first_name} {schedule_obj.professor.last_name}" if schedule_obj.professor else 'TBA',
                'course': schedule_obj.course_section.course_name if schedule_obj.course_section else '',
                'room': schedule_obj.room_assignment or 'TBA',
                'year_section': schedule_obj.course_section.section_name if schedule_obj.course_section else '',
                'schedule': f"{schedule_obj.days} {schedule_obj.time_in}-{schedule_obj.time_out}",
            }
            
        except ClassSchedule.DoesNotExist:
            pass

        # Fetch unique attendance dates for selected class schedule
        attendance_dates = AttendanceRecord.objects.filter(
            class_schedule_id=selected_schedule_id
        ).values_list("date", flat=True).distinct().order_by("date")

        attendance_dates = list(attendance_dates)

        # Group into 8-day ranges for the filter dropdown
        for i in range(0, len(attendance_dates), 8):
            start_date = attendance_dates[i]
            end_date = attendance_dates[min(i + 7, len(attendance_dates) - 1)]
            date_ranges.append({
                "value": f"{start_date}_to_{end_date}",
                "label": f"{start_date.strftime('%B %d, %Y')} - {end_date.strftime('%B %d, %Y')}"
            })

        #if may sinelect na na date range
        if selected_date_range:
            try:
                start_str, end_str = selected_date_range.split("_to_")
                start_date = parse_date(start_str)
                end_date = parse_date(end_str)
            except (ValueError, TypeError):
                start_date = end_date = None

            if start_date and end_date:
                # Get all attendance records within the date range
                attendance_qs = AttendanceRecord.objects.filter(
                    class_schedule_id=selected_schedule_id,
                    date__range=(start_date, end_date)
                ).select_related('student')

                # Get schedule object once
                schedule_obj = ClassSchedule.objects.get(id=selected_schedule_id)

                # Get students in the same course_section as the schedule
                students_in_schedule = Account.objects.filter(
                    course_section_id=schedule_obj.course_section_id
                ).order_by('last_name', 'first_name')

                # Map attendance data: {student_id: {date: {'status': status, 'time_in': time_in, 'time_out': time_out}}}
                attendance_data = defaultdict(lambda: defaultdict(dict))
                for record in attendance_qs:
                    attendance_data[record.student.id][record.date] = {
                        'status': record.status,
                        'time_in': record.time_in,
                        'time_out': record.time_out
                    }

                # Build date headers (max 8 dates)
                date_headers = [d for d in attendance_dates if start_date <= d <= end_date][:8]
                num_empty_date_column = 8 - len(date_headers)
                #create a pseudo list just for the for loop in html to work
                num_empty_date_columns = []
                for i in range(num_empty_date_column):
                    num_empty_date_columns.append("")


                attendance_table = []
                for student in students_in_schedule:
                    course_section_for_student = student.course_section
                    # Build dates_statuses as a list of dicts containing all attendance info
                    dates_statuses = []
                    for date in date_headers:
                        attendance_info = attendance_data[student.id].get(date, {})
                        dates_statuses.append({
                            'status': attendance_info.get('status', ''),
                            'time_in': attendance_info.get('time_in', ''),
                            'time_out': attendance_info.get('time_out', '')
                        })
                    
                    # Pad with empty dicts to always have 8 items
                    while len(dates_statuses) < 8:
                        dates_statuses.append({
                            'status': '',
                            'time_in': '',
                            'time_out': ''
                        })
                    
                        
                    row = {
                        "student_id": student.user_id, 
                        "name": f"{student.first_name} {student.last_name}",
                        "sex": student.sex,
                        "course": course_section_for_student,
                        "subject": schedule_obj.course_code,
                        "room": schedule_obj.room_assignment,
                        "dates": dates_statuses,  # Always 8 items now
                    }
                    attendance_table.append(row)

                else:
                    row = [""]
                # Build date headers (max 8 dates)
                date_headers = [d for d in attendance_dates if start_date <= d <= end_date][:8]
                num_empty_date_column = 8 - len(date_headers)
                #create a pseudo list just for the for loop in html to work
                num_empty_date_columns = []
                for i in range(num_empty_date_column):
                    num_empty_date_columns.append("")

                num_empty_row = 40 - len(attendance_table)
                #create a pseudo list just for the for loop in html to work
                num_empty_rows = []
                num_filled_rows = []
                for i in range(num_empty_row):
                    num_empty_rows.append("")

                for i in range(len(attendance_table)):
                    num_filled_rows.append("")

                print(f"{len(num_empty_rows)}")
                print(f"{len(num_filled_rows)}")

                context = {
                    'attendance_data': attendance_data_attendance_report,
                    "schedules": schedules,
                    "date_ranges": date_ranges,
                    "selected_schedule_id": selected_schedule_id,
                    "selected_date_range": selected_date_range,
                    "attendance_table": attendance_table,
                    "date_headers": date_headers,
                    "num_empty_rows": num_empty_rows,
                    "num_filled_rows": num_filled_rows,
                    "num_empty_date_columns": num_empty_date_columns,
                }
                return render(request, "attendance_report_template.html", context)
        else:
    # If no valid date range selected or dates invalid, still render with schedules & date ranges
            context = {
                'attendance_data': attendance_data_attendance_report,
                "schedules": schedules,
                "date_ranges": date_ranges,
                "selected_schedule_id": selected_schedule_id,
                "attendance_table": [],
                "date_headers": [],
                "num_empty_rows": [""]*40,
                "num_filled_rows": [],
                "num_empty_date_columns": ["", "", "", "", "", "", "", "", ],
            }
            return render(request, "attendance_report_template.html", context)

    # If no schedule selected at all, render with just schedules and empty date ranges
    context = {
        'attendance_data': {"":"",'faculty_name': f"{instructor_account.first_name} {instructor_account.last_name}" if instructor_account else 'TBA',"":"","":"","":"","":""},
        "schedules": schedules,
        "date_ranges": date_ranges,
        "selected_schedule_id": selected_schedule_id,
        "attendance_table": [],
        "date_headers": [],
        "num_empty_rows": [""]*40,
        "num_filled_rows": [],
        "num_empty_date_columns": ["", "", "", "", "", "", "", "", ],
    }
    return render(request, "attendance_report_template.html", context)
    

@admin_required
def set_semester(request):
    today = date.today()
    current_semester = Semester.objects.filter(start_date__lte=today, end_date__gte=today).first()

    if request.method == "POST":
        start = request.POST.get("semester_start")
        end = request.POST.get("semester_end")

        if not start or not end:
            messages.error(request, "Both start and end dates are required.", extra_tags="semester")
            return redirect("class_management")

        try:
            start_date = datetime.strptime(start, "%Y-%m-%d").date()
            end_date = datetime.strptime(end, "%Y-%m-%d").date()
        except ValueError:
            messages.error(request, "Invalid date format.", extra_tags="semester")
            return redirect("class_management")

        if end_date <= start_date:
            messages.error(request, "End date must be after start date.", extra_tags="semester")
            return redirect("class_management")

        if start_date < today:
            messages.error(request, "Semester start date cannot be earlier than today.", extra_tags="semester")
            return redirect("class_management")

        # If a semester exists and is ongoing → block unless editing
        if current_semester and "confirm_edit" not in request.POST:
            messages.error(request, "A semester is already active. Confirm edit to change it.", extra_tags="semester")
            return redirect("class_management")

        # If editing, update existing; else create new
        if current_semester and "confirm_edit" in request.POST:
            current_semester.start_date = start_date
            current_semester.end_date = end_date
            current_semester.save()
            messages.success(request, "Semester period updated successfully.", extra_tags="semester")
        else:
            Semester.objects.all().delete()  # make sure only one exists
            current_semester = Semester.objects.create(start_date=start_date, end_date=end_date)
            messages.success(request, "Semester period saved successfully.", extra_tags="semester")

        return redirect("class_management")

    # this stays at the bottom so the page renders when not POST
    return render(request, "class_management.html", {"current_semester": current_semester,"today": today })

# API views for mobile app integration
class AccountViewSet(viewsets.ModelViewSet):
    queryset = Account.objects.all()
    serializer_class = AccountSerializer
    
    def get_permissions(self):
        """Require authentication for write operations"""
        if self.action in ['list', 'retrieve']:
            return [AllowAny()]
        return [IsAuthenticated()]
    
    def create(self, request, *args, **kwargs):
        """Override create to add debugging"""
        print("=== DEBUG: Incoming account data ===")
        print("Request data:", request.data)
        print("Request headers:", dict(request.headers))
        
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            print("=== DEBUG: Validation errors ===")
            print("Serializer errors:", serializer.errors)
            return Response(serializer.errors, status=400)
        
        return super().create(request, *args, **kwargs) 
    
    def perform_create(self, serializer):
        """Add audit trail and notification for account creation"""
        account = serializer.save()
        
        # Create notification for new account upload
        AccountUploadNotification.objects.create(
            account_name=f"{account.first_name} {account.last_name}"
        )
        
        # Log who created this account
        if self.request.user.username == 'mobile_system':
            print(f"Account {account.user_id} created via mobile upload")
            print(f"Notification created for new account: {account.first_name} {account.last_name}")
        else:
            print(f"Account {account.user_id} created by user {self.request.user.username}")
        
    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def mobile_sync(self, request):
        """Sync accounts from mobile to web"""
        serializer = MobileAccountSerializer(data=request.data, many=True)
        if serializer.is_valid():
            return Response({'status': 'success'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Web app to mobile app account overwrite/syncing
@csrf_exempt
@require_http_methods(["GET"])
def mobile_account_sync(request):
    """API endpoint for mobile apps to fetch all accounts"""
    try:
        # Get all accounts from Django database
        accounts = Account.objects.all()
        
        # Convert to list and format for mobile consumption
        accounts_list = []
        for account in accounts:
            accounts_list.append({
                'user_id': account.user_id,
                'email': account.email,
                'first_name': account.first_name,
                'last_name': account.last_name,
                'role': account.role,
                'password': None,  # Don't send passwords
                'sex': account.sex,
                'status': account.status,
                'course_section': account.course_section.id if account.course_section else None,
                'fingerprint_template': account.fingerprint_template
            })
        
        return JsonResponse(accounts_list, safe=False)
        
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)
        
@csrf_exempt
@require_http_methods(["POST"])
def trigger_mobile_sync(request):
    """Trigger sync to mobile apps"""
    try:
        print("Mobile sync triggered from web admin")
        
        # Get counts of data available for sync
        account_count = Account.objects.count()
        schedule_count = ClassSchedule.objects.count()
        
        return JsonResponse({
            'status': 'success',
            'message': 'Mobile sync triggered successfully',
            'data': {
                'accounts_available': account_count,
                'schedules_available': schedule_count
            }
        })
        
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

class ClassScheduleViewSet(viewsets.ModelViewSet):
    queryset = ClassSchedule.objects.all()
    serializer_class = MobileClassScheduleSerializer
    
    def get_permissions(self):
        """Allow read without auth, require auth for write operations"""
        if self.action in ['list', 'retrieve', 'today_schedules']:
            return [AllowAny()]
        return [IsAuthenticated()]

    @action(detail=False, methods=['get'])
    def today_schedules(self, request):
        """Get today's schedules for mobile"""
        today = timezone.now().date()
        schedules = ClassSchedule.objects.all()
        # Make sure this line uses MobileClassScheduleSerializer
        serializer = MobileClassScheduleSerializer(schedules, many=True)
        return Response(serializer.data)

class AttendanceRecordViewSet(viewsets.ModelViewSet):
    queryset = AttendanceRecord.objects.all()
    serializer_class = AttendanceRecordSerializer
    
    def get_permissions(self):
        """Allow read without auth, require auth for write operations"""
        if self.action in ['list', 'retrieve', 'download_for_mobile']:
            return [AllowAny()]
        return [IsAuthenticated()]

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def mobile_upload(self, request):
        """Upload attendance records from mobile"""
        # Explicitly use MobileAttendanceSerializer (which has the user_id lookup logic)
        serializer = MobileAttendanceSerializer(data=request.data, many=True)
        if serializer.is_valid():
            created_records = serializer.save()
            return Response({
                'status': 'success', 
                'count': len(created_records),
                'message': f'Successfully uploaded {len(created_records)} attendance records'
            })
        else:
            print("Validation errors:", serializer.errors)  # Debug print
            return Response({
                'status': 'error',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'])
    def download_for_mobile(self, request):
        """Download attendance records to mobile"""
        date_param = request.query_params.get('date')
        if date_param:
            try:
                filter_date = datetime.strptime(date_param, '%Y-%m-%d').date()
                records = AttendanceRecord.objects.filter(date=filter_date)
            except ValueError:
                return Response({'error': 'Invalid date format'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            records = AttendanceRecord.objects.all()
        
        serializer = MobileAttendanceSerializer(records, many=True)
        return Response(serializer.data)

@api_view(['POST'])
@permission_classes([AllowAny])
def mobile_login(request):
    """Login endpoint for mobile app"""
    username = request.data.get('username')
    password = request.data.get('password')
    
    if username and password:
        user = authenticate(username=username, password=password)
        if user:
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'token': token.key,
                'user_id': user.id,
                'username': user.username
            })
    
    return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

# For docx file generation
@instructor_or_admin_required
def generate_attendance_pdf_view(request, class_id):
    """Generate PDF attendance form matching DOCX template"""
    try:
        class_schedule = ClassSchedule.objects.get(id=class_id)
        date_range = request.GET.get('date_range')
        
        # Create PDF buffer - PORTRAIT mode to match DOCX
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer, 
            pagesize=letter,  # Portrait like DOCX
            rightMargin=0.5*inch, 
            leftMargin=0.5*inch,
            topMargin=0.5*inch, 
            bottomMargin=0.5*inch
        )
        
        elements = []
        styles = getSampleStyleSheet()
        
        # Header Style
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=12,
            textColor=colors.black,
            spaceAfter=6,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        # University Header
        elements.append(Paragraph("TECHNOLOGICAL UNIVERSITY OF THE PHILIPPINES", title_style))
        elements.append(Paragraph("CAVITE CAMPUS", title_style))
        
        normal_style = ParagraphStyle(
            'Normal',
            fontSize=8,
            alignment=TA_CENTER
        )
        elements.append(Paragraph("Carlos Q. Trinidad Avenue, Salawag, Dasmariñas City, Cavite, Philippines", normal_style))
        elements.append(Paragraph("Telefax: (046) 416-4920 | Email: cavite@tup.edu.ph | Website: www.tup.edu.ph", normal_style))
        elements.append(Spacer(1, 0.2*inch))
        
        # Department and Title
        header_data = [
            ['DEPARTMENT', 'CLASS ATTENDANCE MONITORING FORM', 'Page 1/1']
        ]
        header_table = Table(header_data, colWidths=[1.5*inch, 4*inch, 1*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 0.15*inch))
        
        # Class Details
        class_details_data = [
            ['DETAILS OF CLASS'],
            ['SUBJECT', class_schedule.course_title or class_schedule.course_code, 
             'FACULTY IN-CHARGE', f"{class_schedule.professor.first_name} {class_schedule.professor.last_name}" if class_schedule.professor else "TBA"],
            ['COURSE', class_schedule.course_section.course_name if class_schedule.course_section else "",
             'BLDG. & ROOM NO.', class_schedule.room_assignment or "TBA"],
            ['YEAR & SECTION', class_schedule.course_section.course_section if class_schedule.course_section else "",
             'SCHEDULE', f"{class_schedule.days} {class_schedule.time_in.strftime('%H:%M')}-{class_schedule.time_out.strftime('%H:%M')}"],
        ]
        
        class_details_table = Table(class_details_data, colWidths=[1.2*inch, 2*inch, 1.5*inch, 1.8*inch])
        class_details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('SPAN', (0, 0), (-1, 0)),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (2, 1), (2, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        elements.append(class_details_table)
        elements.append(Spacer(1, 0.2*inch))
        
        # Get attendance data
        if date_range:
            try:
                start_str, end_str = date_range.split('_to_')
                start_date = datetime.strptime(start_str, '%Y-%m-%d').date()
                end_date = datetime.strptime(end_str, '%Y-%m-%d').date()
            except (ValueError, AttributeError):
                start_date = None
                end_date = None
        else:
            start_date = None
            end_date = None
        
        students = Account.objects.filter(
            course_section=class_schedule.course_section,
            role='Student'
        ).order_by('last_name', 'first_name')
        
        if start_date and end_date:
            attendance_dates = AttendanceRecord.objects.filter(
                class_schedule=class_schedule,
                date__range=[start_date, end_date]
            ).values_list('date', flat=True).distinct().order_by('date')[:8]
        else:
            attendance_dates = AttendanceRecord.objects.filter(
                class_schedule=class_schedule
            ).values_list('date', flat=True).distinct().order_by('date')[:8]
        
        dates_list = list(attendance_dates)
        date_headers = [d.strftime('%m/%d') for d in dates_list]
        
        while len(date_headers) < 8:
            date_headers.append('')
        
        # Attendance Table
        attendance_data = []
        attendance_data.append(['No.', 'Name', 'Sex'] + ['Date'] * 8)
        attendance_data.append(['', '', ''] + date_headers)
        
        # Student rows (up to 40)
        for idx, student in enumerate(students[:40], start=1):
            row = [
                str(idx),
                f"{student.last_name}, {student.first_name}",
                student.sex or 'M'
            ]
            
            for date in dates_list:
                try:
                    record = AttendanceRecord.objects.get(
                        class_schedule=class_schedule,
                        student=student,
                        date=date
                    )
                    
                    if record.time_in and record.time_out:
                        time_in_str = record.time_in.strftime('%H:%M')
                        time_out_str = record.time_out.strftime('%H:%M')
                        
                        if time_in_str == '00:00' or time_out_str == '00:00':
                            row.append('Absent')
                        else:
                            row.append(f"{time_in_str}-{time_out_str}")
                    else:
                        row.append(record.status or '')
                        
                except AttendanceRecord.DoesNotExist:
                    row.append('')
            
            while len(row) < 11:
                row.append('')
            
            attendance_data.append(row)
        
        # Fill remaining rows to 40
        for idx in range(len(students) + 1, 41):
            attendance_data.append([str(idx), '', ''] + [''] * 8)
        
        # Create table with proper column widths
        col_widths = [0.3*inch, 1.8*inch, 0.3*inch] + [0.65*inch] * 8
        attendance_table = Table(attendance_data, colWidths=col_widths)
        
        table_style = [
            ('BACKGROUND', (0, 0), (-1, 1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('ALIGN', (1, 2), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 1), 'Helvetica-Bold'),
            ('FONTNAME', (0, 2), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]
        
        attendance_table.setStyle(TableStyle(table_style))
        elements.append(attendance_table)
        
        # Build PDF
        doc.build(elements)
        
        buffer.seek(0)
        response = HttpResponse(buffer.getvalue(), content_type='application/pdf')
        response['Content-Disposition'] = f'inline; filename="Attendance_{class_schedule.course_code}.pdf"'
        
        return response
        
    except ClassSchedule.DoesNotExist:
        return HttpResponse('Class schedule not found', status=404)
    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        import traceback
        traceback.print_exc()
        return HttpResponse(f'Error generating PDF: {str(e)}', status=500)


@api_view(['POST'])
@permission_classes([AllowAny])
def mobile_auth(request):
    """Authentication endpoint for mobile devices"""
    device_id = request.data.get('device_id')
    device_secret = request.data.get('device_secret')
    
    # You can store these in Django settings or environment variables
    VALID_DEVICES = {
        'FINGERPRINT_DEVICE_001': 'Room1_Debug_2025', 
        # Add more devices as needed
    }
    
    if device_id in VALID_DEVICES and VALID_DEVICES[device_id] == device_secret:
        # Create or get a system user for mobile uploads
        user, created = User.objects.get_or_create(
            username='mobile_system',
            defaults={'email': 'mobile@system.local', 'is_active': True}
        )
        
        # Create or get token for this user
        token, created = Token.objects.get_or_create(user=user)
        
        return Response({
            'token': token.key,
            'expires_in': 86400,  # 24 hours
            'device_id': device_id
        })
    
    return Response({'error': 'Invalid device credentials'}, status=401)
@csrf_exempt
@require_http_methods(["PUT", "PATCH", "POST"])
def mobile_update_account(request, user_id):
    """Mobile-specific account update endpoint - allows devices to complete pending accounts"""
    try:
        # Optional: Basic device authentication check
        device_id = request.headers.get('X-Device-ID')
        
        # Get the account
        try:
            account = Account.objects.get(user_id=user_id)
        except Account.DoesNotExist:
            return JsonResponse({'error': 'Account not found'}, status=404)
        
        # Parse update data
        data = json.loads(request.body)
        
        # Update only allowed fields (email, sex, fingerprint, status)
        if 'email' in data and data['email']:
            account.email = data['email']
        if 'sex' in data and data['sex']:
            account.sex = data['sex']
        if 'fingerprint_template' in data:
            account.fingerprint_template = data['fingerprint_template']
        if 'status' in data:
            account.status = data['status']
            
        account.save()
        
        if was_pending and account.status == 'Active':
            AccountUploadNotification.objects.create(
                account_name=f"{account.first_name} {account.last_name}",
                notification_type='update'
            )
            
        # Return updated account
        return JsonResponse({
            'user_id': account.user_id,
            'email': account.email,
            'first_name': account.first_name,
            'last_name': account.last_name,
            'role': account.role,
            'password': None,
            'sex': account.sex,
            'status': account.status,
            'course_section': account.course_section.id if account.course_section else None,
            'fingerprint_template': account.fingerprint_template
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@instructor_or_admin_required
def get_attendance_data_api(request):
    """API endpoint to get attendance data as JSON"""
    schedule_id = request.GET.get('schedule')
    date_range = request.GET.get('date_range')
    
    if not schedule_id:
        return JsonResponse({'error': 'No schedule selected'}, status=400)
    
    try:
        class_schedule = ClassSchedule.objects.get(id=schedule_id)
        
        # Get class details
        class_data = {
            'subject': class_schedule.course_title or class_schedule.course_code,
            'faculty_name': f"{class_schedule.professor.first_name} {class_schedule.professor.last_name}" if class_schedule.professor else "TBA",
            'course': class_schedule.course_section.course_name if class_schedule.course_section else "",
            'room': class_schedule.room_assignment or "TBA",
            'year_section': class_schedule.course_section.course_section if class_schedule.course_section else "",
            'schedule': f"{class_schedule.days} {class_schedule.time_in.strftime('%H:%M')}-{class_schedule.time_out.strftime('%H:%M')}",
        }
        
        # Get date ranges
        attendance_dates = AttendanceRecord.objects.filter(
            class_schedule=class_schedule
        ).values_list('date', flat=True).distinct().order_by('date')
        
        date_ranges = []
        dates_list = list(attendance_dates)
        for i in range(0, len(dates_list), 8):
            chunk = dates_list[i:i+8]
            if chunk:
                start_date = chunk[0]
                end_date = chunk[-1]
                date_ranges.append({
                    'value': f"{start_date.strftime('%Y-%m-%d')}_to_{end_date.strftime('%Y-%m-%d')}",
                    'label': f"{start_date.strftime('%b %d, %Y')} - {end_date.strftime('%b %d, %Y')}"
                })
        
        # Get attendance data if date range is selected
        attendance_table = []
        date_headers = []
        
        if date_range:
            try:
                start_str, end_str = date_range.split('_to_')
                start_date = datetime.strptime(start_str, '%Y-%m-%d').date()
                end_date = datetime.strptime(end_str, '%Y-%m-%d').date()
                
                # Get dates
                dates_in_range = AttendanceRecord.objects.filter(
                    class_schedule=class_schedule,
                    date__range=[start_date, end_date]
                ).values_list('date', flat=True).distinct().order_by('date')
                
                date_headers = [d.strftime('%m/%d') for d in list(dates_in_range)[:8]]
                
                # Get students
                students = Account.objects.filter(
                    course_section=class_schedule.course_section,
                    role='Student'
                ).order_by('last_name', 'first_name')
                
                # Get attendance records
                for student in students:
                    student_data = {
                        'name': f"{student.last_name}, {student.first_name}",
                        'sex': student.sex or '',
                        'dates': []
                    }
                    
                    for date in list(dates_in_range)[:8]:
                        try:
                            record = AttendanceRecord.objects.get(
                                class_schedule=class_schedule,
                                student=student,
                                date=date
                            )
                            student_data['dates'].append({
                                'time_in': record.time_in.strftime('%H:%M') if record.time_in else '',
                                'time_out': record.time_out.strftime('%H:%M') if record.time_out else '',
                                'status': record.status
                            })
                        except AttendanceRecord.DoesNotExist:
                            student_data['dates'].append({
                                'time_in': '',
                                'time_out': '',
                                'status': ''
                            })
                    
                    attendance_table.append(student_data)
                
            except (ValueError, TypeError):
                pass
        
        return JsonResponse({
            'class_data': class_data,
            'date_ranges': date_ranges,
            'date_headers': date_headers,
            'attendance_table': attendance_table,
            'student_count': len(attendance_table)
        })
        
    except ClassSchedule.DoesNotExist:
        return JsonResponse({'error': 'Class schedule not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

# for preview pdf

@instructor_or_admin_required
def generate_attendance_pdf_view(request, class_id):
    """Generate PDF attendance form for preview"""
    try:
        class_schedule = ClassSchedule.objects.get(id=class_id)
        date_range = request.GET.get('date_range')
        
        # Create PDF buffer
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(letter), 
                               rightMargin=0.5*inch, leftMargin=0.5*inch,
                               topMargin=0.5*inch, bottomMargin=0.5*inch)
        
        elements = []
        styles = getSampleStyleSheet()
        
        # Header Style
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=14,
            textColor=colors.black,
            spaceAfter=12,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        # University Header
        elements.append(Paragraph("TECHNOLOGICAL UNIVERSITY OF THE PHILIPPINES", title_style))
        elements.append(Paragraph("CAVITE CAMPUS", title_style))
        elements.append(Paragraph("CLASS ATTENDANCE MONITORING FORM", title_style))
        elements.append(Spacer(1, 0.2*inch))
        
        # Class Details
        class_details_data = [
            ['SUBJECT', class_schedule.course_title or class_schedule.course_code, 
             'FACULTY IN-CHARGE', f"{class_schedule.professor.first_name} {class_schedule.professor.last_name}" if class_schedule.professor else "TBA"],
            ['COURSE', class_schedule.course_section.course_name if class_schedule.course_section else "",
             'BLDG. & ROOM NO.', class_schedule.room_assignment or "Room TBA"],
            ['YEAR & SECTION', class_schedule.course_section.course_section if class_schedule.course_section else "",
             'SCHEDULE', f"{class_schedule.days} {class_schedule.time_in.strftime('%H:%M')}-{class_schedule.time_out.strftime('%H:%M')}"],
        ]
        
        class_details_table = Table(class_details_data, colWidths=[1.2*inch, 2.5*inch, 1.5*inch, 2.5*inch])
        class_details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        elements.append(class_details_table)
        elements.append(Spacer(1, 0.2*inch))
        
        # Get date range
        if date_range:
            try:
                start_str, end_str = date_range.split('_to_')
                start_date = datetime.strptime(start_str, '%Y-%m-%d').date()
                end_date = datetime.strptime(end_str, '%Y-%m-%d').date()
            except (ValueError, AttributeError):
                start_date = None
                end_date = None
        else:
            start_date = None
            end_date = None
        
        # Get students
        students = Account.objects.filter(
            course_section=class_schedule.course_section,
            role='Student'
        ).order_by('last_name', 'first_name')
        
        # Get attendance dates
        if start_date and end_date:
            attendance_dates = AttendanceRecord.objects.filter(
                class_schedule=class_schedule,
                date__range=[start_date, end_date]
            ).values_list('date', flat=True).distinct().order_by('date')[:8]
        else:
            attendance_dates = AttendanceRecord.objects.filter(
                class_schedule=class_schedule
            ).values_list('date', flat=True).distinct().order_by('date')[:8]
        
        dates_list = list(attendance_dates)
        date_headers = [d.strftime('%m/%d') for d in dates_list]
        
        # Pad dates to 8 columns
        while len(date_headers) < 8:
            date_headers.append('')
        
        # Attendance Table
        attendance_data = []
        
        # Header rows
        attendance_data.append(['No.', 'Name', 'Sex'] + ['Date'] * 8)
        attendance_data.append(['', '', ''] + date_headers)
        
        # Student rows
        for idx, student in enumerate(students[:40], start=1):
            row = [
                str(idx),
                f"{student.last_name}, {student.first_name}",
                student.sex or 'M'
            ]
            
            # Get attendance for each date
            for date in dates_list:
                try:
                    record = AttendanceRecord.objects.get(
                        class_schedule=class_schedule,
                        student=student,
                        date=date
                    )
                    
                    if record.time_in and record.time_out:
                        time_in_str = record.time_in.strftime('%H:%M')
                        time_out_str = record.time_out.strftime('%H:%M')
                        
                        if time_in_str == '00:00' or time_out_str == '00:00':
                            row.append('Absent')
                        else:
                            row.append(f"{time_in_str}-{time_out_str}")
                    else:
                        row.append(record.status or '')
                        
                except AttendanceRecord.DoesNotExist:
                    row.append('')
            
            # Pad with empty strings
            while len(row) < 11:
                row.append('')
            
            attendance_data.append(row)
        
        # Fill remaining rows to reach 40
        for idx in range(len(students) + 1, 41):
            attendance_data.append([str(idx), '', ''] + [''] * 8)
        
        # Create table
        col_widths = [0.4*inch, 2.2*inch, 0.4*inch] + [0.9*inch] * 8
        attendance_table = Table(attendance_data, colWidths=col_widths)
        
        # Table styling
        table_style = [
            ('BACKGROUND', (0, 0), (-1, 1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('ALIGN', (1, 2), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 1), 'Helvetica-Bold'),
            ('FONTNAME', (0, 2), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]
        
        attendance_table.setStyle(TableStyle(table_style))
        elements.append(attendance_table)
        
        # Build PDF
        doc.build(elements)
        
        # Return PDF
        buffer.seek(0)
        response = HttpResponse(buffer.getvalue(), content_type='application/pdf')
        response['Content-Disposition'] = f'inline; filename="Attendance_{class_schedule.course_code}.pdf"'
        
        return response
        
    except ClassSchedule.DoesNotExist:
        return HttpResponse('Class schedule not found', status=404)
    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        import traceback
        traceback.print_exc()
        return HttpResponse(f'Error generating PDF: {str(e)}', status=500)
    
# for pdf preview also

@instructor_or_admin_required
def get_attendance_data_api(request):
    """API endpoint to get attendance data as JSON"""
    schedule_id = request.GET.get('schedule')
    date_range = request.GET.get('date_range')
    
    if not schedule_id:
        return JsonResponse({'error': 'No schedule selected'}, status=400)
    
    try:
        class_schedule = ClassSchedule.objects.get(id=schedule_id)
        
        # Get class details
        class_data = {
            'subject': class_schedule.course_title or class_schedule.course_code,
            'faculty_name': f"{class_schedule.professor.first_name} {class_schedule.professor.last_name}" if class_schedule.professor else "TBA",
            'course': class_schedule.course_section.course_name if class_schedule.course_section else "",
            'room': class_schedule.room_assignment or "TBA",
            'year_section': class_schedule.course_section.course_section if class_schedule.course_section else "",
            'schedule': f"{class_schedule.days} {class_schedule.time_in.strftime('%H:%M')}-{class_schedule.time_out.strftime('%H:%M')}",
        }
        
        # Get date ranges
        attendance_dates = AttendanceRecord.objects.filter(
            class_schedule=class_schedule
        ).values_list('date', flat=True).distinct().order_by('date')
        
        date_ranges = []
        dates_list = list(attendance_dates)
        for i in range(0, len(dates_list), 8):
            chunk = dates_list[i:i+8]
            if chunk:
                start_date = chunk[0]
                end_date = chunk[-1]
                date_ranges.append({
                    'value': f"{start_date.strftime('%Y-%m-%d')}_to_{end_date.strftime('%Y-%m-%d')}",
                    'label': f"{start_date.strftime('%b %d, %Y')} - {end_date.strftime('%b %d, %Y')}"
                })
        
        # Get attendance data if date range is selected
        attendance_table = []
        date_headers = []
        
        if date_range:
            try:
                start_str, end_str = date_range.split('_to_')
                start_date = datetime.strptime(start_str, '%Y-%m-%d').date()
                end_date = datetime.strptime(end_str, '%Y-%m-%d').date()
                
                dates_in_range = AttendanceRecord.objects.filter(
                    class_schedule=class_schedule,
                    date__range=[start_date, end_date]
                ).values_list('date', flat=True).distinct().order_by('date')
                
                date_headers = [d.strftime('%m/%d') for d in list(dates_in_range)[:8]]
                
                students = Account.objects.filter(
                    course_section=class_schedule.course_section,
                    role='Student'
                ).order_by('last_name', 'first_name')
                
                for student in students:
                    student_data = {
                        'name': f"{student.last_name}, {student.first_name}",
                        'sex': student.sex or '',
                        'dates': []
                    }
                    
                    for date in list(dates_in_range)[:8]:
                        try:
                            record = AttendanceRecord.objects.get(
                                class_schedule=class_schedule,
                                student=student,
                                date=date
                            )
                            student_data['dates'].append({
                                'time_in': record.time_in.strftime('%H:%M') if record.time_in else '',
                                'time_out': record.time_out.strftime('%H:%M') if record.time_out else '',
                                'status': record.status
                            })
                        except AttendanceRecord.DoesNotExist:
                            student_data['dates'].append({'time_in': '', 'time_out': '', 'status': ''})
                    
                    attendance_table.append(student_data)
                
            except (ValueError, TypeError):
                pass
        
        return JsonResponse({
            'class_data': class_data,
            'date_ranges': date_ranges,
            'date_headers': date_headers,
            'attendance_table': attendance_table,
            'student_count': len(attendance_table)
        })
        
    except ClassSchedule.DoesNotExist:
        return JsonResponse({'error': 'Class schedule not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)