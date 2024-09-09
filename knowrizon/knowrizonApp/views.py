from django.http import JsonResponse
from django.contrib.auth.models import User
from django.shortcuts import render
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login

from .models import Admin, students, academic_staff, content_managers

from django.http import JsonResponse
from django.contrib.auth.models import User
from .models import students  # Ensure you have the 'students' model imported
import logging

logger = logging.getLogger(__name__)


# Create your views here.

def index(request):
    return render(request, 'admin_login.html')


def admin_dasahboard(request):
    return render(request, 'admin_dashboard.html')


def login(request):
    return render(request, 'admin_login.html')


def admin_login(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()
        user = authenticate(request, username=email, password=password)
        print(user)
        print(email, password)

        if user is not None:
            auth_login(request, user)
            return redirect('admin_dashboard')
        else:
            messages.error(request, 'Invalid email or password')
            print('Invalid email or password')
    return render(request, 'admin_login.html')


def admin_register(request):
    if request.method == 'POST':
        fname = request.POST.get('fname', '')
        lname = request.POST.get('lname', '')
        email = request.POST.get('email', '')
        department = request.POST.get('department', '')
        password = request.POST.get('password', '')
        if User.objects.filter(username=email).exists():
            messages.error(request, 'Email already exists')
        else:
            user = User.objects.create_user(username=email, password=password)
            Admin.objects.create(admin_fname=fname, admin_lname=lname, admin_email=email, admin_password=password,
                                 admin_dept=department)
            messages.success(request, 'Admin registered successfully')

            return redirect('admin_login')
    return render(request, 'admin_register.html')


import logging

logger = logging.getLogger(__name__)


# admin view functions
# add users
def add_user(request):
    return render(request, 'add_users.html')


def add_student(request):
    if request.method == 'POST':
        fname = request.POST.get('student_fname', '').strip()
        lname = request.POST.get('student_lname', '').strip()
        email = request.POST.get('student_email', '').strip()
        department = request.POST.get('student_department', '').strip()
        matric_no = request.POST.get('student_mat_no', '').strip()
        gender = request.POST.get('student_gender', '').strip()
        password = request.POST.get('student_password', '').strip()

        if not all([fname, lname, email, department, matric_no, gender, password]):
            messages.error(request, 'All fields are required')
            logger.error('All fields are required')
            print(fname, lname, email, department, matric_no, gender, password)


        if User.objects.filter(username=email).exists():
            messages.error(request, 'Email already exists')
            logger.error('Email already exists')

        else:
            user = User.objects.create_user(username=email, password=password)
            students.objects.create(
                student_fname=fname,
                student_lname=lname,
                student_email=email,
                student_password=password,  # Ensure this field exists in the model
                student_gender=gender,  # Ensure this field exists in the model
                student_dept=department,
                student_matric_no=matric_no
            )

            messages.success(request, 'Student registered successfully')
            logger.info('Student registered successfully')
            return redirect('admin_dashboard')


# Replace the selected code with the following
    return render(request, 'add_students.html')


def add_academic_staff(request):
    if request.method == 'POST':
        fname = request.POST.get('academic_staff_fname', '').strip()
        lname = request.POST.get('academic_staff_lname', '').strip()
        email = request.POST.get('academic_staff_email', '').strip()
        department = request.POST.get('academic_staff_department', '').strip()
        password = request.POST.get('academic_staff_password', '').strip()
        phone = request.POST.get('academic_staff_phone', '').strip()
        position = request.POST.get('academic_staff_position', '').strip()
        interest = request.POST.get('academic_staff_interest', '').strip()
        staffid = request.POST.get('academic_staff_id', '').strip()
        prefix = request.POST.get('academic_staff_prefix', '').strip()

        if not all([fname, lname, email, department, password, phone, position, prefix]):
            messages.error(request, 'All fields are required')
            logger.error('All fields are required')
            print(fname, lname, email, department, password, phone, position, prefix)

        if User.objects.filter(username=email).exists():
            messages.error(request, 'Email already exists')
            logger.error('Email already exists')
        else:
            user = User.objects.create_user(username=email, password=password)
            academic_staff.objects.create(
                academic_staff_fname=fname,
                academic_staff_lname=lname,
                academic_staff_email=email,
                academic_staff_password=password,
                academmic_staff_idenity=staffid,
                academic_staff_interest=interest,
                academic_staff_dept=department,
                academic_staff_position=position,
                academic_staff_phone=phone,
                academic_staff_prefix=prefix
            )
            messages.success(request, 'Academic staff registered successfully')
            logger.info('Academic staff registered successfully')
            return redirect('admin_dashboard')

    return render(request, 'add_academic_staff.html')


def add_content_manager(request):
    if request.method == 'POST':
        fname = request.POST.get('content_manager_fname', '').strip()
        lname = request.POST.get('content_manager_lname', '').strip()
        email = request.POST.get('content_manager_email', '').strip()
        prefix = request.POST.get('content_manager_prefix', '').strip()
        department = request.POST.get('content_manager_department', '').strip()
        password = request.POST.get('content_manager_password', '').strip()
        phone = request.POST.get('content_manager_phone', '').strip()

        if not all([fname, lname, email, department, password, phone]):
            messages.error(request, 'All fields are required')
            logger.error('All fields are required')
            print(fname, lname, email, department, password, phone)

        if User.objects.filter(username=email).exists():
            messages.error(request, 'Email already exists')
            logger.error('Email already exists')
        else:
            user = User.objects.create_user(username=email, password=password)
            content_managers.objects.create(
                content_manager_fname=fname,
                content_manager_lname=lname,
                content_manager_email=email,
                content_manager_prefix=prefix,
                content_manager_password=password,
                content_manager_dept=department,
                contet_manager_phone=phone
            )
            messages.success(request, 'Content manager registered successfully')
            logger.info('Content manager registered successfully')
            return redirect('admin_dashboard')

    return render(request, 'add_content_managers.html')

def library_materials_category(request):
    return render(request, 'library_material_category.html')


def approve_requests(request):
    if request.method == 'POST':
        # Handle approving requests logic
        pass
    return render(request, 'approve_requests.html')


def manage_user_roles(request):
    if request.method == 'POST':
        # Handle managing user roles logic
        pass
    return render(request, 'manage_user_roles.html')


def handle_password_resets(request):
    if request.method == 'POST':
        # Handle password resets logic
        pass
    return render(request, 'handle_password_resets.html')


def monitor_user_activity(request):
    return render(request, 'monitor_user_activity.html')


def oversee_user_permissions(request):
    return render(request, 'oversee_user_permissions.html')
