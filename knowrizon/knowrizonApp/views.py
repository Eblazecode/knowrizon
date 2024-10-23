import os

from django.db.models.functions import datetime
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.shortcuts import render
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login

from .models import Admin, students, academic_staff, content_managers, researchers

import os
import pandas as pd
from datetime import datetime
from django.conf import settings
from django.shortcuts import render
from django.contrib import messages
from .forms import BulkStudentUploadForm, BulkStaffUploadForm
from .models import students
from .models import students  # Ensure the 'students' model is imported
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.shortcuts import render, get_object_or_404, redirect
from .models import students, academic_staff  # Ensure you have the 'students' model imported

from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.contrib.auth import login as auth_login
from django.contrib import messages
import logging

logger = logging.getLogger(__name__)

import logging

logger = logging.getLogger(__name__)

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login
from django.contrib import messages
import logging

logger = logging.getLogger(__name__)

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login, logout
from django.contrib import messages
import logging

logger = logging.getLogger(__name__)

import logging
import pandas as pd

logger = logging.getLogger(__name__)


# Create your views here.

def index(request):
    return render(request, 'index.html')


def login_decider(request):
    return render(request, 'login_decision.html')


def admin_login(request):
    return render(request, 'admin_login.html')


def admin_dasahboard(request):
    return render(request, 'admin_dashboard.html')


def admin_login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        remember_me = request.POST.get('remember')  # Check if "Remember Me" was selected

        user = authenticate(request, username=email, password=password)

        if user is not None:
            auth_login(request, user)

            # Set session expiry based on "Remember Me"
            if remember_me:
                request.session.set_expiry(1209600)  # 2 weeks in seconds
            else:
                request.session.set_expiry(0)  # Session expires when the browser closes

            messages.success(request, 'Login successful')
            logger.info('Login successful')
            # get admin details for display on the dashboard page and pass it to the template
            admin = Admin.objects.get(admin_email=email)
            admin_name = admin.admin_fname + ' ' + admin.admin_lname
            request.session['admin_name'] = admin_name
            request.session['admin_email'] = admin.admin_email
            request.session['admin_dept'] = admin.admin_dept
            request.session['admin_id'] = admin.admin_id

            return render(request, 'admin_dashboard.html',
                          {'admin_name': admin_name, 'admin_email': admin.admin_email, 'admin_dept': admin.admin_dept})

        else:
            messages.error(request, 'Invalid email or password')
            logger.error('Invalid email or password')
            print('Invalid email or password')

    return render(request, 'admin_login.html')


def admin_logout(request):
    logout(request)
    return redirect('admin_login')


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
    return render(request, 'includes/admin_add_users/add_users.html')


def staff_login(request):
    return render(request, 'staff_login.html')


def content_manager_login(request):
    return render(request, 'content_manager_login.html')


def researcher_login(request):
    return render(request, 'researcher_login.html')


def add_student(request):
    if request.method == 'POST':
        fname = request.POST.get('student_fname', '').strip()
        lname = request.POST.get('student_lname', '').strip()
        email = request.POST.get('student_email', '').strip()
        department = request.POST.get('student_department', '').strip()
        matric_no = request.POST.get('student_mat_no', '').strip()
        gender = request.POST.get('student_gender', '').strip()
        generic_password = 'password'  # Default password for all students

        # Check if all required fields are provided
        if not all([fname, lname, email, department, matric_no, gender]):
            messages.error(request, 'All fields are required')
            logger.error('All fields are required')
            return render(request, 'includes/admin_add_users/add_users.html')

        # Check if email is already in use
        if User.objects.filter(username=email).exists():
            messages.error(request, 'Email already exists')
            logger.error('Email already exists')
            return render(request, 'includes/admin_add_users/add_users.html')

        try:
            # Create a new user
            user = User.objects.create_user(username=email, password=generic_password)

            # Ensure fields are correctly mapped to your model attributes
            student = students.objects.create(
                student_fname=fname,
                student_lname=lname,
                student_email=email,
                student_password=generic_password,  # Encrypt if storing
                student_gender=gender,
                student_dept=department,
                student_matric_no=matric_no
            )

            messages.success(request, 'Student registered successfully')
            logger.info('Student registered successfully')
            return redirect(request, 'includes/admin_add_users/add_users.html')

        except Exception as e:
            # Log any unexpected errors and show a generic error message
            logger.error(f'Error occurred while registering student: {e}')

    # Render the form if not POST or on error
    return render(request, 'includes/admin_add_users/add_users.html')


def bulk_upload_students(request):
    if request.method == 'POST':
        form = BulkStudentUploadForm(request.POST, request.FILES)

        if form.is_valid():
            # Process the valid Excel file
            file = form.cleaned_data['file']

            try:
                # Read the Excel file using pandas
                df = pd.read_excel(file, engine='openpyxl')

                # Create a timestamp for the file storage
                current_date = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

                # Define the file path to save the uploaded file as CSV temporarily
                filename = f'students_bulk_upload_{current_date}.csv'
                file_path = os.path.join(settings.MEDIA_ROOT, 'knowrizonApp/studentrecords_upload', filename)

                # Save the dataframe as a CSV file
                df.to_csv(file_path, index=False)

                # Iterate over each row and save student data into the database
                for _, row in df.iterrows():
                    students.objects.create(
                        student_name=row.get('student_name', ''),
                        student_password="password",
                        student_gender=row.get('student_gender', ''),
                        student_dept=row.get('student_dept', ''),  # Corrected field name
                        student_matric_no=row.get('student_matric_number', '')  # Corrected field name
                    )

                # Display success message after processing
                messages.success(request, 'Students uploaded successfully!')
            except Exception as e:
                # Handle any exception during file reading or database insertion
                messages.error(request, f"An error occurred while processing the file: {str(e)}")
        else:
            messages.error(request, 'Invalid form submission. Please upload a valid Excel file.')

    return render(request, 'includes/admin_add_users/add_users.html', {'form': form})


def upload_students_records(request):
    return render(request, 'includes/admin_add_users/add_students_bulk_upload.html')


def add_academic_staff(request):
    if request.method == 'POST':
        fname = request.POST.get('academic_staff_fname', '').strip()
        lname = request.POST.get('academic_staff_lname', '').strip()
        email = request.POST.get('academic_staff_email', '').strip()
        department = request.POST.get('academic_staff_department', '').strip()
        gender = request.POST.get('academic_staff_gender', '').strip()
        password_generic = 'password'  # Default password for all academic staff
        phone = request.POST.get('academic_staff_phone', '').strip()
        position = request.POST.get('academic_staff_position', '').strip()
        interest = request.POST.get('academic_staff_interest', '').strip()
        staffid = request.POST.get('academic_staff_id', '').strip()
        prefix = request.POST.get('academic_staff_prefix', '').strip()

        if not all([fname, lname, email, department, staffid, interest, phone, position, prefix, gender]):
            messages.error(request, 'All fields are required')
            logger.error('All fields are required')
            return render(request, 'includes/admin_add_users/add_users.html')

        if User.objects.filter(username=email).exists():
            messages.error(request, 'Email already exists')
            logger.error('Email already exists')
            return render(request, 'includes/admin_add_users/add_users.html')
        else:
            user = User.objects.create_user(username=email)
            academic_staff.objects.create(
                academic_staff_fname=fname,
                academic_staff_lname=lname,
                academic_staff_email=email,
                academic_staff_password=password_generic,
                academmic_staff_idenity=staffid,
                academic_staff_interest=interest,
                academic_staff_dept=department,
                academic_staff_position=position,
                academic_staff_phone=phone,
                academic_staff_prefix=prefix,
                academic_staff_gender=gender
            )
            messages.success(request, 'Academic staff registered successfully')
            logger.info('Academic staff registered successfully')
            return redirect(request, 'includes/admin_add_users/add_users.html')

    return render(request, 'includes/admin_add_users/add_users.html')


def upload_staff_records(request):
    return render(request, 'includes/admin_add_users/add_staff_bulk_upload.html')


def process_bulk_staff_upload(request):
    if request.method == 'POST':
        form = BulkStaffUploadForm(request.POST, request.FILES)

        if form.is_valid():
            # Process the valid Excel file
            file = form.cleaned_data['file']

            try:
                # Read the Excel file using pandas
                df = pd.read_excel(file, engine='openpyxl')

                # Create a timestamp for the file storage
                current_date = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

                # Define the file path to save the uploaded file as CSV temporarily
                filename = f'staff_bulk_upload_{current_date}.csv'
                file_path = os.path.join(settings.MEDIA_ROOT, 'knowrizonApp/staffrecords_upload', filename)

                # Save the dataframe as a CSV file
                df.to_csv(file_path, index=False)

                # Iterate over each row and save staff data into the database
                for _, row in df.iterrows():
                    academic_staff.objects.create(
                        academic_staff_prefix=row.get('academic_prefix', ''),
                        academic_staff_identity=row.get('academic_staff_identity', ''),
                        academic_staff_position=row.get('academic_staff_position', ''),
                        academic_staff_dept=row.get('academic_staff_dept', ''),
                        academic_staff_phone=row.get('academic_staff_phone', ''),
                        academic_staff_fname=row.get('academic_staff_fname', ''),
                        academic_staff_lname=row.get('academic_staff_lname', ''),
                        academic_staff_email=row.get('academic_staff_email', ''),
                        academic_staff_password="password",
                    )
                messages.success(request, 'Staff uploaded successfully!')
            except Exception as e:
                # Handle any exception during file reading or database insertion
                messages.error(request, f"An error occurred while processing the file: {str(e)}")
        else:
            messages.error(request, 'Invalid form submission. Please upload a valid Excel file.')

    return render(request, 'includes/admin_add_users/add_users.html', {'form': form})


def add_content_manager(request):
    if request.method == 'POST':
        fname = request.POST.get('content_manager_fname', '').strip()
        lname = request.POST.get('content_manager_lname', '').strip()
        email = request.POST.get('content_manager_email', '').strip()
        prefix = request.POST.get('content_manager_prefix', '').strip()
        department = request.POST.get('content_manager_department', '').strip()
        password_generic = 'password'  # Default password for all content managers
        phone = request.POST.get('content_manager_phone', '').strip()

        if not all([fname, lname, email, department, phone]):
            messages.error(request, 'All fields are required')
            print(fname, lname, email, department, phone)
            logger.error('All fields are required')
            return render(request, 'includes/admin_add_users/add_users.html')

        if User.objects.filter(username=email).exists():
            messages.error(request, 'Email already exists')
            logger.error('Email already exists')
            return render(request, 'includes/admin_add_users/add_users.html')
        else:
            user = User.objects.create_user(username=email, password=password_generic)
            content_managers.objects.create(
                content_manager_fname=fname,
                content_manager_lname=lname,
                content_manager_email=email,
                content_manager_prefix=prefix,
                content_manager_password=password_generic,
                content_manager_dept=department,
                contet_manager_phone=phone
            )
            messages.success(request, 'Content manager registered successfully')
            logger.info('Content manager registered successfully')
            return render(request, 'includes/admin_add_users/add_users.html')

    return render(request, 'includes/admin_add_users/add_content_managers.html')


def add_researcher(request):
    if request.method == 'POST':
        fname = request.POST.get('researcher_fname', '').strip()
        lname = request.POST.get('researcher_lname', '').strip()
        email = request.POST.get('researcher_email', '').strip()
        prefix = request.POST.get('researcher_prefix', '').strip()
        department = request.POST.get('researcher_department', '').strip()
        password_generic = 'password'  # Default password for all content managers
        phone = request.POST.get('researcher_phone', '').strip()
        interest = request.POST.get('researcher_interest', '').strip()
        if not all([fname, lname, email, department, phone, interest]):
            messages.error(request, 'All fields are required')
            logger.error('All fields are required')
            return render(request, 'includes/admin_add_users/add_users.html')

        if User.objects.filter(username=email).exists():
            messages.error(request, 'Email already exists')
            logger.error('Email already exists')
            return render(request, 'includes/admin_add_users/add_users.html')
        else:
            user = User.objects.create_user(username=email, password=password_generic)
            researchers.objects.create(
                researcher_fname=fname,
                researcher_lname=lname,
                researcher_email=email,
                researcher_prefix=prefix,
                researcher_password=password_generic,
                researcher_dept=department,
                researcher_phone=phone,
                researcher_interest=interest
            )
            messages.success(request, 'Researcher registered successfully')
            logger.info('Researcher registered successfully')
            return render(request, 'includes/admin_add_users/add_users.html')

    return render(request, 'includes/admin_add_users/add_researcher.html')


###  MANAGING USERS RECORDS


def manage_students(request):
    all_students = students.objects.all()  # Correctly define and assign the 'students' variable
    return render(request, 'admin_manages_users/admin_manage_students.html', {'students': all_students})


def manage_academic_staff(request):
    all_academic_staff = academic_staff.objects.all()  # Correctly define and assign the 'academic_staff' variable
    return render(request, 'admin_manages_users/admin_manage_staff.html', {'academic_staff': all_academic_staff})


# views.py


from .forms import AcademicStaffForm


# views.py

def admin_manage_staff_update(request, academic_staff_id):
    staff = get_object_or_404(academic_staff, pk=academic_staff_id)
    if request.method == 'POST':
        form = AcademicStaffForm(request.POST, instance=staff)
        if form.is_valid():
            form.save()
            return redirect('manage_staff_users')
    else:
        form = AcademicStaffForm(instance=staff)
    return render(request, 'admin_manages_users/admin_updates_staff_records.html', {'form': form})


def admin_manage_staff_delete(request, academic_staff_id):
    staff = get_object_or_404(academic_staff, pk=academic_staff_id)
    if request.method == 'POST':
        staff.delete()
        return redirect('manage_staff_users')
    return render(request, 'admin_manages_users/admin_deletes_staff_record.html', {'staff': staff})


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


# USERS LOGIN

from django.contrib.auth import login as auth_login  # Use Django's built-in login function
from django.contrib.auth.hashers import check_password


def student_login(request):
    if request.method == 'POST':
        matric_no = request.POST.get('mat_no')
        password = request.POST.get('password')

        student = students.objects.filter(student_matric_no=matric_no).first()  # Fetch the student using matric_no

        if student:
            # Check if the password is correct using check_password
            if check_password(password, student.student_password):

                # Check if it's a generic password and prompt to update
                if student.student_password == 'password':  # Assuming "password" is the generic placeholder
                    messages.warning(request, 'Please update your password')
                    logger.info('Prompting student to update password for matric_no: %s', matric_no)
                    return render(request, 'users/students/student_update_password.html')

                else:
                    # If password matches and is valid, log the user in
                    auth_login(request, student)
                    messages.success(request, 'Login successful')
                    logger.info('Login successful for matric_no: %s', matric_no)
                    return render(request, 'users/students/students_dashboard.html')

            else:
                # If password is incorrect
                messages.error(request, 'Invalid username or password.')
                logger.error('Invalid password for matric_no: %s', matric_no)
        else:
            # If no student is found
            messages.error(request, 'Invalid username or password. Please register with the admin.')
            logger.error('No student found for matric_no: %s', matric_no)

    return render(request, 'users/students/students_login.html')


def User_password_update(request, matric_no):
    if request.method == 'POST':
        # Handle password updates logic
        pass
    return render(request, 'update_password.html')


# USERS DASHBOARD
def student_dashboard(request):
    return render(request, 'users/students/students_dashboard.html')
