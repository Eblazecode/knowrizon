from django.db import models


class Admin(models.Model):
    admin_id = models.AutoField(primary_key=True)
    admin_fname = models.CharField(max_length=50)
    admin_lname = models.CharField(max_length=50)
    admin_email = models.EmailField(max_length=50)
    admin_password = models.CharField(max_length=50)
    admin_dept = models.CharField(max_length=50)
    admin_created_at = models.DateTimeField(auto_now_add=True)
    admin_updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.admin_fname


# Create your models here.

# student models
class students(models.Model):
    student_id = models.AutoField(primary_key=True)
    student_matric_no = models.CharField(max_length=50)
    student_fname = models.CharField(max_length=50)
    student_lname = models.CharField(max_length=50)
    student_email = models.EmailField(max_length=50)
    student_password = models.CharField(max_length=50)
    student_gender = models.CharField(max_length=50)  # Corrected field name
    student_dept = models.CharField(max_length=50)
    student_created_at = models.DateTimeField(auto_now_add=True)
    student_updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.student_fname


# content managers models
class content_managers(models.Model):
    content_manager_id = models.AutoField(primary_key=True)
    content_manager_fname = models.CharField(max_length=50)
    content_manager_lname = models.CharField(max_length=50)
    content_manager_email = models.EmailField(max_length=50)
    contet_manager_phone = models.CharField(max_length=50)
    content_manager_prefix = models.CharField(max_length=50)
    content_manager_password = models.CharField(max_length=50)
    content_manager_dept = models.CharField(max_length=50)
    content_manager_created_at = models.DateTimeField(auto_now_add=True)
    content_manager_updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.content_manager_fname


# academic staff models

class academic_staff(models.Model):
    academic_staff_id = models.AutoField(primary_key=True)
    academic_staff_fname = models.CharField(max_length=50)
    academic_staff_lname = models.CharField(max_length=50)
    academic_staff_email = models.EmailField(max_length=50)
    academic_staff_password = models.CharField(max_length=50)
    academic_staff_upload_approval = models.IntegerField(default=0)
    academic_staff_dept = models.CharField(max_length=50)
    academic_staff_position = models.CharField(max_length=50)
    academic_staff_phone = models.CharField(max_length=15, default='')
    academic_staff_prefix = models.CharField(max_length=10, default='')
    academmic_staff_idenity = models.CharField(max_length=50, default='')  # Add this field
    academic_staff_interest = models.CharField(max_length=50, default='')  # Add this field
    research_interest = models.CharField(max_length=50)
    academic_staff_created_at = models.DateTimeField(auto_now_add=True)
    academic_staff_updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.academic_staff_fname



# library materials models
class library_materials(models.Model):
    library_material_id = models.AutoField(primary_key=True)
    library_material_title = models.CharField(max_length=50)
    library_material_author = models.CharField(max_length=50)
    library_material_publisher = models.CharField(max_length=50)
    library_material_year = models.CharField(max_length=50)
    library_material_type = models.CharField(max_length=50)
    description = models.CharField(max_length=255)
    genre = models.CharField(max_length=50)
    publication_date = models.DateField()
    isbn = models.CharField(max_length=13)
    format = models.CharField(max_length=50)
    language = models.CharField(max_length=50)
    file = models.FileField(upload_to='materials/', blank=True, null=True)  # For digital files
    cover_image = models.ImageField(upload_to='materials/covers/', blank=True, null=True)  # Optional cover image
    availability_status = models.CharField(max_length=50)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    tags = models.CharField(max_length=50)
    library_material_created_at = models.DateTimeField(auto_now_add=True)
    library_material_updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.library_material_title
