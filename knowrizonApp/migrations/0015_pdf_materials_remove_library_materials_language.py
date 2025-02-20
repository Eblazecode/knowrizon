# Generated by Django 4.0.6 on 2024-11-08 03:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('knowrizonApp', '0014_students_last_login'),
    ]

    operations = [
        migrations.CreateModel(
            name='PDF_materials',
            fields=[
                ('pdf_material_id', models.AutoField(primary_key=True, serialize=False)),
                ('pdf_material_title', models.CharField(max_length=50)),
                ('pdf_material_author', models.CharField(max_length=50)),
                ('pdf_material_category', models.CharField(max_length=50)),
                ('pdf_material_year', models.CharField(max_length=50)),
                ('pdf_material_tags', models.CharField(max_length=50)),
                ('pdf_for_department', models.CharField(max_length=50)),
                ('pdf_for_faculty', models.CharField(max_length=50)),
                ('pdf_for_level', models.CharField(max_length=50)),
                ('pdf_material_description', models.CharField(max_length=255)),
                ('pdf_material_file', models.FileField(blank=True, null=True, upload_to='materials/pdf/')),
                ('pdf_material_cover_image', models.ImageField(blank=True, null=True, upload_to='materials/pdf/cover/')),
                ('pdf_material_created_at', models.DateTimeField(auto_now_add=True)),
                ('pdf_material_updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.RemoveField(
            model_name='library_materials',
            name='language',
        ),
    ]
