from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('PTLT_App', 'your_last_migration_name_here'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='classschedule',
            name='professor_time_in',
        ),
        migrations.RemoveField(
            model_name='classschedule',
            name='professor_time_out',
        ),
        migrations.AddField(
            model_name='attendancerecord',
            name='professor_time_in',
            field=models.TimeField(verbose_name='Professor Time In', null=True, blank=True),
        ),
        migrations.AddField(
            model_name='attendancerecord',
            name='professor_time_out',
            field=models.TimeField(verbose_name='Professor Time Out', null=True, blank=True),
        ),
    ]
