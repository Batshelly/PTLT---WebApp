from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('PTLT_App', '0010_alter_attendancerecord_status'),  # ← Your last local migration
    ]

    operations = [
        # REMOVE from ClassSchedule (Railway has these, we're dropping them)
        migrations.RemoveField(
            model_name='classschedule',
            name='professor_time_in',
        ),
        migrations.RemoveField(
            model_name='classschedule',
            name='professor_time_out',
        ),
        
        # ADD to AttendanceRecord
        migrations.AddField(
            model_name='attendancerecord',
            name='time_in',
            field=models.TimeField(verbose_name='Time In', default='00:00'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='attendancerecord',
            name='time_out',
            field=models.TimeField(verbose_name='Time Out', null=True, blank=True),
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
