from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('PTLT_App', '0010_classschedule_professor_time_in_and_more'),  # ← Fixed!
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