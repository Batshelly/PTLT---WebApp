from django.db import transaction
from PTLT_App.models import AttendanceRecord, AttendanceRecordArchive, ClassSchedule, Account, CourseSection, Semester

@transaction.atomic
def archive_semester_data(semester):
    # Archive attendance
    attendance_records = AttendanceRecord.objects.all()
    total_records = attendance_records.count()
    for record in attendance_records:
        AttendanceRecordArchive.objects.create(
            date=record.date,
            course_code=record.class_schedule.course_code if record.class_schedule else '',
            course_section_name=record.course_section.course_section if record.course_section else '',
            professor_name=f"{record.professor.first_name} {record.professor.last_name}" if record.professor else '',
            student_user_id=record.student.user_id if record.student else '',
            time_in=record.time_in,
            time_out=record.time_out,
            fingerprint_data=record.fingerprint_data,
            status=record.status,
        )
    AttendanceRecord.objects.all().delete()
    ClassSchedule.objects.all().delete()
    Account.objects.exclude(role='Admin').delete()
    CourseSection.objects.all().delete()
    
    # Mark semester archived
    semester.is_archived = True
    semester.save()
    
    return total_records
