from django.core.management.base import BaseCommand
from django.utils import timezone
from PTLT_App.models import AttendanceRecord, AttendanceRecordArchive, ClassSchedule, Account, CourseSection, Semester
from django.db import transaction

class Command(BaseCommand):
    help = 'Archive attendance records and clear semester data after semester end date at 6:00pm'

    def handle(self, *args, **options):
        now = timezone.now()
        
        # Only proceed if now is past semester end date 6:00pm
        semester = Semester.objects.filter(end_date__lte=now.date()).order_by('-end_date').first()
        if not semester:
            self.stdout.write("No semester found that ended.")
            return

        semester_end_datetime = timezone.datetime.combine(semester.end_date, timezone.datetime.min.time()).replace(tzinfo=timezone.utc).replace(hour=18)

        if now < semester_end_datetime:
            self.stdout.write(f"Too early to archive; current time {now}, wait until 6:00 PM {semester.end_date}.")
            return
        
        self.stdout.write(f"Archiving semester data for semester ended on {semester.end_date}")
        
        # Archival and clearing inside a transaction
        with transaction.atomic():
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
            Account.objects.exclude(role='Admin').delete()  # Keep admins
            CourseSection.objects.all().delete()

        self.stdout.write(f"Archived and cleared {total_records} attendance records and related semester data.")
