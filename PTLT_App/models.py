from django.db import models
from django.utils import timezone

class CourseSection(models.Model):
    course_name = models.CharField(max_length=100)
    section_name = models.CharField(max_length=50)
    course_section = models.CharField(max_length=150, unique=True, editable=False)

    def save(self, *args, **kwargs):
        self.course_section = f"{self.course_name} {self.section_name}"
        super().save(*args, **kwargs)

    def __str__(self):
        return self.course_section


class Account(models.Model):
    user_id = models.CharField(max_length=50, unique=True, verbose_name="User ID")
    email = models.EmailField(unique=True, verbose_name="Email Address")
    first_name = models.CharField(max_length=100, verbose_name="First Name")
    last_name = models.CharField(max_length=100, verbose_name="Last Name")
    role = models.CharField(
        max_length=50,
        choices=[('Admin', 'Admin'), ('Instructor', 'Instructor'), ('Student', 'Student')],
        verbose_name="Role"
    )
    password = models.CharField(max_length=255, verbose_name="Password", null=True)
    sex = models.CharField(
        max_length=10,
        choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')],
        verbose_name="Sex"
    )
    status = models.CharField(
        max_length=20,
        choices=[('Active', 'Active'), ('Inactive', 'Inactive'), ('Pending', 'Pending')],
        default='Pending',
        verbose_name="Account Status"
    )

    course_section = models.ForeignKey(
        CourseSection, on_delete=models.SET_NULL, null=True, blank=True, verbose_name="Course & Section"
    )

    # New fields moved over from FingerprintRegistration
    fingerprint_template = models.TextField(null=True, blank=True, verbose_name="Fingerprint Template")
    date_registered = models.DateTimeField(default=timezone.now, verbose_name="Date of Registration")

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.role})"



class ClassSchedule(models.Model):
    professor = models.ForeignKey(
        Account,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        limit_choices_to={'role': 'Instructor'},
        verbose_name="Professor"
    )
    course_title = models.CharField(max_length=255, verbose_name="Course Title", blank=True, null=True)
    course_code = models.CharField(max_length=50, verbose_name="Course Code")

    course_section = models.ForeignKey(
        CourseSection,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name="Course & Section"
    )

    time_in = models.TimeField(verbose_name="Time In")
    time_out = models.TimeField(verbose_name="Time Out")

    days = models.CharField(max_length=50, verbose_name="Day/s")  # E.g. "Mon/Wed/Fri"
    grace_period = models.PositiveIntegerField(verbose_name="Grace Period (minutes)")
    student_count = models.PositiveIntegerField(verbose_name="Student Count")

    remote_device = models.CharField(max_length=100, verbose_name="Remote Device (Serial or Name)")
    room_assignment = models.CharField(max_length=100, verbose_name="Room Assignment")

    def __str__(self):
        return f"{self.course_code} - {self.course_section} ({self.professor.last_name})"

    @property
    def day_list(self):
        day_map = {
            'mon': 'Monday',
            'tue': 'Tuesday',
            'wed': 'Wednesday',
            'thu': 'Thursday',
            'fri': 'Friday',
            'sat': 'Saturday',
            'sun': 'Sunday',
        }
        return [day_map[abbr.strip()[:3].lower()]
                for abbr in self.days.split('/')
                if abbr.strip()[:3].lower() in day_map]



class AttendanceRecord(models.Model):
    date = models.DateField(default=timezone.now, verbose_name="Date")

    class_schedule = models.ForeignKey(ClassSchedule, on_delete=models.CASCADE, verbose_name="Class Schedule")
    professor = models.ForeignKey(
        Account,
        on_delete=models.CASCADE,
        related_name="attendance_as_professor"  # 👈 unique name
    )
    student = models.ForeignKey(
        Account,
        on_delete=models.CASCADE,
        related_name="attendance_as_student"   # 👈 unique name
    )

    course_section = models.ForeignKey(CourseSection, on_delete=models.SET_NULL, null=True, blank=True, verbose_name="Course & Section")

    time_in = models.TimeField(verbose_name="Time In")
    time_out = models.TimeField(verbose_name="Time Out", null=True, blank=True)

    fingerprint_data = models.BinaryField(verbose_name="Fingerprint Data")

    STATUS_CHOICES = [
        ('Present', 'Present'),
        ('Late', 'Late'),
        ('Absent', 'Absent'),
        ('Excused', 'Excused'),
        ('No time-out', 'No time-out'),
    ]
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, verbose_name="Status")

    def __str__(self):
        return f"{self.date} - {self.student.user_id} - {self.status}"
    
class Semester(models.Model):
    start_date = models.DateField()
    end_date = models.DateField()

    def __str__(self):
        return f"{self.start_date} - {self.end_date}"

class AccountUploadNotification(models.Model):
    uploaded_at = models.DateTimeField(auto_now_add=True)
    account_name = models.CharField(max_length=200)
    is_read = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-uploaded_at']