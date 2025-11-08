from django.core.management.base import BaseCommand
from PTLT_App.models import AttendanceRecord

class Command(BaseCommand):
    help = 'Delete all attendance records'

    def handle(self, *args, **options):
        count = AttendanceRecord.objects.all().count()
        self.stdout.write(f'Found {count} attendance records')
        
        AttendanceRecord.objects.all().delete()
        
        self.stdout.write(self.style.SUCCESS(f'✅ Deleted {count} attendance records!'))
