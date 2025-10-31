# serializers.py
from rest_framework import serializers
from .models import Account, ClassSchedule, AttendanceRecord, CourseSection

class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = '__all__'
        extra_kwargs = {
            'password': {'write_only': True}  # Don't return password in responses
        }

class ClassScheduleSerializer(serializers.ModelSerializer):
    class Meta:
        model = ClassSchedule
        fields = '__all__'

class AttendanceRecordSerializer(serializers.ModelSerializer):
    student_name = serializers.CharField(source='student.get_full_name', read_only=True)
    course_title = serializers.CharField(source='class_schedule.course_title', read_only=True)
    
    class Meta:
        model = AttendanceRecord
        fields = '__all__'


# Simplified serializers for mobile sync
class MobileAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ['user_id', 'email', 'first_name', 'last_name', 'role', 'sex', 'status']
class MobileClassScheduleSerializer(serializers.ModelSerializer):
    professor_user_id = serializers.SerializerMethodField()
    course_section_id = serializers.SerializerMethodField()  # ← ADD THIS
    course_section_label = serializers.SerializerMethodField()  # ← ADD THIS
    
    class Meta:
        model = ClassSchedule
        fields = [
            'id', 
            'course_title', 
            'course_code', 
            'course_section_id',  # ← CHANGED: Use explicit ID field
            'course_section_label',  # ← ADD: Use explicit label field
            'time_in', 
            'time_out', 
            'days', 
            'grace_period', 
            'student_count', 
            'remote_device', 
            'room_assignment', 
            'professor_user_id'
        ]
    
    def get_professor_user_id(self, obj):
        """Return the professor's user_id string, not the FK id"""
        if obj.professor:
            return obj.professor.user_id  # Returns "220135211", not 5
        return None
    
    def get_course_section_id(self, obj):
        """Return the CourseSection primary key ID (numeric)"""
        if obj.course_section:
            return obj.course_section.id  # Returns 8
        return None
    
    def get_course_section_label(self, obj):
        """Return the CourseSection display label from CourseSection table"""
        if obj.course_section:
            return obj.course_section.course_section  # Returns "BET-COET 4A"
        return None

class MobileAttendanceSerializer(serializers.ModelSerializer):
    # Override these fields to accept user_id strings instead of primary keys
    student = serializers.CharField()
    professor = serializers.CharField()
    
    class Meta:
        model = AttendanceRecord
        fields = ['id', 'date', 'class_schedule', 'professor', 'student', 'course_section', 'time_in', 'time_out', 'fingerprint_data', 'status']
    
    def create(self, validated_data):
        # Extract user_id strings
        student_user_id = validated_data.pop('student')
        professor_user_id = validated_data.pop('professor')
        
        try:
            # Look up actual Account objects by user_id
            student = Account.objects.get(user_id=student_user_id)
            professor = Account.objects.get(user_id=professor_user_id)
        except Account.DoesNotExist as e:
            raise serializers.ValidationError({
                'error': f'Account not found with user_id: {e}'
            })
        
        # Create attendance record with actual Account objects
        attendance = AttendanceRecord.objects.create(
            student=student,
            professor=professor,
            **validated_data
        )
        return attendance
    
    def to_representation(self, instance):
        # When returning data, convert back to user_id strings
        representation = super().to_representation(instance)
        representation['student'] = instance.student.user_id
        representation['professor'] = instance.professor.user_id
        return representation
    
class CourseSectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CourseSection
        fields = ['id', 'course_name', 'section_name', 'course_section']

