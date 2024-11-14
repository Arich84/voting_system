from django.db import models
from django.conf import settings

class Program(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name

class Level(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name
    
class Department(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name

class ComparisonData(models.Model):
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    ]

    matriculation_number = models.CharField(max_length=15, blank=True)
    first_name = models.CharField(max_length=15, blank=True)
    middle_name = models.CharField(max_length=15, blank=True, null=True)
    last_name = models.CharField(max_length=15, blank=True)
    phone1 = models.CharField(max_length=15, blank=True, null=True)
    phone2 = models.CharField(max_length=15, blank=True, null=True)
    address = models.CharField(max_length=255, blank=True)  # Increase address length if needed
    email = models.EmailField(max_length=255, blank=True)
    date_of_birth = models.CharField(max_length=15, blank=True, null=True)
    valid = models.BooleanField(default=False)
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    
    # Foreign key relationships
    program = models.ForeignKey(Program, on_delete=models.SET_NULL, null=True, blank=True)
    level = models.ForeignKey(Level, on_delete=models.SET_NULL, null=True, blank=True)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True)

    def is_valid(self):
        return self.valid

    def __str__(self):
        # Only include middle name if it exists
        full_name = f"{self.first_name} {self.middle_name or ''} {self.last_name}".strip()
        return full_name
