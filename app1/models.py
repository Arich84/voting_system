# models.py
from django.conf import settings
from django.db import models
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
import random
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from datetime import timedelta
from django.core.mail import send_mail
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager, Group, Permission
from django.core.exceptions import ValidationError



class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        """Create a new regular user with a required matriculation_number."""
        if not email:
            raise ValueError("Email is required.")
        if extra_fields.get("user_type", "user") == "user" and not extra_fields.get("matriculation_number"):
            raise ValueError("Matriculation number is required for regular users.")

        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_admin_user(self, username, email, password=None, **extra_fields):
        """Create a new admin user with optional matriculation_number."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("user_type", 'admin')

        user = self.create_user(username, email, password, **extra_fields)
        user.is_staff = True
        user.is_admin = True
        user.save(using=self._db)
        return user
       
    def create_superuser(self, username, email, password=None, **extra_fields):
        """Create a new superuser with optional matriculation_number."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("user_type", 'superuser')

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        user = self.create_user(username, email, password, **extra_fields)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

        

class CustomUser(AbstractBaseUser, PermissionsMixin):
    USER_TYPE_CHOICES = (
        ('admin', 'Admin'),
        ('superuser', 'Superuser'),
        ('user', 'User'),
    )

    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    ]
    

    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    matriculation_number = models.CharField(max_length=20, unique=True, blank=True, null=True)  # Optional for admin and superuser
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES, default='user')
    failed_login_attempts = models.IntegerField(default=0)
    last_failed_login = models.DateTimeField(null=True, blank=True)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    otp = models.CharField(max_length=6, blank=True, null=True)
    last_otp_sent = models.DateTimeField(blank=True, null=True)
    is_otp_verified = models.BooleanField(default=False)
    last_password_change = models.DateTimeField(null=True, blank=True)
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES, blank=True, null=True)
    is_deleted = models.BooleanField(default=False)  # Indicates if the user is deleted
    profile_image = models.ImageField(upload_to='profile_images/', default='default_profile.png', blank=True)
    failed_attempts = models.IntegerField(default=0)
    failed_attempts = models.IntegerField(default=0)

    cover_image = models.ImageField(upload_to='cover_images/', default='default_cover.jpg', blank=True)  # New cover image field

    objects = CustomUserManager()  # Use the custom user-specific manager

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email", "first_name", "last_name"]

    groups = models.ManyToManyField(
        Group,
        related_name='customuser_set',
        blank=True
    )

    user_permissions = models.ManyToManyField(
        Permission,
        related_name='customuser_permissions_set',
        blank=True
    )

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"


    def __str__(self):
        return self.username

    def clean(self):
        """Ensure matriculation_number is provided for regular users."""
        super().clean()
        if self.user_type == 'user' and not self.matriculation_number:
            raise ValidationError("Matriculation number is required for regular users.")

    def email_user(self, subject, message, from_email=None, **kwargs):
        """
        Send an email to this user.
        """
        if not from_email:
            from_email = settings.DEFAULT_FROM_EMAIL
        send_mail(subject, message, from_email, [self.email], **kwargs)


    def is_account_locked(self):
            # Check if the account is locked and if the lockout period has expired
            if self.account_locked_until and timezone.now() < self.account_locked_until:
                return True
            return False
    
   


    def increment_failed_attempts(self):
        self.failed_attempts += 1
        if self.failed_attempts >= 3:
            self.account_locked_until = timezone.now() + timedelta(minutes=15)
        self.save()



    def reset_failed_attempts(self):
        # Reset failed attempts and unlock the account
        self.failed_attempts = 0
        self.account_locked_until = None
        self.save()


    def generate_otp(self):
        """Generate a 6-digit OTP and set it with an expiry."""
        self.otp = str(random.randint(100000, 999999))
        self.otp_expiry = timezone.now() + timedelta(minutes=5)  # Set expiration time
        self.last_otp_sent = timezone.now()  # Update last OTP sent time
        self.save()  # Save the changes
    
    def calculate_resend_cooldown(request):
        last_request_time = request.session.get('last_otp_request_time')
        if last_request_time:
            last_request_time = datetime.fromisoformat(last_request_time)
            time_passed = (timezone.now() - last_request_time).total_seconds()
            cooldown_remaining = OTP_RESEND_COOLDOWN_SECONDS - time_passed
            return max(0, int(cooldown_remaining))
        return 0
    
    def generate_new_otp():
        import random
        return random.randint(100000, 999999)  # Generate a random 6-digit OTP
    
    def email_user(self, subject, message, from_email=None, **kwargs):
        """
        Sends an email to this user.
        """
        if not from_email:
            from_email = settings.DEFAULT_FROM_EMAIL  # Uses default email
        send_mail(subject, message, from_email, [self.email], **kwargs)
    
    def set_otp(self):
        self.otp = str(random.randint(100000, 999999))  # Generate a 6-digit OTP
        self.otp_expiry = timezone.now() + timezone.timedelta(minutes=5)  # Set expiry for 5 minutes
        self.save()  # Save to the database

        # Send OTP email (customize the email settings as needed)
        send_mail(
            'Your OTP Code',
            f'Your OTP code is {self.otp}. It is valid for 5 minutes.',
            'from@example.com',  # Change to your from email
            [self.email],
            fail_silently=False,
        )


    def send_otp_email(self, subject):
        """Send OTP email to the user."""
        if not self.email:
            return  # Ensure email exists before sending

        # Email content
        message = f"Your OTP for verification is: {self.otp}"
        from_email = settings.DEFAULT_FROM_EMAIL  # Ensure this is set in your settings
        recipient_list = [self.email]

        # Send the email
        send_mail(subject, message, from_email, recipient_list)



        

class Feedback(models.Model):
    RECIPIENT_TYPE_CHOICES = (
        ('user', 'User'),
        ('admin', 'Admin'),
        ('superuser', 'Superuser'),
    )

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)  # The user who submitted the feedback
    message = models.TextField()  # The feedback message
    rating = models.IntegerField(choices=[(i, i) for i in range(1, 6)], blank=True, null=True)  # Rating (1-5)
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp of when feedback was created
    is_resolved = models.BooleanField(default=False)  # Whether the feedback has been resolved
    recipient_type = models.CharField(max_length=10, choices=RECIPIENT_TYPE_CHOICES, default='admin')  # Recipient role
    priority = models.CharField(max_length=10, choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], default='medium')

    def __str__(self):
        return f"Feedback from {self.user} to {self.recipient_type} - Resolved: {self.is_resolved}"

class FeedbackMessage(models.Model):
    feedback = models.ForeignKey(Feedback, related_name='messages', on_delete=models.CASCADE)  # Link to Feedback
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)  # The user or admin who sent the message
    message = models.TextField()  # The message text
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp of when the message was sent
    image = models.ImageField(upload_to='feedback_images/', null=True, blank=True)  # Image for the message

    def __str__(self):
        return f"Message by {self.sender} on {self.created_at}"




class Activity(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    description = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username}: {self.description} at {self.timestamp}"
    


class UserActivity(models.Model):
    user = models.OneToOneField(get_user_model(), on_delete=models.CASCADE)
    last_activity = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Activity for {self.user.username}"

    def is_active(self):
        # Set the threshold for "active" (e.g., 5 minutes)
        return timezone.now() - self.last_activity < timezone.timedelta(minutes=5)


    
class Role(models.Model):
    name = models.CharField(max_length=255)
    permissions = models.ManyToManyField(Permission, blank=True)

    def __str__(self):
        return self.name

# Password Reset Token Model
class PasswordResetToken(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    token = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        """Check if the password reset token is still valid."""
        return timezone.now() - self.created_at < timedelta(minutes=10)


class Captcha(models.Model):
    captcha_text = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    used_count = models.IntegerField(default=0)
    is_expired = models.BooleanField(default=False)
    is_enabled = models.BooleanField(default=True)  # New field to enable/disable
    font_size = models.IntegerField(default=12)  # New field for font size
    width = models.IntegerField(default=200)  # New field for width
    height = models.IntegerField(default=60)  # New field for height
    color = models.CharField(max_length=7, default='#000000')  # New field for color (hex format)

    def __str__(self):
        return f"Captcha: {self.captcha_text} created at {self.created_at}"
    


class ActivityLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.action} at {self.timestamp}"

class RecentActivity(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    activity = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.activity}"



  #Phase timers part
class RegistrationWindow(models.Model):
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()

    def is_active(self):
        """Check if the registration window is currently active."""
        return self.start_time <= timezone.now() <= self.end_time


class PreparationWindow(models.Model):
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()

    def is_active(self):
        """Check if the preparation window is currently active."""
        return self.start_time <= timezone.now() <= self.end_time


class VotingWindow(models.Model):
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()

    def is_active(self):
        """Check if the voting window is currently active."""
        return self.start_time <= timezone.now() <= self.end_time

#End



# Slide Model
class Slide(models.Model):
    title = models.CharField(max_length=100, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    image = models.ImageField(upload_to='slides/')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title or "Slide"
    

    

# Profile Model
class Profile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    bio = models.TextField(blank=True, null=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)

    def __str__(self):
        return self.user.username


class Position(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name

class CandidateApplication(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    position = models.ForeignKey(Position, on_delete=models.CASCADE)  # Link to Position model
    manifesto = models.TextField()
    image = models.ImageField(upload_to='candidate_images/', null=True, blank=True)
    status = models.CharField(
        max_length=10, 
        choices=[('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected')], 
        default='pending'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    total_votes = models.PositiveIntegerField(default=0)  # Add this field to track votes

    class Meta:
        unique_together = ('user', 'status')

    def __str__(self):
        return f"{self.user.username} - {self.position.name} ({self.status})"





class Vote(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    candidate = models.ForeignKey(CandidateApplication, on_delete=models.CASCADE)
    voted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'candidate')

    def __str__(self):
        return f"{self.user.username} voted for {self.candidate.user.username} in {self.candidate.position.name}"


from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class PastElection(models.Model):
    position = models.CharField(max_length=255)
    winner = models.CharField(max_length=255)
    date = models.DateField()

class CurrentVote(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    candidate = models.ForeignKey(CandidateApplication, on_delete=models.CASCADE)
    date_voted = models.DateTimeField(auto_now_add=True)

#notification /message

User = get_user_model()

class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=50)  # e.g., "New Message", "Vote Received"
    message = models.TextField()  # The message content for the notification
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)  # Track if the notification has been read
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.notification_type} - {self.created_at}"

    class Meta:
        ordering = ['-created_at']

        

from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()

from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model

User = get_user_model()

class Message(models.Model):
    sender = models.ForeignKey(User, related_name='sent_messages', on_delete=models.CASCADE)
    recipient = models.ForeignKey(User, related_name='received_messages', on_delete=models.CASCADE)
    content = models.TextField(blank=True)  # Optional to allow image-only messages
    image = models.ImageField(upload_to='message_images/', blank=True, null=True)
    timestamp = models.DateTimeField(default=timezone.now)
    read = models.BooleanField(default=False)

    def __str__(self):
        return f"Message from {self.sender} to {self.recipient}"


# Admin Log Model
class AdminLog(models.Model):
    admin_user = models.ForeignKey(User, on_delete=models.CASCADE)  # Link to the admin user
    action = models.TextField()  # Description of the action performed
    timestamp = models.DateTimeField(auto_now_add=True)  # Timestamp of the action

    def __str__(self):
        return f"{self.admin_user.username} - {self.action} at {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"


class Announcement(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title
    
   

class RecentActivity(models.Model):
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.action} at {self.timestamp}"


class AuditLog(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.action} on {self.timestamp}"
