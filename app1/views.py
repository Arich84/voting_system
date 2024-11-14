from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.conf import settings
from django.contrib.auth.models import User
from django.utils import timezone
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from django.contrib.auth import get_user_model, login, logout
from django.contrib.auth.hashers import make_password
from datetime import timedelta
import random
from datetime import timedelta

import json
from django.http import JsonResponse
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.core.exceptions import ObjectDoesNotExist
from .models import CustomUser
from .models import RegistrationWindow

from django.utils.safestring import mark_safe
import os
import datetime
import random
import string  
from .models import Slide, RegistrationWindow, VotingWindow
from django.utils import timezone
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout

from django.core.mail import send_mail
from django.contrib.auth.models import User
import random
from django.contrib.sessions.models import Session
from django.contrib.auth import update_session_auth_hash
from .models import Slide
from django.shortcuts import render, redirect, get_object_or_404

from django.http import JsonResponse
from .models import VotingWindow, RegistrationWindow
from django.shortcuts import render
from django.utils import timezone
from django.http import JsonResponse
from .models import RegistrationWindow, VotingWindow, PreparationWindow,Slide
from django.utils import timezone

import base64
import random
import string
from django.contrib import messages
from django.shortcuts import redirect, render
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from .models import  CustomUser, RegistrationWindow
from comparison.models import ComparisonData, Level, Program,Department
from .captcha import generate_captcha_text, create_captcha_image 
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required

from django.shortcuts import render, redirect
from django.contrib.admin.views.decorators import staff_member_required

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import CustomUser, CandidateApplication
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import CustomUser

from django.contrib.auth import authenticate, login
from django.utils import timezone
from django.contrib.auth import get_user_model
from datetime import timedelta

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import CustomUser,CandidateApplication
from django.contrib.auth.decorators import login_required, user_passes_test
from .models import Position, CandidateApplication  # Adjust this based on your project structure

# views.py
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.db.models import Count
import csv
from .models import CustomUser,Feedback, AdminLog # Ensure to import Vote and ComparisonData if used
from django.db.models import Count
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import CustomUser, Feedback, AdminLog

# views.py
from django.shortcuts import redirect, render
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
import random
import base64
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from .models import CustomUser  # Ensure you have your CustomUser model imported
from .captcha import generate_captcha_text, create_captcha_image  # Adjust based on your captcha methods
from django.shortcuts import render, redirect, get_object_or_404
from .models import Feedback
from django.contrib import messages

from django.shortcuts import render, redirect

from .models import Profile

from .models import CandidateApplication, Position
from django.shortcuts import render, redirect, get_object_or_404

from django.shortcuts import render
from django.contrib.auth import get_user_model

from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import CandidateApplication
from .models import CandidateApplication
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import CandidateApplication
from django.db.models import Q
from django.shortcuts import render
from .models import VotingWindow
from django.utils import timezone
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.db.models import Count

from django.shortcuts import render, redirect
from django.utils import timezone
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from .models import CustomUser,  RegistrationWindow
import random
from datetime import timedelta
import base64


from django.shortcuts import render, redirect
from django.contrib import messages
from .models import CustomUser
from django.utils import timezone
from datetime import timedelta
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import CustomUser
import re  # Regular expressions for password validation

# views.py
from django.utils import timezone
from django.shortcuts import redirect, render
from django.contrib import messages
from .models import CustomUser
import random
from .captcha import generate_captcha_text, create_captcha_image  # Assuming CAPTCHA utilities are imported
from .models import CustomUser


from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.shortcuts import render, redirect
from .models import CustomUser

from django.shortcuts import render, redirect
from django.utils import timezone
from django.contrib import messages
from django.http import JsonResponse
from datetime import timedelta, datetime
from .models import CustomUser
from django.views.decorators.csrf import csrf_exempt


from django.utils import timezone
from django.http import JsonResponse
from django.shortcuts import render
from datetime import datetime, timedelta
import pytz
from django.urls import reverse
from django.utils import timezone
from datetime import datetime
import pytz

from django.views.decorators.csrf import csrf_exempt

from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from .models import CustomUser
import random


from django.shortcuts import render, redirect, get_object_or_404
from .models import Notification, CandidateApplication, Feedback
from django.contrib import messages
from django.core.exceptions import ObjectDoesNotExist
from django.db import DatabaseError
from django.utils import timezone


from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.contrib import messages
from django.shortcuts import render, get_object_or_404, redirect
from .models import Notification
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from .models import Announcement

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.utils import timezone


from django.shortcuts import render, redirect, get_object_or_404

from django.contrib import messages

from .models import CandidateApplication


#compare database
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages


from django.shortcuts import render, redirect
from django.http import JsonResponse
from .models import VotingWindow, Slide
from django.contrib.auth.decorators import login_required


from django.utils import timezone
from django.shortcuts import render, redirect
from django.contrib.admin.views.decorators import staff_member_required
from .models import RegistrationWindow, PreparationWindow, VotingWindow

from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from django.contrib.admin.views.decorators import staff_member_required
from .models import Slide

from django.shortcuts import render, redirect, get_object_or_404
from .models import CustomUser

from django.contrib.admin.views.decorators import staff_member_required

from django.contrib.auth.decorators import user_passes_test


from django.shortcuts import render
from app1.models import CustomUser  # Replace with your actual user model

from django.contrib.auth.models import User, Group
from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import render, redirect
from django.urls import reverse

# Helper to check if user is admin
def is_admin(user):
    return user.is_staff

REGISTRATION_LIMIT = timedelta(minutes=30)

def check_registration_time(user):
    current_time = timezone.now()
    time_diff = current_time - user.registration_time
    return time_diff <= REGISTRATION_LIMIT

from .models import CandidateApplication
from django.shortcuts import render
from .models import CandidateApplication
from django.shortcuts import render
from .models import CandidateApplication

def candidates_view(request):
    # Fetch all approved candidates and optimize position fetching
    candidates = CandidateApplication.objects.filter(status='approved').select_related('position')
    return render(request, 'candidates.html', {'candidates': candidates})

#hmoe
def home(request):
     # Redirect based on user roles first
        # Initialize unread messages count
    unread_messages = 0
    if request.user.is_authenticated:
        unread_messages = Notification.objects.filter(
            user=request.user, is_read=False, notification_type="New Message"
        ).count()
    
    
    announcements = Announcement.objects.all().order_by('-created_at')
     
    # Get the active registration, preparation, and voting windows
     # Get candidates with their total vote count
    candidates = CandidateApplication.objects.filter(status='approved').select_related('position')

    registration_window = RegistrationWindow.objects.first()
    preparation_window = PreparationWindow.objects.first()
    voting_window = VotingWindow.objects.first()
    
    # Query the active slides
    active_slides = Slide.objects.filter(is_active=True)

    # Initialize variables for tracking
    registration_active, preparation_active, voting_active = False, False, False
    registration_remaining, preparation_remaining, voting_remaining = None, None, None

    # Handle registration window logic
    if registration_window and registration_window.is_active():
        registration_active = True
        registration_remaining = (registration_window.end_time - timezone.now()).total_seconds()

    # Handle preparation window logic
    elif preparation_window and preparation_window.is_active():
        preparation_active = True
        preparation_remaining = (preparation_window.end_time - timezone.now()).total_seconds()

    # Handle voting window logic
    elif voting_window and voting_window.is_active():
        voting_active = True

    # Live voting results
    
    candidates = CandidateApplication.objects.all()

    context = {
        'registration_active': registration_active,
        'preparation_active': preparation_active,
        'voting_active': voting_active,
        'registration_remaining': registration_remaining,
        'preparation_remaining': preparation_remaining,
        'candidates': candidates,
        'announcements': announcements,
        'slides': active_slides,
        'unread_messages': unread_messages,
    }

    return render(request, 'home.html', context)


#Election phase
@staff_member_required
def custom_admin_view(request):
    # Get current time
    now = timezone.now()

    # Fetch or create windows
    registration_window, _ = RegistrationWindow.objects.get_or_create(
        id=1, defaults={'start_time': now, 'end_time': now}
    )
    preparation_window, _ = PreparationWindow.objects.get_or_create(
        id=1, defaults={'start_time': now, 'end_time': now}
    )
    voting_window, _ = VotingWindow.objects.get_or_create(
        id=1, defaults={'start_time': now, 'end_time': now}
    )

    # Load recent activities from session or initialize them
    registration_activity = request.session.get('registration_activity', [])
    preparation_activity = request.session.get('preparation_activity', [])
    voting_activity = request.session.get('voting_activity', [])

    # Handle form submissions for updates
    if request.method == 'POST':
        if 'update_registration' in request.POST:
            registration_window.start_time = request.POST.get('registration_start', now)
            registration_window.end_time = request.POST.get('registration_end', now)
            registration_window.save()
            registration_activity.append(
                f"{timezone.now()}: Updated Registration Window to {registration_window.start_time} - {registration_window.end_time}"
            )
        elif 'update_preparation' in request.POST:
            preparation_window.start_time = request.POST.get('preparation_start', now)
            preparation_window.end_time = request.POST.get('preparation_end', now)
            preparation_window.save()
            preparation_activity.append(
                f"{timezone.now()}: Updated Preparation Window to {preparation_window.start_time} - {preparation_window.end_time}"
            )
        elif 'update_voting' in request.POST:
            voting_window.start_time = request.POST.get('voting_start', now)
            voting_window.end_time = request.POST.get('voting_end', now)
            voting_window.save()
            voting_activity.append(
                f"{timezone.now()}: Updated Voting Window to {voting_window.start_time} - {voting_window.end_time}"
            )
        # Save recent activities to session
        request.session['registration_activity'] = registration_activity
        request.session['preparation_activity'] = preparation_activity
        request.session['voting_activity'] = voting_activity
        return redirect('custom_admin_view')

    # Handle deletions
    if request.GET.get('delete') == 'registration':
        registration_window.delete()
        registration_activity.append(f"{timezone.now()}: Deleted Registration Window")
    elif request.GET.get('delete') == 'preparation':
        preparation_window.delete()
        preparation_activity.append(f"{timezone.now()}: Deleted Preparation Window")
    elif request.GET.get('delete') == 'voting':
        voting_window.delete()
        voting_activity.append(f"{timezone.now()}: Deleted Voting Window")

    # Handle deletion of specific activities
    if 'clear' in request.GET:
        if request.GET['clear'] == 'registration':
            registration_activity.clear()
        elif request.GET['clear'] == 'preparation':
            preparation_activity.clear()
        elif request.GET['clear'] == 'voting':
            voting_activity.clear()

    # Update session with recent activities
    request.session['registration_activity'] = registration_activity
    request.session['preparation_activity'] = preparation_activity
    request.session['voting_activity'] = voting_activity

    # Context for template
    context = {
        'registration_window': registration_window,
        'preparation_window': preparation_window,
        'voting_window': voting_window,
        'registration_activity': registration_activity,
        'preparation_activity': preparation_activity,
        'voting_activity': voting_activity,
    }
    return render(request, 'Election-phase.html', context)


from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Captcha, RecentActivity  # Import your models
import random
import string  # For generating random strings

def generate_random_captcha(length=6):
    
    """Generate a random string of letters and digits."""
   
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def captcha_management(request):
    if request.method == 'POST':
        # Generate a new CAPTCHA
        if 'generate_new' in request.POST:
            new_captcha_text = generate_random_captcha()
            Captcha.objects.create(captcha_text=new_captcha_text, used_count=0)
            messages.success(request, 'New CAPTCHA generated successfully!')
            RecentActivity.objects.create(action=f'Generated new CAPTCHA: {new_captcha_text}')
            return redirect('captcha_management')  # Adjust to your URL pattern

        # Delete a specific CAPTCHA
        elif 'delete_captcha' in request.POST:
            captcha_id = request.POST.get('captcha_id')
            Captcha.objects.filter(id=captcha_id).delete()
            messages.success(request, 'CAPTCHA deleted successfully!')
            RecentActivity.objects.create(action=f'Deleted CAPTCHA with ID: {captcha_id}')
            return redirect('captcha_management')  # Adjust to your URL pattern

        # Delete all CAPTCHAs
        elif 'delete_all' in request.POST:
            Captcha.objects.all().delete()
            messages.success(request, 'All CAPTCHAs deleted successfully!')
            RecentActivity.objects.create(action='Deleted all CAPTCHAs')
            return redirect('captcha_management')  # Adjust to your URL pattern

        # Test the entered CAPTCHA
        elif 'test_captcha' in request.POST:
            entered_captcha = request.POST.get('captcha_text')
            test_captcha = Captcha.objects.last()  # Get the most recent CAPTCHA for testing
            if test_captcha and test_captcha.captcha_text == entered_captcha:
                messages.success(request, 'CAPTCHA is correct!')
                RecentActivity.objects.create(action='Tested CAPTCHA: Correct')
            else:
                messages.error(request, 'CAPTCHA is incorrect!')
                RecentActivity.objects.create(action='Tested CAPTCHA: Incorrect')
            return redirect('captcha_management')  # Adjust to your URL pattern

        # Delete all recent activities
        elif 'delete_all_activities' in request.POST:
            RecentActivity.objects.all().delete()
            messages.success(request, 'All recent activities deleted successfully!')
            return redirect('captcha_management')  # Adjust to your URL pattern

    # Retrieve all CAPTCHAs and recent activities for display
    captchas = Captcha.objects.all()
    recent_activities = RecentActivity.objects.all()

    # For testing, get the last CAPTCHA text
    test_captcha_text = captchas.last().captcha_text if captchas.exists() else ''

    context = {
        'captchas': captchas,
        'test_captcha_text': test_captcha_text,
        'recent_activity': recent_activities,
    }

    return render(request, 'captcha_management.html', context)  # Adjust to your template name

#Slide
def is_admin(user):
    return user.is_superuser or user.is_staff
@login_required
@user_passes_test(is_admin)
def custom_admin_image(request):
    slides = Slide.objects.all().order_by('-created_at')
    recent_activity = []

    if request.method == 'POST':
        if 'create_slide' in request.POST:
            title = request.POST.get('title')
            description = request.POST.get('description')
            image = request.FILES.get('image')
            is_active = 'is_active' in request.POST
            Slide.objects.create(title=title, description=description, image=image, is_active=is_active)
            recent_activity.append(f"Created Slide: {title}")
        else:
            for slide in slides:
                if f'update_slide_{slide.id}' in request.POST:
                    slide.is_active = f'is_active_{slide.id}' in request.POST
                    slide.save()
                    recent_activity.append(f"Updated Slide: {slide.title}")

        return redirect('custom_admin_image')

    if request.method == 'GET' and 'delete_slide' in request.GET:
        slide_id = request.GET.get('delete_slide')
        slide = get_object_or_404(Slide, id=slide_id)
        slide.delete()
        recent_activity.append(f"Deleted Slide: {slide.title}")
        return redirect('custom_admin_image')

    context = {
        'slides': slides,
        'recent_activity': recent_activity,
    }
    return render(request, 'custom_admin_image.html', context)

def get_remaining_time(end_time):
    """Calculate the remaining time until the registration period ends."""
    now = timezone.now()
    remaining_time = end_time - now
    if remaining_time.total_seconds() < 0:
        return 0, 0, 0, 0  # No time left

    days, seconds = remaining_time.days, remaining_time.seconds
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60

    return days, hours, minutes, seconds

    
def get_remaining_time(end_time):
    """Returns the remaining time in days, hours, minutes, and seconds."""
    remaining = end_time - timezone.now()
    days = remaining.days
    seconds = remaining.seconds
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60
    return days, hours, minutes, seconds

def about(request):
    return render(request, 'about.html')

def rules(request):
    return render(request, 'rules.html')

def candidates(request):
    return render(request, 'candidates.html')


def generate_captcha_text(length=6):
    """Generate a random CAPTCHA text."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

#Superuser
# Define allowed IPs for superuser registration
ALLOWED_IPS = ['127.0.0.1']  # Add your local IP
  # Replace with actual allowed IP addresses

import re  # Regular expression module
from django.contrib.auth.hashers import make_password
from django.contrib import messages
from django.shortcuts import redirect, render
from django.utils import timezone
from datetime import timedelta
from .models import CustomUser  # Adjust import based on your project structure
from .captcha import generate_captcha_text, create_captcha_image  # Adjust imports as necessary

def is_strong_password(password):
    """Check if the password is strong."""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):  # At least one uppercase letter
        return False
    if not re.search(r"[a-z]", password):  # At least one lowercase letter
        return False
    if not re.search(r"[0-9]", password):  # At least one digit
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):  # At least one special character
        return False
    return True

def register_superuser(request):
    # Get the client's IP address
    client_ip = request.META.get('REMOTE_ADDR')

    # Check if the client's IP is in the allowed list
    if client_ip not in ALLOWED_IPS:
        messages.error(request, 'Superuser registration is restricted from your IP address.')
        return redirect('loginme')  # Redirect to login or another appropriate page

    if request.method == 'POST':
        # Capture inputs
        username = request.POST.get('username')
        gender = request.POST.get('gender')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        captcha_response = request.POST.get('captcha_response')

        # Basic validation
        if not all([username,gender, email, password, confirm_password, captcha_response]):
            messages.error(request, 'All fields are required.')
            return redirect('register_superuser')

        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('register_superuser')
        
         # Strong password validation
        if not is_strong_password(password):
            messages.error(request, 'Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one digit, and one special character.')
            return redirect('register_superuser')

        # CAPTCHA validation
        if captcha_response != request.session.get('captcha_text', ''):
            messages.error(request, 'Invalid CAPTCHA. Please try again.')
            return redirect('register_superuser')

        # Check if superuser with the same username and email already exists
        existing_user = CustomUser.objects.filter(username=username, email=email, user_type='superuser').first()
        if existing_user:
            if existing_user.is_active:  # If the account is verified
                messages.info(request, "Superuser account already exists. Please log in.")
                return redirect('login')
            else:  # If the account exists but is not verified, prompt OTP verification
                request.session["user_id"] = existing_user.id
                messages.info(request, "Complete your OTP verification to activate your superuser account.")
                return redirect("verify_otp_view")

        # Check if only the username or email is already in use
        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists for a superuser account.')
            return redirect('register_superuser')

        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists for a superuser account.')
            return redirect('register_superuser')

        # Create an inactive superuser until OTP verification
        user = CustomUser.objects.create_user(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            gender=gender,
            password=make_password(password),  # Hash the password
            is_staff=True,
            is_superuser=True,  # Grant superuser status
            user_type='superuser',  # Set user_type if you have different user types
            is_active=False  # Account is inactive until OTP verification
        )


        otp = str(random.randint(100000, 999999))
        user.otp = otp
        user.otp_expiry = timezone.now() + timezone.timedelta(minutes=5)
        user.save()

        # Use email_user method to send the OTP email
        user.email_user("Verify your Superuser account", f"Your OTP is {otp}")


        
        # Store user ID in session and redirect to OTP verification
        request.session['user_id'] = user.id
        messages.success(request, 'Registration successful! Please check your email for OTP verification.')
        return redirect('verify_otp_view')

    # Generate CAPTCHA for page load
    captcha_text = generate_captcha_text()
    captcha_image = create_captcha_image(captcha_text)

    # Store CAPTCHA text in session for validation
    request.session['captcha_text'] = captcha_text

    # Convert CAPTCHA image to Base64 for template display
    captcha_image_base64 = base64.b64encode(captcha_image.read()).decode('utf-8')
    captcha_image_data = f"data:image/png;base64,{captcha_image_base64}"
    user_type = request.user.user_type if request.user.is_authenticated else None
    return render(request, 'register_superuser.html', {
        'captcha_image': captcha_image_data,  # Assuming captcha image function
        'user_type': user_type,
    })


    
#Admin registration    
import re  # Regular expression module
from django.contrib.auth.hashers import make_password
from django.contrib import messages
from django.shortcuts import redirect, render, get_object_or_404
from django.utils import timezone
from datetime import timedelta
from .models import CustomUser  # Adjust import based on your project structure
from .captcha import generate_captcha_text, create_captcha_image  # Adjust imports as necessary

def is_strong_password(password):
    """Check if the password is strong."""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):  # At least one uppercase letter
        return False
    if not re.search(r"[a-z]", password):  # At least one lowercase letter
        return False
    if not re.search(r"[0-9]", password):  # At least one digit
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):  # At least one special character
        return False
    return True

def register_admin(request):
    if request.method == 'POST':
        # Capture inputs
        username = request.POST.get('username')
        email = request.POST.get('email')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        password = request.POST.get('password')
        gender = request.POST.get('gender')
        confirm_password = request.POST.get('confirm_password')
        captcha_response = request.POST.get('captcha_response')

        # Basic validation
        if not all([username, gender, email, first_name, last_name, password, confirm_password, captcha_response]):
            messages.error(request, 'All fields are required.')
            return redirect('register_admin')

        # CAPTCHA validation
        if captcha_response != request.session.get('captcha_text', ''):
            messages.error(request, 'Invalid CAPTCHA. Please try again.')
            return redirect('register_admin')

        # Password match validation
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('register_admin')

        # Strong password validation
        if not is_strong_password(password):
            messages.error(request, 'Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one digit, and one special character.')
            return redirect('register_admin')

        # Unique username and email checks (including admin)
        existing_user = CustomUser.objects.filter(username=username, email=email, user_type='admin').first()

        if existing_user and existing_user.user_type == 'admin':
            if existing_user.is_active:  # If admin exists and is active (OTP verified)
                messages.success(request, 'You can now log in!')
                return redirect('login')
            else:  # If admin exists but OTP not verified
                request.session["user_id"] = existing_user.id
                messages.info(request, "Your admin account exists but is not verified. Please verify your OTP.")
                existing_user.set_otp()  # Generate a new OTP
                existing_user.send_otp_email("Admin Account Verification")  # Send the OTP email
                request.session['otp_expiry'] = (timezone.now() + timedelta(minutes=5)).isoformat()  # Set expiry
                return redirect("verify_otp_view")

        # Check if only the username or email is already in use
        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists')
            return redirect('register_admin')

        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists ')
            return redirect('register_admin')

        # Create the admin user as inactive until OTP verification
        admin_user = CustomUser.objects.create(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            gender=gender,
            password=make_password(password),  # Hash the password
            is_staff=True,
            is_active=False,
            user_type='admin'  # Ensure user_type is set to 'admin'
        )

        # Set admin permissions
        admin_user.is_superuser = True  # Grant superuser status
        admin_user.save()  # Save the user instance to update the database

        # Generate and store OTP
        admin_user.set_otp()  # Ensure this method generates and sends the OTP

        request.session['user_id'] = admin_user.id  # Store user ID in session for verification
        request.session['otp_expiry'] = (timezone.now() + timedelta(minutes=5)).isoformat()  # Set OTP expiry
        messages.success(request, 'Admin registration successful! Check your email for OTP verification.')
        return redirect('verify_otp_view')

    # Generate CAPTCHA for page load
    captcha_text = generate_captcha_text()
    captcha_image = create_captcha_image(captcha_text)

    # Store CAPTCHA text in session for validation
    request.session['captcha_text'] = captcha_text

    # Convert CAPTCHA image to Base64 for template display
    captcha_image_base64 = base64.b64encode(captcha_image.read()).decode('utf-8')
    captcha_image_data = f"data:image/png;base64,{captcha_image_base64}"

    user_type = request.user.user_type if request.user.is_authenticated else None
    return render(request, 'register-admin.html', {
        'captcha_image': captcha_image_data,  # Assuming captcha image function
        'user_type': user_type,
    })



#registration for regular user
def register(request):
    registration_window = RegistrationWindow.objects.first()  # Assuming only one active window

    if not registration_window or registration_window.end_time <= timezone.now():
        return render(request, 'registration_closed.html')

    days, hours, minutes, seconds = get_remaining_time(registration_window.end_time)

    if request.method == 'POST':
        # Capture and normalize inputs
        username = request.POST.get('username')
        email = request.POST.get('email', '').strip().lower()
        first_name = request.POST.get('first_name', '').strip().lower()
        last_name = request.POST.get('last_name', '').strip().lower()
        gender = request.POST.get('gender')
        matriculation_number = request.POST.get('matriculation_number', '').strip()
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        captcha_response = request.POST.get('captcha_response')

        # Check for empty fields
        if not all([username,gender, email, first_name, last_name, matriculation_number, password, confirm_password, captcha_response]):
            messages.error(request, 'All fields are required.')
            return redirect('register')


        # Validate CAPTCHA
        if captcha_response != request.session.get('captcha_text', ''):
            messages.error(request, 'Invalid CAPTCHA. Please try again.')
            return redirect('register')

        # Verify password match
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('register')

            # Check if user with the same username and email already exists
        existing_user = CustomUser.objects.filter(username=username, email=email,matriculation_number=matriculation_number, user_type='user').first()
        if existing_user:
            if existing_user.is_active:  # If the account is verified
                messages.info(request, "Account already exists. Please log in.")
                return redirect('loginme')
        elif existing_user and not existing_user.is_active:  # If user exists but OTP not verified
            request.session["user_id"] = existing_user.id
            messages.info(request, "Your account exists but is not verified. Please verify your OTP.")
            existing_user.set_otp()  # Generate a new OTP
            existing_user.send_otp_email("Account Verification")  # Send the OTP email
            request.session['otp_expiry'] = (timezone.now() + timedelta(minutes=5)).isoformat()  # Set expiry
            return redirect("verify_otp_view")
        
        
        # Check if only the username or email is already in use
        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists')
            return redirect('register')

        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists ')
            return redirect('register')

        if CustomUser.objects.filter(matriculation_number=matriculation_number).exists():
            messages.error(request, 'Matriculation number already exists.')
            return redirect('register')
        

        # Check if user data exists in ComparisonData
        if not ComparisonData.objects.filter(matriculation_number=matriculation_number, email=email,gender=gender).exists():
            messages.error(request, 'User data not found ')
            return redirect('register')

        # Create user if all validations pass
        user = CustomUser.objects.create(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            gender=gender,
            matriculation_number=matriculation_number,
            password=make_password(password),
            is_staff=False,
            is_active=False,
            user_type='user'  # Ensure user_type is set to 'user'
        )

        # Generate and store OTP
        user.set_otp()  # Ensure this method generates and sends the OTP

        request.session['user_id'] = user.id
        request.session['otp_expiry'] = (timezone.now() + timedelta(minutes=5)).isoformat()
        messages.success(request, 'Registration successful! Check your email for OTP verification.')
        return redirect('verify_otp_view')

    # Generate CAPTCHA for initial page load
    captcha_text = generate_captcha_text()
    captcha_image = create_captcha_image(captcha_text)

    # Store CAPTCHA text in session
    request.session['captcha_text'] = captcha_text

    # Convert CAPTCHA image to Base64 string
    captcha_image_base64 = base64.b64encode(captcha_image.read()).decode('utf-8')
    captcha_image_data = f"data:image/png;base64,{captcha_image_base64}"

    return render(request, 'register.html', {
        'captcha_image': captcha_image_data,
        'days': days,
        'hours': hours,
        'minutes': minutes,
        'seconds': seconds,
    })


#registration closed page
def registration_closed_view(request):
    return render(request, 'registration_closed.html')


#user Dashboard
from django.shortcuts import render
from django.contrib.auth.decorators import login_required

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from .models import CustomUser

@login_required
def user_dashboard(request):
    if request.method == "POST" and request.FILES.get('cover_image'):
        cover_image = request.FILES['cover_image']
        try:
            profile = request.user.profile  # Assuming you have a one-to-one profile relation
        except ObjectDoesNotExist:
            profile = CustomUser.objects.create(user=request.user)
        
        profile.cover_image = cover_image
        profile.save()

        return redirect('user_dashboard')  # Redirect to refresh the page and show the updated cover image

    return render(request, 'user_dashboard.html', {
        'profile': request.user,  # Pass the user object as profile
    })

#profile Section
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from .models import CustomUser
@login_required
def update_cover_image(request):
    if request.method == 'POST' and request.FILES.get('cover_image'):
        cover_image = request.FILES['cover_image']
        request.user.cover_image = cover_image  # Updating the cover image for the logged-in user
        request.user.save()  # Save the changes to the user instance
        return redirect('update_cover_image')  # Redirect after saving

    return render(request, 'update_cover_image.html', {
        'profile': request.user,  # Pass the user object as profile
    })

@login_required
def update_profile_image_page(request):
    if request.method == 'POST' and request.FILES.get('profile_image'):
        # Update profile image
        request.user.profile_image = request.FILES['profile_image']
        request.user.save()

        # Show a success message
        messages.success(request, "Profile image updated successfully!")

        # Redirect based on user type (Superuser, Admin, Regular User)
        if request.user.is_superuser:
            return redirect('superuser_dashboard')  # Redirect to Superuser Dashboard
        elif request.user.is_staff:
            return redirect('admin_dashboard')  # Redirect to Admin Dashboard
        else:
            return redirect('user_dashboard')  # Redirect to Regular User Dashboard

    return render(request, 'update_profile_image.html')

from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.contrib import messages

@login_required
def remove_profile_image(request):
    if request.method == "POST":
        if request.user.profile_image:
            # Delete the profile image
            request.user.profile_image.delete()
            request.user.save()
            messages.success(request, "Profile image removed successfully.")
        else:
            messages.warning(request, "No profile image to remove.")
        
        # Redirect based on user type (Superuser, Admin, Regular User)
        if request.user.is_superuser:
            return redirect('superuser_dashboard')  # Redirect to Superuser Dashboard
        elif request.user.is_staff:
            return redirect('admin_dashboard')  # Redirect to Admin Dashboard
        else:
            return redirect('user_dashboard')  # Redirect to Regular User Dashboard
    
    return redirect('user_dashboard')  # Default redirect if not POST


# Profile View
from django.contrib.auth.decorators import login_required
from django.shortcuts import render

@login_required
def user_profile(request):
    user = request.user

    # Only regular users should have comparison data
    comparison_data = None
    if not (user.is_superuser or user.is_staff):
        # Assuming the matriculation_number is unique and matches an entry in ComparisonData
        comparison_data = ComparisonData.objects.filter(matriculation_number=user.matriculation_number).first()

    # Pass user and comparison_data to the template
    return render(request, 'profile.html', {
        'user': user,
        'comparison_data': comparison_data,
    })

# @login_required
def update_profile(request):
    if request.method == 'POST':
        # Get data from the form
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        bio = request.POST.get('bio')
        profile_picture = request.FILES.get('profile_picture')

        # Update the User model
        user = request.user
        user.first_name = first_name
        user.last_name = last_name
        user.save()

        # Update the UserProfile model
        profile, created = Profile.objects.get_or_create(user=user)
        profile.bio = bio
        if profile_picture:
            profile.profile_picture = profile_picture
        profile.save()

        # Feedback message
        messages.success(request, 'Your profile has been updated.')
        return redirect('profile')  # Redirect to the profile page after updating

    return render(request, 'update_profile.html')

@login_required
def edit_profile(request):
    user = request.user
    
    # Check if the user is a regular user (not superuser or admin)
    if user.is_superuser or user.is_staff:
        # For superusers and admins, allow editing of basic user fields (including gender)
        if request.method == 'POST':
            user.first_name = request.POST.get('first_name')
            user.last_name = request.POST.get('last_name')
            user.email = request.POST.get('email')
            user.gender = request.POST.get('gender')  # Allow editing of gender
            user.save()
            messages.success(request, 'Your profile has been successfully updated!')
            return redirect('edit_profile_page')  # Redirect to the user dashboard after saving
        return render(request, 'edit_profile.html', {'user': user})

    # Regular users can edit their comparison data
    comparison_data = ComparisonData.objects.filter(email=user.email).first()

    if not comparison_data:
        messages.error(request, "No profile data found to edit.")
        return redirect('user_dashboard')  # Redirect back to the profile if no data is found

    # Fetch all available programs, levels, and departments
    programs = Program.objects.all()
    levels = Level.objects.all()
    departments = Department.objects.all()

    if request.method == 'POST':
        # Capture data from the form and update comparison data
        comparison_data.first_name = request.POST.get('first_name')
        comparison_data.middle_name = request.POST.get('middle_name')
        comparison_data.last_name = request.POST.get('last_name')
        comparison_data.matriculation_number = request.POST.get('matriculation_number')
        comparison_data.phone1 = request.POST.get('phone1')
        comparison_data.phone2 = request.POST.get('phone2')
        comparison_data.address = request.POST.get('address')
        comparison_data.email = request.POST.get('email')
        comparison_data.date_of_birth = request.POST.get('date_of_birth')
        comparison_data.gender = request.POST.get('gender')  # Regular users can update gender here
        comparison_data.program_id = request.POST.get('program')  # If you're using a ForeignKey field
        comparison_data.level_id = request.POST.get('level')  # If you're using a ForeignKey field
        comparison_data.department_id = request.POST.get('department')  # If you're using a ForeignKey field
        comparison_data.save()

        # Optionally, update user info (same as before)
        user.first_name = comparison_data.first_name
        user.last_name = comparison_data.last_name
        user.matriculation_number = comparison_data.matriculation_number
        user.email = comparison_data.email
        user.save()

        # Add a success message
        messages.success(request, 'Your profile has been successfully updated!')
        return redirect('user_dashboard')  # Redirect to the user dashboard after saving
    
    # Pre-fill the form with the existing comparison data
    return render(request, 'edit_profile.html', {
        'comparison_data': comparison_data,
        'user': user,
        'programs': programs,
        'levels': levels,
        'departments': departments
    })


#Signals.py
from .models import User, Profile
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import CustomUser, Profile  # Ensure Profile is imported

@receiver(post_save, sender=CustomUser)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)  # Create Profile when a new CustomUser is created
    else:
        # Save the existing profile if it exists
        if hasattr(instance, 'profile'):
            instance.profile.save()

#Dashboard direction 
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import render
from django.contrib.auth import get_user_model
from .models import UserActivity
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required

@login_required
def dashboard_redirect(request):
    """Redirect users to their respective dashboards based on user_type."""
    if request.user.user_type == 'superuser':
        return redirect('superuser_dashboard')
    elif request.user.user_type == 'admin':
        return redirect('admin_dashboard')
    else:  # For regular users
        return redirect('user_dashboard')

@login_required
def user_dashboard(request):
    if request.user.user_type != 'user':
        return redirect('home')
    if request.method == "POST" and request.FILES.get('cover_image'):
        cover_image = request.FILES['cover_image']
        try:
            profile = request.user.profile  # Assuming you have a one-to-one profile relation
        except ObjectDoesNotExist:
            profile = CustomUser.objects.create(user=request.user)
        
        profile.cover_image = cover_image
        profile.save()

        return redirect('user_dashboard')  # Redirect to refresh the page and show the updated cover image

    return render(request, 'user_dashboard.html', {
        'profile': request.user,  # Pass the user object as profile
    })

@login_required
def admin_dashboard(request):
      
    if request.user.user_type != 'admin':
        return redirect('home') 
    
    if not request.user.is_staff:
        messages.error(request, "You do not have permission to access the admin dashboard.")
        return redirect('user_dashboard')

    User = get_user_model()

    # Get statistics
    verifiy_users = User.objects.filter(is_active=True).count()
    total_users = User.objects.count()
    active_users = UserActivity.objects.filter(last_activity__gte=timezone.now() - timedelta(minutes=5)).count()
    total_admins = User.objects.filter(is_staff=True).count()

    # Debug print to verify the values
    print(f"Total Users: {total_users}, Active Users: {active_users}, Total Admins: {total_admins}")

    context = {
        'total_users': total_users,
        'active_users': active_users,
        'total_admins': total_admins,
        'verifiy_users':verifiy_users,
    }

    return render(request, 'admin_dashboard.html', context)

@login_required
def superuser_dashboard(request):
    if request.user.user_type != 'superuser':
        return redirect('home') 
    
    User = get_user_model()
    total_users = User.objects.count()
    active_users = User.objects.filter(is_active=True).count()
    regular_users_count = CustomUser.objects.filter(user_type='user').count()
    
    # Adjust these queries based on how you categorize users
    total_candidates = User.objects.filter(user_type='candidate').count()  # Replace 'candidate' with your actual type if necessary
    total_admin = User.objects.filter(is_staff=True, is_superuser=False).count()
    total_superuser = User.objects.filter(is_superuser=True).count()

    context = {
        'total_users': total_users,
        'active_users': active_users,
        'total_candidates': total_candidates,
        'total_admin': total_admin,
        'total_superuser': total_superuser,
        'regular_users_count': regular_users_count,
    }
    
    return render(request, 'superuser_dashboard.html', context)






from django.shortcuts import render, redirect, get_object_or_404
from .models import  RecentActivity  # Ensure RecentActivity is defined in models.py
from django.contrib.auth.models import Permission, User
from django.contrib.auth.decorators import user_passes_test
from django.contrib import messages
from django.utils import timezone
    
import logging
from datetime import datetime
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.models import User, Permission

# Configure logging settings
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("activity_log.txt"),  # Save to a file
        logging.StreamHandler()                   # Print to console
    ]
)

def log_activity(user, action):
    """Helper function to log activities with a timestamp and username."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logging.info(f"{timestamp} - {user.username} - {action}")

def manage_roles(request):
    if request.method == 'POST':
        role_id = request.POST.get('role_id')

        if 'update_permissions' in request.POST:
            selected_permissions = request.POST.getlist('permissions')
            user = get_object_or_404(User, id=role_id)
            user.user_permissions.set(selected_permissions)
            messages.success(request, f"Permissions updated for {user.username}.")

            log_activity(request.user, f"Updated permissions for {user.username}")
            return redirect('manage_roles')

        elif 'delete_permission' in request.POST:
            selected_permissions = request.POST.getlist('permissions')
            user = get_object_or_404(User, id=role_id)
            removed_permissions = []
            for perm_id in selected_permissions:
                permission = get_object_or_404(Permission, id=perm_id)
                user.user_permissions.remove(permission)
                removed_permissions.append(permission.name)

            if removed_permissions:
                messages.success(request, f"Permissions removed from {user.username}: {', '.join(removed_permissions)}.")
                log_activity(request.user, f"Removed permissions {', '.join(removed_permissions)} from {user.username}")
            else:
                messages.info(request, "No permissions were removed.")

            return redirect('manage_roles')

        elif 'delete_superuser' in request.POST:
            user = get_object_or_404(User, id=role_id)
            username = user.username
            user.delete()
            messages.success(request, f"Superuser '{username}' deleted.")
            log_activity(request.user, f"Deleted superuser '{username}'")
            return redirect('manage_roles')

        elif 'delete_admin' in request.POST:
            user = get_object_or_404(User, id=role_id)
            username = user.username
            user.delete()
            messages.success(request, f"Admin '{username}' deleted.")
            log_activity(request.user, f"Deleted admin '{username}'")
            return redirect('manage_roles')

    # Retrieve recent activities by reading the last 10 lines from the log file
    recent_activities = []
    try:
        with open("activity_log.txt", "r") as file:
            lines = file.readlines()[-10:]  # Get the last 10 entries
            recent_activities = [line.strip() for line in lines if line.strip()]
    except FileNotFoundError:
        recent_activities = ["No recent activity found."]
    except IOError:
        recent_activities = ["Error reading activity log file."]

    superusers = User.objects.filter(is_superuser=True)
    admins = User.objects.filter(is_staff=True, is_superuser=False)
    permissions = Permission.objects.all()
    


    return render(request, 'manage_roles.html', {
        'superusers': superusers,
        'admins': admins,
        'permissions': permissions,
        'recent_activities': recent_activities,
    })

import os

def clear_recent_activities(request):
    if request.method == 'POST':
        # Clear recent activities in the activity log file
        log_file_path = "activity_log.txt"  # Path to your activity log file
        if os.path.exists(log_file_path):
            open(log_file_path, 'w').close()  # Clear the contents of the file
            messages.success(request, "Recent activities cleared successfully.")
        else:
            messages.error(request, "Activity log file not found.")
    else:
        messages.error(request, "Invalid request method.")
        
    return redirect('manage_roles')  # Redirect to your management page

#LOGIN,LOGOUT,FORGET PASSWORD,VERIFY OTP.RESET PASSWORD SECTION CHANGE PASSWORD

from django.contrib.auth import authenticate, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib import messages
from django.shortcuts import render, redirect

@login_required
def change_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        # Check if the current password is correct
        if not request.user.check_password(current_password):
            messages.error(request, 'Current password is incorrect.')
            return render(request, 'change_password.html')

        # Check if the new password and confirm password match
        if new_password != confirm_password:
            messages.error(request, 'New passwords do not match.')
            return render(request, 'change_password.html')

        # Set the new password
        request.user.set_password(new_password)
        request.user.save()

        # Update the session to keep the user logged in after password change
        update_session_auth_hash(request, request.user)

        messages.success(request, 'Your password has been successfully changed.')
        return redirect('change_password')  # or wherever you want to redirect

    return render(request, 'change_password.html')


User = get_user_model()

def loginme(request):
    # Redirect if the user is already authenticated
    if request.user.is_authenticated:
        return redirect("admin_dashboard" if request.user.is_superuser or request.user.is_staff else "user_dashboard")

    if request.method == "POST":
        username_or_email = request.POST.get("username_or_email")
        password = request.POST.get("password")
        captcha_response = request.POST.get("captcha_response")

        # Validate CAPTCHA
        if captcha_response != request.session.get("captcha_text", ""):
            messages.error(request, "Invalid CAPTCHA. Please try again.")
            return redirect("loginme")

        # Authenticate by username or email
        user = CustomUser.objects.filter(username=username_or_email).first() or \
               CustomUser.objects.filter(email=username_or_email).first()
        
        if user:
            # Check if account is locked
            if user.is_account_locked():
                messages.error(request, "Your account is temporarily locked due to multiple failed login attempts.")
                return render(request, "login.html")

            # Authenticate user
            authenticated_user = authenticate(request, username=user.username, password=password)
            if authenticated_user:
                login(request, authenticated_user)
                user.reset_failed_attempts()  # Reset failed attempts
                messages.success(request, "Login successful.")
                return redirect("admin_dashboard" if authenticated_user.is_superuser or authenticated_user.is_staff else "user_dashboard")
            else:
                user.increment_failed_attempts()  # Increment failed attempts on wrong password
                messages.error(request, "Invalid password. Please try again.")
        else:
            messages.error(request, "Invalid username or email. Please try again.")

    # Generate CAPTCHA for page load
    captcha_text = generate_captcha_text()
    captcha_image = create_captcha_image(captcha_text)

    # Store CAPTCHA text in session
    request.session["captcha_text"] = captcha_text

    # Convert CAPTCHA image to Base64 for template
    captcha_image_base64 = base64.b64encode(captcha_image.read()).decode("utf-8")
    captcha_image_data = f"data:image/png;base64,{captcha_image_base64}"

    return render(request, "login.html", {"captcha_image": captcha_image_data})

def logoutme(request):
    logout(request)
    return redirect('loginme')

OTP_RESEND_COOLDOWN_SECONDS = 120  # Cooldown time for resending OTP

def verify_otp_view(request):
    if request.method == 'POST':
        user_id = request.session.get('user_id')
        otp_input = request.POST.get('otp')
        is_password_reset = request.session.get('is_password_reset', False)
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            return JsonResponse({'success': False, 'message': "User not found. Please try again."}, status=400)

        otp_expiry = request.session.get('otp_expiry')
        if otp_expiry:
            otp_expiry_time = datetime.fromisoformat(otp_expiry).replace(tzinfo=pytz.UTC)
            if timezone.now() > otp_expiry_time:
                message = "Password reset OTP has expired. Please request a new OTP." if is_password_reset else "OTP has expired. Please request a new OTP."
                return JsonResponse({'success': False, 'message': message}, status=400)
        else:
            return JsonResponse({'success': False, 'message': "OTP expiry not found. Please request a new OTP."}, status=400)

        if str(user.otp) == otp_input:
            if is_password_reset:
                request.session['is_password_reset'] = False
                return JsonResponse({
                    'success': True,
                    'message': "OTP verified! Proceed to set your new password.",
                    'redirect_url': reverse('reset_password_view')
                })
            
            else:
                if not user.is_active:
                    user.is_active = True
                    user.is_otp_verified = True
                    user.save()
                    return JsonResponse({
                        'success': True,
                        'message': "Account activated successfully! You can now log in.",
                        'redirect_url': reverse('loginme')
                    })
                else:
                    return JsonResponse({
                        'success': True,
                        'message': "Your account is already active. You can log in.",
                        'redirect_url': reverse('loginme')
                    })
        else:
            return JsonResponse({'success': False, 'message': "Invalid OTP. Please try again."}, status=400)

    existing_time_left = calculate_resend_cooldown(request)
    return render(request, 'verify_otp.html', {'existing_time_left': existing_time_left})

@csrf_exempt
def resend_otp_view(request):
    user_id = request.session.get('user_id')
    user = CustomUser.objects.filter(id=user_id).first()

    if not user:
        return JsonResponse({'success': False, 'message': "User not found."}, status=400)

    remaining_cooldown = calculate_resend_cooldown(request)
    if remaining_cooldown > 0:
        return JsonResponse({
            'success': False,
            'message': "Please wait before requesting a new OTP.",
            'time_left': remaining_cooldown
        }, status=400)

    new_otp = generate_new_otp()  # Implement this function
    user.otp = new_otp
    user.save()

    otp_expiry_time = timezone.now() + timedelta(minutes=5)
    request.session['otp_expiry'] = otp_expiry_time.isoformat()
    request.session['last_otp_request_time'] = timezone.now().isoformat()

    send_otp_email(user.email, new_otp)

    return JsonResponse({
        'success': True,
        'message': "A new OTP has been sent to your email.",
        'time_left': OTP_RESEND_COOLDOWN_SECONDS
    })



def calculate_resend_cooldown(request):
    last_request_time = request.session.get('last_otp_request_time')
    if last_request_time:
        last_request_time = datetime.fromisoformat(last_request_time)
        time_passed = (timezone.now() - last_request_time).total_seconds()
        cooldown_remaining = OTP_RESEND_COOLDOWN_SECONDS - time_passed
        return max(0, int(cooldown_remaining))
    return 0


def send_otp_email(email, otp):
    subject = "Your OTP Code for Verification"
    message = f"Dear user,\n\nYour OTP code is: {otp}\n\nPlease use this code to complete your verification process. This code will expire in 5 minutes.\n\nThank you!"
    from_email = settings.DEFAULT_FROM_EMAIL

    
    send_mail(subject, message, from_email, [email], fail_silently=False)
  
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


def password_reset_request_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        user = CustomUser.objects.filter(email=email).first()

        if user:
            # Generate a 6-digit OTP
            otp = random.randint(100000, 999999)
            user.otp = otp  # Assuming `otp` is a field in your CustomUser model
            user.save()

            # Set OTP expiry
            otp_expiry = timezone.now() + timezone.timedelta(minutes=5)  # OTP expires in 10 minutes
            request.session['user_id'] = user.id
            request.session['otp_expiry'] = otp_expiry.isoformat()
            request.session['is_password_reset'] = True  # Flag to indicate password reset flow

            # Send OTP email
            send_mail(
                'Your Password Reset OTP',
                f'Hello {user.username},\n\nYour OTP for password reset is: {otp}\n\nPlease enter this code to reset your password.',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )

            messages.success(request, "An OTP has been sent to your email.")
            return redirect('verify_otp_view')  # Redirect to OTP verification page
        else:
            messages.error(request, "Email not found. Please check your email address.")

    return render(request, 'password_reset_request.html')


def is_strong_password(password):
    """Check if the password is strong."""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):  # At least one uppercase letter
        return False
    if not re.search(r"[a-z]", password):  # At least one lowercase letter
        return False
    if not re.search(r"[0-9]", password):  # At least one digit
        return False
    if not re.search(r"[!@#$%^&*()_+]", password):  # At least one special character
        return False
    return True

def reset_password_view(request):
    if request.method == 'POST':
        user_id = request.session.get('user_id')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        # Fetch the user based on the stored user_id
        user = CustomUser.objects.filter(id=user_id).first()
        
        if not user:
            messages.error(request, "User not found. Please try again.")
            return redirect('reset_password_view')

        # Check if the new password matches the old one
        if user.check_password(new_password):
            messages.error(request, "New password cannot be the same as the old password.")
            return redirect('reset_password_view')

        # Check if the passwords match
        if new_password != confirm_password:
            messages.error(request, "Passwords do not match. Please try again.")
            return redirect('reset_password_view')

        # Check if the new password is strong
        if not is_strong_password(new_password):
            messages.error(request, "Password must be at least 8 characters long, "
                                    "include at least one uppercase letter, one lowercase letter, "
                                    "one digit, and one special character.")
            return redirect('reset_password_view')

        # Check if the user has changed their password in the last 10 days
        if user.last_password_change:
            if timezone.now() < user.last_password_change + timedelta(days=10):
                messages.error(request, "You must wait 10 days before changing your password again.")
                return redirect('reset_password_view')

        # Set the new password and update last_password_change
        user.set_password(new_password)
        user.last_password_change = timezone.now()  # Save the time of the password change
        user.save()
        messages.success(request, "Password reset successful! You can now log in.")
        return redirect('loginme')  # Redirect to login page

    return render(request, 'reset_password.html')

#End of it

#Notification
from django.shortcuts import render
from django.http import JsonResponse
from .models import Notification
from django.contrib.auth.decorators import login_required

from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import Notification

@login_required
def get_unread_notifications_count(request):
    # Get the count of unread notifications for the current user
    unread_notifications_count = Notification.objects.filter(
        user=request.user, is_read=False
    ).count()

    return JsonResponse({'unread_notifications': unread_notifications_count})

from django.http import JsonResponse
from .models import Notification
from django.contrib.auth.decorators import login_required

@login_required
def notifications(request):
    # Fetch all notifications for the current user, ordered by created_at
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    unread_notifications = notifications.filter(is_read=False)
    
    return render(request, 'notifications.html', {
        'notifications': notifications,
        'unread_notifications_count': unread_notifications.count()
    })

from django.shortcuts import get_object_or_404, redirect
from django.http import JsonResponse
from .models import Notification
from django.contrib.auth.decorators import login_required

@login_required
def delete_notification(request):
    if request.method == 'POST':
        notification_id = request.POST.get('id')
        
        # Fetch the notification based on ID and ensure the logged-in user owns the notification
        notification = get_object_or_404(Notification, id=notification_id, user=request.user)
        
        # Delete the notification
        notification.delete()
        
        return JsonResponse({'status': 'Notification deleted successfully'})

    return JsonResponse({'status': 'Invalid request'}, status=400)


@login_required
def mark_notifications_as_read(request):
    # Mark all notifications as read for the current user
    notifications = Notification.objects.filter(
        user=request.user, is_read=False
    )
    notifications.update(is_read=True)  # Mark them as read
    return JsonResponse({'status': 'Notifications marked as read'})

from .models import Notification

def new_user_registration(user):
    # Notify all superusers and admins when a new user registers
    if user.is_superuser or user.is_staff:
        Notification.objects.create(
            user=user,
            notification_type='New User Registration',
            message=f'A new user {user.username} has registered.'
        )

def new_candidate_application(candidate):
    # Notify admins or superusers about new candidate applications
    if candidate.user.is_superuser or candidate.user.is_staff:
        Notification.objects.create(
            user=candidate.user,
            notification_type='New Candidate Application',
            message=f'New candidate application for {candidate.position} by {candidate.user.username}.'
        )

def feedback_response(feedback):
    # Notify about feedback responses
    Notification.objects.create(
        user=feedback.user,
        notification_type='Feedback Response',
        message=f'Your feedback has been responded to by {feedback.recipient}.'
    )

def candidate_approval(candidate):
    # Notify the user when their candidate application is approved
    Notification.objects.create(
        user=candidate.user,
        notification_type='Candidate Approved',
        message=f'Your application for the {candidate.position} position has been approved!'
    )

def feedback_response_to_user(feedback):
    # Notify regular users when they get a response to their feedback
    Notification.objects.create(
        user=feedback.user,
        notification_type='Feedback Response User',
        message=f'You have a response to your feedback from {feedback.recipient}.'
    )

def election_result(candidate, result):
    # Notify the candidate of the election result (win/lose)
    Notification.objects.create(
        user=candidate.user,
        notification_type='Election Results',
        message=f'You have {result} the election for {candidate.position}.'
    )

#message
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from .models import Message, User, Notification




from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from .models import Message, User, Notification


from django.db.models import Q, Max
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import Message
@login_required
def messages_overview(request):
    # Get the latest message between the user and each unique conversation partner
    recent_messages = Message.objects.filter(
        Q(sender=request.user) | Q(recipient=request.user)
    ).values('sender', 'recipient').annotate(last_message=Max('timestamp')).order_by('-last_message')

    # Identify conversation partners and retrieve full message objects
    conversation_partners = set()
    conversations = []
    for msg in recent_messages:
        # Determine the conversation partner (sender or recipient)
        partner_id = msg['recipient'] if msg['sender'] == request.user.id else msg['sender']
        if partner_id not in conversation_partners:
            conversation_partners.add(partner_id)
            conversations.append(Message.objects.filter(
                (Q(sender=request.user, recipient_id=partner_id) | 
                 Q(sender_id=partner_id, recipient=request.user)
                )).order_by('-timestamp').first())

    return render(request, 'messages_overview.html', {'conversations': conversations})



@login_required
def search_users(request):
    # Handle the search for users when a query is provided
    query = request.GET.get('query', '')
    if query:
        users = User.objects.filter(Q(username__icontains=query)).exclude(id=request.user.id)
        user_data = [{'id': user.id, 'username': user.username} for user in users]
        return JsonResponse({'users': user_data})
    return JsonResponse({'users': []})
# views.py
from django.shortcuts import render
from django.http import JsonResponse
from .models import Message
from django.contrib.auth.decorators import login_required
from datetime import datetime
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import Message, User


import json
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.core.files.storage import FileSystemStorage
from .models import Message
from django.http import JsonResponse
import json
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.db.models import Q
from .models import Message, Notification, User

@login_required
def send_and_view_messages(request, user_id):
    recipient = get_object_or_404(User, id=user_id)

    if request.method == 'POST':
        # Handle text content and image upload
        content = request.POST.get('content')
        image = request.FILES.get('image')

        if content or image:
            # Create the message
            message = Message.objects.create(
                sender=request.user,
                recipient=recipient,
                content=content,
                image=image
            )
            
            # Create a notification for the recipient
            Notification.objects.create(
                user=recipient,
                notification_type="New Message",
                message=f"You have a new message from {request.user.username}",
                is_read=False
            )

            return JsonResponse({'status': 'Message sent successfully'})

    # Fetching new messages based on the last message ID
    last_message_id = request.GET.get('last_message_id')
    messages_query = Message.objects.filter(
        Q(sender=request.user, recipient=recipient) | 
        Q(sender=recipient, recipient=request.user)
    ).order_by('timestamp')

    if last_message_id:
        messages_query = messages_query.filter(id__gt=last_message_id)

    messages = [
        {'id': msg.id, 'content': msg.content, 'sender': msg.sender.username, 'timestamp': msg.timestamp, 'image_url': msg.image.url if msg.image else None}
        for msg in messages_query
    ]

    if request.method == 'GET' and last_message_id:
        return JsonResponse({'messages': messages})

    return render(request, 'send_and_view_messages.html', {
        'messages': messages_query,
        'recipient': recipient,
    })


@login_required
def check_notifications(request):
    # Get unread notifications for the user
    unread_messages = Notification.objects.filter(
        user=request.user, is_read=False, notification_type="New Message"
    ).count()

    return JsonResponse({'unread_notifications': unread_messages})

@login_required
def mark_notifications_as_read(request):
    Notification.objects.filter(user=request.user, is_read=False).update(is_read=True)
    return JsonResponse({'status': 'Notifications marked as read'})


#end of it

#feedback section
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Feedback

@login_required
def user_feedback_page(request):
    if request.method == 'POST':
        # Handle new feedback submission
        new_feedback_content = request.POST.get('new_feedback')
        rating = request.POST.get('rating')
        if new_feedback_content and rating:
            feedback = Feedback.objects.create(
                user=request.user,
                message=new_feedback_content,
                rating=rating
            )
            messages.success(request, "Your feedback has been submitted.")
            return redirect('feedback_chat', feedback_id=feedback.id)

    user_feedbacks = Feedback.objects.filter(user=request.user)
    return render(request, 'user_feedback_page.html', {'user_feedbacks': user_feedbacks})


from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import Feedback, FeedbackMessage, CustomUser
from django.contrib import messages
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import CustomUser, Feedback, FeedbackMessage

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import CustomUser, Feedback, FeedbackMessage

from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Feedback, FeedbackMessage

@login_required
def reply_to_feedback(request, feedback_id):
    feedback = get_object_or_404(Feedback, id=feedback_id, user=request.user)

    if request.method == 'POST':
        reply_content = request.POST.get('reply')
        if reply_content:
            FeedbackMessage.objects.create(
                feedback=feedback,
                sender=request.user,
                message=reply_content
            )
            messages.success(request, "Your reply has been sent.")
        else:
            messages.error(request, "Please enter a message.")

    return redirect('view_messages')
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Feedback

@login_required
def admin_view_replies(request):
    # Check if the user is an admin or superuser
    if not request.user.is_staff and not request.user.is_superuser:
        return redirect('home')  # Redirect if not authorized

    # Retrieve all feedbacks with their messages
    feedbacks = Feedback.objects.all().prefetch_related('messages')  # Prefetch related messages

    return render(request, 'admin_view_replies.html', {'feedbacks': feedbacks})



@login_required
def admin_feedback_page(request):
    if not request.user.is_staff:
        return redirect('user_feedback_page')

    feedbacks = Feedback.objects.all()
    return render(request, 'admin_feedback_page.html', {'feedbacks': feedbacks})
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from .models import Feedback, FeedbackMessage
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from .models import FeedbackMessage
@login_required
def feedback_chat(request, feedback_id):
    feedback = get_object_or_404(Feedback, id=feedback_id)

    # Handle POST request for new messages
    if request.method == 'POST':
        new_message = request.POST.get('message')
        image = request.FILES.get('image')
        if new_message:
            feedback_message = FeedbackMessage.objects.create(
                feedback=feedback,
                sender=request.user,
                message=new_message,
                image=image
            )
            message_data = {
                'sender': feedback_message.sender.username,
                'message': feedback_message.message,
                'image': feedback_message.image.url if feedback_message.image else None,
                'created_at': feedback_message.created_at.strftime('%Y-%m-%d %H:%M:%S')
            }
            return JsonResponse(message_data)

    # Handle AJAX request to fetch all messages
    elif request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        messages = FeedbackMessage.objects.filter(feedback=feedback).order_by('created_at')
        message_data = [
            {
                'id': msg.id,  # Send message ID for later deletion
                'sender': msg.sender.username,
                'message': msg.message,
                'image': msg.image.url if msg.image else None,
                'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S')
            } for msg in messages
        ]
        return JsonResponse(message_data, safe=False)

    # Handle DELETE request to delete a message
    elif request.method == 'DELETE':
        message_id = request.GET.get('message_id')  # Get message ID from request
        message = get_object_or_404(FeedbackMessage, id=message_id)
        
        # Check if the user has permission to delete (either the message sender or a superuser)
        if request.user == message.sender or request.user.is_superuser:
            message.delete()
            return JsonResponse({'success': True})

        return JsonResponse({'error': 'Permission denied'}, status=403)

    # For initial load, render the full template
    messages = FeedbackMessage.objects.filter(feedback=feedback).order_by('created_at')
    return render(request, 'feedback_chat.html', {'feedback': feedback, 'messages': messages})

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from .models import Feedback

@login_required
@csrf_exempt  # Optional: add this if you face CSRF issues with AJAX DELETE requests
def delete_feedback(request, feedback_id):
    # Get the feedback item
    feedback = get_object_or_404(Feedback, id=feedback_id)

    # Check if the user is an admin or superuser
    if request.user.is_staff or request.user.is_superuser:
        feedback.delete()  # Delete the feedback item
        return JsonResponse({'success': True})

    return JsonResponse({'error': 'Permission denied'}, status=403)
#End of it

#Announcement section
from django.contrib import messages
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from .models import Announcement

def is_admin(user):
    return user.is_superuser or user.is_staff

@login_required
@user_passes_test(is_admin)
def create_announcement(request):
    announcements = Announcement.objects.all().order_by('-created_at')  # Query all announcements

    if request.method == 'POST':
        title = request.POST.get('title')
        content = request.POST.get('content')
   
        if title and content:
            Announcement.objects.create(title=title, content=content)
            messages.success(request, "Announcement created successfully.")
            return redirect('create_announcement')
        else:
            messages.error(request, "Both title and content are required.")

    context = {
        'announcements': announcements,
    }
    return render(request, 'create_announcement.html', context)

@login_required
@user_passes_test(is_admin)
def edit_announcement(request, announcement_id):
    announcement = get_object_or_404(Announcement, id=announcement_id)
    
    if request.method == 'POST':
        title = request.POST.get('title')
        content = request.POST.get('content')
        if title and content:
            announcement.title = title
            announcement.content = content
            announcement.save()
            messages.success(request, "Announcement updated successfully.")
            return redirect('create_announcement')
        else:
            messages.error(request, "Both title and content are required.")
    
    return render(request, 'edit_announcement.html', {'announcement': announcement})

@login_required
@user_passes_test(is_admin)
def delete_announcement(request, announcement_id):
    announcement = get_object_or_404(Announcement, id=announcement_id)
    
    if request.method == 'POST':
        announcement.delete()
        messages.success(request, "Announcement deleted successfully.")
        return redirect('create_announcement')
    
    return render(request, 'delete_announcement.html', {'announcement': announcement})
#end of it



#election part
#position section
@login_required
def manage_positions(request):
    if request.method == 'POST':
        position_name = request.POST.get('position_name')
        if not Position.objects.filter(name=position_name).exists():
            Position.objects.create(name=position_name)
            messages.success(request, 'Position added successfully.')
        else:
            messages.error(request, 'Position already exists.')
        return redirect('manage_positions')

    positions = Position.objects.all()
    return render(request, 'manage_positions.html', {'positions': positions})

@login_required
def edit_position(request, position_id):
    position = Position.objects.get(id=position_id)
    if request.method == 'POST':
        new_position_name = request.POST.get('position_name')
        position.name = new_position_name
        position.save()
        messages.success(request, 'Position updated successfully.')
        return redirect('manage_positions')
    return render(request, 'edit_position.html', {'position': position})

@login_required
def delete_position(request, position_id):
    position = get_object_or_404(Position, id=position_id)
    position.delete()
    messages.success(request, 'Position deleted successfully.')
    return redirect('manage_positions')


from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import CandidateApplication

from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import CandidateApplication

@receiver(post_save, sender=CandidateApplication)
def create_candidate(sender, instance, created, **kwargs):
    # Check if the application status is 'approved'
    if instance.status == 'approved':
        # Logic for creating or processing the approved application
        # (No need for a separate Candidate model, just work with CandidateApplication)
        pass
    elif instance.status == 'rejected':
        # Logic for handling rejected applications
        pass

def admin_users(request):
    users = User.objects.all()  # Retrieve all users
    return render(request, 'admin_users.html', {'users': users})

#user database function delete
def delete_user(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    user.delete()
    # Optionally, add a success message or redirect to another page
    return redirect('admin_users') 

def log_admin_action(action, user):
    AdminLog.objects.create(action=action, admin=user)  # Assuming admin field in AdminLog model

# @login_required
# def candidate_detail(request, candidate_id):
#     candidate = get_object_or_404(Candidate, id=candidate_id)
#     return render(request, 'candidate_detail.html', {'candidate': candidate})


# Approve Candidate View
@login_required
@user_passes_test(is_admin)
def approve_candidate(request, user_id):
    user = CustomUser.objects.get(id=user_id)
    user.is_candidate = True
    user.save()
    messages.success(request, f'{user.username} is now a candidate.')
    return redirect('admin_dashboard')

#for the voting process
# Manage Candidates View
@login_required
@user_passes_test(is_admin)
def manage_candidates(request):
    candidates = CustomUser.objects.filter(is_candidate=True)
    return render(request, 'manage_candidates.html', {'candidates': candidates})
# views.py
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages

@login_required
def vote(request, candidate_id):
    candidate = get_object_or_404(Candidate, id=candidate_id)

    # Check if the user has already voted for this position
    has_voted = Vote.objects.filter(voter=request.user, candidate__position=candidate.position).exists()

    if has_voted:
        messages.error(request, "You have already voted for this position.")
        return redirect('vote_page')

    # Record the vote
    Vote.objects.create(voter=request.user, candidate=candidate, timestamp=timezone.now())
    messages.success(request, f"You voted for {candidate.user.username}.")
    return redirect('vote_page')
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, get_object_or_404
from django.contrib import messages
from django.http import HttpResponseForbidden
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import CandidateApplication, Vote

@login_required
def vote_page(request):

    # Check if the voting window is active
    voting_window = VotingWindow.objects.first()  # Assuming you have a VotingWindow model
    if not (voting_window and voting_window.is_active()):
        messages.error(request, "Voting is currently not possible now.")
        return redirect('candidates')  
    # Exclude the logged-in user if they are a candidate
    candidates = CandidateApplication.objects.exclude(user=request.user) if hasattr(request.user, 'candidateapplication') else CandidateApplication.objects.all()

    if request.method == 'POST':
        candidate_id = request.POST.get('candidate_id')
        candidate = get_object_or_404(CandidateApplication, id=candidate_id)

        # Check if the user has already voted for a candidate in the same position
        if Vote.objects.filter(user=request.user, candidate__position=candidate.position).exists():
            messages.error(request, "You have already voted for a candidate in this position.")
            return redirect('vote_page')

        # Check if the user has already voted for this specific candidate
        if Vote.objects.filter(user=request.user, candidate=candidate).exists():
            messages.error(request, "You have already voted for this candidate.")
            return redirect('vote_page')  # Or redirect to any other page as needed

        # Record the vote
        Vote.objects.create(user=request.user, candidate=candidate)

        # Update the total_votes for the candidate (if necessary)
        candidate.total_votes = Vote.objects.filter(candidate=candidate).count()
        candidate.save()

        messages.success(request, f"Your vote for {candidate.user.first_name} {candidate.user.last_name} ({candidate.position.name}) has been recorded.")
        return redirect('vote_page')  # Or redirect to a thank you page, etc.

    return render(request, 'vote_page.html', {'candidates': candidates})


import matplotlib
matplotlib.use('Agg')  # Non-GUI backend to avoid Tkinter errors
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages
from xhtml2pdf import pisa
from django.template.loader import render_to_string
import io
import base64
import matplotlib.pyplot as plt
from .models import Position, CandidateApplication, VotingWindow

def election_results(request):
    # Fetch the active voting window (if any)
    voting_window = VotingWindow.objects.first()

    if voting_window and voting_window.is_active():
        # If voting window is active, redirect to the homepage with a message
        messages.warning(request, "The voting window is currently active. Please wait until voting ends to view the results.")
        return redirect('candidates')  # Replace 'home' with the actual name of your home URL

    # Fetch all positions and approved candidates for each
    positions = Position.objects.all()
    position_votes = {}

    # Loop through each position, gather candidates' names, votes, and images
    for position in positions:
        candidates = CandidateApplication.objects.filter(position=position, status='approved')
        candidate_data = [
            (
                f"{candidate.user.first_name} {candidate.user.last_name}",
                candidate.total_votes,
                candidate.image.url if candidate.image else None
            )
            for candidate in candidates
        ]
        position_votes[position.name] = candidate_data

    # Create a bar chart for the election results
    plt.figure(figsize=(10, 6))
    for position_name, data in position_votes.items():
        names = [name for name, _, _ in data]
        votes = [votes for _, votes, _ in data]
        plt.bar(names, votes, label=position_name)

    plt.xlabel('Candidates')
    plt.ylabel('Votes')
    plt.title('Election Results by Position')
    plt.legend()

    # Save chart to a buffer and encode it as base64
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    plt.close()  # Close the plot to free memory
    buffer.seek(0)
    chart_url = base64.b64encode(buffer.getvalue()).decode('utf-8')

    # Check if PDF generation is requested
    if 'generate_pdf' in request.GET:
        return generate_pdf(request, position_votes=position_votes, chart_url=chart_url)

    # Render the results page with the chart and candidate data
    return render(request, 'results_page.html', {'chart_url': chart_url, 'position_votes': position_votes})
from django.templatetags.static import static
from django.http import HttpResponse
from django.template.loader import render_to_string
import base64
import os
import io
from xhtml2pdf import pisa
from .models import CandidateApplication

def generate_pdf(request, position_votes, chart_url):
    # Set up content type for PDF and disposition
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="election_results.pdf"'

    # Ensure chart_url is a valid path or URL
    if chart_url.startswith("data:image/png;base64,"):
        # Save the base64 image as a temporary file
        chart_image_path = os.path.join(settings.MEDIA_ROOT, 'chart_image.png')
        with open(chart_image_path, 'wb') as f:
            f.write(base64.b64decode(chart_url.split(',')[1]))

        chart_url = request.build_absolute_uri(chart_image_path)  # Use the absolute path for chart

    # Ensure candidate images are properly referenced with absolute URLs
    for position_name, candidates in position_votes.items():
        for i, (candidate_name, votes, image_url) in enumerate(candidates):
            if image_url:
                image_url = request.build_absolute_uri(image_url)  # Ensure absolute URL for images
                candidates[i] = (candidate_name, votes, image_url)

    # Template path and context
    template_path = 'election_results.html'
    context = {
        'position_votes': position_votes,
        'chart_url': chart_url
    }

    # Render HTML to PDF
    html = render_to_string(template_path, context)
    pisa_status = pisa.CreatePDF(io.BytesIO(html.encode('utf-8')), dest=response)

    if pisa_status.err:
        return HttpResponse('There was an error generating the PDF document.')

    return response



from django.shortcuts import render
from .models import CandidateApplication, Vote
from django.shortcuts import render
from django.utils import timezone
from .models import CandidateApplication, VotingWindow

def past_elections(request):
    # Get the first (or the relevant) voting window
    voting_window = VotingWindow.objects.first()  # Assuming one voting window for simplicity

    # If there is an active voting window, exclude elections within that period
    if voting_window and voting_window.is_active():
        past_elections = CandidateApplication.objects.filter(
            status='approved', 
            created_at__lt=timezone.now()  # Ensure the election is past
        ).exclude(
            created_at__gte=voting_window.end_time  # Ensure the election is past the end_time
        )
    else:
        # If no voting window is active, show all approved candidate applications
        past_elections = CandidateApplication.objects.filter(status='approved')

    return render(request, 'past_elections.html', {'past_elections': past_elections})


def current_votes(request):
    # Fetch all current voting records for candidates in an active voting period
       # Retrieve all votes along with related user and candidate data
    votes_data = Vote.objects.select_related('user', 'candidate__user', 'candidate__position').all()


    return render(request, 'current_votes.html', {'votes': votes_data})



from django.contrib import messages
from django.shortcuts import redirect, render
from django.contrib.auth.decorators import login_required
from .models import CandidateApplication, Position
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, get_object_or_404
from django.contrib import messages

@login_required
def apply_to_be_candidate(request):
    # Check if the voting window is active
    voting_window = VotingWindow.objects.first()
    if voting_window and voting_window.is_active():
        messages.info(request, 'Applications are not accepted during the voting period.')
        return redirect('candidates')

    # Check if the user already has an application for any position (approved or pending)
    existing_application = CandidateApplication.objects.filter(user=request.user)
    if existing_application.exists():
        if existing_application.filter(status='approved').exists():
            messages.info(request, 'You already have an approved application for a position.')
            return redirect('candidates')
        elif existing_application.filter(status='pending').exists():
            messages.info(request, 'You already have a pending application for a position.')
            return redirect('candidates')

    positions = Position.objects.all()  # Fetch all available positions

    if request.method == 'POST':
        position_id = request.POST.get('position')
        manifesto = request.POST.get('manifesto')
        image = request.FILES.get('image')

        if position_id and manifesto:
            position = Position.objects.get(id=position_id)
            application = CandidateApplication(
                user=request.user,
                position=position,
                manifesto=manifesto,
                status='pending'
            )
            if image:
                application.image = image  # Django will handle saving it
            application.save()
            new_candidate_application(application)  # Call with the correct instance
            messages.success(request, 'Your application has been submitted and is pending approval.')
            return redirect('candidates')
        else:
            messages.error(request, 'Please provide a position and manifesto.')
            return redirect('apply_to_be_candidate')

    return render(request, 'apply_to_be_candidate.html', {'positions': positions})


# views.py
from django.shortcuts import render
from .models import CandidateApplication

def candidates_view(request):
    # Fetch all approved candidates
    approved_candidates = CandidateApplication.objects.filter(status='approved')
    return render(request, 'approved_candidates.html', {'approved_candidates': approved_candidates})


from django.db.models import Count
from django.shortcuts import render

@login_required
def admin_results(request):
    # Aggregate total votes per candidate
    results = Vote.objects.values('candidate__user__username', 'candidate__position__name')\
                           .annotate(total_votes=Count('id'))\
                           .order_by('-total_votes')

    return render(request, 'admin_results.html', {'results': results})


#Apply to be candidate section
from .models import Position, RegistrationWindow
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
# View to handle candidate application
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import CandidateApplication, Position, RegistrationWindow
from django.contrib import messages
from django.utils import timezone

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import CandidateApplication, Vote

@login_required
def vote_view(request):
    approved_candidates = CandidateApplication.objects.filter(status='approved')

    if request.method == 'POST':
        candidate_id = request.POST.get('candidate')
        candidate = CandidateApplication.objects.get(id=candidate_id)

        # Get the position of the selected candidate
        position = candidate.position

        # Check if the user has already voted for a candidate in the same position
        if Vote.objects.filter(user=request.user, candidate__position=position).exists():
            return redirect('already_voted')  # Redirect to "already voted" page

        # Record the vote
        Vote.objects.create(user=request.user, candidate=candidate)
        return redirect('vote_success')

    return render(request, 'vote.html', {'approved_candidates': approved_candidates})


from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from .models import CandidateApplication

@login_required
def admin_view_candidate_applications(request):
    # Ensure the user is an admin
    if not request.user.is_staff:
        messages.error(request, 'You are not authorized to access this page.')
        return redirect('home')

    # Get the search query from GET parameters
    search_query = request.GET.get('search_query', '')

    # Fetch all applications, with search filtering if search_query exists
    if search_query:
        applications = CandidateApplication.objects.filter(
            user__username__icontains=search_query
        ) | CandidateApplication.objects.filter(
            position__name__icontains=search_query
        )
    else:
        applications = CandidateApplication.objects.all()

    return render(request, 'admin_view_applications.html', {'applications': applications, 'search_query': search_query})


@login_required
def approve_application(request, application_id):
    application = get_object_or_404(CandidateApplication, id=application_id)

    # Update the application status to 'approved'
    application.status = 'approved'
    application.save()

    messages.success(request, 'Candidate application approved successfully.')
    return redirect('admin_view_candidate_applications')

@login_required
def reject_application(request, application_id):
    application = get_object_or_404(CandidateApplication, id=application_id)

    # Update the application status to 'rejected'
    application.status = 'rejected'
    application.save()

    messages.success(request, 'Candidate application rejected successfully.')
    return redirect('admin_view_candidate_applications')

@login_required
def delete_application(request, application_id):
    application = get_object_or_404(CandidateApplication, id=application_id)

    # Delete the application
    application.delete()

    messages.success(request, 'Candidate application deleted successfully.')
    return redirect('admin_view_candidate_applications')

@login_required
def reject_application(request, application_id):
    application = get_object_or_404(CandidateApplication, id=application_id)

    # Update the application status to 'rejected'
    application.status = 'rejected'
    application.save()

    messages.success(request, 'Candidate application rejected successfully.')
    return redirect('admin_view_candidate_applications')

@login_required
def delete_application(request, application_id):
    application = get_object_or_404(CandidateApplication, id=application_id)

    # Delete the application
    application.delete()

    messages.success(request, 'Candidate application deleted successfully.')
    return redirect('admin_view_candidate_applications')

# views.py
from django.db.models import Count

def results_view(request):
    results = CandidateApplication.objects.filter(status='approved').annotate(vote_count=Count('vote'))
    return render(request, 'results.html', {'results': results})

@login_required
def candidates_list(request):
    # Fetch candidates
    candidates = Candidate.objects.filter(is_approved=True)
    context = {'candidates': candidates}
    return render(request, 'candidates_list.html', context)



def admin_results(request): 
    results = Vote.objects.values('candidate__user__username').annotate(total_votes=Count('id'))
    return render(request, 'admin_results.html', {'results': results})

def vote_results(request):
    # Aggregate vote counts per candidate
    results = Vote.objects.values('candidate__user__username').annotate(total_votes=Count('id'))
    return JsonResponse(list(results), safe=False)


from django.db.models import Count
from django.http import JsonResponse
from .models import Vote, CandidateApplication

from django.http import JsonResponse
from django.db.models import Count
from .models import Vote

def get_live_results(request):
    # Get the number of votes for each candidate grouped by the position and candidate
    results = Vote.objects.select_related('candidate__position', 'candidate__user') \
        .values('candidate__position__name', 'candidate__user__first_name', 'candidate__user__last_name', 'candidate') \
        .annotate(votes_count=Count('id')) \
        .order_by('-votes_count')

    # Format the results to include the full name of the candidate
    formatted_results = [
        {
            'voter_name': f"{candidate['candidate__user__first_name']} {candidate['candidate__user__last_name']}",  # Full name
            'position': candidate['candidate__position__name'],
            'votes_count': candidate['votes_count']
        }
        for candidate in results
    ]

    return JsonResponse(formatted_results, safe=False)


def candidate_page(request):
    candidates = Candidate.objects.all()  # Or filter as necessary
    return render(request, 'vote_page.html', {'candidates': candidates})



from django.shortcuts import render
from django.utils import timezone
from django.db.models import Count
from .models import VotingWindow, CandidateApplication, Position, Vote, CustomUser

@login_required
def voting_dashboard(request):
    # Check if there is an active voting window
    current_window = VotingWindow.objects.filter(start_time__lte=timezone.now(), end_time__gte=timezone.now()).first()

    # If no active voting window, return a message or redirect
    if not current_window:
        return render(request, 'view_vote.html', {"current_window": None, "message": "Voting has not started yet."})

    # Retrieve metrics if there is an active voting window
    candidate_count = CandidateApplication.objects.count()
    position_count = Position.objects.count()
    vote_count = Vote.objects.count()
    voter_count = Vote.objects.values('user').distinct().count()

    # Prepare data to be used in the charts, modifying the candidate_stats query
    candidate_stats = Vote.objects.values('candidate__user__first_name', 'candidate__user__last_name') \
                                    .annotate(total_votes=Count('id'))

    position_stats = Position.objects.annotate(total_candidates=Count('candidateapplication'))

    # Pass all the data to the template
    context = {
        'current_window': current_window,
        'candidate_count': candidate_count,
        'position_count': position_count,
        'vote_count': vote_count,
        'voter_count': voter_count,
        'candidate_stats': candidate_stats,
        'position_stats': position_stats,
    }

    return render(request, 'view_vote.html', context)


from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.db.models import Count
from .models import CandidateApplication, Position

@api_view(['GET'])
def candidate_voting_statistics(request):
    # Annotate candidates with vote counts
    candidates = CandidateApplication.objects.annotate(vote_count=Count('vote'))
    data = {
        "labels": [f"{candidate.user.first_name} {candidate.user.last_name}" for candidate in candidates],  # Full name
        "data": [candidate.vote_count for candidate in candidates],
    }
    return Response(data)


@api_view(['GET'])
def position_voting_statistics(request):
    # Annotate positions with vote counts through candidates
    positions = Position.objects.annotate(total_votes=Count('candidateapplication__vote'))
    data = {
        "labels": [position.name for position in positions],
        "data": [position.total_votes for position in positions],
    }
    return Response(data)


from django.http import JsonResponse
from django.db.models import Count
from .models import CandidateApplication
from django.http import JsonResponse
from django.db.models import Count
from .models import CandidateApplication

def voting_data(request):
    # Retrieve candidate vote counts with full name (first_name + last_name)
    candidates = CandidateApplication.objects.annotate(vote_count=Count('vote')).values('user__first_name', 'user__last_name', 'vote_count')

    data = {
        'candidates': list(candidates),
    }
    return JsonResponse(data)


from django.http import JsonResponse
from django.db.models import Count
from .models import Vote, CandidateApplication

def vote_results(request):
    # Aggregate vote counts per candidate based on CandidateApplication model
    results = Vote.objects.values('candidate__user__username').annotate(total_votes=Count('id'))

    # Return the aggregated results as JSON
    return JsonResponse(list(results), safe=False)
# views.py
from django.db.models import Count
from django.http import JsonResponse
from .models import CandidateApplication, Vote
# views.py
from django.db.models import Count
from django.http import JsonResponse
from .models import CandidateApplication, Vote

from django.http import JsonResponse
from django.db.models import Count
from .models import Vote

from django.db.models import Count
from django.http import JsonResponse
from .models import Vote

def live_vote_results(request):
    # Aggregate vote counts per position
    results = (
        Vote.objects
        .values('candidate__position__name', 'candidate__user__first_name', 'candidate__user__last_name')
        .annotate(vote_count=Count('id'))
        .order_by('candidate__position__name')
    )

    # Format data for easy access by JavaScript
    data = {}
    for result in results:
        position = result['candidate__position__name']
        if position not in data:
            data[position] = {'candidates': [], 'votes': []}
        # Combine first and last name to get full name
        full_name = f"{result['candidate__user__first_name']} {result['candidate__user__last_name']}"
        data[position]['candidates'].append(full_name)
        data[position]['votes'].append(result['vote_count'])

    return JsonResponse(data)


#end of it

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
import logging
# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("activity_log.txt"),  # Save to a file
        logging.StreamHandler()                   # Print to console
    ]
)

def log_activity(user, action):
    """Helper function to log activities with a timestamp and username."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logging.info(f"{timestamp} - {user.username} - {action}")

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from comparison.models import ComparisonData  # Import ComparisonData from the comparison app

def user_input(request):
    if request.method == "POST":
        matriculation_number = request.POST.get('matriculation_number', '').strip()
        first_name = request.POST.get('first_name', '').strip()
        middle_name = request.POST.get('middle_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        email = request.POST.get('email', '').strip()
        phone1 = request.POST.get('phone1', '').strip()
        phone2 = request.POST.get('phone2', '').strip()
        address = request.POST.get('address', '').strip()
        date_of_birth = request.POST.get('date_of_birth', '').strip()
        gender = request.POST.get('gender')
        level_id = request.POST.get('level') or None
        program_id = request.POST.get('program') or None
        department_id = request.POST.get('department') or None

        missing_fields = []
        if not matriculation_number:
            missing_fields.append("matriculation_number")
        if not first_name:
            missing_fields.append("first_name")
        if not last_name:
            missing_fields.append("last_name")
        
        if missing_fields:
            messages.error(request, f"Missing required fields: {', '.join(missing_fields)}")
            return render(request, 'user_input.html', {
                'comparison_data_list': ComparisonData.objects.all(),
                'levels': Level.objects.all(),
                'programs': Program.objects.all(),
                'departments': Department.objects.all(),
                'form_data': request.POST  # Retain form data
            })

        if 'update_data' in request.POST:
            comparison_data_id = request.POST.get('update_data')
            comparison_data = get_object_or_404(ComparisonData, id=comparison_data_id)

            # Update the existing record
            comparison_data.matriculation_number = matriculation_number
            comparison_data.first_name = first_name
            comparison_data.middle_name = middle_name
            comparison_data.last_name = last_name
            comparison_data.email = email
            comparison_data.gender = gender
            comparison_data.phone1 = phone1
            comparison_data.phone2 = phone2
            comparison_data.address = address
            comparison_data.date_of_birth = date_of_birth
            comparison_data.level_id = level_id
            comparison_data.program_id = program_id
            comparison_data.department_id = department_id
            
            comparison_data.save()
            messages.success(request, "Comparison data updated successfully.")
            
            # Log the update action
            log_activity(request.user, f"Updated ComparisonData ID: {comparison_data_id} for {first_name} {last_name}")

        else:
            # Create a new record
            new_data = ComparisonData(
                matriculation_number=matriculation_number,
                first_name=first_name,
                middle_name=middle_name,
                last_name=last_name,
                gender=gender,
                email=email,
                phone1=phone1,
                phone2=phone2,
                address=address,
                date_of_birth=date_of_birth,
                level_id=level_id,
                program_id=program_id,
                department_id=department_id,
                
            )
            new_data.save()
            messages.success(request, "Comparison data created successfully.")

            # Log the creation action
            log_activity(request.user, f"Created new ComparisonData for {first_name} {last_name}")

        return redirect('user_input')

    elif request.method == "GET":
        if 'delete_data' in request.GET:
            delete_data_id = request.GET.get('delete_data')
            comparison_data = get_object_or_404(ComparisonData, id=delete_data_id)
            comparison_data.delete()
            messages.success(request, "Comparison data deleted successfully.")

            # Log the deletion action
            log_activity(request.user, f"Deleted ComparisonData ID: {delete_data_id} for {comparison_data.first_name} {comparison_data.last_name}")

        elif any(key.startswith('valid_') for key in request.GET):
            for key, value in request.GET.items():
                if key.startswith('valid_'):
                    data_id = key.split('_')[1]
                    try:
                        comparison_data = ComparisonData.objects.get(id=data_id)

                        # Set validity to True if checked (value is 'on'), otherwise set to False
                        comparison_data.valid = (value == 'on')
                        comparison_data.save()

                        # Provide feedback based on the new state
                        if comparison_data.valid:
                            messages.success(request, f"Validity updated for ID: {data_id} to valid.")
                            log_activity(request.user, f"Set ComparisonData ID: {data_id} to valid.")
                        else:
                            messages.success(request, f"Validity updated for ID: {data_id} to invalid.")
                            log_activity(request.user, f"Set ComparisonData ID: {data_id} to invalid.")

                    except ComparisonData.DoesNotExist:
                        messages.error(request, f"Comparison data not found for ID: {data_id}")

    comparison_data_list = ComparisonData.objects.all()
    levels = Level.objects.all()
    programs = Program.objects.all()
    departments = Department.objects.all()

    return render(request, 'user_input.html', {
        'comparison_data_list': comparison_data_list,
        'levels': levels,
        'programs': programs,
        'departments': departments,
    })


@login_required
def view_comparison_data(request):
    comparison_data = ComparisonData.objects.all()
    return render(request, 'comparison_data.html', {'comparison_data': comparison_data})

def insert_program_and_level(request):
    if request.method == "POST":
        messages_dict = {}
        
        # Handle Program Submission
        program_name = request.POST.get('program_name', '').strip()
        if program_name:
            Program.objects.create(name=program_name)
            messages_dict['program'] = "Program created successfully."
        else:
            messages_dict['program_error'] = "Program name is required."

        # Handle Level Submission
        level_name = request.POST.get('level_name', '').strip()
        if level_name:
            Level.objects.create(name=level_name)
            messages_dict['level'] = "Level created successfully."
        else:
            messages_dict['level_error'] = "Level name is required."

        # Handle Department Submission
        department_name = request.POST.get('department_name', '').strip()
        if department_name:
            Department.objects.create(name=department_name)
            messages_dict['department'] = "Department created successfully."
        else:
            messages_dict['department_error'] = "Department name is required."

        # Display all messages at once
        for key, message in messages_dict.items():
            if 'error' in key:
                messages.error(request, message)
            else:
                messages.success(request, message)

        return redirect('insert_program_and_level')

    # Handle Deletion
    delete_mapping = {
        'delete_program': Program,
        'delete_level': Level,
        'delete_department': Department,
    }
    for key, model in delete_mapping.items():
        delete_id = request.GET.get(key)
        if delete_id:
            instance = get_object_or_404(model, id=delete_id)
            instance.delete()
            messages.success(request, f"{model.__name__} deleted successfully.")
            return redirect('insert_program_and_level')

    # Fetch existing programs, levels, and departments
    programs = Program.objects.all()
    levels = Level.objects.all()
    departments = Department.objects.all()

    return render(request, 'insert_program_and_level.html', {
        'programs': programs,
        'levels': levels,
        'departments': departments,
    })





@login_required
def mark_invalid(request, user_id):
    user = CustomUser.objects.get(id=user_id)
    user.is_valid = False
    user.save()
    return redirect('admin_users')

# Handle actions for user management
def mark_user_valid(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    user.is_valid = True
    user.save()
    return redirect('admin_dashboard')

def mark_user_invalid(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    user.is_valid = False
    user.save()
    return redirect('admin_dashboard')

def delete_user(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    user.delete()
    return redirect('admin_dashboard')


#User-management
# Check if user is superuser
def is_superuser(user):
    return user.is_superuser


@user_passes_test(is_superuser)
def superuser_management(request):
    if not request.user.is_superuser:
        return redirect('user_dashboard')
    # Filter users into three categories
    superusers = CustomUser.objects.filter(user_type='superuser')
    context = {
        'superusers': superusers,
       
    }
    
    return render(request, 'superuser_management.html', context)

# Check if user is admin
def is_admin(user):
    return user.is_staff  # or any condition that defines an admin

@user_passes_test(is_admin)
def admin_management(request):
    # Filter users to include only those with user_type 'admin'
    users = CustomUser.objects.filter(user_type='admin')  
    return render(request, 'admin_management.html', {'users': users})


def user_management(request):
    # Filter users to only show those of type 'user'
    users = CustomUser.objects.filter(user_type='user')
    return render(request, 'user_management.html', {'users': users})

def delete_user(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    user.delete()
    if user.is_superuser:
        return redirect('superuser_management')
    elif user.is_staff:
        return redirect('admin_management')
    else:
        return redirect('user_management')

def undelete_user(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    user.is_deleted = False  # Mark user as undeleted
    user.save()
    if user.is_superuser:
        return redirect('superuser_management')
    elif user.is_staff:
        return redirect('admin_management')
    else:
        return redirect('user_management')
    
def mark_user_valid(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    user.is_active = True  # Mark user as valid
    user.save()
    if user.is_superuser:
        return redirect('superuser_management')
    elif user.is_staff:
        return redirect('admin_management')
    else:
        return redirect('user_management')
   
def mark_user_invalid(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    user.is_active = False  # Mark user as invalid
    user.save()
    if user.is_superuser:
        return redirect('superuser_management')
    elif user.is_staff:
        return redirect('admin_management')
    else:
        return redirect('user_management')

