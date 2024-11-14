# middleware.py
from django.shortcuts import redirect
from django.contrib import messages

ALLOWED_IPS = ['127.0.0.1']   # Replace with actual allowed IP addresses

class IPRestrictionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        client_ip = request.META.get('REMOTE_ADDR')
        if request.path.startswith('/register-superuser/') and client_ip not in ALLOWED_IPS:
            messages.error(request, 'Access denied. Your IP address is not authorized to view this page.')
            return redirect('loginme')  # Redirect to an error page or login
        response = self.get_response(request)
        return response

from datetime import timedelta
from django.utils import timezone
from .models import UserActivity
from django.utils.deprecation import MiddlewareMixin

class UserActivityMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.user.is_authenticated:
            # Update the last activity time for authenticated users
            user_activity, created = UserActivity.objects.get_or_create(user=request.user)
            user_activity.last_activity = timezone.now()
            user_activity.save()
