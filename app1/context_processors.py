from .models import Notification

# In context_processors.py
from django.contrib.auth.models import AnonymousUser

def user_role(request):
    user = request.user
    if isinstance(user, AnonymousUser):  # Handle cases where user isn't logged in
        return {'is_superuser': False, 'is_staff': False}
    return {
        'is_superuser': user.is_superuser,
        'is_staff': user.is_staff,
    }


# context_processors.py

def role_based_notifications(request):
    if request.user.is_authenticated:
        unread_count = request.user.notifications.filter(is_read=False).count()
        return {
            'unread_notifications': unread_count
        }
    return {}


