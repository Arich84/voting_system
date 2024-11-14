# management/commands/check_superuser.py
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils.crypto import get_random_string

class Command(BaseCommand):
    help = "Ensures at least one superuser exists. Creates one if none exists or if all are inactive."

    def handle(self, *args, **kwargs):
        User = get_user_model()
        # Check for any superuser, regardless of active status
        superuser_exists = User.objects.filter(is_superuser=True).exists()

        if not superuser_exists:
            # No superusers exist, create one
            username = "admin"
            password = get_random_string(12)
            email = "admin@example.com"
            User.objects.create_superuser(username=username, email=email, password=password)
            self.stdout.write(self.style.SUCCESS(f"Superuser created with username: {username} and password: {password}"))
        else:
            # At least one superuser exists; check if any is active
            active_superuser_exists = User.objects.filter(is_superuser=True, is_active=True).exists()
            if not active_superuser_exists:
                # No active superusers; create a new one
                username = "admin"
                password = get_random_string(12)
                email = "admin@example.com"
                User.objects.create_superuser(username=username, email=email, password=password)
                self.stdout.write(self.style.SUCCESS(f"Superuser created with username: {username} and password: {password}"))
            else:
                self.stdout.write(self.style.NOTICE("An active superuser already exists."))
