from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (CustomUser, Feedback, Captcha, RegistrationWindow, 
                     PreparationWindow, VotingWindow, 
                     Slide)


@admin.register(RegistrationWindow)
class RegistrationWindowAdmin(admin.ModelAdmin):
    list_display = ['start_time', 'end_time']

@admin.register(PreparationWindow)
class PreparationWindowAdmin(admin.ModelAdmin):
    list_display = ['start_time', 'end_time']

@admin.register(VotingWindow)
class VotingWindowAdmin(admin.ModelAdmin):
    list_display = ['start_time', 'end_time']

   

@admin.register(Slide)
class SlideAdmin(admin.ModelAdmin):
    list_display = ('title', 'is_active', 'created_at')
    list_filter = ('is_active',)
    search_fields = ('title',)


from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser  # Specify the model

    list_display = ('username', 'email', 'first_name', 'last_name', 'user_type', 'is_staff', 'is_active')
    list_filter = ('user_type', 'is_staff', 'is_active')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('username',)

    fieldsets = (
        (None, {
            'fields': ('username', 'email', 'first_name', 'last_name', 'password', 'matriculation_number'),
        }),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'groups', 'user_permissions', 'user_type'),  # Removed is_superuser
        }),
        ('Important dates', {
            'fields': ('last_login',),
        }),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'first_name', 'last_name', 'password1', 'password2', 'matriculation_number', 'is_active', 'is_staff', 'user_type'),
        }),
    )



@admin.register(Captcha)
class CaptchaAdmin(admin.ModelAdmin):
    list_display = ['captcha_text', 'created_at']
    search_fields = ['captcha_text']
    readonly_fields = ['created_at']




# app1/admin.py
from django.contrib import admin
from .models import Feedback

class FeedbackAdmin(admin.ModelAdmin):
    list_display = ('user', 'message', 'rating', 'get_response', 'is_resolved')

    def get_response(self, obj):
        return obj.response  # This assumes 'response' is a field on the model
    get_response.short_description = 'Response'  # This will be the column name in the admin

admin.site.register(Feedback, FeedbackAdmin)


from django.contrib import admin
from .models import Position, CandidateApplication

@admin.register(Position)
class PositionAdmin(admin.ModelAdmin):
    list_display = ('name',)





from django.contrib import admin
from .models import Announcement

@admin.register(Announcement)
class AnnouncementAdmin(admin.ModelAdmin):
    list_display = ('title', 'created_at')
    search_fields = ('title',)
    ordering = ('-created_at',)


# admin.py
from django.contrib import admin
from .models import CandidateApplication

class CandidateApplicationAdmin(admin.ModelAdmin):
    list_display = ('user', 'position', 'status', 'created_at')
    list_filter = ('status',)
    search_fields = ('user__username', 'position')
    actions = ['approve_candidates', 'reject_candidates']

    def approve_candidates(self, request, queryset):
        queryset.update(status='approved')  # Admin can approve multiple applications
    approve_candidates.short_description = "Approve selected candidates"

    def reject_candidates(self, request, queryset):
        queryset.update(status='rejected')  # Admin can reject multiple applications
    reject_candidates.short_description = "Reject selected candidates"

admin.site.register(CandidateApplication, CandidateApplicationAdmin)


