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
