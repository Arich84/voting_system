from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard_redirect, name='dashboard_redirect'),
    path('get_remaining_time/', views.get_remaining_time, name='get_remaining_time'),
    path('about/', views.about, name='about'),
    path('rules/', views.rules, name='rules'),
    path('Candi/', views.candidates_view, name='candidates'),  # Example URL for candidates
    path('profile/', views.user_profile, name='user_profile'),  # For authenticated users
    path('update-profile/', views.update_profile, name='update_profile'),

    path('login/', views.loginme, name='loginme'),
    path('logout/', views.logoutme, name='logout'),
    path('verify-otp/', views.verify_otp_view, name='verify_otp_view'),
    path('resend_otp/', views.resend_otp_view, name='resend_otp_view'),  # Add this line
    path('password-reset/', views.password_reset_request_view, name='password_reset_request_view'),
    path('reset-password/', views.reset_password_view, name='reset_password_view'),
    path('generate_captcha_text/', views.generate_captcha_text, name='generate_captcha_text'),
    path('compare database/', views.user_input, name='user_input'),
    path('change-password/', views.change_password, name='change_password'),
    path('captcha-management/', views.captcha_management, name='captcha_management'),
    path('Edit program and level/', views.insert_program_and_level, name='insert_program_and_level'),


 
   
    #User dashboard
    path('register/', views.register, name='register'),
    path('registration/closed/', views.registration_closed_view, name='registration_closed'),
    path('user_dashboard/', views.user_dashboard, name='user_dashboard'),
    path('update-profile-image/', views.update_profile_image_page, name='update_profile_image_page'),
    path('remove-profile-image/', views.remove_profile_image, name='remove_profile_image'),
    path('edit-profile/', views.edit_profile, name='edit_profile_page'),
    path('update_cover_image/', views.update_cover_image, name='update_cover_image'),

    # Voting action
   path('election-results/', views.election_results, name='election_results'),
    path('generate_pdf/', views.generate_pdf, name='generate_pdf'),
    path('past-elections/', views.past_elections, name='past_elections'),
    path('current-votes/', views.current_votes, name='current_votes'),
    path('vote/<int:candidate_id>/', views.vote, name='vote'),
    path('vote/<int:candidate_id>/', views.vote, name='views.vote'),
    path('vote-results/', views.vote_results, name='vote_results'),
    path('get_live_results/', views.get_live_results, name='get_live_results'),
    path('vote/<int:candidate_id>/', views.vote, name='vote'),  
    path('vote/', views.vote_page, name='vote_page'),
    path('can/', views.candidates_list, name='candidates_list'),
    path('manage-positions/', views.manage_positions, name='manage_positions'),
    path('edit-position/<int:position_id>/', views.edit_position, name='edit_position'),
    path('positions/delete/<int:position_id>/', views.delete_position, name='delete_position'), 
    path('view vote/', views.voting_dashboard, name='voting_dashboard'),
    path('api/candidate-voting-statistics/', views.candidate_voting_statistics, name='candidate_voting_statistics'),
    path('api/position-voting-statistics/', views.position_voting_statistics, name='position_voting_statistics'),
    path('voting-data/', views.voting_data, name='voting-data'), 
    path('live_vote_results/', views.live_vote_results, name='live_vote_results'),
    path('approve_application/<int:application_id>/', views.approve_application, name='approve_application'),
    path('reject_application/<int:application_id>/', views.reject_application, name='reject_application'),
    path('delete_application/<int:application_id>/', views.delete_application, name='delete_application'),
    path('admin applications/', views.admin_view_candidate_applications, name='admin_view_candidate_applications'),
    path('applications/approve/<int:application_id>/', views.approve_application, name='approve_application'),
    path('applications/reject/<int:application_id>/', views.reject_application, name='reject_application'),
    path('applications/delete/<int:application_id>/', views.delete_application, name='delete_application'),
    path('apply/', views.apply_to_be_candidate, name='apply_to_be_candidate'),
    # path('application_submitted/', views.application_submitted, name='application_submitted'),   
    path('approved_candidates', views.candidates_view, name='approved_candidates'),
    path('vote/', views.vote_view, name='vote'),
    # path('vote_success/', views.vote_success, name='vote_success'),  
    # path('already_voted/', views.already_voted, name='already_voted'),  
    path('results/', views.results_view, name='results'),
    path('admin/candidate/<int:candidate_id>/approve/', views.approve_candidate, name='approve_candidate'),
    path('vote/<int:candidate_id>/', views.vote, name='vote'),
    path('admin_results/', views.admin_results, name='admin_results'),
    path('Election phase/', views.custom_admin_view, name='custom_admin_view'),
    path('slide/', views.custom_admin_image, name='custom_admin_image'),


#message# 
    path('messages/', views.messages_overview, name='messages_overview'),
    path('search-users/', views.search_users, name='search_users'),
    path('messages/<int:user_id>/', views.send_and_view_messages, name='send_and_view_messages'),
    path('check_notifications/', views.check_notifications, name='check_notifications'),
   # Feedback section
    path('user-feedback/', views.user_feedback_page, name='user_feedback_page'),
    path('feedback-chat/<int:feedback_id>/', views.feedback_chat, name='feedback_chat'),
    path('admin-feedback/', views.admin_feedback_page, name='admin_feedback_page'),
    path('feedback/chat/<int:feedback_id>/', views.feedback_chat, name='feedback_chat'),
  #  path('delete_message/<int:message_id>/', views.delete_message, name='delete_message'),
     path('delete_feedback/<int:feedback_id>/', views.delete_feedback, name='delete_feedback'),
   
    path('feedback_chat/<int:feedback_id>/', views.feedback_chat, name='feedback_chat'),
    # path('respond_to_feedback/<int:feedback_id>/', views.respond_to_feedback, name='respond_to_feedback'),
    # path('feedback-chat/<int:feedback_id>/', views.feedback_chat, name='feedback_chat'),
    #  path('feedback-chat/<int:feedback_id>/', views.feedback_chat, name='feedback_chat'),
    # path('respond-feedback/<int:feedback_id>/', views.respond_to_feedback, name='respond_to_feedback'),
    # # URL for deleting a feedback item (accessible to admins and feedback owners)
    path('delete-feedback/<int:feedback_id>/', views.delete_feedback, name='delete_feedback'),
    
   

    # Admin 
    path('register-admin/', views.register_admin, name='register_admin'),
    path('admin/users/', views.admin_users, name='admin_users'),
    path('results/', views.admin_results, name='admin_results'),
    path('admin_dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin/approve-candidate/<int:candidate_id>/', views.approve_candidate, name='approve_candidate'),

    path('admin/users/delete/<int:user_id>/', views.delete_user, name='delete_user'),
    #  path('admin/users/mark-valid/<int:user_id>/', views.mark_valid, name='mark_valid'),
    # path('admin/users/mark-invalid/<int:user_id>/', views.mark_invalid, name='mark_invalid'),
    path('admin/comparison_data/', views.view_comparison_data, name='view_comparison_data'),
    # path('candidates/manage/', views.candidate_management, name='candidate_management'),
   
    path('admin/user/<int:user_id>/mark_valid/', views.mark_user_valid, name='mark_valid'),
    path('admin/user/<int:user_id>/mark_invalid/', views.mark_user_invalid, name='mark_invalid'),
    path('admin/user/<int:user_id>/delete/', views.delete_user, name='delete_user'),
   
    #Superuser
    path('superuser_dashboard/', views.superuser_dashboard, name='superuser_dashboard'),
    path('manage roles/', views.manage_roles, name='manage_roles'),
    path('superuser management/', views.superuser_management, name='superuser_management'),
    path('admin management/', views.admin_management, name='admin_management'),
    path('user management/', views.user_management, name='user_management'),
    path('undelete_user/<int:user_id>/', views.undelete_user, name='undelete_user'),
    path('clear_recent_activities/', views.clear_recent_activities, name='clear_recent_activities'),  
    path('delete_user/<int:user_id>/', views.delete_user, name='delete_user'),
    path('mark_valid/<int:user_id>/', views.mark_user_valid, name='mark_valid'),
    path('mark_invalid/<int:user_id>/', views.mark_user_invalid, name='mark_invalid'),
    path('register-superuser/', views.register_superuser, name='register_superuser'),

 
    # notifcation
    path('delete-notification/', views.delete_notification, name='delete_notification'),
    path('check-notifications/', views.get_unread_notifications_count, name='check_notifications'),
    path('notifications/', views.notifications, name='notifications'),
    path('mark-notifications-as-read/', views.mark_notifications_as_read, name='mark_notifications_as_read'),

    #Announcement
    path('Announcement/', views.create_announcement, name='create_announcement'),
    path('edit-announcement/<int:announcement_id>/', views.edit_announcement, name='edit_announcement'),
    path('delete-announcement/<int:announcement_id>/', views.delete_announcement, name='delete_announcement'),
   



]
