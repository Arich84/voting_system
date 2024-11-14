
document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('form');
    form.addEventListener('submit', function(event) {
        event.preventDefault();

        const nameInput = document.getElementById('name');
        const emailInput = document.getElementById('email');
        const passwordInput = document.getElementById('password');

        // Perform client-side validation
        if (nameInput.value.trim() === '') {
            alert('Please enter your name.');
            return;
        }

        if (emailInput.value.trim() === '') {
            alert('Please enter your email.');
            return;
        }

        if (passwordInput.value.trim() === '') {
            alert('Please enter a password.');
            return;
        }

        // If validation passes, submit the form
        form.submit();
    });
});



{% extends 'base.html' %}


{% block scripts %}
<script src="{% static 'js/register.js' %}"></script>
{% endblock %}