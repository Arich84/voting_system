// Get the theme toggle switch
const themeToggle = document.querySelector('.theme-switch');

// Function to switch themes
const switchTheme = () => {
    document.body.classList.toggle('dark-mode');
    // Update the localStorage with the current theme
    if (document.body.classList.contains('dark-mode')) {
        localStorage.setItem('theme', 'light');
    } else {
        localStorage.setItem('theme', 'dark');
    }
};

// Event listener for theme toggle switch
themeToggle.addEventListener('change', switchTheme);

// Function to check and apply the saved theme on page load
const applySavedTheme = () => {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'light') {
        document.body.classList.add('dark-mode');
        themeToggle.checked = true; // Set the toggle switch to checked if dark mode is saved
    }
};

// Apply saved theme on page load
document.addEventListener('DOMContentLoaded', applySavedTheme);


