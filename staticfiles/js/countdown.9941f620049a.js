// Countdown Timer Script
const countdown = document.getElementById('countdown');
let daysElement = document.getElementById('days');
let hoursElement = document.getElementById('hours');
let minutesElement = document.getElementById('minutes');
let secondsElement = document.getElementById('seconds');

// Initial time values (replace with dynamic data from the server)
let remainingDays = parseInt(daysElement.innerHTML);
let remainingHours = parseInt(hoursElement.innerHTML);
let remainingMinutes = parseInt(minutesElement.innerHTML);
let remainingSeconds = parseInt(secondsElement.innerHTML);

function updateCountdown() {
    if (remainingSeconds === 0) {
        if (remainingMinutes === 0) {
            if (remainingHours === 0) {
                if (remainingDays === 0) {
                    clearInterval(timer);
                } else {
                    remainingDays -= 1;
                    remainingHours = 23;
                    remainingMinutes = 59;
                    remainingSeconds = 59;
                }
            } else {
                remainingHours -= 1;
                remainingMinutes = 59;
                remainingSeconds = 59;
            }
        } else {
            remainingMinutes -= 1;
            remainingSeconds = 59;
        }
    } else {
        remainingSeconds -= 1;
    }

    daysElement.innerHTML = remainingDays;
    hoursElement.innerHTML = remainingHours;
    minutesElement.innerHTML = remainingMinutes;
    secondsElement.innerHTML = remainingSeconds;
}

let timer = setInterval(updateCountdown, 1000);
