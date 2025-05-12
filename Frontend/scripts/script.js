// This script handles the login and signup functionality for the web application.
const API_BASE_URL = window.location.origin + '/backend';

// Initialize form event listeners
document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('loginForm');
  const signupForm = document.getElementById('signupForm');
  
  if (loginForm) {
    loginForm.addEventListener('submit', (e) => {
      e.preventDefault();
      handleLogin();
    });
  }
  
  if (signupForm) {
    signupForm.addEventListener('submit', (e) => {
      e.preventDefault();
      handleSignup();
    });
  }
});

// Shared validation functions
const validateEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const validatePassword = (pw) => pw.length >= 8;

function handleLogin() {
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value.trim();
  const submitBtn = document.querySelector('#loginForm button[type="submit"]');

  // Frontend validation
  if (!email || !password) {
    showAlert("Email and Password are required.", "error");
    return;
  }

  if (!validateEmail(email)) {
    showAlert("Invalid email format.", "error");
    return;
  }

  // Set loading state
  submitBtn.disabled = true;
  submitBtn.innerHTML = 'Logging in...';

  fetch(`${API_BASE_URL}/login.php`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
    credentials: 'include'
  })
  .then(handleApiResponse)
  .then(data => {
    if (data.status === "success") {
      showAlert("Login successful! Redirecting...", "success");
      setTimeout(() => {
        window.location.href = data.redirect || "/dashboard.html";
      }, 1000);
    }
  })
  .catch(error => {
    console.error("Login Error:", error);
    showAlert(error.message || "Login failed. Please try again.", "error");
  })
  .finally(() => {
    submitBtn.disabled = false;
    submitBtn.innerHTML = 'Sign In';
  });
}

function handleSignup() {
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value.trim();
  const confirmPassword = document.getElementById("confirmPassword").value.trim();
  const submitBtn = document.querySelector('#signupForm button[type="submit"]');

  // Validation
  if (!email || !password || !confirmPassword) {
    showAlert("All fields are required.", "error");
    return;
  }

  if (!validateEmail(email)) {
    showAlert("Invalid email format.", "error");
    return;
  }

  if (!validatePassword(password)) {
    showAlert("Password must be 8+ characters.", "error");
    return;
  }

  if (password !== confirmPassword) {
    showAlert("Passwords do not match.", "error");
    return;
  }

  // Set loading state
  submitBtn.disabled = true;
  submitBtn.innerHTML = 'Creating account...';

  fetch(`${API_BASE_URL}/signup.php`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, confirmPassword }),
    credentials: 'include'
  })
  .then(handleApiResponse)
  .then(data => {
    showAlert("Account created! Redirecting...", "success");
    setTimeout(() => {
      window.location.href = data.redirect || "/login.html";
    }, 1500);
  })
  .catch(error => {
    console.error("Signup Error:", error);
    showAlert(error.message || "Registration failed. Please try again.", "error");
  })
  .finally(() => {
    submitBtn.disabled = false;
    submitBtn.innerHTML = 'Sign Up';
  });
}

// Shared API response handler
function handleApiResponse(response) {
  if (!response.ok) {
    return response.json().then(err => {
      throw new Error(err.message || 'Request failed');
    });
  }
  return response.json();
}

// Improved alert function
function showAlert(message, type = 'error') {
  // Remove existing alerts
  document.querySelectorAll('.custom-alert').forEach(el => el.remove());

  const alertDiv = document.createElement('div');
  alertDiv.className = `custom-alert ${type}`;
  alertDiv.innerHTML = `
    <span>${message}</span>
    <button class="alert-close">&times;</button>
  `;

  document.body.appendChild(alertDiv);

  // Add close functionality
  alertDiv.querySelector('.alert-close').addEventListener('click', () => {
    alertDiv.remove();
  });

  // Auto-remove after 5s
  setTimeout(() => alertDiv.classList.add('fade-out'), 4500);
  setTimeout(() => alertDiv.remove(), 5000);
}