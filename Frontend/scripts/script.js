// This script handles the login and signup functionality for the web application.
function handleLogin() {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  if (!email || !password) {
    alert("Email and Password are required.");
    return;
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    alert("Invalid email format.");
    return;
  }

  // Make the POST request to the backend (assuming it's running on localhost:3000)
  fetch("http://localhost:3000/api/user/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ email, password })
  })
    .then(response => response.json())
    .then(data => {
      if (data.status === "success") {
        window.location.href = "/"; // Redirect to home page
      } else {
        alert("Login failed. Invalid email or password.");
      }
    })
    .catch(error => {
      console.error("Error:", error);
      alert("Unable to login. Please try again later.");
    });
}

function oauthSignIn(provider) {
  // Implement OAuth logic (redirect to OAuth provider)
  alert(`Sign in with ${provider}`);
}



function handleSignup() {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  const confirmPassword = document.getElementById("confirmPassword").value;

  // Validate the form inputs
  if (!email || !password || !confirmPassword) {
    alert("All fields are required.");
    return;
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    alert("Invalid email format.");
    return;
  }

  if (password !== confirmPassword) {
    alert("Passwords do not match.");
    return;
  }

  // Make the POST request to the backend
  fetch("http://localhost:3000/api/user/register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ email, password })
  })
    .then(response => response.json())
    .then(data => {
      if (data.status === "success") {
        alert("Account created successfully!");
        window.location.href = "/signIn.html";
      } else {
        alert("Registration failed. Please try again.");
      }
    })
    .catch(error => {
      console.error("Error:", error);
      alert("Unable to register. Please try again later.");
    });
}
