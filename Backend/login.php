<?php
require_once __DIR__ . '/config.php';

// Set headers for JSON response
header("Content-Type: application/json");

// Only accept POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); // Method Not Allowed
    echo json_encode(['status' => 'error', 'message' => 'Only POST method is allowed']);
    exit;
}

// Get and sanitize input data
$rawData = file_get_contents('php://input');
$data = json_decode($rawData, true);

if (json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400); // Bad Request
    echo json_encode(['status' => 'error', 'message' => 'Invalid JSON data']);
    exit;
}

$email = filter_var($data['email'] ?? '', FILTER_SANITIZE_EMAIL);
$password = $data['password'] ?? '';

// Input validation
if (empty($email) || empty($password)) {
    http_response_code(400); // Bad Request
    echo json_encode(['status' => 'error', 'message' => 'Email and password are required']);
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400); // Bad Request
    echo json_encode(['status' => 'error', 'message' => 'Invalid email format']);
    exit;
}

// Rate limiting - simple implementation
session_start();
$loginAttempts = $_SESSION['login_attempts'] ?? 0;
$lastAttempt = $_SESSION['last_attempt'] ?? 0;

if (time() - $lastAttempt < 60 && $loginAttempts >= 5) {
    http_response_code(429); // Too Many Requests
    echo json_encode(['status' => 'error', 'message' => 'Too many login attempts. Please wait 1 minute.']);
    exit;
}

try {
    // Prepare statement to prevent SQL injection
    $stmt = $mysqli->prepare("SELECT id, email, password FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        // User doesn't exist
        $_SESSION['login_attempts'] = $loginAttempts + 1;
        $_SESSION['last_attempt'] = time();
        
        http_response_code(401); // Unauthorized
        echo json_encode(['status' => 'error', 'message' => 'Invalid credentials']);
        exit;
    }
    
    $user = $result->fetch_assoc();
    
    if (password_verify($password, $user['password'])) {
        // Successful login
        
        // Regenerate session ID to prevent fixation
        session_regenerate_id(true);
        
        // Clear login attempts
        unset($_SESSION['login_attempts']);
        unset($_SESSION['last_attempt']);
        
        // Set session variables
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['email'] = $user['email'];
        $_SESSION['logged_in'] = true;
        $_SESSION['last_activity'] = time();
        
        // Set secure session cookie
        session_set_cookie_params([
            'lifetime' => 86400, // 1 day
            'path' => '/',
            'domain' => $_SERVER['HTTP_HOST'],
            'secure' => true,    // Requires HTTPS
            'httponly' => true,  // Prevent JavaScript access
            'samesite' => 'Strict' // CSRF protection
        ]);
        
        // Success response
        echo json_encode([
            'status' => 'success',
            'message' => 'Login successful',
            'redirect' => '/dashboard.html',
            'user' => [
                'id' => $user['id'],
                'email' => $user['email']
            ]
        ]);
    } else {
        // Wrong password
        $_SESSION['login_attempts'] = $loginAttempts + 1;
        $_SESSION['last_attempt'] = time();
        
        http_response_code(401); // Unauthorized
        echo json_encode(['status' => 'error', 'message' => 'Invalid credentials']);
    }
} catch (Exception $e) {
    // Log the error for debugging
    error_log('Login error: ' . $e->getMessage());
    
    http_response_code(500); // Internal Server Error
    echo json_encode([
        'status' => 'error',
        'message' => 'An error occurred during login. Please try again.'
    ]);
} finally {
    if (isset($stmt)) {
        $stmt->close();
    }
}
?>