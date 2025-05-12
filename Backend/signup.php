<?php
// Enable error reporting
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/config.php';

// Set headers for JSON response
header("Content-Type: application/json");

// Only accept POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Only POST method is allowed']);
    exit;
}

// Get and decode input data
$rawData = file_get_contents('php://input');
$data = json_decode($rawData, true);

if ($data === null || json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid JSON data']);
    exit;
}

// Input validation
$email = filter_var($data['email'] ?? '', FILTER_SANITIZE_EMAIL);
$password = $data['password'] ?? '';
$confirmPassword = $data['confirmPassword'] ?? '';

$errors = [];

if (empty($email)) {
    $errors[] = 'Email is required';
} elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'Invalid email format';
}

if (empty($password)) {
    $errors[] = 'Password is required';
} elseif (strlen($password) < 8) {
    $errors[] = 'Password must be at least 8 characters';
}

if ($password !== $confirmPassword) {
    $errors[] = 'Passwords do not match';
}

if (!empty($errors)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => implode(', ', $errors)]);
    exit;
}

try {
    // Check if user exists
    $checkStmt = $mysqli->prepare("SELECT id FROM users WHERE email = ?");
    $checkStmt->bind_param("s", $email);
    $checkStmt->execute();
    $checkStmt->store_result();
    
    if ($checkStmt->num_rows > 0) {
        http_response_code(409);
        echo json_encode(['status' => 'error', 'message' => 'Email already registered']);
        exit;
    }
    
    // Hash password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    
    // Insert new user
    $insertStmt = $mysqli->prepare("INSERT INTO users (email, password) VALUES (?, ?)");
    $insertStmt->bind_param("ss", $email, $hashedPassword);
    
    if ($insertStmt->execute()) {
        // Success response
        http_response_code(201);
        echo json_encode([
            'status' => 'success',
            'message' => 'Registration successful',
            'user' => [
                'id' => $insertStmt->insert_id,
                'email' => $email
            ]
        ]);
    } else {
        throw new Exception('Database insertion failed');
    }
} catch (Exception $e) {
    error_log('Registration error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Registration failed']);
} finally {
    if (isset($checkStmt)) $checkStmt->close();
    if (isset($insertStmt)) $insertStmt->close();
}