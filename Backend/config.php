<?php
// Database Configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'webproject_db');
define('DB_CHARSET', 'utf8mb4');
define('DEFAULT_TIMEZONE', 'UTC');

// Security Configuration
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_TIMEOUT', 60);
define('SESSION_TIMEOUT', 86400);

// Error Reporting
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/php_errors.log');
error_reporting(E_ALL);

// Create database connection
$mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS);

// Check connection
if ($mysqli->connect_error) {
    error_log("Database connection failed: " . $mysqli->connect_error);
    die(json_encode([
        'status' => 'error',
        'message' => 'Database connection failed'
    ]));
}

// Create database if not exists
$stmt = $mysqli->prepare("CREATE DATABASE IF NOT EXISTS ?");
$stmt->bind_param("s", DB_NAME);
if (!$stmt->execute()) {
    error_log("Database creation failed: " . $mysqli->error);
    die(json_encode([
        'status' => 'error',
        'message' => 'Database setup failed'
    ]));
}
$stmt->close();

// Select database
$mysqli->select_db(DB_NAME);
if ($mysqli->error) {
    error_log("Database selection failed: " . $mysqli->error);
    die(json_encode([
        'status' => 'error',
        'message' => 'Database selection failed'
    ]));
}

// Create users table if not exists
$createTable = $mysqli->query("
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    login_attempts INT DEFAULT 0,
    account_locked_until TIMESTAMP NULL
) ENGINE=InnoDB DEFAULT CHARSET=" . DB_CHARSET);

if (!$createTable) {
    error_log("Table creation failed: " . $mysqli->error);
    die(json_encode([
        'status' => 'error',
        'message' => 'Table setup failed'
    ]));
}

// Set charset
$mysqli->set_charset(DB_CHARSET);

// Security Headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:");

// Session configuration
session_set_cookie_params([
    'lifetime' => SESSION_TIMEOUT,
    'path' => '/',
    'domain' => $_SERVER['HTTP_HOST'] ?? 'localhost',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);

class SecureSessionHandler extends SessionHandler {
    private static $encryption_key;
    
    public function __construct() {
        if (empty(self::$encryption_key)) {
            self::$encryption_key = openssl_random_pseudo_bytes(32);
        }
    }
    
    public function read(string $id): string|false {
        $data = parent::read($id);
        if (!$data) return '';
        
        try {
            return $this->decrypt($data);
        } catch (Exception $e) {
            error_log("Session decryption failed: " . $e->getMessage());
            return '';
        }
    }

    public function write(string $id, string $data): bool {
        try {
            $encrypted = $this->encrypt($data);
            return parent::write($id, $encrypted);
        } catch (Exception $e) {
            error_log("Session encryption failed: " . $e->getMessage());
            return false;
        }
    }

    private function encrypt(string $data): string {
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $encrypted = openssl_encrypt($data, 'aes-256-cbc', self::$encryption_key, 0, $iv);
        return base64_encode($iv . $encrypted);
    }

    private function decrypt(string $data): string {
        $data = base64_decode($data);
        $iv_length = openssl_cipher_iv_length('aes-256-cbc');
        $iv = substr($data, 0, $iv_length);
        $encrypted = substr($data, $iv_length);
        return openssl_decrypt($encrypted, 'aes-256-cbc', self::$encryption_key, 0, $iv);
    }
}

// Initialize secure session
$handler = new SecureSessionHandler();
session_set_save_handler($handler, true);
session_start();

// CSRF Token Generation
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Timezone
date_default_timezone_set(DEFAULT_TIMEZONE);

// Custom error handler
set_error_handler(function($severity, $message, $file, $line) {
    error_log("Error: $message in $file on line $line");
    
    if (error_reporting() & $severity) {
        http_response_code(500);
        if (ini_get('display_errors')) {
            echo json_encode([
                'status' => 'error',
                'message' => 'An error occurred',
                'details' => $message
            ]);
        }
    }
    return true;
});

// Shutdown function for clean up
register_shutdown_function(function() use ($mysqli) {
    if (isset($mysqli) && $mysqli instanceof mysqli) {
        $mysqli->close();
    }
});
?>