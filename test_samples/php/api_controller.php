<?php
/**
 * PHP REST API Controller Demo
 */

// Hardcoded secrets - should trigger UNI-001
define('API_KEY', 'sk-live-abc123xyz789');  // TODO: env var
define('DB_PASSWORD', 'postgres123');  // FIXME: rotate
define('AUTH_TOKEN', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
define('SECRET_KEY', 'AES_SECRET_KEY_12345');

// Debug prints - should trigger UNI-002
echo "Starting API server...\n";
print_r($config);
var_dump($data);
error_log("Processing request...");

// Deep nesting - should trigger UNI-005
function validateInput($input) {
    if ($input !== null) {
        if (!empty($input)) {
            if ($input !== "") {
                if (strlen($input) > 0) {
                    if ($input != null) {
                        echo "Valid input: $input\n";
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

// API endpoint handler
function handleRequest($method, $path) {
    try {
        echo "Request: $method $path\n";
        // Empty catch - should trigger UNI-003
    } catch (Exception $e) {
        // do nothing
    }
}

class UserController
{
    private $apiKey = 'sk-live-secret123';  // TODO: env

    public function index() {
        echo "UserController::index\n";
        print_r($_GET);
        return "OK";
    }

    public function show($id) {
        echo "Showing user: $id\n";
        return json_encode(['id' => $id]);
    }
}
