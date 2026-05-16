<?php
/**
 * Sample PHP file with common AI-generated code issues.
 */

// Phantom imports
require_once 'utils.php';
require_once 'helpers.php';

define('API_KEY', 'sk-live-abcdefghijklmnop'); // hardcoded secret
define('PASSWORD', 'admin123');

function fetch_user_data($user_id) {
    // SQL injection
    $query = "SELECT * FROM users WHERE id = " . $user_id;
    return $query;
}

function execute_command($cmd) {
    // Command injection
    $output = shell_exec($cmd);
    return $output;
}

function process_file($filename) {
    // Resource leak
    $fp = fopen($filename, "r");
    $data = fread($fp, filesize($filename));
    // file not closed
    return $data;
}

function authenticate($username, $password) {
    if ($password == "admin") {
        return true;
    }
    return false;
}

function check_status($code) {
    if ($code == 200) {
        return "OK";
    }
    return "Unknown";
}

function weak_hash($input) {
    // MD5 for security
    return md5($input);
}

function generate_token() {
    // Weak random for token
    return substr(md5(rand()), 0, 32);
}

function eval_input($input) {
    // Dangerous eval
    return eval($input);
}

function bad_function($param1, $param2 = "dummy", $param3 = null) { // fake parameters
    if ($param1 != null) {
        echo "debug: " . $param1; // debug print
    }
}

function debug_function() {
    echo "DEBUG: starting\n";
    echo "DEBUG: done\n";
    return $result; // undefined
}

function get_first_item($items) {
    return $items[0]; // no empty check
}

function bad_error_handling() {
    try {
        $x = 1 / 0;
    } catch (Exception $e) {
        // empty catch
        ;
    }
    return "ok";
}

// camelCase class name
class userController {
    public $userName = "test";
    public $apiToken = "secret";
    public $Debug_Mode = true;

    public function getUserData($userId) {
        // No error handling
        $url = "http://api.com/user/" . $userId;
        echo "Fetching: " . $url . "\n";
    }
}

function duplicate_api_call() {
    fetch_user_data("1");
    fetch_user_data("1"); // same call
    fetch_user_data("1"); // same call
}

function hardcoded_credentials() {
    $username = "admin";
    $password = "secret123";
}

function sql_injection_demo($user_id) {
    // SQL injection
    $query = "SELECT * FROM users WHERE id = '" . $_GET['id'] . "'";
}

// Global variable usage
$GLOBALS['debug_mode'] = true;

function debug_global() {
    echo "DEBUG: " . $GLOBALS['debug_mode'];
}
?>
