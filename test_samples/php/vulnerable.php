<?php
// ==================== PHP-SEC-001: Code Injection (CRITICAL) ====================

// eval with user input
$code = $_GET['code'];
eval($code);
// Line: eval with user input

// include with user input
$page = $_GET['page'];
include($page . '.php');
// Line: include with user input

// create_function (deprecated)
$func = create_function('$x', 'return $x + ' . $_POST['expr'] . ';');
// Line: create_function code injection

// preg_replace /e (code execution)
$text = preg_replace('/\[b\](.*?)\[\/b\]/e', 'stripslashes("$1")', $text);
// Line: preg_replace /e code injection

// ==================== PHP-SEC-002: SQL Injection (CRITICAL) ====================

// mysqli_query with concat
$name = $_GET['name'];
$query = "SELECT * FROM users WHERE name = '" . $name . "'";
mysqli_query($conn, $query);
// Line: mysqli_query SQL injection

// PDO query with concat
$id = $_POST['id'];
$stmt = $pdo->query("SELECT * FROM products WHERE id = " . $id);
// Line: PDO query SQL injection

// ==================== PHP-SEC-003: Unsafe Deserialization (CRITICAL) ====================

// unserialize with user input
$data = $_COOKIE['user_data'];
$obj = unserialize($data);
// Line: unserialize RCE

// unserialize variable
$serialized = $_POST['data'];
$result = unserialize($serialized);
// Line: unserialize object injection

// ==================== PHP-SEC-004: Command Injection (CRITICAL) ====================

// system with user input
$host = $_GET['host'];
system('ping -c 4 ' . $host);
// Line: system command injection

// shell_exec with user input
$file = $_POST['filename'];
$output = shell_exec('cat ' . $file);
// Line: shell_exec command injection

// ==================== PHP-SEC-005: XSS (HIGH) ====================

// echo user input directly
echo $_GET['name'];
// Line: reflected XSS

// header injection
$redirect = $_GET['url'];
header("Location: " . $redirect);
// Line: header injection CRLF

// ==================== PHP-SEC-006: Path Traversal / LFI (HIGH) ====================

// file_get_contents with user input
$file = $_GET['file'];
$data = file_get_contents('/var/www/' . $file);
// Line: path traversal

// include with user input
include('pages/' . $_GET['page'] . '.php');
// Line: LFI path traversal

// ==================== PHP-SEC-007: Hardcoded Secrets (HIGH) ====================

define('API_KEY', 'sk-live-abc123xyz456secret789key12345'); // Line: hardcoded API key
define('AWS_KEY', 'AKIAIOSFODNN7EXAMPLE');                  // Line: hardcoded AWS key
$GITHUB_TOKEN = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; // Line: hardcoded GitHub token
$db_password = 'MySecretPass123!';                          // Line: hardcoded password

// ==================== PHP-SEC-008: Weak Crypto (MEDIUM) ====================

// md5 for passwords
$hash = md5($password);
// Line: md5 weak crypto

// sha1 deprecated
$sig = sha1($data);
// Line: sha1 deprecated

// ==================== Clean code (no issues) ====================

$safe_query = "SELECT * FROM users WHERE id = ?";
$stmt = $pdo->prepare($safe_query);
$stmt->execute([$user_id]);
// Parameterized - safe

$safe_hash = password_hash($password, PASSWORD_DEFAULT);
// password_hash - safe

$safe_file = basename($_GET['file']);
include('pages/' . $safe_file . '.php');
// basename sanitized - safe
