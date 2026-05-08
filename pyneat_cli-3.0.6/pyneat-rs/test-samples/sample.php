// // Debug output // FIXME: removed debug output<?php
// SQL Injection test
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $user_id;
$result = mysqli_query($conn, $query);

// XSS test
// echo $_POST['name']; // FIXME: removed debug output
// Command injection
$file = $_GET['file'];
exec("cat " . $file);

// Hardcoded secret
// $password = "super_secret_123"; // FIXME: removed debug output
// Debug output
// echo "Debug: starting..."; // FIXME: removed debug output// var_dump($data); // FIXME: removed debug output); // FIXME: removed debug output
// Eval usage
eval($_POST['code']);

// Weak hashing
// $hash = md5($password); // FIXME: removed debug output
// Object injection
$data = unserialize($_COOKIE['user_data']);
?>
