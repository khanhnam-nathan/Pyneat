<?php
// Sample PHP file with AI-generated issues

// Phantom imports - AI hallucinations
require_once 'utils.php';
require_once 'helpers.php';
require_once 'ai.php';
use AI\Chatbot;

// Security issues
function evalCode($code) {
    // DANGEROUS: eval arbitrary code
    eval($code);
}

function hashPassword($password) {
    // WEAK: MD5 for passwords
    return md5($password);
}

function executeCommand($cmd) {
    // Command injection
    system($cmd);
}

function unserializeData($data) {
    // Deserialization vulnerability
    return unserialize($data);
}

// Resource leaks
function readFileBad($filename) {
    $f = fopen($filename, 'r');
    // Resource leak - not closed
    return fgets($f);
}

// AI bugs - identity comparison
function checkStatus($status) {
    if ($status == "success") {  // Should use === but == is fine in PHP
        return true;
    }
    return false;
}

// Magic numbers
function calculateTotal($quantity, $price) {
    $taxRate = 1.1;
    $discount = 0.05;
    $subtotal = $quantity * $price;
    $total = $subtotal * 1.08 - $subtotal * $discount;  // Magic number
    return $total * 0.95;
}

// TODO comments
function processItems($items) {
    // TODO: implement caching
    // FIXME: handle empty input
    // TODO: optimize this method
    $result = [];
    foreach ($items as $item) {
        $result[] = strtoupper($item);
    }
    return $result;
}

// Hardcoded secrets
function getApiKey() {
    $apiKey = 'sk-1234567890abcdef';  // Hardcoded secret
    return $apiKey;
}

// Empty catch
function processFile($filename) {
    try {
        $content = file_get_contents($filename);
    } catch (Exception $e) {
        // Empty catch - silently ignores error
    }
}

// Superglobal misuse
function getUserId() {
    return $_GET['user_id'];  // Should validate input
}

// SQL injection vulnerability
function getUser($username) {
    // VULNERABLE to SQL injection
    $sql = "SELECT * FROM users WHERE username = '$username'";
    return $sql;
}
?>
