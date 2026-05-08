package main

import (
    "fmt"
    "os/exec"
    "database/sql"
)

func main() {
    // Command Injection - GO-SEC-001
    cmd := exec.Command("sh", "-c", "ls -la " + userInput)
    
    // SQL Injection - GO-SEC-002
    query := "SELECT * FROM users WHERE id = " + userId
    
    // Hardcoded Secret - GO-SEC-004
    password := "super_secret_123"
    apiKey := "AKIAIOSFODNN7EXAMPLE"
    
    // Insecure TLS - GO-SEC-006
    tlsConfig := &tls.Config{InsecureSkipVerify: true}
    
    // MD5 Hash - GO-SEC-012
    hash := md5.New()
}
