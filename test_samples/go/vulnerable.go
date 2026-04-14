package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"strings"
)

// ==================== GO-SEC-001: Command Injection (CRITICAL) ====================

func runCommand(userInput string) {
	cmd := exec.Command("sh", "-c", "ls "+userInput)
	_ = cmd
	// Line: exec.Command with concat
}

// ==================== GO-SEC-002: SQL Injection (CRITICAL) ====================

func queryDB(userName string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userName)
	_ = query
	// Line: SQL injection fmt.Sprintf

	query2 := fmt.Sprintf("SELECT * FROM orders WHERE id = '%s'", userName)
	_ = query2
	// Line: SQL concat
}

// ==================== GO-SEC-003: Hardcoded Secrets (HIGH) ====================

const API_KEY = "sk-live-abc123xyz456secret789key12345"
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
const GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

var dbPassword = "MySecretPass123!"
var jwtSecret = "super_secret_jwt_key"
var authToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"

// ==================== GO-SEC-004: Path Traversal (HIGH) ====================

func readFile(userPath string) {
	data, _ := ioutil.ReadFile(userPath + "/data.txt")
	_ = data
	// Line: ioutil.ReadFile path traversal
}

// ==================== GO-SEC-005: Weak Crypto (MEDIUM) ====================

func hashPassword(password string) string {
	h := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", h)
	// Line: MD5 weak crypto
}

func generateToken() string {
	n, _ := rand.Int(rand.Reader, 1000000)
	return fmt.Sprintf("%d", n)
	// Line: rand.Intn not crypto secure
}

func generateRSA() {
	_, _ = rsa.GenerateKey(rand.Reader, 1024)
	// Line: 1024-bit RSA weak
}

// ==================== GO-SEC-006: SSRF (HIGH) ====================

func fetchURL(userURL string) {
	resp, err := http.Get("https://api.example.com/" + userURL)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()
	_ = resp
	// Line: SSRF http.Get
}

// ==================== GO-SEC-007: Insecure Cookie (MEDIUM) ====================

func setCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   "session",
		Value:  "abc123",
		Secure: false,
	}
	http.SetCookie(w, cookie)
	// Line: insecure cookie Secure=false
}

// ==================== GO-SEC-008: Information Disclosure (LOW) ====================

func logData(password string) {
	log.Println("Password:", password)
	log.Printf("Secret: %s", jwtSecret)
	// Line: log sensitive data
}

// ==================== Clean code (no issues) ====================

func safeQuery(userID string) {
	// Use parameterized queries: db.Query("SELECT * FROM users WHERE id = $1", userID)
}

func safeHash(password string) string {
	h := sha256.Sum256([]byte(password))
	return fmt.Sprintf("%x", h)
}

func safeToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func safeRedirect(userURL string) {
	if !strings.HasPrefix(userURL, "https://trusted.com/") {
		return
	}
	_ = userURL
}
