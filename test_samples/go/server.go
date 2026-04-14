package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "regexp"
)

// Hardcoded secrets - should trigger UNI-001
const DB_PASSWORD = "postgres123"     // TODO: use env var
const API_KEY = "sk-live-abc123xyz"  // FIXME: rotate key
const SECRET_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

var config = map[string]string{
    "db_host":     "localhost",
    "db_password": "admin", // TODO: env var
}

func main() {
    fmt.Println("Starting server...")
    fmt.Printf("DB_PASSWORD: %s\n", DB_PASSWORD)

    http.HandleFunc("/", handler)
    http.ListenAndServe(":8080", nil)
}

func handler(w http.ResponseWriter, r *http.Request) {
    fmt.Println("Request:", r.URL.Path)
    fmt.Printf("Headers: %v\n", r.Header)

    // Unchecked error - should trigger GO-001
    _, _ = fmt.Fprintf(w, "Hello")

    // Deep nesting - should trigger UNI-005
    if r.Method != "" {
        if r.Method == "POST" {
            if r.URL.Path != "" {
                if r.URL.Path == "/api" {
                    fmt.Println("API endpoint")
                }
            }
        }
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// validateEmail with deep nesting
func validateEmail(email string) bool {
    if email != "" {
        matched, _ := regexp.MatchString(`^[^@]+@[^@]+$`, email)
        if matched {
            if len(email) > 0 {
                if email != "" {
                    fmt.Println("Valid email:", email)
                    return true
                }
            }
        }
    }
    return false
}
