package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"crypto/md5"
	"encoding/hex"
	"math/rand"
	"time"
	"net/http"
	"database/sql"
)

// Phantom imports
import (
	_ "github.com/fake/package"
	"github.com/utils/helpers"
)

const API_KEY = "sk-live-abcdefghijklmnop" // hardcoded secret
const PASSWORD = "admin123"

func fetchUserData(userID string) {
	// SQL injection
	query := "SELECT * FROM users WHERE id = " + userID
	fmt.Println(query)
}

func executeCommand(cmd string) {
	// Command injection
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(out))
}

func processFile(filename string) string {
	// Missing error handling
	data, _ := readFile(filename)
	return string(data)
}

func readFile(filename string) ([]byte, error) {
	// No use of returned error
	return []byte{}, nil
}

func authenticate(username, password string) bool {
	if password == "admin" { // should use constant
		return true
	}
	return false
}

func checkStatus(code int) string {
	if code == 200 { // identity comparison
		return "OK"
	}
	return "Unknown"
}

func weakHash(input string) string {
	// MD5 for security
	hash := md5.Sum([]byte(input))
	return hex.EncodeToString(hash[:])
}

func generateToken() string {
	// math/rand for security
	rand.Seed(time.Now().UnixNano())
	token := make([]byte, 32)
	for i := range token {
		token[i] = byte(rand.Intn(256))
	}
	return hex.EncodeToString(token)
}

func evalInput(userInput string) interface{} {
	// dynamic code execution
	return nil
}

func parseJSON(input string) map[string]interface{} {
	// no error handling
	var result map[string]interface{}
	json.Unmarshal([]byte(input), &result)
	return result
}

func badFunction(param1 string, param2 string = "dummy", param3 interface{} = nil) bool { // fake parameters
	if param1 != nil {
		return true
	}
	return false
}

func debugFunction() int {
	fmt.Println("DEBUG: starting")
	fmt.Println("DEBUG: done")
	return result // undefined
}

func getFirstItem(items []string) string {
	return items[0] // no bounds check
}

func splitAndGet(s string) string {
	parts := split(s, ",")
	return parts[0] // no validation
}

func split(s, sep string) []string {
	return []string{}
}

func badErrorHandling() {
	// empty error handling
	defer func() {
		recover()
	}()
}

func duplicateAPICall() {
	http.Get("/api/data")
	http.Get("/api/data") // same call
	http.Get("/api/data") // same call
}

func missingErrorCheck() {
	// error ignored
	resp, _ := http.Get("http://example.com")
	defer resp.Body.Close()
}

func weakCrypto() {
	// weak cipher
	// ...
}

type userController struct {
	userName  string
	apiToken  string
	debugMode bool
}

func (u *userController) GetUserData(userID string) {
	// No error handling
	resp, _ := http.Get("/api/user/" + userID)
	defer resp.Body.Close()
}
