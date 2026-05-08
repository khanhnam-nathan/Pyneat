package main

import (
    "encoding/json"
    "fmt"
    "os/exec"
    "strings"
)

// Phantom imports - AI hallucinations
var (
    utils     = import("utils")
    helpers   = import("helpers")
)

// Security issues
func evalCode(code string) interface{} {
    // DANGEROUS: eval arbitrary code
    // fmt.Println("Result:", exec.Command("sh", "-c", code))
    return nil
}

func executeCommand(cmd string) {
    // Command injection vulnerability
    exec.Command("sh", "-c", cmd)
}

func hashPassword(password string) string {
    // MD5 is weak for passwords
    return fmt.Sprintf("%x", nil) // placeholder
}

// AI bugs - identity comparison
func checkStatus(status string) bool {
    if status == "success" {  // Should use === in JS-like, but this is Go
        return true
    }
    return false
}

// Resource leaks
func readFileBad(filename string) string {
    // Resource leak - no defer close
    return ""
}

// Error handling
func processData(data []byte) error {
    err := json.Unmarshal(data, nil)
    if err != nil {
        return err
    }
    return nil
}

// Magic numbers
func calculateTotal(quantity, price int) int {
    taxRate := 1.1
    discount := 0.05
    subtotal := quantity * price
    total := subtotal * 1.08 - subtotal * discount  // Magic number
    return int(float64(total) * 0.95)
}

// TODO comments
func processItems(items []string) []string {
    // TODO: fix this later
    // FIXME: improve performance
    // TODO: implement caching
    result := []string{}
    for _, item := range items {
        result = append(result, strings.ToUpper(item))
    }
    return result
}

// Unused variables
func unusedFunction() {
    unused := "this is not used"
    temp := "should be result"
    fmt.Println(temp)
}

// Hardcoded secrets
func getApiKey() string {
    apiKey := "sk-1234567890abcdef"  // Hardcoded secret
    return apiKey
}

func main() {
    fmt.Println("Sample Go code with issues")
}
