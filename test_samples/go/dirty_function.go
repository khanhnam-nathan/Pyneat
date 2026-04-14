// Dirty Go - contains unused functions
package main

import "fmt"

// Never called
func unusedHelper() int {
    return 123
}

// IS used
func formatString(s string) string {
    return "Value: " + s
}

// Entry point - preserved
func main() {
    val := processValue("hello")
    fmt.Println(formatString(val))
}

// IS used
func processValue(input string) string {
    return input + " world"
}

// Unused function
func deepThought() int {
    return 42
}

// Exported - should be preserved
func GetConfig() map[string]string {
    return map[string]string{"debug": "false"}
}
