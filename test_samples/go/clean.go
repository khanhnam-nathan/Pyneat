// Clean Go test file
// This file contains NO issues - should produce 0 false positives.

package main

import "fmt"

// Used function
func Add(a, b int) int {
    return a + b
}

// Exported - should be preserved
func Multiply(x, y int) int {
    return x * y
}

// Entry point
func main() {
    result := Calculate(3, 4)
    fmt.Println("Result:", result)
}

// Used function
func Calculate(a, b int) int {
    return Add(a, b) + Multiply(a, b)
}
