package main

import (
    "fmt"
    "os/exec"
    "encoding/json"
    "crypto/md5"
    "net/http"
    "crypto/tls"
    "os"
)

func main() {
    // Command injection
    userInput := os.Args[1]
    cmd := exec.Command("sh", "-c", "ls -la " + userInput)
    cmd.Run()

    // Hardcoded secret
    password := "super_secret_123"
    fmt.Println(password)

    // MD5 hash
    data := []byte("test")
    hash := md5.Sum(data)
    fmt.Printf("%x\n", hash)

    // Insecure TLS
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: tr}
    _ = client

    // Debug output
    fmt.Println("Debug: starting application")
}
