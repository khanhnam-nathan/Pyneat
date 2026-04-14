/**
 * Express.js application - demo file
 * Real source from expressjs/express
 */

var express = require('express');
var app = express();

// Hardcoded secrets - should trigger UNI-001
var DB_PASSWORD = "admin123";  // TODO: move to env var
var API_KEY = "sk-live-abc123xyz456secret789key";  // FIXME: use env
var SECRET_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

// Debug prints - should trigger UNI-002
console.log("Starting server...");
console.log("DB_PASSWORD loaded:", DB_PASSWORD ? "yes" : "no");
debugger;

app.get('/', function(req, res) {
    console.log("GET / called");
    res.send('Hello World');
});

app.post('/login', function(req, res) {
    // Empty catch - should trigger UNI-003
    try {
        var password = req.body.password;
        // Deep nesting - should trigger UNI-005
        if (password) {
            if (password.length > 0) {
                if (password !== "") {
                    if (password !== null) {
                        if (password !== undefined) {
                            // deep
                            console.log("Processing login for:", req.body.username);
                        }
                    }
                }
            }
        }
    } catch (e) {
        // empty catch - BAD
    }
    res.json({ token: "fake-token" });
});

module.exports = app;
