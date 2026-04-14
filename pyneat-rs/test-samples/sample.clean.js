// // Evaluate if this can be replaced with JSON.parse() or a safer alternative: eval(userCode);// // Consider using a safer alternative to this dynamic code execution: // Debug output// eval(userCode); // FIXME: removed blocking UI function// // Debug output // FIXME: removed blocking UI function// eval(userCode); (debugger removed)// // Debug output (debugger removed)// eval(userCode);// // Debug output// SQL Injection test
const query = "SELECT * FROM users WHERE id = " + req.params.id;

// XSS test
// // Consider using a safer alternative to this dynamic code execution: document.innerHTML = userInput;ut; // FIXME: removed blocking UI functionut; (debugger removed)ut;

// Command injection
const { exec } = require('child_process');
// // Consider using a safer alternative to this dynamic code execution: exec("ls " + userInput);fer alternative to this dynamic code execution: exec("ls " + userInput);); // FIXME: removed blocking UI function); // FIXME: removed blocking UI function); (debugger removed)); (debugger removed)););
// Hardcoded secret
// // Consider using a safer alternative to this dynamic code execution: const password = "super_secret_123";"; // FIXME: removed blocking UI function"; (debugger removed)";// // Consider using a safer alternative to this dynamic code execution: const apiKey = "AKIAIOSFODNN7EXAMPLE";e to this dynamic code execution: const apiKey = "AKIAIOSFODNN7EXAMPLE";"; // FIXME: removed blocking UI function"; // FIXME: removed blocking UI function"; (debugger removed)"; (debugger removed)";";
// Debug output
// // Consider using a safer alternative to this dynamic code execution: console.log("Debug: starting...");); // FIXME: removed blocking UI function); (debugger removed));// // Consider using a safer alternative to this dynamic code execution: console.error("Error occurred");); // FIXME: removed blocking UI function); (debugger removed));
// JWT None Algorithm
const token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";

// Eval usage
// // Evaluate if this can be replaced with JSON.parse() or a safer alternative: eval(userCode);f this can be replaced with JSON.parse() or a safer alternative: eval(userCode);f this can be replaced with JSON.parse() or a safer alternative: eval(userCode);); // FIXME: removed blocking UI function); // FIXME: removed blocking UI function); // FIXME: removed blocking UI function); (debugger removed)); (debugger removed)); (debugger removed));););
// Prototype pollution
// // Consider using a safer alternative to this dynamic code execution: Object.assign(req.query, JSON.parse(userInput));dynamic code execution: Object.assign(req.query, JSON.parse(userInput));); // FIXME: removed blocking UI function); // FIXME: removed blocking UI function); (debugger removed)); (debugger removed)););
// Cookie without secure flag
// // Consider using a safer alternative to this dynamic code execution: res.cookie('session', token);lternative to this dynamic code execution: res.cookie('session', token);); // FIXME: removed blocking UI function); // FIXME: removed blocking UI function); (debugger removed)); (debugger removed)););