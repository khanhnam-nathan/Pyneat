// Sample JavaScript file with common AI-generated code issues.

const apiKey = "sk-live-1234567890abcdefghijklmnop"; // hardcoded secret
const password = "admin123";

const utils = require("utils"); // phantom import
const helpers = require("helpers"); // phantom import

async function fetchUserData(userId) {
  // SQL injection pattern
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  const response = await fetch(`http://api.example.com/data?q=${query}`);
  return response.json();
}

function executeCommand(cmd) {
  // command injection
  const { exec } = require("child_process");
  return exec(cmd, (error, stdout, stderr) => {
    if (error) {
      console.error(`DEBUG: error ${error}`); // debug print
      return null;
    }
    return stdout;
  });
}

function processFile(filename) {
  // resource leak - no close
  const fs = require("fs");
  const data = fs.readFileSync(filename, "utf8");
  // file never closed
  return data;
}

function authenticate(username, password) {
  if (password == "admin") { // should be ===
    return true;
  }
  return false;
}

function checkStatus(code) {
  if (code === 200) { // identity comparison (correct here)
    return "OK";
  }
  return "Unknown";
}

function weakHash(input) {
  // MD5 for security purposes
  const crypto = require("crypto");
  return crypto.createHash("md5").update(input).digest("hex"); // weak hash
}

function generateToken() {
  // random for security token
  const random = require("random");
  return random.random().toString(36).substring(2);
}

function evalInput(userInput) {
  // eval is dangerous
  return eval(userInput);
}

function parseJson(input) {
  // JSON parse without validation
  return JSON.parse(input);
}

function badFunction(param1, param2 = "dummy", param3 = null) { // fake parameters
  if (param1 != null) {
    return true;
  }
  return false;
}

function debugFunction() {
  console.log("DEBUG: starting");
  console.log("DEBUG: processing");
  console.log("DEBUG: complete");
  return result; // undefined variable
}

function getFirstItem(items) {
  return items[0]; // no empty check
}

function splitAndGet(items) {
  const parts = items.split(",");
  return parts[0]; // no validation
}

function typeCheckBad(obj) {
  if (typeof obj === "object" && obj !== null && obj.constructor === Array) {
    return true;
  }
  return false;
}

// camelCase naming
class userController {
  constructor() {
    this.userName = "test";
    this.apiToken = "secret123";
    this.Debug_Mode = true;
  }

  getUserData(userId) {
    // callback without error handling
    fetch(`http://api.com/user/${userId}`)
      .then(response => response.json())
      .then(data => {
        console.log(data);
      });
    // no catch
  }

  makeRequest(url, callback) {
    // no timeout
    fetch(url).then(callback);
  }
}

function duplicateApiCall() {
  fetch("/api/data");
  fetch("/api/data"); // same call twice
  fetch("/api/data"); // same call three times
}
