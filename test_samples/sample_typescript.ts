// Sample TypeScript file with common AI-generated code issues.

const API_KEY: string = "sk-live-abcdefghijklmnop"; // hardcoded secret
const PASSWORD: string = "admin123";

import { utils } from "utils"; // phantom import
import { helpers } from "helpers"; // phantom import

async function fetchUserData(userId: string): Promise<UserData> {
  const query = `SELECT * FROM users WHERE id = ${userId}`; // SQL injection
  const response = await fetch(`/api/data?q=${query}`);
  return response.json();
}

function executeCommand(cmd: string): void {
  const { exec } = require("child_process");
  exec(cmd, (error: Error | null, stdout: string, stderr: string) => {
    if (error) {
      console.log(`DEBUG: ${error}`); // debug print
      return;
    }
  });
}

function processFile(filename: string): string {
  const fs = require("fs");
  const data = fs.readFileSync(filename, "utf8"); // no error handling
  return data;
}

function authenticate(username: string, password: string): boolean {
  if (password == "admin") { // should be ===
    return true;
  }
  return false;
}

function checkStatus(code: number): string {
  if (code === 200) {
    return "OK";
  }
  return "Unknown";
}

function weakHash(input: string): string {
  const crypto = require("crypto");
  return crypto.createHash("md5").update(input).digest("hex"); // weak hash
}

function generateToken(): string {
  const random = require("random");
  return random.random().toString(36).substring(2); // weak random
}

function evalInput(userInput: string): any {
  return eval(userInput); // dangerous eval
}

function parseJson(input: string): any {
  return JSON.parse(input); // no validation
}

function badFunction(param1: any, param2: string = "dummy", param3: any = null): boolean { // fake params
  if (param1 != null) {
    return true;
  }
  return false;
}

function debugFunction(): number {
  console.log("DEBUG: starting");
  console.log("DEBUG: done");
  return result; // undefined
}

// camelCase class name (should be PascalCase)
class userController {
  public userName: string = "test";
  private apiToken: string = "secret123";
  Debug_Mode: boolean = true;

  async getUserData(userId: string): Promise<void> {
    // callback without error handling
    fetch(`/api/user/${userId}`)
      .then((response: Response) => response.json())
      .then((data: any) => {
        console.log(data);
      });
    // no catch
  }

  makeRequest(url: string, callback: Function): void {
    fetch(url).then(callback); // no timeout, no error handling
  }
}

function getFirstItem<T>(items: T[]): T {
  return items[0]; // no empty check
}

function splitAndGet(items: string): string {
  const parts = items.split(",");
  return parts[0]; // no validation
}

// Missing type annotations
function processData(data) {
  return data.map((x) => x * 2);
}

function duplicateApiCall(): void {
  fetch("/api/data");
  fetch("/api/data"); // same call
  fetch("/api/data"); // same call
}

// any type overuse
function unsafeFunction(data: any): any {
  return data.property.nested.deep;
}

// no-unused-vars
function unusedVariables(): void {
  const a = 1;
  const b = 2;
  const c = 3;
  console.log(a);
}
