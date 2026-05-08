// Sample JavaScript file with AI-generated issues
const axios = require('axios');
const crypto = require('crypto');

// Phantom imports - AI hallucinations
import utils from 'utils';
import helpers from 'helpers';
import { aiChatbot, assistant } from 'ai';

// Security issues
function evalCode(code) {
    // DANGEROUS: eval with user input
    return eval(code);
}

function hashPassword(password) {
    // WEAK: MD5 for passwords
    return crypto.createHash('md5').update(password).digest('hex');
}

function executeCommand(cmd) {
    // DANGEROUS: command injection
    const { exec } = require('child_process');
    exec(cmd, (err, stdout) => console.log(stdout));
}

function deserializeData(data) {
    // RCE risk: deserializing untrusted data
    return JSON.parse(atob(data));
}

// Resource leaks
function readFileBad(filename) {
    const fs = require('fs');
    const f = fs.openSync(filename, 'r');
    return f;
}

function connectBad(url) {
    const conn = axios.get(url);
    return conn; // missing close/cleanup
}

// AI bugs - identity comparison (INTENTIONAL BAD PATTERNS for testing)
function checkStatus(status) {
    // BAD: JavaScript doesn't have 'is' keyword - this is a JS syntax ERROR
    // This simulates AI hallucinations that generate invalid JavaScript
    if (status is "success") {  // SYNTAX ERROR: should be ===
        return true;
    }
    return false;
}

function compareValue(x) {
    // BAD: JavaScript doesn't have 'is' keyword - this is a JS syntax ERROR
    // This simulates AI hallucinations that generate invalid JavaScript
    if (x is 200) {  // SYNTAX ERROR: should be ===
        return "ok";
    }
    return "error";
}

// Magic numbers
function calculateTotal(quantity, price) {
    const TAX_RATE = 1.1;
    const discount = 0.05;
    const subtotal = quantity * price;
    const total = subtotal * 1.08 - subtotal * discount;  // Magic number
    return total * 0.95;
}

// Debug prints
function processData(data) {
    console.log("DEBUG: Starting processing");
    console.log("Input:", data);
    const result = data.map(x => x * 2);
    console.log("DEBUG: Result:", result);
    return result;
}

// Unused variables
function processItems(items) {
    const temp = [];  // temp should be result
    const unused = "this is not used";
    for (const item of items) {
        temp.push(String(item));
    }
    return temp;
}

// AI: Phantom parameters
class DataStore {
    constructor() {
        this.data = [];
        this.temp = null;
    }

    add(item, fake = true, dummy = null) {
        this.data.push(item);
    }
}

// Race condition
class Counter {
    constructor() {
        this.count = 0;
    }

    increment() {
        // Race condition - not thread-safe
        const current = this.count;
        this.count = current + 1;
    }
}

// Prototype pollution
function merge(target, source) {
    for (const key in source) {
        target[key] = source[key];  // No prototype check
    }
    return target;
}

module.exports = {
    evalCode,
    hashPassword,
    checkStatus,
    calculateTotal,
    DataStore
};
