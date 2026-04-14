/**
 * Vulnerable JavaScript/TypeScript test file
 * This file intentionally contains security vulnerabilities to test detection.
 * DO NOT use this code in production.
 */

// ==================== JS-SEC-001: Code Injection (CRITICAL) ====================

// eval with user input
const userInput = req.body.code;
eval(userInput);                              // LINE: eval with request body

// new Function with dynamic code
const dynamicFn = new Function('x', 'return x + ' + userInput); // LINE: new Function

// vm.runInContext (Node.js specific)
const vm = require('vm');
const sandbox = { data: userInput };
vm.runInContext('data = data + require("child_process").execSync("ls")', sandbox); // LINE: vm.runInContext

// vm.compileFunction
const compiled = vm.compileFunction('return ' + userInput, [], { parsingContext: sandbox }); // LINE: compileFunction

// ==================== JS-SEC-002: SQL Injection (CRITICAL) ====================

// Template literal in SQL query
const sql = `SELECT * FROM users WHERE name = '${req.query.username}'`; // LINE: SQL template
db.query(sql);

// String concatenation in query
const q = "SELECT * FROM products WHERE id = " + req.params.id; // LINE: SQL concat
connection.execute(q);

// execute with string interpolation
await pool.execute("SELECT * FROM orders WHERE customer = '" + req.body.name + "'"); // LINE: execute concat

// ==================== JS-SEC-003: SSRF (HIGH) ====================

// fetch with template literal URL
const targetUrl = req.query.url;
fetch(`https://api.example.com/data?url=${targetUrl}`); // LINE: fetch SSRF

// axios with dynamic URL
axios.get(`${process.env.API_BASE}/${req.params.endpoint}`); // LINE: axios SSRF

// request library with user URL
const request = require('request');
request({ url: req.body.redirectUrl }, callback); // LINE: request SSRF

// undici with overridable origin
const { request: undiciReq } = require('undici');
undiciReq({ origin: 'http://internal-admin', pathname: '/' + req.query.path }); // LINE: undici SSRF

// ==================== JS-SEC-004: Path Traversal (HIGH) ====================

// readFile with dynamic path
const fs = require('fs');
const file = req.query.filename;
const content = fs.readFileSync(`${file}`, 'utf8'); // LINE: readFile traversal

// createReadStream with user path
fs.createReadStream(req.params.path + '/data.txt'); // LINE: createReadStream traversal

// dynamic require
const moduleName = req.body.module;
const mod = require(`${moduleName}`); // LINE: dynamic require traversal

// dynamic import
import(`${process.cwd()}/modules/${req.query.name}`).then(m => m.run()); // LINE: dynamic import traversal

// ==================== JS-SEC-005: XSS / DOM Injection (HIGH) ====================

// innerHTML with template literal
document.getElementById('output').innerHTML = `<div>${userData}</div>`; // LINE: innerHTML XSS

// innerHTML with concatenation
document.querySelector('.content').innerHTML = '<p>' + req.body.text + '</p>'; // LINE: innerHTML concat XSS

// jQuery .html() with dynamic content
$('#comments').html(req.query.comment); // LINE: jQuery HTML XSS

// React dangerouslySetInnerHTML
return <div dangerouslySetInnerHTML={{ __html: rawUserContent }} />; // LINE: React XSS

// document.write
document.write('<script>' + location.hash.substring(1) + '</script>'); // LINE: document.write XSS

// ==================== JS-SEC-006: Hardcoded Secrets (HIGH) ====================

const API_KEY = "sk-live-abc123xyz456secret789key"; // LINE: hardcoded API key
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"; // LINE: hardcoded AWS key
const GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; // LINE: hardcoded GitHub token
const JWT_SECRET = "super_secret_jwt_key_do_not_use_in_prod"; // LINE: hardcoded JWT secret
const DB_PASSWORD = "MySecretPass123!"; // LINE: hardcoded password
const AUTH_BEARER = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; // LINE: hardcoded Bearer token
const PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAL..."; // LINE: hardcoded private key

// ==================== JS-SEC-007: Weak Crypto (MEDIUM) ====================

const crypto = require('crypto');

// MD5 hash
const md5hash = crypto.createHash('md5').update(userInput).digest('hex'); // LINE: MD5

// SHA1 hash
const sha1hash = crypto.createHash('sha1').update(password).digest('hex'); // LINE: SHA1

// Weak DES cipher
const cipher = crypto.createCipher('des', encryptionKey); // LINE: DES

// Math.random for security
const sessionToken = Math.random().toString(36).substring(2); // LINE: Math.random

// JWT with verify disabled
const token = jwt.sign(payload, secret, { algorithm: 'HS256', verify: false }); // LINE: JWT verify disabled

// ==================== JS-SEC-008: Insecure TLS (HIGH) ====================

// HTTPS agent with verify disabled
const agent = new https.Agent({
    rejectUnauthorized: false // LINE: TLS verify disabled
});

// Cookie without secure flag
const cookie = cookieParser.serialize('session', sessionId, {
    httpOnly: true,
    secure: false // LINE: cookie secure flag disabled
});

// ==================== JS-SEC-009: Prototype Pollution (HIGH) ====================

// __proto__ assignment
const userPayload = JSON.parse(req.body.data);
userPayload.__proto__.isAdmin = true; // LINE: proto pollution

// constructor.prototype modification
const config = { ...req.query };
config.constructor.prototype.validate = function() {}; // LINE: constructor prototype

// Object.assign with user data
const merged = Object.assign({}, defaultConfig, req.body); // LINE: Object.assign pollution

// Dynamic key with user input
const key = req.query.propName;
obj[`__${key}__`] = req.body.value; // LINE: dynamic key pollution

// ==================== JS-SEC-010: Information Disclosure (LOW) ====================

// Console log with sensitive data
console.log('Password:', user.password); // LINE: console log password
console.log('Token:', process.env.API_TOKEN); // LINE: console log token
console.log('Full request:', req); // LINE: console log full request

// ==================== Clean code (no issues) ====================

// This should NOT trigger any rules
function sanitize(input) {
    return input.replace(/[<>'"]/g, '');
}

const safeQuery = db.query('SELECT * FROM users WHERE id = ?', [userId]);
const safeUrl = fetch('https://trusted-api.example.com/data');
const safePath = path.resolve('/allowed/dir', req.params.file);
const safeInner = document.getElementById('output').textContent = userData;
const safeKey = process.env.SECURE_API_KEY;
