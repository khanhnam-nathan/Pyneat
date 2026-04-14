# PyNeat Multi-Language Rule Reference

> **Purpose**: AI agent instruction file — defines every rule, what it detects, severity, action (tag/fix), and example patterns for all supported languages.
> **Version**: 1.0 — 2026-04-12
> **Companion**: `MULTI_LANGUAGE_PLAN.md` (architecture), this file (rule details)

---

## How to Read This Document

Each rule entry contains:
- **ID**: Unique rule identifier
- **Category**: `universal` (all languages) / `language-specific`
- **Severity**: `critical` / `high` / `medium` / `low` / `info`
- **Action**: `TAG` (report only) / `FIX` (auto-fix) / `SUGGEST` (suggest change)
- **Languages**: Which languages this rule applies to
- **Detection**: What tree-sitter node types / patterns to look for
- **Examples**: Bad code → Good code (per language)

---

## PART 1: UNIVERSAL RULES (All Languages)

These rules use the `LanguageAdapter` interface and work with ANY language adapter.

---

### U-001: Hardcoded Secrets

| Field | Value |
|-------|-------|
| **ID** | `hardcoded-secrets` |
| **File** | `pyneat/rules/universal/hardcoded_secrets.py` |
| **Severity** | `critical` |
| **Action** | `TAG` — never auto-delete secrets, just flag them |
| **CWE** | CWE-798 (Use of Hard-coded Credentials) |
| **OWASP** | A07:2021 — Identification and Authentication Failures |

**Detection Logic:**
1. Get all `AssignmentNode` from adapter
2. Check if `name` matches secret patterns: `password`, `secret`, `api_key`, `token`, `auth`, `credential`, `private_key`, `access_key`, `db_password`, `jwt_secret`
3. Check if `value` is a non-empty string literal (not empty, not placeholder like `"***"`, not env var read)
4. Also check: string literals containing patterns like `-----BEGIN RSA PRIVATE KEY-----`, `ghp_`, `sk-`, `AKIA`

**Language Examples:**

```python
# Python — TAG
password = "super_secret_123"          # ← CRITICAL: Hardcoded password
API_KEY = "sk-1234567890abcdef"        # ← CRITICAL: Hardcoded API key
DB_URL = "postgresql://user:pass@host" # ← CRITICAL: Credentials in connection string

# OK — these are fine
password = os.environ.get("PASSWORD")  # ← Reading from env
API_KEY = config.get("api_key")        # ← Reading from config
```

```javascript
// JavaScript — TAG
const password = "super_secret_123";
const apiKey = "sk-1234567890abcdef";
const dbUrl = "mongodb://admin:pass123@localhost";

// OK
const password = process.env.PASSWORD;
const apiKey = config.apiKey;
```

```go
// Go — TAG
password := "super_secret_123"
apiKey := "sk-1234567890abcdef"

// OK
password := os.Getenv("PASSWORD")
```

```java
// Java — TAG
private String password = "super_secret_123";
private static final String API_KEY = "sk-1234567890abcdef";

// OK
private String password = System.getenv("PASSWORD");
```

```rust
// Rust — TAG
let password = "super_secret_123";
let api_key = "sk-1234567890abcdef";

// OK
let password = std::env::var("PASSWORD").unwrap_or_default();
```

```csharp
// C# — TAG
private string password = "super_secret_123";
private const string ApiKey = "sk-1234567890abcdef";

// OK
var password = Environment.GetEnvironmentVariable("PASSWORD");
```

```php
// PHP — TAG
$password = "super_secret_123";
$apiKey = "sk-1234567890abcdef";

// OK
$password = getenv("PASSWORD");
$password = $_ENV["PASSWORD"];
```

```ruby
# Ruby — TAG
password = "super_secret_123"
api_key = "sk-1234567890abcdef"

# OK
password = ENV["PASSWORD"]
```

---

### U-002: Debug Artifacts

| Field | Value |
|-------|-------|
| **ID** | `debug-artifacts` |
| **File** | `pyneat/rules/universal/debug_artifacts.py` |
| **Severity** | `medium` |
| **Action** | `FIX` — remove debug calls (mode: safe = smart, aggressive = all) |
| **CWE** | CWE-489 (Active Debug Code) |

**Detection Logic:**
1. Get all `CallNode` from adapter
2. Match `callee` against `adapter.get_debug_call_patterns()`
3. In `safe` mode: only remove if call looks debug-like (contains variable dumps, "debug", log levels)
4. In `aggressive` mode: remove ALL matching calls

**Debug patterns per language:**

| Language | Debug Calls to Remove |
|----------|----------------------|
| Python | `print()`, `pprint()`, `pdb.set_trace()`, `breakpoint()`, `ic()`, `icecream.ic()` |
| JavaScript | `console.log()`, `console.warn()`, `console.error()`, `console.info()`, `console.debug()`, `console.trace()`, `console.dir()`, `alert()`, `debugger` (statement) |
| TypeScript | Same as JavaScript |
| Go | `fmt.Println()`, `fmt.Printf()`, `fmt.Print()`, `log.Println()`, `log.Printf()`, `log.Print()` |
| Java | `System.out.println()`, `System.out.print()`, `System.err.println()`, `e.printStackTrace()` |
| Rust | `println!()`, `print!()`, `eprintln!()`, `eprint!()`, `dbg!()` |
| C# | `Console.WriteLine()`, `Console.Write()`, `Debug.WriteLine()`, `Trace.WriteLine()` |
| PHP | `var_dump()`, `print_r()`, `die()`, `dd()`, `dump()`, `echo` (in class methods) |
| Ruby | `puts`, `p`, `pp`, `print`, `binding.pry`, `binding.irb`, `byebug`, `debugger` |

---

### U-003: Empty Catch/Except Blocks

| Field | Value |
|-------|-------|
| **ID** | `empty-catch` |
| **File** | `pyneat/rules/universal/empty_catch.py` |
| **Severity** | `high` |
| **Action** | `TAG` — flag for review, suggest adding error handling |
| **CWE** | CWE-390 (Detection of Error Condition Without Action) |

**Detection Logic:**
1. Get all `CatchNode` from adapter
2. Check `is_empty == True`
3. Also flag bare catches (no exception type specified)

**Catch node types per language:**

| Language | tree-sitter node type | Empty body check |
|----------|----------------------|------------------|
| Python | `except_clause` (via `ast.ExceptHandler`) | Body is single `pass` or empty |
| JavaScript | `catch_clause` | Body `{}` has no meaningful children |
| Go | N/A (Go uses error returns, not try/catch) | Skip — use U-GO-001 instead |
| Java | `catch_clause` | Body has no statements |
| Rust | N/A (Rust uses `Result<>`, not exceptions) | Skip — use U-RS-001 instead |
| C# | `catch_clause` | Body has no statements |
| PHP | `catch_clause` | Body has no statements |
| Ruby | `rescue` | Body has no statements |

---

### U-004: SQL Injection

| Field | Value |
|-------|-------|
| **ID** | `sql-injection` |
| **File** | `pyneat/rules/universal/sql_injection.py` |
| **Severity** | `critical` |
| **Action** | `TAG` — flag, suggest parameterized queries |
| **CWE** | CWE-89 (SQL Injection) |
| **OWASP** | A03:2021 — Injection |

**Detection Logic:**
1. Get all `CallNode` from adapter
2. Match `callee` against `adapter.get_sql_patterns()`
3. Check if any argument is a string concatenation (binary `+` with string operand) or f-string/template string containing variable interpolation

**SQL patterns per language:**

| Language | SQL Call Patterns |
|----------|------------------|
| Python | `cursor.execute`, `db.execute`, `connection.execute`, `session.execute`, `engine.execute` |
| JavaScript | `query()`, `pool.query()`, `client.query()`, `connection.query()`, `knex.raw()`, `sequelize.query()` |
| Go | `db.Query()`, `db.QueryRow()`, `db.Exec()`, `tx.Query()`, `tx.Exec()` |
| Java | `Statement.execute*()`, `createQuery()`, `nativeQuery()`, `PreparedStatement` with string concat |
| Rust | `sqlx::query()`, `diesel::sql_query()`, `client.execute()` |
| C# | `SqlCommand()`, `ExecuteReader()`, `ExecuteNonQuery()`, `FromSqlRaw()` |
| PHP | `mysql_query()`, `mysqli_query()`, `$pdo->query()`, `$db->query()` |
| Ruby | `ActiveRecord::Base.connection.execute()`, `find_by_sql()`, `where()` with string interpolation |

---

### U-005: Eval/Exec Detection

| Field | Value |
|-------|-------|
| **ID** | `eval-detection` |
| **File** | `pyneat/rules/universal/eval_detection.py` |
| **Severity** | `critical` |
| **Action** | `TAG` — always flag, never auto-fix |
| **CWE** | CWE-95 (Eval Injection) |

**Eval patterns per language:**

| Language | Dangerous Functions |
|----------|--------------------|
| Python | `eval()`, `exec()`, `compile()`, `__import__()` |
| JavaScript | `eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)` |
| Go | N/A (Go has no eval) — **skip** |
| Java | `ScriptEngine.eval()`, `Runtime.exec()`, `ProcessBuilder` with user input |
| Rust | N/A (Rust has no eval) — **skip** |
| C# | `CSharpScript.EvaluateAsync()`, `Process.Start()` with user input |
| PHP | `eval()`, `assert()` (as function), `preg_replace()` with `/e` modifier, `create_function()` |
| Ruby | `eval()`, `instance_eval()`, `class_eval()`, `module_eval()`, `send()` with user input |

---

### U-006: Arrow Anti-Pattern (Deep Nesting)

| Field | Value |
|-------|-------|
| **ID** | `arrow-antipattern` |
| **File** | `pyneat/rules/universal/arrow_antipattern.py` |
| **Severity** | `medium` |
| **Action** | `TAG` at depth ≥ 4, `SUGGEST` guard clause refactoring |

**Detection Logic:**
1. Call `adapter.get_nesting_depth(tree)`
2. Flag any block where depth ≥ 4

**Nesting node types per language:**

| Language | Nesting Nodes |
|----------|---------------|
| Python | `if`, `for`, `while`, `with`, `try` |
| JavaScript | `if_statement`, `for_statement`, `while_statement`, `for_in_statement`, `try_statement` |
| Go | `if_statement`, `for_statement`, `select_statement` |
| Java | `if_statement`, `for_statement`, `while_statement`, `try_statement`, `switch_expression` |
| Rust | `if_expression`, `for_expression`, `while_expression`, `loop_expression`, `match_expression` |
| C# | `if_statement`, `for_statement`, `while_statement`, `try_statement`, `switch_statement` |
| PHP | `if_statement`, `for_statement`, `while_statement`, `foreach_statement`, `try_statement` |
| Ruby | `if`, `unless`, `while`, `until`, `for`, `begin` (rescue) |

---

### U-007: Dead Code Detection

| Field | Value |
|-------|-------|
| **ID** | `dead-code` |
| **File** | `pyneat/rules/universal/dead_code.py` |
| **Severity** | `low` |
| **Action** | `TAG` — flag unused functions/classes, `FIX` in destructive mode |

**Detection Logic:**
1. Get all `FunctionNode` from adapter
2. Get all `CallNode` from adapter
3. Mark function as dead if its `name` does not appear in any call's `callee`
4. Exclude: `main`, `__init__`, exported functions, test functions, decorated functions

---

### U-008: Magic Numbers

| Field | Value |
|-------|-------|
| **ID** | `magic-numbers` |
| **File** | `pyneat/rules/universal/magic_numbers.py` |
| **Severity** | `info` |
| **Action** | `TAG` — suggest extracting to named constant |

**Detection Logic:**
1. Find numeric literals in assignments, comparisons, function arguments
2. Exclude: 0, 1, -1, 2, 100 (common safe values)
3. Flag any other literal number used directly

---

## PART 2: LANGUAGE-SPECIFIC RULES

---

### JAVASCRIPT / TYPESCRIPT

#### JS-001: Strict Equality

| Field | Value |
|-------|-------|
| **ID** | `strict-equality` |
| **File** | `pyneat/rules/javascript/strict_equality.py` |
| **Severity** | `medium` |
| **Action** | `FIX` — replace `==` with `===`, `!=` with `!==` |

**Detection**: Find `binary_expression` nodes where operator is `==` or `!=`
**Exclude**: Comparisons with `null` (e.g., `x == null` checks for both `null` and `undefined` — intentional)

```javascript
// BAD → FIX
if (x == 1) { }        // → if (x === 1) { }
if (x != "hello") { }  // → if (x !== "hello") { }

// OK — don't touch
if (x == null) { }     // Intentional: checks null AND undefined
```

#### JS-002: Var to Let/Const

| Field | Value |
|-------|-------|
| **ID** | `var-to-const` |
| **File** | `pyneat/rules/javascript/var_to_const.py` |
| **Severity** | `medium` |
| **Action** | `FIX` — replace `var` with `const` (if never reassigned) or `let` |

**Detection**: Find `variable_declaration` nodes with `kind == "var"`

```javascript
// BAD → FIX
var x = 1;       // → const x = 1;  (never reassigned)
var y = [];      // → let y = [];   (reassigned later)
y.push(1);

// OK
const z = 42;    // Already const
let w = 0;       // Already let
```

#### JS-003: Console.log Removal

| Field | Value |
|-------|-------|
| **ID** | `console-log` |
| **File** | `pyneat/rules/javascript/console_log.py` |
| **Severity** | `medium` |
| **Action** | `FIX` — remove entire statement |

**Detection**: `call_expression` where callee starts with `console.`

#### JS-004: Unused Require/Import

| Field | Value |
|-------|-------|
| **ID** | `unused-require` |
| **File** | `pyneat/rules/javascript/unused_require.py` |
| **Severity** | `low` |
| **Action** | `TAG` — flag unused, `FIX` in aggressive mode |

#### JS-005: Prototype Pollution

| Field | Value |
|-------|-------|
| **ID** | `prototype-pollution` |
| **File** | `pyneat/rules/javascript/prototype_pollution.py` |
| **Severity** | `critical` |
| **Action** | `TAG` |
| **CWE** | CWE-1321 |

**Detection**: Assignment to `__proto__`, `constructor.prototype`, or `Object.assign` with untrusted source

---

### GO

#### GO-001: Unchecked Error

| Field | Value |
|-------|-------|
| **ID** | `unchecked-error` |
| **File** | `pyneat/rules/go/unchecked_error.py` |
| **Severity** | `high` |
| **Action** | `TAG` — flag for review |

**Detection**: `short_var_declaration` where one variable is `_` and the function returns an error
```go
// BAD — TAG
f, _ := os.Open("file.txt")     // Error ignored!
data, _ := json.Marshal(obj)    // Error ignored!

// OK
f, err := os.Open("file.txt")
if err != nil { return err }
```

#### GO-002: Fmt.Println Debug

| Field | Value |
|-------|-------|
| **ID** | `fmt-println` |
| **File** | `pyneat/rules/go/fmt_println.py` |
| **Severity** | `medium` |
| **Action** | `FIX` — remove debug print statements |

#### GO-003: Defer in Loop

| Field | Value |
|-------|-------|
| **ID** | `defer-in-loop` |
| **File** | `pyneat/rules/go/defer_in_loop.py` |
| **Severity** | `high` |
| **Action** | `TAG` — resource leak risk |

**Detection**: `defer_statement` inside `for_statement` body
```go
// BAD — TAG (deferred calls pile up, not freed until function returns)
for _, file := range files {
    f, _ := os.Open(file)
    defer f.Close()  // ← Leaked until function exits!
}

// OK
for _, file := range files {
    func() {
        f, _ := os.Open(file)
        defer f.Close()
    }()
}
```

#### GO-004: Shadow Variable

| Field | Value |
|-------|-------|
| **ID** | `shadow-variable` |
| **File** | `pyneat/rules/go/shadow_variable.py` |
| **Severity** | `medium` |
| **Action** | `TAG` |

**Detection**: Inner `:=` declaration that shadows an outer variable with the same name

---

### JAVA

#### JAVA-001: Raw Types

| Field | Value |
|-------|-------|
| **ID** | `raw-types` |
| **File** | `pyneat/rules/java/raw_types.py` |
| **Severity** | `medium` |
| **Action** | `TAG` — suggest adding type parameters |

```java
// BAD — TAG
List items = new ArrayList();           // Raw type!
Map config = new HashMap();             // Raw type!

// OK
List<String> items = new ArrayList<>();
Map<String, Object> config = new HashMap<>();
```

#### JAVA-002: System.out.println

| Field | Value |
|-------|-------|
| **ID** | `sysout` |
| **File** | `pyneat/rules/java/sysout.py` |
| **Severity** | `medium` |
| **Action** | `FIX` — remove, suggest using Logger |

#### JAVA-003: Empty Catch

Covered by universal `U-003`, uses Java's `catch_clause` node.

#### JAVA-004: Resource Leak

| Field | Value |
|-------|-------|
| **ID** | `resource-leak` |
| **File** | `pyneat/rules/java/resource_leak.py` |
| **Severity** | `high` |
| **Action** | `TAG` — suggest try-with-resources |
| **CWE** | CWE-404 (Improper Resource Shutdown or Release) |

```java
// BAD — TAG
Connection conn = DriverManager.getConnection(url);  // Not closed!
InputStream is = new FileInputStream("f.txt");       // Not closed!

// OK
try (Connection conn = DriverManager.getConnection(url)) {
    // auto-closed
}
```

---

### RUST

#### RS-001: Unwrap Usage

| Field | Value |
|-------|-------|
| **ID** | `unwrap-usage` |
| **File** | `pyneat/rules/rust_lang/unwrap_usage.py` |
| **Severity** | `high` |
| **Action** | `TAG` — suggest `?` operator or `expect()` with message |

**Detection**: `call_expression` where method is `.unwrap()` — exclude test functions (`#[test]`, `#[cfg(test)]`)

```rust
// BAD — TAG (in non-test code)
let data = std::fs::read_to_string("f.txt").unwrap();  // Panics on error!
let value = map.get("key").unwrap();                    // Panics if missing!

// OK
let data = std::fs::read_to_string("f.txt")?;          // Propagates error
let data = std::fs::read_to_string("f.txt")
    .expect("Failed to read config file");              // Explicit panic message

// OK — in test code
#[test]
fn test_something() {
    let data = parse("input").unwrap();  // OK in tests
}
```

#### RS-002: Unsafe Audit

| Field | Value |
|-------|-------|
| **ID** | `unsafe-audit` |
| **File** | `pyneat/rules/rust_lang/unsafe_audit.py` |
| **Severity** | `high` |
| **Action** | `TAG` — flag for security review |

**Detection**: `unsafe_block` node type

```rust
// TAG — requires security review
unsafe {
    let ptr = 0x1234 as *const i32;
    std::ptr::read(ptr);
}
```

#### RS-003: Unused Result

| Field | Value |
|-------|-------|
| **ID** | `unused-result` |
| **File** | `pyneat/rules/rust_lang/unused_result.py` |
| **Severity** | `medium` |
| **Action** | `TAG` — suggest handling or explicitly ignoring with `let _ =` |

**Detection**: `expression_statement` containing a `call_expression` that returns `Result<>` but is not assigned

#### RS-004: Clone Overuse

| Field | Value |
|-------|-------|
| **ID** | `clone-overuse` |
| **File** | `pyneat/rules/rust_lang/clone_overuse.py` |
| **Severity** | `info` |
| **Action** | `TAG` — suggest borrowing instead |

**Detection**: `call_expression` where method is `.clone()` — flag if cloning inside loops or if the value is only read after cloning

---

### C# / .NET

#### CS-001: Async Void

| Field | Value |
|-------|-------|
| **ID** | `async-void` |
| **File** | `pyneat/rules/csharp/async_void.py` |
| **Severity** | `high` |
| **Action** | `TAG` — suggest `async Task` instead |

**Detection**: `method_declaration` with `async` modifier and `void` return type (exclude event handlers)

```csharp
// BAD — TAG
public async void DoWork() {          // Exceptions can't be caught!
    await SomeOperation();
}

// OK
public async Task DoWork() {          // Proper async
    await SomeOperation();
}

// OK — event handler exception
private async void Button_Click(object sender, EventArgs e) {
    await SomeOperation();  // Event handlers are OK as async void
}
```

#### CS-002: Console.WriteLine

| Field | Value |
|-------|-------|
| **ID** | `console-writeline` |
| **File** | `pyneat/rules/csharp/console_writeline.py` |
| **Severity** | `medium` |
| **Action** | `FIX` — remove, suggest `ILogger` |

#### CS-003: IDisposable Leak

| Field | Value |
|-------|-------|
| **ID** | `disposable-leak` |
| **File** | `pyneat/rules/csharp/disposable_leak.py` |
| **Severity** | `high` |
| **Action** | `TAG` — suggest `using` block |
| **CWE** | CWE-404 |

**Detection**: `variable_declaration` where type implements `IDisposable` but is not inside a `using_statement`

```csharp
// BAD — TAG
var conn = new SqlConnection(connStr);  // Not disposed!
var stream = File.OpenRead("f.txt");    // Not disposed!

// OK
using var conn = new SqlConnection(connStr);
using (var stream = File.OpenRead("f.txt")) { }
```

#### CS-004: Raw SQL

| Field | Value |
|-------|-------|
| **ID** | `raw-sql` |
| **File** | `pyneat/rules/csharp/raw_sql.py` |
| **Severity** | `critical` |
| **Action** | `TAG` — suggest parameterized queries |

---

### PHP

#### PHP-001: Var Dump / Print R

| Field | Value |
|-------|-------|
| **ID** | `var-dump` |
| **File** | `pyneat/rules/php/var_dump.py` |
| **Severity** | `medium` |
| **Action** | `FIX` — remove debug output calls |

**Detection**: `function_call_expression` where name is `var_dump`, `print_r`, `die`, `dd`, `dump`

#### PHP-002: Deprecated mysql_* Functions

| Field | Value |
|-------|-------|
| **ID** | `deprecated-mysql` |
| **File** | `pyneat/rules/php/deprecated_mysql.py` |
| **Severity** | `critical` |
| **Action** | `TAG` — suggest PDO or mysqli |

**Detection**: `function_call_expression` where name starts with `mysql_` (NOT `mysqli_`)

```php
// BAD — TAG (removed in PHP 7.0)
$result = mysql_query($sql);           // DEPRECATED!
$conn = mysql_connect($host);          // DEPRECATED!
$row = mysql_fetch_assoc($result);     // DEPRECATED!

// OK
$stmt = $pdo->prepare($sql);
$stmt->execute([$param]);
```

#### PHP-003: Variable Variables

| Field | Value |
|-------|-------|
| **ID** | `variable-variables` |
| **File** | `pyneat/rules/php/variable_variables.py` |
| **Severity** | `high` |
| **Action** | `TAG` — suggest associative array |
| **CWE** | CWE-914 (Improper Control of Dynamically-Identified Variables) |

**Detection**: `dynamic_variable_name` node type (the `$$var` syntax)

```php
// BAD — TAG
$$varname = "value";       // Dynamic variable — security risk!
echo $$user_input;         // Could access ANY variable!

// OK
$data[$varname] = "value"; // Use associative array instead
```

#### PHP-004: Extract Usage

| Field | Value |
|-------|-------|
| **ID** | `extract-usage` |
| **File** | `pyneat/rules/php/extract_usage.py` |
| **Severity** | `critical` |
| **Action** | `TAG` — suggest explicit variable assignment |
| **CWE** | CWE-621 (Variable Extraction Error) |

```php
// BAD — TAG (overwrites local variables with user data!)
extract($_POST);           // CRITICAL: user controls variable names!
extract($_GET);            // CRITICAL!
extract($untrusted_data);  // CRITICAL!

// OK — explicit
$name = $_POST['name'];
$email = $_POST['email'];
```

---

### RUBY

#### RB-001: Puts/P Removal

| Field | Value |
|-------|-------|
| **ID** | `puts-removal` |
| **File** | `pyneat/rules/ruby/puts_removal.py` |
| **Severity** | `medium` |
| **Action** | `FIX` — remove debug output |

**Detection**: `method_call` or bare `identifier` call to `puts`, `p`, `pp`, `print`

#### RB-002: Eval Usage

| Field | Value |
|-------|-------|
| **ID** | `eval-usage` |
| **File** | `pyneat/rules/ruby/eval_usage.py` |
| **Severity** | `critical` |
| **Action** | `TAG` |

**Detection**: Calls to `eval`, `instance_eval`, `class_eval`, `module_eval`, `Kernel.eval`

```ruby
# BAD — TAG
eval(user_input)                    # Code injection!
obj.instance_eval(user_input)       # Code injection!
klass.class_eval(dynamic_string)    # Code injection!

# OK — literal block form (safe)
obj.instance_eval { @ivar }         # Block form, no injection risk
```

#### RB-003: Send Injection

| Field | Value |
|-------|-------|
| **ID** | `send-injection` |
| **File** | `pyneat/rules/ruby/send_injection.py` |
| **Severity** | `high` |
| **Action** | `TAG` — flag when argument comes from user input |
| **CWE** | CWE-470 (Use of Externally-Controlled Input to Select Classes or Code) |

```ruby
# BAD — TAG
obj.send(params[:method])              # User controls method name!
obj.public_send(user_input, *args)     # User controls method name!

# OK — whitelist approach
ALLOWED = %w[name email phone]
method = params[:field]
obj.send(method) if ALLOWED.include?(method)
```

#### RB-004: Binding.pry Removal

| Field | Value |
|-------|-------|
| **ID** | `binding-pry` |
| **File** | `pyneat/rules/ruby/binding_pry.py` |
| **Severity** | `high` |
| **Action** | `FIX` — remove debugger statements |

**Detection**: Calls to `binding.pry`, `binding.irb`, `byebug`, `debugger`

---

## PART 3: AI-SPECIFIC RULES (Cross-Language)

These rules specifically target patterns that AI coding assistants commonly introduce.

---

### AI-001: Phantom Package Detection

| Field | Value |
|-------|-------|
| **ID** | `phantom-package` |
| **Severity** | `critical` |
| **Action** | `TAG` |
| **CWE** | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |

**Detection**: Import/require of packages that don't exist (hallucinated by AI)
- Check import names against known package registries
- Flag imports with suspicious names that match no known package

| Language | How to Detect |
|----------|---------------|
| Python | `import nonexistent_lib` — check against PyPI |
| JavaScript | `require('nonexistent-pkg')` — check against npm |
| Go | `import "github.com/fake/repo"` — check against pkg.go.dev |
| Java | Not applicable (compile-time check) |
| PHP | `use NonExistent\Package;` — check against Packagist |
| Ruby | `require 'nonexistent_gem'` — check against RubyGems |

### AI-002: Fake Parameters

| Field | Value |
|-------|-------|
| **ID** | `fake-params` |
| **Severity** | `high` |
| **Action** | `TAG` |

**Detection**: Function parameters with generic/placeholder names that suggest AI hallucination:
- `param1`, `param2`, `arg1`, `arg2`
- `dummy_arg`, `placeholder`, `fake_param`
- `temp_var`, `unused_param`

### AI-003: Redundant I/O

| Field | Value |
|-------|-------|
| **ID** | `redundant-io` |
| **Severity** | `medium` |
| **Action** | `TAG` |

**Detection**: Duplicate API calls, file reads, or database queries where the result is already available from a previous call.

### AI-004: Naming Inconsistency

| Field | Value |
|-------|-------|
| **ID** | `naming-inconsistency` |
| **Severity** | `low` |
| **Action** | `TAG` |

**Detection**: Mixed naming conventions within the same file (e.g., `camelCase` and `snake_case` functions) — a common sign of AI-generated code pasted from different contexts.

---

## PART 4: SUMMARY TABLE — ALL RULES

| ID | Rule | Severity | Action | Languages |
|----|------|----------|--------|-----------|
| U-001 | Hardcoded Secrets | critical | TAG | All |
| U-002 | Debug Artifacts | medium | FIX | All |
| U-003 | Empty Catch | high | TAG | All (except Go, Rust) |
| U-004 | SQL Injection | critical | TAG | All |
| U-005 | Eval Detection | critical | TAG | All (except Go, Rust) |
| U-006 | Arrow Anti-Pattern | medium | TAG | All |
| U-007 | Dead Code | low | TAG/FIX | All |
| U-008 | Magic Numbers | info | TAG | All |
| JS-001 | Strict Equality | medium | FIX | JS/TS |
| JS-002 | Var to Const | medium | FIX | JS |
| JS-003 | Console.log | medium | FIX | JS/TS |
| JS-004 | Unused Require | low | TAG | JS/TS |
| JS-005 | Prototype Pollution | critical | TAG | JS/TS |
| GO-001 | Unchecked Error | high | TAG | Go |
| GO-002 | Fmt.Println | medium | FIX | Go |
| GO-003 | Defer in Loop | high | TAG | Go |
| GO-004 | Shadow Variable | medium | TAG | Go |
| JAVA-001 | Raw Types | medium | TAG | Java |
| JAVA-002 | System.out.println | medium | FIX | Java |
| JAVA-003 | Empty Catch | high | TAG | Java |
| JAVA-004 | Resource Leak | high | TAG | Java |
| RS-001 | Unwrap Usage | high | TAG | Rust |
| RS-002 | Unsafe Audit | high | TAG | Rust |
| RS-003 | Unused Result | medium | TAG | Rust |
| RS-004 | Clone Overuse | info | TAG | Rust |
| CS-001 | Async Void | high | TAG | C# |
| CS-002 | Console.WriteLine | medium | FIX | C# |
| CS-003 | IDisposable Leak | high | TAG | C# |
| CS-004 | Raw SQL | critical | TAG | C# |
| PHP-001 | Var Dump | medium | FIX | PHP |
| PHP-002 | Deprecated mysql_* | critical | TAG | PHP |
| PHP-003 | Variable Variables | high | TAG | PHP |
| PHP-004 | Extract Usage | critical | TAG | PHP |
| RB-001 | Puts/P Removal | medium | FIX | Ruby |
| RB-002 | Eval Usage | critical | TAG | Ruby |
| RB-003 | Send Injection | high | TAG | Ruby |
| RB-004 | Binding.pry | high | FIX | Ruby |
| AI-001 | Phantom Package | critical | TAG | All |
| AI-002 | Fake Parameters | high | TAG | All |
| AI-003 | Redundant I/O | medium | TAG | All |
| AI-004 | Naming Inconsistency | low | TAG | All |

**Total: 40 rules** (8 universal + 5 JS + 4 Go + 4 Java + 4 Rust + 4 C# + 4 PHP + 4 Ruby + 4 AI-specific + existing Python rules unchanged)

---

## PART 5: ACTION DEFINITIONS

| Action | Meaning | When to Use |
|--------|---------|-------------|
| `TAG` | Report issue, do NOT modify code. Add to findings/manifest. | Security issues, patterns needing human judgment |
| `FIX` | Auto-fix the code. Remove or replace the problematic pattern. | Debug artifacts, style fixes, clear improvements |
| `SUGGEST` | Add comment or suggestion, don't modify functional code. | Refactoring opportunities, potential improvements |

### Severity → Exit Code Mapping

For CI/CD integration (`pyneat check --fail-on`):

| Severity | Exit Code | Block CI? |
|----------|-----------|-----------|
| `critical` | 2 | Yes (always) |
| `high` | 1 | Yes (if `--fail-on high`) |
| `medium` | 0 | No (warning only) |
| `low` | 0 | No (info only) |
| `info` | 0 | No (suggestion only) |
