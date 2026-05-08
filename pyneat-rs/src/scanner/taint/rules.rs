//! Built-in taint analysis rules for common vulnerabilities.
//!
//! Each rule defines sources, sinks, sanitizers, and propagators.
//! All rules work cross-language (Python, JavaScript, Go, Java, PHP, Ruby, C#, Rust).

#[allow(dead_code)]

use crate::scanner::taint::labels::{
    SanitizerPattern, SinkPosition, SourcePattern, TaintLabel, TaintPropagator, TaintRule,
    TaintSanitizer, TaintSink, TaintSource,
};

// --------------------------------------------------------------------------
// Common cross-language source patterns
// --------------------------------------------------------------------------

fn all_user_input_sources(rule_id: &str) -> Vec<TaintSource> {
    vec![
        // Python
        TaintSource {
            rule_id: rule_id.to_string(),
            name: "Python user input".into(),
            label: TaintLabel::UserInput,
            patterns: vec![
                SourcePattern::CallPrefix("input".into()),
                SourcePattern::CallPrefix("sys.argv".into()),
                SourcePattern::CallPrefix("os.environ".into()),
                SourcePattern::CallPrefix("os.getenv".into()),
                SourcePattern::CallPrefix("getenv".into()),
            ],
        },
        // Python web frameworks (Flask, Django, FastAPI, Starlette)
        TaintSource {
            rule_id: rule_id.to_string(),
            name: "Python web framework input".into(),
            label: TaintLabel::UserInput,
            patterns: vec![
                SourcePattern::CallPrefix("request.args.get".into()),
                SourcePattern::CallPrefix("request.form.get".into()),
                SourcePattern::CallPrefix("request.json".into()),
                SourcePattern::CallPrefix("request.values".into()),
                SourcePattern::CallPrefix("request.data".into()),
                SourcePattern::CallPrefix("request.files".into()),
                SourcePattern::CallPrefix("request.GET".into()),
                SourcePattern::CallPrefix("request.POST".into()),
                SourcePattern::CallPrefix("request.COOKIES".into()),
                SourcePattern::CallPrefix("request.body".into()),
                SourcePattern::CallPrefix("request.session".into()),
                SourcePattern::CallPrefix("request.META".into()),
                SourcePattern::IdentifierPattern("request".into()),
                SourcePattern::CallPrefix("query_params".into()),
                SourcePattern::CallPrefix("Body()".into()),
                SourcePattern::CallPrefix("Form()".into()),
                SourcePattern::CallPrefix("Header()".into()),
                SourcePattern::CallPrefix("Path()".into()),
                SourcePattern::CallPrefix("Request".into()),
            ],
        },
        // JavaScript/TypeScript
        TaintSource {
            rule_id: rule_id.to_string(),
            name: "JavaScript user input".into(),
            label: TaintLabel::UserInput,
            patterns: vec![
                SourcePattern::CallPrefix("req.body".into()),
                SourcePattern::CallPrefix("req.params".into()),
                SourcePattern::CallPrefix("req.query".into()),
                SourcePattern::CallPrefix("req.headers".into()),
                SourcePattern::CallPrefix("req.cookies".into()),
                SourcePattern::CallPrefix("req.files".into()),
                SourcePattern::CallPrefix("process.argv".into()),
                SourcePattern::CallPrefix("process.env".into()),
                SourcePattern::CallPrefix("window.location".into()),
                SourcePattern::CallPrefix("document.cookie".into()),
                SourcePattern::CallPrefix("localStorage".into()),
                SourcePattern::CallPrefix("sessionStorage".into()),
                SourcePattern::CallPrefix("URLSearchParams".into()),
                SourcePattern::CallPrefix("fetch(".into()),
                SourcePattern::CallPrefix("axios.".into()),
                SourcePattern::CallPrefix("http.request".into()),
                SourcePattern::CallPrefix("https.request".into()),
            ],
        },
        // Go
        TaintSource {
            rule_id: rule_id.to_string(),
            name: "Go user input".into(),
            label: TaintLabel::UserInput,
            patterns: vec![
                SourcePattern::CallPrefix("r.FormValue".into()),
                SourcePattern::CallPrefix("r.Form".into()),
                SourcePattern::CallPrefix("r.PostForm".into()),
                SourcePattern::CallPrefix("r.URL.Query".into()),
                SourcePattern::CallPrefix("r.Header".into()),
                SourcePattern::CallPrefix("r.Cookie".into()),
                SourcePattern::CallPrefix("r.MultipartForm".into()),
                SourcePattern::CallPrefix("r.ParseForm".into()),
                SourcePattern::CallPrefix("r.ParseMultipartForm".into()),
                SourcePattern::CallPrefix("r.Body".into()),
                SourcePattern::CallPrefix("os.Args".into()),
                SourcePattern::CallPrefix("os.Getenv".into()),
                SourcePattern::CallPrefix("os.LookupEnv".into()),
                SourcePattern::CallPrefix("http.Request".into()),
                SourcePattern::IdentifierPattern("http.Request".into()),
            ],
        },
        // Java
        TaintSource {
            rule_id: rule_id.to_string(),
            name: "Java user input".into(),
            label: TaintLabel::UserInput,
            patterns: vec![
                SourcePattern::CallPrefix("getParameter".into()),
                SourcePattern::CallPrefix("getHeader".into()),
                SourcePattern::CallPrefix("getQueryString".into()),
                SourcePattern::CallPrefix("getCookies".into()),
                SourcePattern::CallPrefix("getInputStream".into()),
                SourcePattern::CallPrefix("getReader".into()),
                SourcePattern::CallPrefix("@RequestParam".into()),
                SourcePattern::CallPrefix("@PathVariable".into()),
                SourcePattern::CallPrefix("@RequestBody".into()),
                SourcePattern::CallPrefix("@ModelAttribute".into()),
                SourcePattern::CallPrefix("@RequestHeader".into()),
                SourcePattern::CallPrefix("@CookieValue".into()),
                SourcePattern::CallPrefix("request.getParameter".into()),
                SourcePattern::CallPrefix("HttpServletRequest".into()),
                SourcePattern::CallPrefix("BufferedReader".into()),
                SourcePattern::CallPrefix("Scanner".into()),
            ],
        },
        // PHP
        TaintSource {
            rule_id: rule_id.to_string(),
            name: "PHP user input".into(),
            label: TaintLabel::UserInput,
            patterns: vec![
                SourcePattern::CallPrefix("$_GET".into()),
                SourcePattern::CallPrefix("$_POST".into()),
                SourcePattern::CallPrefix("$_REQUEST".into()),
                SourcePattern::CallPrefix("$_COOKIE".into()),
                SourcePattern::CallPrefix("$_FILES".into()),
                SourcePattern::CallPrefix("$_SERVER".into()),
                SourcePattern::CallPrefix("$_ENV".into()),
                SourcePattern::CallPrefix("file_get_contents".into()),
                SourcePattern::CallPrefix("fopen".into()),
                SourcePattern::CallPrefix("getenv".into()),
            ],
        },
        // Ruby
        TaintSource {
            rule_id: rule_id.to_string(),
            name: "Ruby user input".into(),
            label: TaintLabel::UserInput,
            patterns: vec![
                SourcePattern::CallPrefix("params".into()),
                SourcePattern::CallPrefix("request.params".into()),
                SourcePattern::CallPrefix("request.body".into()),
                SourcePattern::CallPrefix("request.query_parameters".into()),
                SourcePattern::CallPrefix("request.request_parameters".into()),
                SourcePattern::CallPrefix("request.headers".into()),
                SourcePattern::CallPrefix("request.cookies".into()),
                SourcePattern::CallPrefix("cookies".into()),
                SourcePattern::CallPrefix("session".into()),
                SourcePattern::CallPrefix("ENV".into()),
                SourcePattern::CallPrefix("ARGV".into()),
                SourcePattern::CallPrefix("gets".into()),
            ],
        },
        // C#
        TaintSource {
            rule_id: rule_id.to_string(),
            name: "C# user input".into(),
            label: TaintLabel::UserInput,
            patterns: vec![
                SourcePattern::CallPrefix("Request.QueryString".into()),
                SourcePattern::CallPrefix("Request.Form".into()),
                SourcePattern::CallPrefix("Request.Params".into()),
                SourcePattern::CallPrefix("Request.Cookies".into()),
                SourcePattern::CallPrefix("Request.Body".into()),
                SourcePattern::CallPrefix("Request.Headers".into()),
                SourcePattern::CallPrefix("Request.InputStream".into()),
                SourcePattern::CallPrefix("HttpContext".into()),
                SourcePattern::CallPrefix("RouteData".into()),
                SourcePattern::CallPrefix("RouteValue".into()),
            ],
        },
    ]
}

fn sql_sanitizers() -> Vec<TaintSanitizer> {
    vec![
        TaintSanitizer { rule_id: "TAINT-SQL001".to_string(), pattern: SanitizerPattern::CallPrefix("escape".into()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-SQL001".to_string(), pattern: SanitizerPattern::CallPrefix("quote".into()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-SQL001".to_string(), pattern: SanitizerPattern::CallPrefix("prepare".into()), by_side_effect: false },
        TaintSanitizer { rule_id: "TAINT-SQL001".to_string(), pattern: SanitizerPattern::CallPrefix("parameterized".into()), by_side_effect: false },
        TaintSanitizer { rule_id: "TAINT-SQL001".to_string(), pattern: SanitizerPattern::CallPrefix("bind".into()), by_side_effect: false },
        TaintSanitizer { rule_id: "TAINT-SQL001".to_string(), pattern: SanitizerPattern::CallPrefix("param".into()), by_side_effect: false },
        TaintSanitizer { rule_id: "TAINT-SQL001".to_string(), pattern: SanitizerPattern::CallPrefix("html.escape".into()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-SQL001".to_string(), pattern: SanitizerPattern::CallPrefix(" bleach.clean".into()), by_side_effect: true },
    ]
}

fn xss_sanitizers() -> Vec<TaintSanitizer> {
    vec![
        TaintSanitizer { rule_id: "TAINT-XSS001".to_string(), pattern: SanitizerPattern::CallPrefix("escape".to_string()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-XSS001".to_string(), pattern: SanitizerPattern::CallPrefix("encode".to_string()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-XSS001".to_string(), pattern: SanitizerPattern::CallPrefix("textContent".to_string()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-XSS001".to_string(), pattern: SanitizerPattern::CallPrefix("innerText".to_string()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-XSS001".to_string(), pattern: SanitizerPattern::Identifier("DOMPurify".to_string()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-XSS001".to_string(), pattern: SanitizerPattern::Identifier("sanitize".to_string()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-XSS001".to_string(), pattern: SanitizerPattern::Identifier("escape".to_string()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-XSS001".to_string(), pattern: SanitizerPattern::Identifier("html_escape".to_string()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-XSS001".to_string(), pattern: SanitizerPattern::Identifier("strip_tags".to_string()), by_side_effect: true },
    ]
}

fn cmd_sanitizers() -> Vec<TaintSanitizer> {
    vec![
        TaintSanitizer { rule_id: "TAINT-CMD001".to_string(), pattern: SanitizerPattern::CallPrefix("shlex.quote".to_string()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-CMD001".to_string(), pattern: SanitizerPattern::CallPrefix("quote".to_string()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-CMD001".to_string(), pattern: SanitizerPattern::CallPrefix("validate".to_string()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-CMD001".to_string(), pattern: SanitizerPattern::Identifier("shell_escape".to_string()), by_side_effect: true },
    ]
}

fn path_sanitizers() -> Vec<TaintSanitizer> {
    vec![
        TaintSanitizer { rule_id: "TAINT-PATH001".to_string(), pattern: SanitizerPattern::CallPrefix("basename".into()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-PATH001".to_string(), pattern: SanitizerPattern::CallPrefix("normpath".into()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-PATH001".to_string(), pattern: SanitizerPattern::CallPrefix("realpath".into()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-PATH001".to_string(), pattern: SanitizerPattern::CallPrefix("abspath".into()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-PATH001".to_string(), pattern: SanitizerPattern::CallPrefix("Path(".to_string()), by_side_effect: true },
        TaintSanitizer { rule_id: "TAINT-PATH001".to_string(), pattern: SanitizerPattern::CallPrefix("SafeFileName".to_string()), by_side_effect: true },
    ]
}

// --------------------------------------------------------------------------
// TAINT-SQL001: SQL Injection (cross-language)
// --------------------------------------------------------------------------

pub struct SqlInjectionRule;

impl TaintRule for SqlInjectionRule {
    fn id(&self) -> &str { "TAINT-SQL001" }
    fn name(&self) -> &str { "SQL Injection (Cross-Language)" }
    fn severity(&self) -> &'static str { "critical" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // Python
            TaintSink { rule_id: self.id().to_string(), name: "cursor.execute".into(), severity: "CRITICAL".into(), description: "SQL query built from untrusted input — SQL injection".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "cursor.executemany".into(), severity: "CRITICAL".into(), description: "SQL executemany with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "db.execute".into(), severity: "CRITICAL".into(), description: "Generic db.execute with untrusted input — SQL injection".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "database.execute".into(), severity: "CRITICAL".into(), description: "Database execute with untrusted input — SQL injection".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "engine.execute".into(), severity: "CRITICAL".into(), description: "SQLAlchemy/engine execute with untrusted input — SQL injection".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "sqlite3.execute".into(), severity: "CRITICAL".into(), description: "SQLite query with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "sqlite3.connect".into(), severity: "CRITICAL".into(), description: "SQLite connection with untrusted query".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "Model.objects.raw".into(), severity: "CRITICAL".into(), description: "Django ORM raw SQL with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "session.query".into(), severity: "CRITICAL".into(), description: "SQLAlchemy session query with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "connection.execute".into(), severity: "CRITICAL".into(), description: "Database connection execute with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            // JavaScript/TypeScript
            TaintSink { rule_id: self.id().to_string(), name: "query".into(), severity: "CRITICAL".into(), description: "Database query with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "pool.query".into(), severity: "CRITICAL".into(), description: "DB pool query with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "connection.query".into(), severity: "CRITICAL".into(), description: "DB connection query with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: " knex".into(), severity: "CRITICAL".into(), description: "Knex query builder with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "sequelize.query".into(), severity: "CRITICAL".into(), description: "Sequelize raw query with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            // Go
            TaintSink { rule_id: self.id().to_string(), name: "db.Query".into(), severity: "CRITICAL".into(), description: "Go database Query with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "db.QueryRow".into(), severity: "CRITICAL".into(), description: "Go database QueryRow with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "db.Exec".into(), severity: "CRITICAL".into(), description: "Go database Exec with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "db.QueryContext".into(), severity: "CRITICAL".into(), description: "Go database QueryContext with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "db.ExecContext".into(), severity: "CRITICAL".into(), description: "Go database ExecContext with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "sql.DB".into(), severity: "CRITICAL".into(), description: "Go sql.DB call with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            // Java
            TaintSink { rule_id: self.id().to_string(), name: "Statement.execute".into(), severity: "CRITICAL".into(), description: "JDBC Statement.execute() with untrusted SQL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "Statement.executeQuery".into(), severity: "CRITICAL".into(), description: "JDBC executeQuery with untrusted SQL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "Connection.prepareStatement".into(), severity: "CRITICAL".into(), description: "JDBC prepareStatement with string concat".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "EntityManager.createQuery".into(), severity: "CRITICAL".into(), description: "JPA createQuery with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "JdbcTemplate.query".into(), severity: "CRITICAL".into(), description: "Spring JdbcTemplate query with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "JdbcTemplate.execute".into(), severity: "CRITICAL".into(), description: "Spring JdbcTemplate execute with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "createQuery".into(), severity: "CRITICAL".into(), description: "JPA createQuery with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            // PHP
            TaintSink { rule_id: self.id().to_string(), name: "mysqli_query".into(), severity: "CRITICAL".into(), description: "mysqli_query with untrusted input".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "mysql_query".into(), severity: "CRITICAL".into(), description: "mysql_query (deprecated) with untrusted input".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "pg_query".into(), severity: "CRITICAL".into(), description: "PostgreSQL pg_query with untrusted input".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "PDO->query".into(), severity: "CRITICAL".into(), description: "PDO query with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "query".into(), severity: "CRITICAL".into(), description: "PDO/Laravel query with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            // Ruby
            TaintSink { rule_id: self.id().to_string(), name: "find_by_sql".into(), severity: "CRITICAL".into(), description: "ActiveRecord find_by_sql with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "connection.execute".into(), severity: "CRITICAL".into(), description: "Ruby DB connection execute with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "ActiveRecord::Base.connection.execute".into(), severity: "CRITICAL".into(), description: "ActiveRecord execute with untrusted SQL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            // C#
            TaintSink { rule_id: self.id().to_string(), name: "ExecuteReader".into(), severity: "CRITICAL".into(), description: "ADO.NET ExecuteReader with untrusted SQL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "ExecuteNonQuery".into(), severity: "CRITICAL".into(), description: "ADO.NET ExecuteNonQuery with untrusted SQL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "ExecuteScalar".into(), severity: "CRITICAL".into(), description: "ADO.NET ExecuteScalar with untrusted SQL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "SqlCommand".into(), severity: "CRITICAL".into(), description: "SqlCommand with string concatenation — SQL injection risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "DbCommand".into(), severity: "CRITICAL".into(), description: "DbCommand with string concatenation".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Sql] },
        ]
    }

    fn sanitizers(&self) -> Vec<TaintSanitizer> { sql_sanitizers() }

    fn propagators(&self) -> Vec<TaintPropagator> {
        vec![
            TaintPropagator { rule_id: self.id().to_string(), trigger_pattern: "format".into(), from_arg: "$ARG".into(), to_arg: "$RESULT".into() },
            TaintPropagator { rule_id: self.id().to_string(), trigger_pattern: "join".into(), from_arg: "$ARG".into(), to_arg: "$RESULT".into() },
            TaintPropagator { rule_id: self.id().to_string(), trigger_pattern: "concat".into(), from_arg: "$ARG".into(), to_arg: "$RESULT".into() },
            TaintPropagator { rule_id: self.id().to_string(), trigger_pattern: "replace".into(), from_arg: "$ARG".into(), to_arg: "$RESULT".into() },
            TaintPropagator { rule_id: self.id().to_string(), trigger_pattern: "f-string".into(), from_arg: "$ARG".into(), to_arg: "$RESULT".into() },
            TaintPropagator { rule_id: self.id().to_string(), trigger_pattern: "interpolate".into(), from_arg: "$ARG".into(), to_arg: "$RESULT".into() },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-XSS001: Cross-Site Scripting (cross-language)
// --------------------------------------------------------------------------

pub struct XssRule;

impl TaintRule for XssRule {
    fn id(&self) -> &str { "TAINT-XSS001" }
    fn name(&self) -> &str { "Cross-Site Scripting (Cross-Language)" }
    fn severity(&self) -> &'static str { "high" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // JavaScript/TypeScript (DOM)
            TaintSink { rule_id: self.id().to_string(), name: "innerHTML".into(), severity: "HIGH".into(), description: "Direct HTML injection via innerHTML — XSS vulnerability".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "outerHTML".into(), severity: "HIGH".into(), description: "HTML injection via outerHTML".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "insertAdjacentHTML".into(), severity: "HIGH".into(), description: "Dynamic HTML insertion — XSS risk".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "document.write".into(), severity: "HIGH".into(), description: "Dynamic document.write — XSS risk".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "writeln".into(), severity: "HIGH".into(), description: "Dynamic writeln — XSS risk".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "eval".into(), severity: "CRITICAL".into(), description: "Dynamic code execution via eval — potential XSS".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "Function".into(), severity: "CRITICAL".into(), description: "Dynamic function creation — XSS risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "setTimeout".into(), severity: "HIGH".into(), description: "Dynamic code in setTimeout — XSS risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "setInterval".into(), severity: "HIGH".into(), description: "Dynamic code in setInterval — XSS risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "dangerouslySetInnerHTML".into(), severity: "HIGH".into(), description: "React dangerouslySetInnerHTML with untrusted content".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "v-html".into(), severity: "HIGH".into(), description: "Vue v-html directive with untrusted content".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "htmlWebpackPlugin".into(), severity: "HIGH".into(), description: "Template injection via html-webpack-plugin".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            // Python (server-side template injection)
            TaintSink { rule_id: self.id().to_string(), name: "render_template_string".into(), severity: "CRITICAL".into(), description: "Flask render_template_string with untrusted input — SSTI/XSS".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "Markup".into(), severity: "HIGH".into(), description: "Flask Markup with untrusted input — mark_safe equivalent".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "|safe".into(), severity: "HIGH".into(), description: "Jinja2 safe filter disables escaping — XSS risk".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "mark_safe".into(), severity: "HIGH".into(), description: "Django mark_safe disables escaping — XSS risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Html] },
            // PHP
            TaintSink { rule_id: self.id().to_string(), name: "echo".into(), severity: "HIGH".into(), description: "PHP echo with untrusted data — XSS risk".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "print".into(), severity: "HIGH".into(), description: "PHP print with untrusted data — XSS risk".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "printf".into(), severity: "HIGH".into(), description: "PHP printf with untrusted format — XSS risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "heredoc".into(), severity: "MEDIUM".into(), description: "PHP heredoc with untrusted data".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            // Ruby
            TaintSink { rule_id: self.id().to_string(), name: "html_safe".into(), severity: "HIGH".into(), description: "Rails html_safe disables escaping — XSS risk".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "raw".into(), severity: "HIGH".into(), description: "Rails raw helper disables escaping — XSS risk".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "render inline".into(), severity: "CRITICAL".into(), description: "Rails inline template rendering — template injection risk".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
        ]
    }

    fn sanitizers(&self) -> Vec<TaintSanitizer> { xss_sanitizers() }
}

// --------------------------------------------------------------------------
// TAINT-CMD001: OS Command Injection (cross-language)
// --------------------------------------------------------------------------

pub struct CommandInjectionRule;

impl TaintRule for CommandInjectionRule {
    fn id(&self) -> &str { "TAINT-CMD001" }
    fn name(&self) -> &str { "OS Command Injection (Cross-Language)" }
    fn severity(&self) -> &'static str { "critical" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // Python
            TaintSink { rule_id: self.id().to_string(), name: "os.system".into(), severity: "CRITICAL".into(), description: "os.system() with untrusted input — command injection".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "os.popen".into(), severity: "CRITICAL".into(), description: "os.popen() with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "subprocess.run".into(), severity: "CRITICAL".into(), description: "subprocess.run() with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "subprocess.Popen".into(), severity: "CRITICAL".into(), description: "subprocess.Popen with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "subprocess.call".into(), severity: "CRITICAL".into(), description: "subprocess.call() with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "subprocess.check_output".into(), severity: "CRITICAL".into(), description: "subprocess.check_output() with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "os.execl".into(), severity: "CRITICAL".into(), description: "os.execl() with untrusted arguments".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "os.execv".into(), severity: "CRITICAL".into(), description: "os.execv() with untrusted arguments".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "os.spawn".into(), severity: "CRITICAL".into(), description: "os.spawn() with untrusted arguments".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "exec".into(), severity: "CRITICAL".into(), description: "exec() with untrusted input — code injection".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "eval".into(), severity: "CRITICAL".into(), description: "eval() with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "shell=True".into(), severity: "CRITICAL".into(), description: "subprocess with shell=True — shell injection".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Command] },
            // Go
            TaintSink { rule_id: self.id().to_string(), name: "exec.Command".into(), severity: "CRITICAL".into(), description: "Go exec.Command with untrusted arguments — command injection".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "os/exec.Run".into(), severity: "CRITICAL".into(), description: "os/exec.Run with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "os/exec.Lookup".into(), severity: "HIGH".into(), description: "Command lookup with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            // Java
            TaintSink { rule_id: self.id().to_string(), name: "Runtime.getRuntime().exec".into(), severity: "CRITICAL".into(), description: "Runtime.exec() with untrusted input — command injection".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "ProcessBuilder".into(), severity: "CRITICAL".into(), description: "ProcessBuilder with untrusted commands".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "getRuntime.exec".into(), severity: "CRITICAL".into(), description: "getRuntime.exec() with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            // JavaScript/TypeScript
            TaintSink { rule_id: self.id().to_string(), name: "child_process.exec".into(), severity: "CRITICAL".into(), description: "Node.js child_process.exec with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "child_process.execSync".into(), severity: "CRITICAL".into(), description: "Node.js execSync with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "exec(".into(), severity: "CRITICAL".into(), description: "exec() call with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "execSync(".into(), severity: "CRITICAL".into(), description: "execSync() with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "spawn(".into(), severity: "HIGH".into(), description: "spawn() with shell option — command injection risk".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Command] },
            // PHP
            TaintSink { rule_id: self.id().to_string(), name: "exec(".into(), severity: "CRITICAL".into(), description: "PHP exec() with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "shell_exec".into(), severity: "CRITICAL".into(), description: "PHP shell_exec() with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "system(".into(), severity: "CRITICAL".into(), description: "PHP system() with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "passthru".into(), severity: "CRITICAL".into(), description: "PHP passthru() with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "popen".into(), severity: "CRITICAL".into(), description: "PHP popen() with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "proc_open".into(), severity: "CRITICAL".into(), description: "PHP proc_open() with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "shell_exec".into(), severity: "CRITICAL".into(), description: "PHP shell_exec backtick operator with untrusted data".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "`".into(), severity: "CRITICAL".into(), description: "PHP backtick operator with untrusted data".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Command] },
            // Ruby
            TaintSink { rule_id: self.id().to_string(), name: "`".into(), severity: "CRITICAL".into(), description: "Ruby backtick with untrusted input — command injection".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "system(".into(), severity: "CRITICAL".into(), description: "Ruby system() with untrusted input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "spawn(".into(), severity: "CRITICAL".into(), description: "Ruby spawn() with untrusted arguments".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "exec(".into(), severity: "CRITICAL".into(), description: "Ruby exec() with untrusted arguments".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "Open3.popen3".into(), severity: "HIGH".into(), description: "Open3 popen3 with untrusted input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Command] },
            // C#
            TaintSink { rule_id: self.id().to_string(), name: "Process.Start".into(), severity: "CRITICAL".into(), description: "C# Process.Start with untrusted input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Command] },
            TaintSink { rule_id: self.id().to_string(), name: "Shell".into(), severity: "CRITICAL".into(), description: "C# Shell() with untrusted input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Command] },
        ]
    }

    fn sanitizers(&self) -> Vec<TaintSanitizer> { cmd_sanitizers() }
}

// --------------------------------------------------------------------------
// TAINT-PATH001: Path Traversal (cross-language)
// --------------------------------------------------------------------------

pub struct PathTraversalRule;

impl TaintRule for PathTraversalRule {
    fn id(&self) -> &str { "TAINT-PATH001" }
    fn name(&self) -> &str { "Path Traversal (Cross-Language)" }
    fn severity(&self) -> &'static str { "high" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // Python
            TaintSink { rule_id: self.id().to_string(), name: "open".into(), severity: "HIGH".into(), description: "File open with untrusted path — path traversal risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "file".into(), severity: "HIGH".into(), description: "File access with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "include".into(), severity: "HIGH".into(), description: "Dynamic include with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "require".into(), severity: "MEDIUM".into(), description: "Dynamic require with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "pathlib.Path".into(), severity: "HIGH".into(), description: "pathlib.Path with untrusted input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "os.path.join".into(), severity: "MEDIUM".into(), description: "os.path.join with untrusted components".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            // JavaScript/TypeScript (Node.js)
            TaintSink { rule_id: self.id().to_string(), name: "fs.readFile".into(), severity: "HIGH".into(), description: "fs.readFile with untrusted path — path traversal".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "fs.readFileSync".into(), severity: "HIGH".into(), description: "fs.readFileSync with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "fs.writeFile".into(), severity: "HIGH".into(), description: "fs.writeFile with untrusted path — arbitrary write".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "fs.createReadStream".into(), severity: "HIGH".into(), description: "fs.createReadStream with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "fs.stat".into(), severity: "MEDIUM".into(), description: "fs.stat with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "fs.access".into(), severity: "MEDIUM".into(), description: "fs.access with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "require(".into(), severity: "MEDIUM".into(), description: "require() with untrusted module path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "import(".into(), severity: "MEDIUM".into(), description: "Dynamic import with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "path.join".into(), severity: "MEDIUM".into(), description: "path.join with untrusted components".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "path.resolve".into(), severity: "MEDIUM".into(), description: "path.resolve with untrusted input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Path] },
            // PHP
            TaintSink { rule_id: self.id().to_string(), name: "fopen".into(), severity: "HIGH".into(), description: "PHP fopen() with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "file_get_contents".into(), severity: "HIGH".into(), description: "PHP file_get_contents() with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "file_put_contents".into(), severity: "HIGH".into(), description: "PHP file_put_contents() with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "include".into(), severity: "HIGH".into(), description: "PHP include with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "require".into(), severity: "HIGH".into(), description: "PHP require with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "include_once".into(), severity: "HIGH".into(), description: "PHP include_once with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "require_once".into(), severity: "HIGH".into(), description: "PHP require_once with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "readfile".into(), severity: "MEDIUM".into(), description: "PHP readfile() with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "move_uploaded_file".into(), severity: "HIGH".into(), description: "PHP move_uploaded_file with untrusted destination".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            // Ruby
            TaintSink { rule_id: self.id().to_string(), name: "File.open".into(), severity: "HIGH".into(), description: "Ruby File.open with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "File.read".into(), severity: "HIGH".into(), description: "Ruby File.read with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "File.write".into(), severity: "HIGH".into(), description: "Ruby File.write with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "require".into(), severity: "MEDIUM".into(), description: "Ruby require with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "load".into(), severity: "MEDIUM".into(), description: "Ruby load with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "open".into(), severity: "HIGH".into(), description: "Ruby open() with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            // Java
            TaintSink { rule_id: self.id().to_string(), name: "new FileInputStream".into(), severity: "HIGH".into(), description: "Java FileInputStream with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "new FileOutputStream".into(), severity: "HIGH".into(), description: "Java FileOutputStream with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "new FileReader".into(), severity: "HIGH".into(), description: "Java FileReader with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "Files.newBufferedReader".into(), severity: "HIGH".into(), description: "Java Files.newBufferedReader with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "Paths.get".into(), severity: "MEDIUM".into(), description: "Java Paths.get with untrusted input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Path] },
            // Go
            TaintSink { rule_id: self.id().to_string(), name: "ioutil.ReadFile".into(), severity: "HIGH".into(), description: "Go ioutil.ReadFile with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "ioutil.WriteFile".into(), severity: "HIGH".into(), description: "Go ioutil.WriteFile with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "os.Open".into(), severity: "HIGH".into(), description: "Go os.Open with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "os.Create".into(), severity: "HIGH".into(), description: "Go os.Create with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "os.Rename".into(), severity: "HIGH".into(), description: "Go os.Rename with untrusted paths".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Path] },
            // C#
            TaintSink { rule_id: self.id().to_string(), name: "File.Open".into(), severity: "HIGH".into(), description: "C# File.Open with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "File.ReadAllText".into(), severity: "HIGH".into(), description: "C# File.ReadAllText with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "File.WriteAllText".into(), severity: "HIGH".into(), description: "C# File.WriteAllText with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
            TaintSink { rule_id: self.id().to_string(), name: "Directory.GetFiles".into(), severity: "MEDIUM".into(), description: "C# Directory.GetFiles with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Path] },
        ]
    }

    fn sanitizers(&self) -> Vec<TaintSanitizer> { path_sanitizers() }
}

// --------------------------------------------------------------------------
// TAINT-NOSQL001: NoSQL / MongoDB Injection (cross-language)
// --------------------------------------------------------------------------

pub struct NoSqlInjectionRule;

impl TaintRule for NoSqlInjectionRule {
    fn id(&self) -> &str { "TAINT-NOSQL001" }
    fn name(&self) -> &str { "NoSQL / MongoDB Injection (Cross-Language)" }
    fn severity(&self) -> &'static str { "critical" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // Python
            TaintSink { rule_id: self.id().to_string(), name: "db.collection.find".into(), severity: "CRITICAL".into(), description: "MongoDB find() with user-controlled query — NoSQL injection".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "db.collection.find_one".into(), severity: "CRITICAL".into(), description: "MongoDB find_one with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "db.command".into(), severity: "CRITICAL".into(), description: "MongoDB command with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "$where".into(), severity: "CRITICAL".into(), description: "MongoDB $where clause with user input — code injection risk".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("nosql".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "pymongo.find".into(), severity: "CRITICAL".into(), description: "PyMongo find() with user-controlled filter".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "insert_one".into(), severity: "HIGH".into(), description: "NoSQL injection risk in document insertion".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "update_one".into(), severity: "HIGH".into(), description: "NoSQL injection risk in document update".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "delete_one".into(), severity: "HIGH".into(), description: "NoSQL injection risk in document deletion".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "find_one_and_update".into(), severity: "HIGH".into(), description: "NoSQL injection risk in findOneAndUpdate".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
            // JavaScript/TypeScript
            TaintSink { rule_id: self.id().to_string(), name: "collection.find".into(), severity: "CRITICAL".into(), description: "MongoDB collection.find with untrusted query".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "collection.findOne".into(), severity: "CRITICAL".into(), description: "MongoDB findOne with untrusted filter".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "collection.updateOne".into(), severity: "HIGH".into(), description: "MongoDB updateOne with untrusted filter".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "collection.deleteOne".into(), severity: "HIGH".into(), description: "MongoDB deleteOne with untrusted filter".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "mongoClient.db".into(), severity: "CRITICAL".into(), description: "MongoDB client with untrusted query".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "mongoose.Query".into(), severity: "HIGH".into(), description: "Mongoose Query with untrusted filter".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "find(".into(), severity: "HIGH".into(), description: "MongoDB find() with untrusted argument".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "findOne(".into(), severity: "HIGH".into(), description: "MongoDB findOne() with untrusted argument".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
            // PHP
            TaintSink { rule_id: self.id().to_string(), name: "MongoDB\\Driver\\Manager".into(), severity: "CRITICAL".into(), description: "MongoDB PHP driver with untrusted query".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("nosql".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "execute".into(), severity: "CRITICAL".into(), description: "MongoDB execute() with untrusted command".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
            // Ruby
            TaintSink { rule_id: self.id().to_string(), name: "Mongo(:collection)".into(), severity: "CRITICAL".into(), description: "Ruby MongoDB with untrusted query".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("nosql".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "collection.find".into(), severity: "CRITICAL".into(), description: "Ruby MongoDB collection find with untrusted query".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("nosql".into())] },
        ]
    }

    fn sanitizers(&self) -> Vec<TaintSanitizer> {
        vec![
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::Identifier("escape".to_string()), by_side_effect: true },
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::Identifier("validate".to_string()), by_side_effect: true },
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::Identifier("sanitize".to_string()), by_side_effect: true },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-SSRF001: Server-Side Request Forgery (cross-language)
// --------------------------------------------------------------------------

pub struct SsrfRule;

impl TaintRule for SsrfRule {
    fn id(&self) -> &str { "TAINT-SSRF001" }
    fn name(&self) -> &str { "Server-Side Request Forgery (Cross-Language)" }
    fn severity(&self) -> &'static str { "high" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // Python
            TaintSink { rule_id: self.id().to_string(), name: "requests.get".into(), severity: "HIGH".into(), description: "requests.get() with untrusted URL — SSRF risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "requests.post".into(), severity: "HIGH".into(), description: "requests.post() with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "requests.put".into(), severity: "HIGH".into(), description: "requests.put() with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "requests.request".into(), severity: "HIGH".into(), description: "requests.request() with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "urllib.request".into(), severity: "HIGH".into(), description: "urllib with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "urlopen".into(), severity: "HIGH".into(), description: "urllib.urlopen with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "httpx.get".into(), severity: "HIGH".into(), description: "httpx.get() with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "aiohttp.ClientSession".into(), severity: "HIGH".into(), description: "aiohttp with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            // JavaScript/TypeScript
            TaintSink { rule_id: self.id().to_string(), name: "fetch(".into(), severity: "HIGH".into(), description: "fetch() with untrusted URL — SSRF risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "axios.get".into(), severity: "HIGH".into(), description: "axios.get() with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "axios.post".into(), severity: "HIGH".into(), description: "axios.post() with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "axios.request".into(), severity: "HIGH".into(), description: "axios.request() with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "http.request".into(), severity: "HIGH".into(), description: "Node.js http.request with untrusted URL".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "https.request".into(), severity: "HIGH".into(), description: "Node.js https.request with untrusted URL".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "node-fetch".into(), severity: "HIGH".into(), description: "node-fetch with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            // Go
            TaintSink { rule_id: self.id().to_string(), name: "http.Get".into(), severity: "HIGH".into(), description: "Go http.Get with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "http.Post".into(), severity: "HIGH".into(), description: "Go http.Post with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "http.NewRequest".into(), severity: "HIGH".into(), description: "Go http.NewRequest with untrusted URL".into(), sink_arg: SinkPosition::Argument(2), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "Client.Do".into(), severity: "HIGH".into(), description: "Go http.Client.Do with untrusted request".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Network] },
            // Java
            TaintSink { rule_id: self.id().to_string(), name: "new URL".into(), severity: "HIGH".into(), description: "Java URL constructor with untrusted input — SSRF risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "HttpClient.newBuilder".into(), severity: "HIGH".into(), description: "Java HttpClient with untrusted URL".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "OkHttpClient".into(), severity: "HIGH".into(), description: "OkHttp with untrusted URL".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "RestTemplate".into(), severity: "HIGH".into(), description: "Spring RestTemplate with untrusted URL".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Network] },
            // PHP
            TaintSink { rule_id: self.id().to_string(), name: "file_get_contents".into(), severity: "HIGH".into(), description: "PHP file_get_contents() with untrusted URL — SSRF risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "curl_setopt".into(), severity: "HIGH".into(), description: "PHP cURL with untrusted URL".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "simplexml_load_string".into(), severity: "HIGH".into(), description: "PHP simplexml with untrusted XML — XXE/SSRF risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            // Ruby
            TaintSink { rule_id: self.id().to_string(), name: "Net::HTTP.start".into(), severity: "HIGH".into(), description: "Ruby Net::HTTP with untrusted URL".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "open-uri".into(), severity: "HIGH".into(), description: "Ruby open-uri with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "RestClient.get".into(), severity: "HIGH".into(), description: "Ruby RestClient with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "HTTParty.get".into(), severity: "HIGH".into(), description: "Ruby HTTParty with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            // C#
            TaintSink { rule_id: self.id().to_string(), name: "WebRequest.Create".into(), severity: "HIGH".into(), description: "C# WebRequest.Create with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "HttpClient.GetAsync".into(), severity: "HIGH".into(), description: "C# HttpClient with untrusted URL".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Network] },
            TaintSink { rule_id: self.id().to_string(), name: "new HttpClient".into(), severity: "HIGH".into(), description: "C# new HttpClient with untrusted base URL".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Network] },
        ]
    }

    fn sanitizers(&self) -> Vec<TaintSanitizer> {
        vec![
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::Identifier("validate_url".to_string()), by_side_effect: true },
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::Identifier("is_internal".to_string()), by_side_effect: true },
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::Identifier("block_internal".to_string()), by_side_effect: true },
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::Identifier("allowlist".to_string()), by_side_effect: true },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-XXE001: XML External Entity (XXE) Injection
// --------------------------------------------------------------------------

pub struct XxeRule;

impl TaintRule for XxeRule {
    fn id(&self) -> &str { "TAINT-XXE001" }
    fn name(&self) -> &str { "XML External Entity (XXE) Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // Python
            TaintSink { rule_id: self.id().to_string(), name: "etree.parse".into(), severity: "CRITICAL".into(), description: "lxml etree.parse with untrusted XML — XXE risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("xml".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "fromstring".into(), severity: "CRITICAL".into(), description: "lxml fromstring with untrusted XML".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("xml".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "xml.dom.minidom.parse".into(), severity: "CRITICAL".into(), description: "xml.dom with untrusted XML".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("xml".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "xml.etree.ElementTree.parse".into(), severity: "CRITICAL".into(), description: "xml.etree with untrusted XML".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("xml".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "defusedxml".into(), severity: "MEDIUM".into(), description: "Non-defusedxml XML parsing with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("xml".into())] },
            // JavaScript/TypeScript
            TaintSink { rule_id: self.id().to_string(), name: "new DOMParser".into(), severity: "CRITICAL".into(), description: "DOMParser with untrusted XML — XXE risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("xml".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "parseFromString".into(), severity: "CRITICAL".into(), description: "DOMParser.parseFromString with untrusted XML".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("xml".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "xmldom".into(), severity: "CRITICAL".into(), description: "xmldom parser with untrusted XML".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("xml".into())] },
            // Java
            TaintSink { rule_id: self.id().to_string(), name: "DocumentBuilderFactory".into(), severity: "CRITICAL".into(), description: "Java DocumentBuilder with untrusted XML — XXE".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("xml".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "SAXParserFactory".into(), severity: "CRITICAL".into(), description: "Java SAXParser with untrusted XML".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("xml".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "XMLInputFactory".into(), severity: "CRITICAL".into(), description: "Java XMLInputFactory with untrusted XML".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("xml".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "TransformerFactory".into(), severity: "CRITICAL".into(), description: "Java TransformerFactory with untrusted XSLT".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("xml".into())] },
            // PHP
            TaintSink { rule_id: self.id().to_string(), name: "simplexml_load_string".into(), severity: "CRITICAL".into(), description: "PHP SimpleXML with untrusted XML — XXE".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("xml".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "simplexml_load_file".into(), severity: "CRITICAL".into(), description: "PHP SimpleXML load_file with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("xml".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "DOMDocument->load".into(), severity: "CRITICAL".into(), description: "PHP DOMDocument load with untrusted XML".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("xml".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "DOMDocument->loadXML".into(), severity: "CRITICAL".into(), description: "PHP DOMDocument loadXML with untrusted XML".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("xml".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "xml_parse".into(), severity: "CRITICAL".into(), description: "PHP xml_parse with untrusted XML".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("xml".into())] },
            // Ruby
            TaintSink { rule_id: self.id().to_string(), name: "REXML::Document".into(), severity: "CRITICAL".into(), description: "Ruby REXML with untrusted XML".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("xml".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "Nokogiri::XML".into(), severity: "CRITICAL".into(), description: "Ruby Nokogiri with untrusted XML".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("xml".into())] },
            // Go
            TaintSink { rule_id: self.id().to_string(), name: "xml.Unmarshal".into(), severity: "CRITICAL".into(), description: "Go xml.Unmarshal with untrusted XML".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::Custom("xml".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "xml.NewDecoder".into(), severity: "CRITICAL".into(), description: "Go XML decoder with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("xml".into())] },
        ]
    }

    fn sanitizers(&self) -> Vec<TaintSanitizer> {
        vec![
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::Identifier("DTD_DISABLED".to_string()), by_side_effect: false },
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::Identifier("DISALLOW_DOCTYPE_DECL".to_string()), by_side_effect: false },
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::Identifier("XXE_SAFE".to_string()), by_side_effect: false },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-SSTI001: Server-Side Template Injection
// --------------------------------------------------------------------------

pub struct SstiRule;

impl TaintRule for SstiRule {
    fn id(&self) -> &str { "TAINT-SSTI001" }
    fn name(&self) -> &str { "Server-Side Template Injection (SSTI)" }
    fn severity(&self) -> &'static str { "critical" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // Python (Jinja2, Mako, Chameleon, Genshi)
            TaintSink { rule_id: self.id().to_string(), name: "render_template_string".into(), severity: "CRITICAL".into(), description: "Flask render_template_string with user input — SSTI".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "Template.render".into(), severity: "CRITICAL".into(), description: "Mako Template.render with user input — SSTI".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "ChameleonPageTemplate".into(), severity: "CRITICAL".into(), description: "Chameleon template with user input — SSTI".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "genshi.TextTemplate".into(), severity: "CRITICAL".into(), description: "Genshi template with user input — SSTI".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "mark_safe".into(), severity: "HIGH".into(), description: "Django mark_safe with user input — potential SSTI".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "format_html".into(), severity: "MEDIUM".into(), description: "Django format_html with untrusted input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "mark_for_escaping".into(), severity: "MEDIUM".into(), description: "mark_for_escaping bypass".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            // JavaScript/TypeScript (template engines)
            TaintSink { rule_id: self.id().to_string(), name: "ejs.render".into(), severity: "CRITICAL".into(), description: "EJS render with user input — SSTI".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "pug.render".into(), severity: "CRITICAL".into(), description: "Pug render with user input — SSTI".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "handlebars.compile".into(), severity: "CRITICAL".into(), description: "Handlebars compile with user input — SSTI".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "nunjucks.render".into(), severity: "CRITICAL".into(), description: "Nunjucks render with user input — SSTI".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "dot.template".into(), severity: "CRITICAL".into(), description: "doT template with user input — SSTI".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Html] },
            // PHP (Twig, Blade)
            TaintSink { rule_id: self.id().to_string(), name: "Twig_Template".into(), severity: "CRITICAL".into(), description: "Twig template with user input — SSTI".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "Blade".into(), severity: "HIGH".into(), description: "Laravel Blade with user input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            // Ruby (ERB, Haml, Slim)
            TaintSink { rule_id: self.id().to_string(), name: "ERB.new".into(), severity: "CRITICAL".into(), description: "Ruby ERB with user input — SSTI".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "Haml::Template".into(), severity: "HIGH".into(), description: "Haml template with user input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "render inline".into(), severity: "CRITICAL".into(), description: "Rails inline rendering with user input — SSTI".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            // Java (Velocity, Freemarker, Thymeleaf)
            TaintSink { rule_id: self.id().to_string(), name: "Velocity.evaluate".into(), severity: "CRITICAL".into(), description: "Velocity engine with user input — SSTI".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
            TaintSink { rule_id: self.id().to_string(), name: "freemarker.core".into(), severity: "CRITICAL".into(), description: "FreeMarker with user input — SSTI".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Html] },
        ]
    }

    fn sanitizers(&self) -> Vec<TaintSanitizer> {
        vec![
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::Identifier("render_template".to_string()), by_side_effect: false },
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::Identifier("auto_escape".to_string()), by_side_effect: false },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-DES001: Unsafe Deserialization
// --------------------------------------------------------------------------

pub struct DeserializationRule;

impl TaintRule for DeserializationRule {
    fn id(&self) -> &str { "TAINT-DES001" }
    fn name(&self) -> &str { "Unsafe Deserialization" }
    fn severity(&self) -> &'static str { "critical" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // Python
            TaintSink { rule_id: self.id().to_string(), name: "pickle.load".into(), severity: "CRITICAL".into(), description: "pickle.load() with untrusted data — RCE risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "pickle.loads".into(), severity: "CRITICAL".into(), description: "pickle.loads() with untrusted data".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "yaml.load".into(), severity: "CRITICAL".into(), description: "yaml.load() without SafeLoader — arbitrary code execution".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "yaml.unsafe_load".into(), severity: "CRITICAL".into(), description: "yaml.unsafe_load with untrusted data".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "marshal.load".into(), severity: "CRITICAL".into(), description: "marshal.load with untrusted data".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "shelve.open".into(), severity: "HIGH".into(), description: "shelve with untrusted data — pickle-based".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "jsonpickle.decode".into(), severity: "CRITICAL".into(), description: "jsonpickle.decode with untrusted data".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            // JavaScript/TypeScript
            TaintSink { rule_id: self.id().to_string(), name: "JSON.parse".into(), severity: "MEDIUM".into(), description: "JSON.parse with deeply nested data — DoS risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "vm.runInContext".into(), severity: "CRITICAL".into(), description: "vm.runInContext with untrusted code — RCE".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "eval(".into(), severity: "CRITICAL".into(), description: "eval() with untrusted serialized data".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "Function(".into(), severity: "CRITICAL".into(), description: "Function() constructor with untrusted data".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "untrusted eval".into(), severity: "CRITICAL".into(), description: "Direct eval of untrusted serialized data".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            // PHP
            TaintSink { rule_id: self.id().to_string(), name: "unserialize".into(), severity: "CRITICAL".into(), description: "PHP unserialize() with untrusted data — PHP object injection".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "var_export".into(), severity: "MEDIUM".into(), description: "PHP var_export with untrusted data".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "eval(".into(), severity: "CRITICAL".into(), description: "PHP eval() with untrusted serialized data".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            // Ruby
            TaintSink { rule_id: self.id().to_string(), name: "Marshal.load".into(), severity: "CRITICAL".into(), description: "Ruby Marshal.load with untrusted data — RCE risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "YAML.load".into(), severity: "CRITICAL".into(), description: "Ruby YAML.load with untrusted data".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "Psych.load".into(), severity: "CRITICAL".into(), description: "Ruby Psych.load with untrusted YAML".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "load(".into(), severity: "CRITICAL".into(), description: "Ruby load() with untrusted path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "eval(".into(), severity: "CRITICAL".into(), description: "Ruby eval with untrusted serialized data".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            // Java
            TaintSink { rule_id: self.id().to_string(), name: "ObjectInputStream".into(), severity: "CRITICAL".into(), description: "Java ObjectInputStream with untrusted data — deserialization RCE".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "readObject".into(), severity: "CRITICAL".into(), description: "Java readObject() with untrusted stream".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("deserialize".into())] },
            // Go
            TaintSink { rule_id: self.id().to_string(), name: "json.Unmarshal".into(), severity: "MEDIUM".into(), description: "Go json.Unmarshal with untrusted JSON — DoS via large numbers".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "gob.NewDecoder".into(), severity: "CRITICAL".into(), description: "Go gob decoder with untrusted data".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "encoding/gob".into(), severity: "CRITICAL".into(), description: "Go gob encoding with untrusted data".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("deserialize".into())] },
            // C#
            TaintSink { rule_id: self.id().to_string(), name: "BinaryFormatter.Deserialize".into(), severity: "CRITICAL".into(), description: "C# BinaryFormatter.Deserialize — deserialization RCE".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "LosFormatter.Deserialize".into(), severity: "CRITICAL".into(), description: "C# LosFormatter with untrusted data".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "SoapFormatter.Deserialize".into(), severity: "CRITICAL".into(), description: "C# SoapFormatter with untrusted data".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Custom("deserialize".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "NetDataContractSerializer".into(), severity: "CRITICAL".into(), description: "C# NetDataContractSerializer — deserialization RCE".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("deserialize".into())] },
        ]
    }

    fn sanitizers(&self) -> Vec<TaintSanitizer> {
        vec![
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::Identifier("yaml.safe_load".to_string()), by_side_effect: false },
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::Identifier("SafeConstructor".to_string()), by_side_effect: false },
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::Identifier("JSONDecoder".to_string()), by_side_effect: false },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-RE001: Regex Denial of Service (ReDoS)
// --------------------------------------------------------------------------

pub struct RedosRule;

impl TaintRule for RedosRule {
    fn id(&self) -> &str { "TAINT-RE001" }
    fn name(&self) -> &str { "Regex Denial of Service (ReDoS)" }
    fn severity(&self) -> &'static str { "medium" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // Python
            TaintSink { rule_id: self.id().to_string(), name: "re.compile".into(), severity: "MEDIUM".into(), description: "re.compile with untrusted pattern — ReDoS risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "re.match".into(), severity: "MEDIUM".into(), description: "re.match with untrusted pattern".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "re.search".into(), severity: "MEDIUM".into(), description: "re.search with untrusted pattern".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "re.findall".into(), severity: "MEDIUM".into(), description: "re.findall with untrusted pattern".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "re.finditer".into(), severity: "MEDIUM".into(), description: "re.finditer with untrusted pattern".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "re.sub".into(), severity: "MEDIUM".into(), description: "re.sub with untrusted pattern".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "re.split".into(), severity: "MEDIUM".into(), description: "re.split with untrusted pattern".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Tainted] },
            // JavaScript/TypeScript
            TaintSink { rule_id: self.id().to_string(), name: "new RegExp".into(), severity: "MEDIUM".into(), description: "RegExp constructor with untrusted pattern — ReDoS".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "RegExp(".into(), severity: "MEDIUM".into(), description: "RegExp() with untrusted pattern".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "regexpu".into(), severity: "MEDIUM".into(), description: "regexpu with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Tainted] },
            // Go
            TaintSink { rule_id: self.id().to_string(), name: "regexp.Compile".into(), severity: "MEDIUM".into(), description: "Go regexp.Compile with untrusted pattern".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "regexp.MustCompile".into(), severity: "MEDIUM".into(), description: "Go regexp.MustCompile with untrusted pattern".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Tainted] },
            // PHP
            TaintSink { rule_id: self.id().to_string(), name: "preg_match".into(), severity: "MEDIUM".into(), description: "PHP preg_match with untrusted pattern — ReDoS".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "preg_replace".into(), severity: "MEDIUM".into(), description: "PHP preg_replace with untrusted pattern".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "preg_match_all".into(), severity: "MEDIUM".into(), description: "PHP preg_match_all with untrusted pattern".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Tainted] },
            // Ruby
            TaintSink { rule_id: self.id().to_string(), name: "Regexp.new".into(), severity: "MEDIUM".into(), description: "Ruby Regexp.new with untrusted pattern".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::Tainted] },
        ]
    }

    fn sanitizers(&self) -> Vec<TaintSanitizer> {
        vec![
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::Identifier("timeout".to_string()), by_side_effect: false },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-HC001: Hardcoded Credentials
// (no sources needed — detects hardcoded constants)
// --------------------------------------------------------------------------

pub struct HardcodedCredentialsRule;

impl TaintRule for HardcodedCredentialsRule {
    fn id(&self) -> &str { "TAINT-HC001" }
    fn name(&self) -> &str { "Hardcoded Credentials" }
    fn severity(&self) -> &'static str { "high" }

    fn sources(&self) -> Vec<TaintSource> { vec![] }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            TaintSink { rule_id: self.id().to_string(), name: "password".into(), severity: "HIGH".into(), description: "Hardcoded password detected".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "secret".into(), severity: "HIGH".into(), description: "Hardcoded secret detected".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "api_key".into(), severity: "HIGH".into(), description: "Hardcoded API key detected".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "aws_access_key".into(), severity: "CRITICAL".into(), description: "Hardcoded AWS access key detected".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "aws_secret".into(), severity: "CRITICAL".into(), description: "Hardcoded AWS secret key detected".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "private_key".into(), severity: "CRITICAL".into(), description: "Hardcoded private key detected".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "bearer".into(), severity: "HIGH".into(), description: "Hardcoded bearer token detected".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "Authorization".into(), severity: "HIGH".into(), description: "Hardcoded Authorization header value".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "token".into(), severity: "HIGH".into(), description: "Hardcoded token detected".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "credential".into(), severity: "HIGH".into(), description: "Hardcoded credential detected".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "passwd".into(), severity: "HIGH".into(), description: "Hardcoded password field detected".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "db_password".into(), severity: "HIGH".into(), description: "Hardcoded database password detected".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "encryption_key".into(), severity: "CRITICAL".into(), description: "Hardcoded encryption key detected".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "jwt_secret".into(), severity: "HIGH".into(), description: "Hardcoded JWT secret detected".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Tainted] },
            TaintSink { rule_id: self.id().to_string(), name: "google_api".into(), severity: "HIGH".into(), description: "Hardcoded Google API key detected".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Tainted] },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-WCRYPTO001: Weak Cryptography
// --------------------------------------------------------------------------

pub struct WeakCryptoRule;

impl TaintRule for WeakCryptoRule {
    fn id(&self) -> &str { "TAINT-WCRYPTO001" }
    fn name(&self) -> &str { "Weak Cryptography" }
    fn severity(&self) -> &'static str { "medium" }

    fn sources(&self) -> Vec<TaintSource> { vec![] }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // Hashing
            TaintSink { rule_id: self.id().to_string(), name: "md5".into(), severity: "MEDIUM".into(), description: "MD5 hash — cryptographically broken".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "sha1".into(), severity: "MEDIUM".into(), description: "SHA1 hash — deprecated for security".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "hashlib.md5".into(), severity: "MEDIUM".into(), description: "Python hashlib.md5 — cryptographically broken".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "hashlib.sha1".into(), severity: "MEDIUM".into(), description: "Python hashlib.sha1 — deprecated".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "cryptography.hazmat.primitives.hashes.MD5".into(), severity: "MEDIUM".into(), description: "cryptography library MD5 — do not use for security".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            // Encryption
            TaintSink { rule_id: self.id().to_string(), name: "DES".into(), severity: "HIGH".into(), description: "DES encryption — insecure, 56-bit key".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "RC4".into(), severity: "HIGH".into(), description: "RC4 cipher — deprecated and insecure".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "ARC4".into(), severity: "HIGH".into(), description: "ARC4 cipher — insecure".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "Blowfish".into(), severity: "MEDIUM".into(), description: "Blowfish with default/random IV — weak".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "RSA".into(), severity: "MEDIUM".into(), description: "RSA encryption without OAEP — weak".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "DSA".into(), severity: "MEDIUM".into(), description: "DSA signature — insecure key sizes".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "DH".into(), severity: "MEDIUM".into(), description: "Diffie-Hellman with weak parameters".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            // Randomness
            TaintSink { rule_id: self.id().to_string(), name: "random.random".into(), severity: "HIGH".into(), description: "random.random() — not cryptographically secure".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "Math.random".into(), severity: "HIGH".into(), description: "JavaScript Math.random() — not cryptographically secure".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "math/rand.New".into(), severity: "HIGH".into(), description: "Go math/rand — not cryptographically secure".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "rand.Rand".into(), severity: "HIGH".into(), description: "Go rand.Rand with default source".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "SecureRandom".into(), severity: "HIGH".into(), description: "Java SecureRandom with weak seed".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            // SSH keys
            TaintSink { rule_id: self.id().to_string(), name: "ssh-rsa".into(), severity: "MEDIUM".into(), description: "SSH RSA key — consider using Ed25519".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-INSEC001: Insecure TLS / SSL
// --------------------------------------------------------------------------

pub struct InsecureTlsRule;

impl TaintRule for InsecureTlsRule {
    fn id(&self) -> &str { "TAINT-INSEC001" }
    fn name(&self) -> &str { "Insecure TLS / SSL Configuration" }
    fn severity(&self) -> &'static str { "high" }

    fn sources(&self) -> Vec<TaintSource> { vec![] }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // Python
            TaintSink { rule_id: self.id().to_string(), name: "verify=False".into(), severity: "HIGH".into(), description: "SSL/TLS certificate verification disabled — MITM vulnerable".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "check_hostname=False".into(), severity: "HIGH".into(), description: "SSL hostname check disabled".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "ssl._create_unverified_context".into(), severity: "HIGH".into(), description: "Python SSL context without verification — MITM risk".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "CURLOPT_SSL_VERIFYPEER".into(), severity: "HIGH".into(), description: "cURL SSL_VERIFYPEER disabled".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "CURLOPT_SSL_VERIFYHOST".into(), severity: "HIGH".into(), description: "cURL SSL_VERIFYHOST disabled".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            // Go
            TaintSink { rule_id: self.id().to_string(), name: "InsecureSkipVerify".into(), severity: "HIGH".into(), description: "Go TLS InsecureSkipVerify=true — disables certificate verification".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "tls.Config".into(), severity: "MEDIUM".into(), description: "Go TLS Config without proper settings".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            // JavaScript/TypeScript
            TaintSink { rule_id: self.id().to_string(), name: "rejectUnauthorized".into(), severity: "HIGH".into(), description: "Node.js rejectUnauthorized=false — TLS verification disabled".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "secure".into(), severity: "MEDIUM".into(), description: "Cookie secure=false over HTTP — session hijack risk".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "https=false".into(), severity: "MEDIUM".into(), description: "Express cookie over HTTP — MITM risk".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            // Java
            TaintSink { rule_id: self.id().to_string(), name: "TrustManager".into(), severity: "HIGH".into(), description: "Java custom TrustManager that bypasses verification".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "HostnameVerifier".into(), severity: "HIGH".into(), description: "Java custom HostnameVerifier that always returns true".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "setDefaultSSLContext".into(), severity: "HIGH".into(), description: "Java setDefaultSSLContext with untrusted certs".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            // PHP
            TaintSink { rule_id: self.id().to_string(), name: "stream_context_create".into(), severity: "HIGH".into(), description: "PHP stream_context with SSL verification disabled".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "CURLOPT_SSL_VERIFYPEER".into(), severity: "HIGH".into(), description: "PHP cURL SSL_VERIFYPEER disabled".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            // Ruby
            TaintSink { rule_id: self.id().to_string(), name: "verify_mode".into(), severity: "HIGH".into(), description: "Ruby OpenSSL with verification disabled".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "ssl_verify_mode".into(), severity: "HIGH".into(), description: "Ruby Net::HTTP ssl_verify_mode disabled".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-LDAP001: LDAP Injection
// --------------------------------------------------------------------------

pub struct LdapInjectionRule;

impl TaintRule for LdapInjectionRule {
    fn id(&self) -> &str { "TAINT-LDAP001" }
    fn name(&self) -> &str { "LDAP Injection" }
    fn severity(&self) -> &'static str { "high" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // Python
            TaintSink { rule_id: self.id().to_string(), name: "ldap.initialize".into(), severity: "HIGH".into(), description: "Python ldap with untrusted DN — LDAP injection".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("ldap".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "ldap.search_s".into(), severity: "HIGH".into(), description: "LDAP search with untrusted filter".into(), sink_arg: SinkPosition::Argument(2), requires: vec![TaintLabel::Custom("ldap".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "ldap3".into(), severity: "HIGH".into(), description: "ldap3 library with untrusted input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("ldap".into())] },
            // JavaScript/TypeScript
            TaintSink { rule_id: self.id().to_string(), name: "ldapjs".into(), severity: "HIGH".into(), description: "ldapjs with untrusted DN — LDAP injection".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("ldap".into())] },
            // Java
            TaintSink { rule_id: self.id().to_string(), name: "DirContext.search".into(), severity: "HIGH".into(), description: "Java JNDI/LDAP search with untrusted filter".into(), sink_arg: SinkPosition::Argument(2), requires: vec![TaintLabel::Custom("ldap".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "InitialLdapCtx".into(), severity: "HIGH".into(), description: "Java InitialLdapCtx with untrusted DN".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("ldap".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "LdapTemplate".into(), severity: "HIGH".into(), description: "Spring LdapTemplate with untrusted filter".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("ldap".into())] },
            // C#
            TaintSink { rule_id: self.id().to_string(), name: "DirectoryEntry".into(), severity: "HIGH".into(), description: "C# DirectoryEntry with untrusted DN — LDAP injection".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("ldap".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "DirectorySearcher".into(), severity: "HIGH".into(), description: "C# DirectorySearcher with untrusted filter".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("ldap".into())] },
            // PHP
            TaintSink { rule_id: self.id().to_string(), name: "ldap_search".into(), severity: "HIGH".into(), description: "PHP ldap_search with untrusted filter".into(), sink_arg: SinkPosition::Argument(4), requires: vec![TaintLabel::Custom("ldap".into())] },
            TaintSink { rule_id: self.id().to_string(), name: "ldap_bind".into(), severity: "HIGH".into(), description: "PHP ldap_bind with untrusted DN".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Custom("ldap".into())] },
        ]
    }

    fn sanitizers(&self) -> Vec<TaintSanitizer> {
        vec![
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::Identifier("escape".to_string()), by_side_effect: true },
        ]
    }
}

// --------------------------------------------------------------------------
// Format String Injection
// --------------------------------------------------------------------------

pub struct FormatStringInjectionRule;

impl TaintRule for FormatStringInjectionRule {
    fn id(&self) -> &str { "TAINT-FORMAT001" }
    fn name(&self) -> &str { "Format String Injection (Cross-Language)" }
    fn severity(&self) -> &'static str { "high" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // Python
            TaintSink { rule_id: self.id().to_string(), name: "print".into(), severity: "HIGH".into(), description: "print() with format string from user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "logging.error".into(), severity: "HIGH".into(), description: "logging.error() with format string from user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "logging.info".into(), severity: "MEDIUM".into(), description: "logging.info() with format string from user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "logging.debug".into(), severity: "MEDIUM".into(), description: "logging.debug() with format string from user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "logger.error".into(), severity: "HIGH".into(), description: "logger.error() with format string from user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // JavaScript/TypeScript
            TaintSink { rule_id: self.id().to_string(), name: "console.log".into(), severity: "MEDIUM".into(), description: "console.log() with format string from user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "console.error".into(), severity: "MEDIUM".into(), description: "console.error() with format string from user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "new Error".into(), severity: "LOW".into(), description: "Error constructor with user input message".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "winston.error".into(), severity: "MEDIUM".into(), description: "winston logger with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // Java
            TaintSink { rule_id: self.id().to_string(), name: "String.format".into(), severity: "HIGH".into(), description: "String.format() with user-controlled format string".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "System.out.printf".into(), severity: "HIGH".into(), description: "printf() with user-controlled format string".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "MessageFormat.format".into(), severity: "HIGH".into(), description: "MessageFormat.format() with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "logger.info".into(), severity: "MEDIUM".into(), description: "Java logger with user input in format string".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // Go
            TaintSink { rule_id: self.id().to_string(), name: "fmt.Printf".into(), severity: "HIGH".into(), description: "fmt.Printf() with user-controlled format string".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "fmt.Sprintf".into(), severity: "HIGH".into(), description: "fmt.Sprintf() with user-controlled format string".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "log.Printf".into(), severity: "MEDIUM".into(), description: "log.Printf() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "fmt.Fprintf".into(), severity: "HIGH".into(), description: "fmt.Fprintf() with user-controlled format string".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // PHP
            TaintSink { rule_id: self.id().to_string(), name: "sprintf".into(), severity: "HIGH".into(), description: "sprintf() with format string from user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "printf".into(), severity: "HIGH".into(), description: "printf() with format string from user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "vsprintf".into(), severity: "HIGH".into(), description: "vsprintf() with format string from user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "error_log".into(), severity: "MEDIUM".into(), description: "error_log() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // Ruby
            TaintSink { rule_id: self.id().to_string(), name: "printf".into(), severity: "HIGH".into(), description: "printf() with user-controlled format string".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "sprintf".into(), severity: "HIGH".into(), description: "sprintf() with user-controlled format string".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "format".into(), severity: "HIGH".into(), description: "format() with user-controlled format string".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Rails.logger".into(), severity: "MEDIUM".into(), description: "Rails.logger with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // Rust
            TaintSink { rule_id: self.id().to_string(), name: "format!".into(), severity: "MEDIUM".into(), description: "format!() macro with user-controlled input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "panic!".into(), severity: "HIGH".into(), description: "panic!() with user-controlled format string".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // C#
            TaintSink { rule_id: self.id().to_string(), name: "string.Format".into(), severity: "HIGH".into(), description: "string.Format() with user-controlled format string".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Console.WriteLine".into(), severity: "MEDIUM".into(), description: "Console.WriteLine() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Logger.LogInformation".into(), severity: "MEDIUM".into(), description: "Logger with user input in format string".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
        ]
    }

    fn propagators(&self) -> Vec<TaintPropagator> {
        vec![
            TaintPropagator { rule_id: self.id().into(), trigger_pattern: "format".into(), from_arg: "$ARG".into(), to_arg: "$RESULT".into() },
            TaintPropagator { rule_id: self.id().into(), trigger_pattern: "interpolate".into(), from_arg: "$ARG".into(), to_arg: "$RESULT".into() },
            TaintPropagator { rule_id: self.id().into(), trigger_pattern: "join".into(), from_arg: "$ARG".into(), to_arg: "$RESULT".into() },
        ]
    }
}

// --------------------------------------------------------------------------
// Mass Assignment
// --------------------------------------------------------------------------

pub struct MassAssignmentRule;

impl TaintRule for MassAssignmentRule {
    fn id(&self) -> &str { "TAINT-MASS001" }
    fn name(&self) -> &str { "Mass Assignment (Cross-Language)" }
    fn severity(&self) -> &'static str { "high" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // Python
            TaintSink { rule_id: self.id().to_string(), name: "**request".into(), severity: "HIGH".into(), description: "Dict unpacking with user input (mass assignment risk)".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "User.create".into(), severity: "HIGH".into(), description: "Model.create() with user input dict".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "User.new".into(), severity: "MEDIUM".into(), description: "Model.new() with user input dict".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "update_from_request".into(), severity: "HIGH".into(), description: "Direct update from request data".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            // JavaScript/TypeScript
            TaintSink { rule_id: self.id().to_string(), name: "Object.assign".into(), severity: "HIGH".into(), description: "Object.assign() merging user input into object".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Object.assign".into(), severity: "HIGH".into(), description: "Object.assign() merging user input into object".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "spread".into(), severity: "HIGH".into(), description: "Object spread with user input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Object.freeze".into(), severity: "LOW".into(), description: "Object.freeze on user input (mutation attempt)".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // Java
            TaintSink { rule_id: self.id().to_string(), name: "BeanUtils.populate".into(), severity: "HIGH".into(), description: "BeanUtils.populate() with user-controlled map".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "convertValue".into(), severity: "HIGH".into(), description: "ObjectMapper.convertValue() with untrusted data".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "bindParameters".into(), severity: "HIGH".into(), description: "Parameter binding with user input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            // Go
            TaintSink { rule_id: self.id().to_string(), name: "json.Unmarshal".into(), severity: "HIGH".into(), description: "json.Unmarshal() into struct with untrusted data".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Decode".into(), severity: "HIGH".into(), description: "Struct decode with user input".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            // Ruby
            TaintSink { rule_id: self.id().to_string(), name: "new".into(), severity: "HIGH".into(), description: "Model.new() with params hash".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "assign_attributes".into(), severity: "HIGH".into(), description: "assign_attributes() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "update".into(), severity: "HIGH".into(), description: "update() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // PHP
            TaintSink { rule_id: self.id().to_string(), name: "extract".into(), severity: "HIGH".into(), description: "extract() on user input — creates variables from array keys".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "parse_str".into(), severity: "HIGH".into(), description: "parse_str() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "$$".into(), severity: "HIGH".into(), description: "Variable variable ($$) with user input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            // C#
            TaintSink { rule_id: self.id().to_string(), name: "JsonConvert.DeserializeObject".into(), severity: "MEDIUM".into(), description: "JsonConvert.DeserializeObject with untrusted JSON".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Deserialize".into(), severity: "HIGH".into(), description: "JSON.Deserialize into dynamic with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
        ]
    }
}

// --------------------------------------------------------------------------
// Unsafe Reflection
// --------------------------------------------------------------------------

pub struct UnsafeReflectionRule;

impl TaintRule for UnsafeReflectionRule {
    fn id(&self) -> &str { "TAINT-REFLECT001" }
    fn name(&self) -> &str { "Unsafe Reflection (Cross-Language)" }
    fn severity(&self) -> &'static str { "medium" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // Python
            TaintSink { rule_id: self.id().to_string(), name: "getattr".into(), severity: "HIGH".into(), description: "getattr() with user-controlled attribute name".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "setattr".into(), severity: "HIGH".into(), description: "setattr() with user-controlled attribute name".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "hasattr".into(), severity: "MEDIUM".into(), description: "hasattr() with user-controlled attribute name".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "delattr".into(), severity: "HIGH".into(), description: "delattr() with user-controlled attribute name".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "__import__".into(), severity: "CRITICAL".into(), description: "__import__() with user-controlled module name".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "importlib.import_module".into(), severity: "CRITICAL".into(), description: "import_module() with user-controlled module name".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "eval".into(), severity: "CRITICAL".into(), description: "eval() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "exec".into(), severity: "CRITICAL".into(), description: "exec() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "locals".into(), severity: "HIGH".into(), description: "locals() access with user input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            // JavaScript/TypeScript
            TaintSink { rule_id: self.id().to_string(), name: "eval".into(), severity: "CRITICAL".into(), description: "eval() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "new Function".into(), severity: "CRITICAL".into(), description: "new Function() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Reflect.apply".into(), severity: "HIGH".into(), description: "Reflect.apply() with user-controlled function".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Function".into(), severity: "CRITICAL".into(), description: "Function() constructor with user input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            // Java
            TaintSink { rule_id: self.id().to_string(), name: "Class.forName".into(), severity: "HIGH".into(), description: "Class.forName() with user-controlled class name".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Method.invoke".into(), severity: "HIGH".into(), description: "Method.invoke() with user-controlled method name".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Constructor.newInstance".into(), severity: "HIGH".into(), description: "Constructor.newInstance() with user-controlled class".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Field.get".into(), severity: "HIGH".into(), description: "Field.get() with user-controlled field name".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            // Go
            TaintSink { rule_id: self.id().to_string(), name: "reflect.ValueOf".into(), severity: "MEDIUM".into(), description: "reflect.ValueOf() with user-controlled value".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "reflect.TypeOf".into(), severity: "MEDIUM".into(), description: "reflect.TypeOf() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "reflect.FieldByName".into(), severity: "HIGH".into(), description: "reflect.FieldByName() with user-controlled field name".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // Ruby
            TaintSink { rule_id: self.id().to_string(), name: "const_get".into(), severity: "HIGH".into(), description: "const_get() with user-controlled class name".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "send".into(), severity: "HIGH".into(), description: "send() with user-controlled method name".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "public_send".into(), severity: "HIGH".into(), description: "public_send() with user-controlled method name".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "instance_variable_get".into(), severity: "HIGH".into(), description: "instance_variable_get() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // PHP
            TaintSink { rule_id: self.id().to_string(), name: "call_user_func".into(), severity: "HIGH".into(), description: "call_user_func() with user-controlled function name".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "call_user_func_array".into(), severity: "HIGH".into(), description: "call_user_func_array() with user-controlled function".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "ReflectionMethod".into(), severity: "HIGH".into(), description: "ReflectionMethod with user-controlled method name".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "classkit_method_invoke".into(), severity: "HIGH".into(), description: "classkit_method_invoke with user input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            // C#
            TaintSink { rule_id: self.id().to_string(), name: "Type.GetType".into(), severity: "HIGH".into(), description: "Type.GetType() with user-controlled type name".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Activator.CreateInstance".into(), severity: "HIGH".into(), description: "Activator.CreateInstance() with user-controlled type".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "MethodInfo.Invoke".into(), severity: "HIGH".into(), description: "MethodInfo.Invoke() with user-controlled method".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
        ]
    }
}

// --------------------------------------------------------------------------
// Type Confusion / Loose Comparison
// --------------------------------------------------------------------------

pub struct TypeConfusionRule;

impl TaintRule for TypeConfusionRule {
    fn id(&self) -> &str { "TAINT-TYPE001" }
    fn name(&self) -> &str { "Type Confusion / Loose Comparison (Cross-Language)" }
    fn severity(&self) -> &'static str { "medium" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // PHP
            TaintSink { rule_id: self.id().to_string(), name: "==".into(), severity: "MEDIUM".into(), description: "Loose comparison (==) with user input — type coercion may bypass checks".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "!=".into(), severity: "MEDIUM".into(), description: "Loose not-equal comparison (!=) with user input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "switch".into(), severity: "MEDIUM".into(), description: "switch() with user input — loose comparison in case statements".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "in_array".into(), severity: "MEDIUM".into(), description: "in_array() with strict=false (default) using user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "array_search".into(), severity: "MEDIUM".into(), description: "array_search() with user input — type coercion in return value".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // JavaScript/TypeScript
            TaintSink { rule_id: self.id().to_string(), name: "==".into(), severity: "MEDIUM".into(), description: "Loose equality (==) with user input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "!=".into(), severity: "MEDIUM".into(), description: "Loose inequality (!=) with user input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "if".into(), severity: "LOW".into(), description: "Conditional check with user input — verify strict equality (===) is used".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            // Python
            TaintSink { rule_id: self.id().to_string(), name: "is".into(), severity: "LOW".into(), description: "Identity check (is) with user input — unusual pattern".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "bool".into(), severity: "LOW".into(), description: "Boolean conversion of user input in conditional — verify correct type handling".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
        ]
    }
}

// --------------------------------------------------------------------------
// Log Injection
// --------------------------------------------------------------------------

pub struct LogInjectionRule;

impl TaintRule for LogInjectionRule {
    fn id(&self) -> &str { "TAINT-LOG001" }
    fn name(&self) -> &str { "Log Injection (Cross-Language)" }
    fn severity(&self) -> &'static str { "medium" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // Python
            TaintSink { rule_id: self.id().to_string(), name: "logging.info".into(), severity: "MEDIUM".into(), description: "logging.info() with unescaped user input — newline injection in logs".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "logging.error".into(), severity: "MEDIUM".into(), description: "logging.error() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "logging.warning".into(), severity: "MEDIUM".into(), description: "logging.warning() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "logging.debug".into(), severity: "LOW".into(), description: "logging.debug() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "print".into(), severity: "LOW".into(), description: "print() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "structlog".into(), severity: "MEDIUM".into(), description: "structlog with user input in message fields".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            // JavaScript/TypeScript
            TaintSink { rule_id: self.id().to_string(), name: "console.log".into(), severity: "LOW".into(), description: "console.log() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "console.error".into(), severity: "LOW".into(), description: "console.error() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "winston.info".into(), severity: "MEDIUM".into(), description: "winston logger with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "winston.error".into(), severity: "MEDIUM".into(), description: "winston.error() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "pino.info".into(), severity: "MEDIUM".into(), description: "pino logger with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "morgan".into(), severity: "MEDIUM".into(), description: "morgan HTTP logger with user input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            // Java
            TaintSink { rule_id: self.id().to_string(), name: "System.out.println".into(), severity: "LOW".into(), description: "System.out.println() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "System.err.println".into(), severity: "LOW".into(), description: "System.err.println() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "logger.info".into(), severity: "MEDIUM".into(), description: "Logger.info() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "logger.warn".into(), severity: "MEDIUM".into(), description: "Logger.warn() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "log.info".into(), severity: "MEDIUM".into(), description: "Log.info() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "log.error".into(), severity: "MEDIUM".into(), description: "Log.error() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // Go
            TaintSink { rule_id: self.id().to_string(), name: "log.Printf".into(), severity: "MEDIUM".into(), description: "log.Printf() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "log.Print".into(), severity: "MEDIUM".into(), description: "log.Print() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "logrus.Info".into(), severity: "MEDIUM".into(), description: "logrus.Info() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "logrus.Error".into(), severity: "MEDIUM".into(), description: "logrus.Error() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "zap.S".into(), severity: "MEDIUM".into(), description: "zap.S() logging with unescaped user input".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            // PHP
            TaintSink { rule_id: self.id().to_string(), name: "error_log".into(), severity: "MEDIUM".into(), description: "error_log() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "syslog".into(), severity: "MEDIUM".into(), description: "syslog() with unescaped user input — log injection possible".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "file_put_contents".into(), severity: "MEDIUM".into(), description: "file_put_contents() writing to log file with user input".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            // Ruby
            TaintSink { rule_id: self.id().to_string(), name: "Rails.logger".into(), severity: "MEDIUM".into(), description: "Rails.logger with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Logger.info".into(), severity: "MEDIUM".into(), description: "Logger.info() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "puts".into(), severity: "LOW".into(), description: "puts() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // Rust
            TaintSink { rule_id: self.id().to_string(), name: "println!".into(), severity: "LOW".into(), description: "println!() with user input — generally safe due to format macros".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "eprintln!".into(), severity: "LOW".into(), description: "eprintln!() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // C#
            TaintSink { rule_id: self.id().to_string(), name: "Console.WriteLine".into(), severity: "LOW".into(), description: "Console.WriteLine() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Logger.LogInformation".into(), severity: "MEDIUM".into(), description: "Logger.LogInformation() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Logger.LogWarning".into(), severity: "MEDIUM".into(), description: "Logger.LogWarning() with unescaped user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Trace.TraceInformation".into(), severity: "MEDIUM".into(), description: "Trace.TraceInformation() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
        ]
    }

    fn sanitizers(&self) -> Vec<TaintSanitizer> {
        vec![
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::CallPrefix("strip".to_string()), by_side_effect: false },
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::CallPrefix("sanitize".to_string()), by_side_effect: false },
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::CallPrefix("escape".to_string()), by_side_effect: false },
        ]
    }
}

// --------------------------------------------------------------------------
// YAML Unsafe Deserialization
// --------------------------------------------------------------------------

pub struct YamlUnsafeRule;

impl TaintRule for YamlUnsafeRule {
    fn id(&self) -> &str { "TAINT-YAML001" }
    fn name(&self) -> &str { "YAML Unsafe Deserialization (Cross-Language)" }
    fn severity(&self) -> &'static str { "critical" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            // Python
            TaintSink { rule_id: self.id().to_string(), name: "yaml.load".into(), severity: "CRITICAL".into(), description: "yaml.load() without SafeLoader — arbitrary code execution risk".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "yaml.unsafe_load".into(), severity: "CRITICAL".into(), description: "yaml.unsafe_load() — always dangerous with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "yaml.unsafe_load_all".into(), severity: "CRITICAL".into(), description: "yaml.unsafe_load_all() — dangerous with untrusted input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // Java
            TaintSink { rule_id: self.id().to_string(), name: "new Yaml".into(), severity: "CRITICAL".into(), description: "SnakeYAML new Yaml() with user input — arbitrary constructor execution".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Yaml.load".into(), severity: "CRITICAL".into(), description: "Yaml.load() with user input — arbitrary code execution".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Yaml.loadAll".into(), severity: "CRITICAL".into(), description: "Yaml.loadAll() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // Ruby
            TaintSink { rule_id: self.id().to_string(), name: "YAML.load".into(), severity: "CRITICAL".into(), description: "YAML.load() with user input — arbitrary Ruby object deserialization".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "YAML.load_stream".into(), severity: "CRITICAL".into(), description: "YAML.load_stream() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Psych.load".into(), severity: "CRITICAL".into(), description: "Psych.load() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            // Go
            TaintSink { rule_id: self.id().to_string(), name: "yaml.Unmarshal".into(), severity: "HIGH".into(), description: "yaml.Unmarshal() decoding to interface{} with user input".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            // PHP
            TaintSink { rule_id: self.id().to_string(), name: "yaml_parse".into(), severity: "HIGH".into(), description: "yaml_parse() with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "yaml_parse_file".into(), severity: "HIGH".into(), description: "yaml_parse_file() with user-controlled path".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
        ]
    }

    fn sanitizers(&self) -> Vec<TaintSanitizer> {
        vec![
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::CallPrefix("SafeLoader".to_string()), by_side_effect: false },
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::CallPrefix("safe_load".to_string()), by_side_effect: false },
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::CallPrefix("SafeConstructor".to_string()), by_side_effect: false },
            TaintSanitizer { rule_id: self.id().to_string(), pattern: SanitizerPattern::CallPrefix("YAML.safe_load".to_string()), by_side_effect: false },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-PP001: Prototype Pollution
// --------------------------------------------------------------------------

pub struct PrototypePollutionRule;

impl TaintRule for PrototypePollutionRule {
    fn id(&self) -> &str { "TAINT-PP001" }
    fn name(&self) -> &str { "Prototype Pollution (CWE-1321)" }
    fn severity(&self) -> &'static str { "high" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            TaintSink { rule_id: self.id().to_string(), name: "bracket_access_assignment".into(), severity: "HIGH".into(), description: "Object property assignment with user-controlled key — prototype pollution".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "__proto__".into(), severity: "CRITICAL".into(), description: "Direct __proto__ assignment — prototype pollution".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "constructor.prototype".into(), severity: "CRITICAL".into(), description: "constructor.prototype pollution — prototype pollution".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Object.assign".into(), severity: "HIGH".into(), description: "Object.assign with user-controlled properties — prototype pollution".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "merge".into(), severity: "HIGH".into(), description: "Deep merge with user input — prototype pollution".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "clone".into(), severity: "HIGH".into(), description: "Clone function with user input — prototype pollution".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-JWT001: JWT Security Issues
// --------------------------------------------------------------------------

pub struct JwtSecurityRule;

impl TaintRule for JwtSecurityRule {
    fn id(&self) -> &str { "TAINT-JWT001" }
    fn name(&self) -> &str { "JWT Security Misconfiguration" }
    fn severity(&self) -> &'static str { "high" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            TaintSink { rule_id: self.id().to_string(), name: "jwt.decode".into(), severity: "HIGH".into(), description: "JWT decode without verification — authentication bypass".into(), sink_arg: SinkPosition::Entire, requires: vec![] },
            TaintSink { rule_id: self.id().to_string(), name: "jwt.encode".into(), severity: "MEDIUM".into(), description: "JWT encode with weak algorithm — algorithm confusion attack".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "jsonwebtoken.verify".into(), severity: "HIGH".into(), description: "JWT verify without proper validation".into(), sink_arg: SinkPosition::Entire, requires: vec![] },
            TaintSink { rule_id: self.id().to_string(), name: "jwtService.verify".into(), severity: "HIGH".into(), description: "JWT verify with weak secret or none algorithm".into(), sink_arg: SinkPosition::Entire, requires: vec![] },
            TaintSink { rule_id: self.id().to_string(), name: "jwt.sign".into(), severity: "MEDIUM".into(), description: "JWT sign with weak secret".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::Crypto] },
            TaintSink { rule_id: self.id().to_string(), name: "Jwts.parser".into(), severity: "HIGH".into(), description: "JJWT parser without required validation".into(), sink_arg: SinkPosition::Entire, requires: vec![] },
            TaintSink { rule_id: self.id().to_string(), name: "jwt-go.Parse".into(), severity: "HIGH".into(), description: "jwt.Parse without key function — verification bypass".into(), sink_arg: SinkPosition::Entire, requires: vec![] },
            TaintSink { rule_id: self.id().to_string(), name: "golang-jwt.Parse".into(), severity: "HIGH".into(), description: "golang-jwt Parse without key — verification bypass".into(), sink_arg: SinkPosition::Entire, requires: vec![] },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-OPENREDIRECT001: Open Redirect
// --------------------------------------------------------------------------

pub struct OpenRedirectRule;

impl TaintRule for OpenRedirectRule {
    fn id(&self) -> &str { "TAINT-OPENREDIRECT001" }
    fn name(&self) -> &str { "Open Redirect Vulnerability" }
    fn severity(&self) -> &'static str { "medium" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            TaintSink { rule_id: self.id().to_string(), name: "redirect".into(), severity: "MEDIUM".into(), description: "Flask redirect with user input — open redirect".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "HttpResponseRedirect".into(), severity: "MEDIUM".into(), description: "Django redirect with user input — open redirect".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "RedirectResponse".into(), severity: "MEDIUM".into(), description: "FastAPI redirect with user input — open redirect".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "res.redirect".into(), severity: "MEDIUM".into(), description: "Express redirect with user input — open redirect".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "ctx.redirect".into(), severity: "MEDIUM".into(), description: "Koa redirect with user input — open redirect".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "sendRedirect".into(), severity: "MEDIUM".into(), description: "Servlet sendRedirect with user input — open redirect".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "header".into(), severity: "MEDIUM".into(), description: "PHP header(Location:) with user input — open redirect".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "redirect_to".into(), severity: "MEDIUM".into(), description: "Rails redirect_to with user input — open redirect".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "http.Redirect".into(), severity: "MEDIUM".into(), description: "Go http.Redirect with user input — open redirect".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Response.Redirect".into(), severity: "MEDIUM".into(), description: "ASP.NET redirect with user input — open redirect".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-COOKIE001: Cookie Security Issues
// --------------------------------------------------------------------------

pub struct CookieSecurityRule;

impl TaintRule for CookieSecurityRule {
    fn id(&self) -> &str { "TAINT-COOKIE001" }
    fn name(&self) -> &str { "Insecure Cookie Configuration" }
    fn severity(&self) -> &'static str { "medium" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            TaintSink { rule_id: self.id().to_string(), name: "res.cookie".into(), severity: "MEDIUM".into(), description: "Express cookie without httpOnly — XSS cookie theft".into(), sink_arg: SinkPosition::Entire, requires: vec![] },
            TaintSink { rule_id: self.id().to_string(), name: "document.cookie".into(), severity: "HIGH".into(), description: "Reading document.cookie directly — sensitive data exposure".into(), sink_arg: SinkPosition::Entire, requires: vec![] },
            TaintSink { rule_id: self.id().to_string(), name: "set_cookie".into(), severity: "MEDIUM".into(), description: "Django cookie without secure/httpOnly — session hijacking".into(), sink_arg: SinkPosition::Entire, requires: vec![] },
            TaintSink { rule_id: self.id().to_string(), name: "setcookie".into(), severity: "MEDIUM".into(), description: "PHP setcookie without secure/httpOnly — session security".into(), sink_arg: SinkPosition::Entire, requires: vec![] },
            TaintSink { rule_id: self.id().to_string(), name: "cookies".into(), severity: "MEDIUM".into(), description: "Rails cookie without httpOnly — XSS cookie theft".into(), sink_arg: SinkPosition::Entire, requires: vec![] },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-SESSION001: Session Fixation
// --------------------------------------------------------------------------

pub struct SessionFixationRule;

impl TaintRule for SessionFixationRule {
    fn id(&self) -> &str { "TAINT-SESSION001" }
    fn name(&self) -> &str { "Session Fixation Vulnerability" }
    fn severity(&self) -> &'static str { "medium" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            TaintSink { rule_id: self.id().to_string(), name: "session.permanent".into(), severity: "MEDIUM".into(), description: "Flask permanent session set from user input — session fixation".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "sessionID".into(), severity: "MEDIUM".into(), description: "Session ID set from user input — session fixation".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "session_id".into(), severity: "HIGH".into(), description: "PHP session_id() called with user input — session fixation".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-AUTHZ001: Improper Authorization / IDOR
// --------------------------------------------------------------------------

pub struct ImproperAuthorizationRule;

impl TaintRule for ImproperAuthorizationRule {
    fn id(&self) -> &str { "TAINT-AUTHZ001" }
    fn name(&self) -> &str { "Improper Authorization / IDOR" }
    fn severity(&self) -> &'static str { "high" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            TaintSink { rule_id: self.id().to_string(), name: "objects.get".into(), severity: "HIGH".into(), description: "Django ORM get() with user ID — IDOR vulnerability".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Model.query.get".into(), severity: "HIGH".into(), description: "SQLAlchemy query.get with user input — IDOR".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "findById".into(), severity: "HIGH".into(), description: "Mongoose findById with user input — IDOR".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "entityManager.find".into(), severity: "HIGH".into(), description: "JPA entityManager.find with user input — IDOR".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "User.find".into(), severity: "HIGH".into(), description: "Rails User.find with user input — IDOR".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "First".into(), severity: "HIGH".into(), description: "GORM First() with user input — IDOR".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput, TaintLabel::Sql] },
            TaintSink { rule_id: self.id().to_string(), name: "DbSet.Find".into(), severity: "HIGH".into(), description: "EF Core DbSet.Find with user input — IDOR".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-CODE001: Code Injection / Eval
// --------------------------------------------------------------------------

pub struct CodeInjectionRule;

impl TaintRule for CodeInjectionRule {
    fn id(&self) -> &str { "TAINT-CODE001" }
    fn name(&self) -> &str { "Code Injection / Eval Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            TaintSink { rule_id: self.id().to_string(), name: "eval".into(), severity: "CRITICAL".into(), description: "eval() with user input — arbitrary code execution".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "exec".into(), severity: "CRITICAL".into(), description: "exec() with user input — arbitrary code execution".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "compile".into(), severity: "CRITICAL".into(), description: "compile() with user input — arbitrary code execution".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "Function(".into(), severity: "CRITICAL".into(), description: "new Function() with user input — arbitrary JS execution".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "setTimeout".into(), severity: "HIGH".into(), description: "setTimeout with string and user input — eval injection".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "vm.runIn".into(), severity: "CRITICAL".into(), description: "Node vm.runIn* with user input — sandbox escape".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "assert".into(), severity: "CRITICAL".into(), description: "PHP assert() with string and user input — RCE".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "call_user_func".into(), severity: "HIGH".into(), description: "call_user_func with user-controlled function name — RCE".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "send".into(), severity: "HIGH".into(), description: "Object.send with user-controlled method — code execution".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "ScriptEngine".into(), severity: "CRITICAL".into(), description: "JavaScript ScriptEngine with user input — code execution".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "GroovyShell".into(), severity: "CRITICAL".into(), description: "GroovyShell.evaluate with user input — code execution".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-SMUGGLE001: HTTP Request Smuggling
// --------------------------------------------------------------------------

pub struct RequestSmugglingRule;

impl TaintRule for RequestSmugglingRule {
    fn id(&self) -> &str { "TAINT-SMUGGLE001" }
    fn name(&self) -> &str { "HTTP Request Smuggling" }
    fn severity(&self) -> &'static str { "high" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            TaintSink { rule_id: self.id().to_string(), name: "ReverseProxy".into(), severity: "HIGH".into(), description: "httputil.ReverseProxy without request body handling — smuggling".into(), sink_arg: SinkPosition::Entire, requires: vec![] },
            TaintSink { rule_id: self.id().to_string(), name: "NewSingleHostReverseProxy".into(), severity: "HIGH".into(), description: "Reverse proxy without CL.TE handling — request smuggling".into(), sink_arg: SinkPosition::Entire, requires: vec![] },
            TaintSink { rule_id: self.id().to_string(), name: "http.createServer".into(), severity: "MEDIUM".into(), description: "HTTP server without proper header parsing — smuggling".into(), sink_arg: SinkPosition::Entire, requires: vec![] },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-XPATH001: XPath Injection
// --------------------------------------------------------------------------

pub struct XPathInjectionRule;

impl TaintRule for XPathInjectionRule {
    fn id(&self) -> &str { "TAINT-XPATH001" }
    fn name(&self) -> &str { "XPath Injection" }
    fn severity(&self) -> &'static str { "high" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            TaintSink { rule_id: self.id().to_string(), name: "etree.iterparse".into(), severity: "HIGH".into(), description: "lxml iterparse with user input — XPath injection".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput, TaintLabel::Xml] },
            TaintSink { rule_id: self.id().to_string(), name: "ElementPath".into(), severity: "HIGH".into(), description: "ElementPath with user input — XPath injection".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput, TaintLabel::Xml] },
            TaintSink { rule_id: self.id().to_string(), name: "xpath".into(), severity: "HIGH".into(), description: "xpath library with user input — XPath injection".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "evaluate".into(), severity: "HIGH".into(), description: "XPath evaluate with user input — XPath injection".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "DOMXPath".into(), severity: "HIGH".into(), description: "DOMXPath.query with user input — XPath injection".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "XPathFactory".into(), severity: "HIGH".into(), description: "XPath evaluation with user input — XPath injection".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput, TaintLabel::Xml] },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-HEADER001: HTTP Header Injection
// --------------------------------------------------------------------------

pub struct HTTPHeaderInjectionRule;

impl TaintRule for HTTPHeaderInjectionRule {
    fn id(&self) -> &str { "TAINT-HEADER001" }
    fn name(&self) -> &str { "HTTP Header Injection" }
    fn severity(&self) -> &'static str { "medium" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            TaintSink { rule_id: self.id().to_string(), name: "w.Header.Set".into(), severity: "MEDIUM".into(), description: "Header.Set with user input — header injection".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "res.setHeader".into(), severity: "MEDIUM".into(), description: "res.setHeader with user input — header injection".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "header".into(), severity: "HIGH".into(), description: "PHP header() with user input — response splitting / cache poisoning".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "response.setHeader".into(), severity: "MEDIUM".into(), description: "Servlet setHeader with user input — header injection".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "headers".into(), severity: "MEDIUM".into(), description: "Rails response headers with user input — header injection".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-EVAL001: Eval Injection via Dynamic Strings
// --------------------------------------------------------------------------

pub struct EvalInjectionRule;

impl TaintRule for EvalInjectionRule {
    fn id(&self) -> &str { "TAINT-EVAL001" }
    fn name(&self) -> &str { "Eval Injection via Dynamic Strings" }
    fn severity(&self) -> &'static str { "high" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            TaintSink { rule_id: self.id().to_string(), name: "innerHTML".into(), severity: "HIGH".into(), description: "innerHTML with user input — XSS (indirect script execution)".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "outerHTML".into(), severity: "HIGH".into(), description: "outerHTML with user input — XSS".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "insertAdjacentHTML".into(), severity: "HIGH".into(), description: "insertAdjacentHTML with user input — XSS".into(), sink_arg: SinkPosition::Argument(1), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "document.write".into(), severity: "HIGH".into(), description: "document.write with user input — XSS".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "dangerouslySetInnerHTML".into(), severity: "HIGH".into(), description: "React dangerouslySetInnerHTML with user input — XSS".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "v-html".into(), severity: "HIGH".into(), description: "Vue v-html directive with user input — XSS".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "bypassSecurityTrustHtml".into(), severity: "HIGH".into(), description: "Angular bypassSecurityTrustHtml — CSP bypass".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "safe".into(), severity: "HIGH".into(), description: "Jinja2 safe filter on user input — XSS".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
        ]
    }
}

// --------------------------------------------------------------------------
// TAINT-REDIRECT001: URL Redirect Without Validation
// --------------------------------------------------------------------------

pub struct URLRedirectRule;

impl TaintRule for URLRedirectRule {
    fn id(&self) -> &str { "TAINT-REDIRECT001" }
    fn name(&self) -> &str { "URL Redirect Without Validation" }
    fn severity(&self) -> &'static str { "medium" }

    fn sources(&self) -> Vec<TaintSource> { all_user_input_sources(self.id()) }

    fn sinks(&self) -> Vec<TaintSink> {
        vec![
            TaintSink { rule_id: self.id().to_string(), name: "urlparse".into(), severity: "MEDIUM".into(), description: "URL parsing of user input for redirect — open redirect".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "URL(".into(), severity: "MEDIUM".into(), description: "URL object constructed with user input".into(), sink_arg: SinkPosition::Argument(0), requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "urljoin".into(), severity: "MEDIUM".into(), description: "urljoin with user-controlled base or relative — redirect".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "pathJoin".into(), severity: "MEDIUM".into(), description: "path.Join with user input — path traversal in redirect".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
            TaintSink { rule_id: self.id().to_string(), name: "path.resolve".into(), severity: "MEDIUM".into(), description: "path.resolve with user input — redirect to arbitrary domain".into(), sink_arg: SinkPosition::Entire, requires: vec![TaintLabel::UserInput] },
        ]
    }
}

// --------------------------------------------------------------------------
// Get all built-in taint rules
// --------------------------------------------------------------------------

pub fn all_taint_rules() -> Vec<Box<dyn TaintRule>> {
    vec![
        // Phase 1: Core cross-language rules
        Box::new(SqlInjectionRule),
        Box::new(XssRule),
        Box::new(CommandInjectionRule),
        Box::new(PathTraversalRule),
        Box::new(NoSqlInjectionRule),
        // Phase 2: Additional vulnerability classes
        Box::new(SsrfRule),
        Box::new(XxeRule),
        Box::new(SstiRule),
        Box::new(DeserializationRule),
        Box::new(RedosRule),
        Box::new(HardcodedCredentialsRule),
        Box::new(WeakCryptoRule),
        Box::new(InsecureTlsRule),
        Box::new(LdapInjectionRule),
        // Phase 3: Newly converted rules
        Box::new(FormatStringInjectionRule),
        Box::new(MassAssignmentRule),
        Box::new(UnsafeReflectionRule),
        Box::new(TypeConfusionRule),
        Box::new(LogInjectionRule),
        Box::new(YamlUnsafeRule),
        // Phase 4: Additional language-specific and cross-language rules
        Box::new(PrototypePollutionRule),
        Box::new(JwtSecurityRule),
        Box::new(OpenRedirectRule),
        Box::new(CookieSecurityRule),
        Box::new(SessionFixationRule),
        Box::new(ImproperAuthorizationRule),
        Box::new(CodeInjectionRule),
        Box::new(RequestSmugglingRule),
        Box::new(XPathInjectionRule),
        Box::new(HTTPHeaderInjectionRule),
        Box::new(EvalInjectionRule),
        Box::new(URLRedirectRule),
    ]
}
