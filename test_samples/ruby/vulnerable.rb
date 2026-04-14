# Ruby vulnerable test file

# ==================== RUBY-SEC-001: SQL Injection (CRITICAL) ====================

# Rails SQL injection with interpolation
def bad_query(user_name)
  User.where("name = '#{user_name}'")
  # Line: ActiveRecord where with SQL injection
end

def bad_find(name)
  User.find_by_sql("SELECT * FROM users WHERE name = '#{name}'")
  # Line: find_by_sql with interpolation
end

def bad_order(user_input)
  items = Item.order("created_at #{user_input}")
  # Line: order with interpolation
end

# ==================== RUBY-SEC-002: Code Injection (CRITICAL) ====================

def eval_user(user_code)
  eval(user_code)
  # Line: eval code injection
end

def send_dynamic(user_method)
  obj.send(user_method.to_sym)
  # Line: send with dynamic method - code injection
end

# ==================== RUBY-SEC-003: Command Injection (CRITICAL) ====================

def run_cmd(user_host)
  result = `ping -c 4 #{user_host}`
  # Line: backtick command injection
end

def system_cmd(user_file)
  system("ls -la #{user_file}")
  # Line: system command injection
end

def spawn_cmd(user_arg)
  spawn("echo #{user_arg}")
  # Line: spawn command injection
end

# ==================== RUBY-SEC-004: Path Traversal (HIGH) ====================

def read_file(user_path)
  data = File.read("/data/" + user_path)
  # Line: File.read path traversal
end

def open_file(user_name)
  File.open("files/" + user_name, "r") { |f| f.read }
  # Line: File.open path traversal
end

# ==================== RUBY-SEC-005: Hardcoded Secrets (HIGH) ====================

API_KEY = "sk-live-abc123xyz456secret789key12345"   # Line: hardcoded API key
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"                   # Line: hardcoded AWS key
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # Line: hardcoded GitHub token
JWT_SECRET = "super_secret_jwt_key_do_not_use"      # Line: hardcoded secret
db_password = "MySecretPass123!"                   # Line: hardcoded password

# ==================== RUBY-SEC-006: Weak Crypto (MEDIUM) ====================

def hash_md5(data)
  require 'digest/md5'
  Digest::MD5.hexdigest(data)
  # Line: MD5 weak crypto
end

def hash_sha1(data)
  require 'digest/sha1'
  Digest::SHA1.hexdigest(data)
  # Line: SHA1 deprecated
end

def weak_cipher
  cipher = OpenSSL::Cipher.new("des-ecb")
  # Line: ECB mode insecure
end

# ==================== RUBY-SEC-007: XSS (HIGH) ====================

def render_user_name(name)
  raw("<h1>Hello #{name}</h1>")
  # Line: raw() with interpolation XSS
end

def html_safe_render(content)
  content.html_safe
  # Line: html_safe XSS risk
end

# ERB in Rails views
def erb_example(user_input)
  # <%= user_input %> in template
  # This would be <%= raw(user_input) %> for XSS
  "<div>#{user_input}</div>"
end

# ==================== Clean code (no issues) ====================

def safe_query(user_id)
  User.where(id: user_id)
  # Parameterized - safe
end

def safe_order(sort_column)
  allowed = ['created_at', 'updated_at']
  if allowed.include?(sort_column)
    Item.order(sort_column)
  end
  # Whitelist - safe
end

def safe_read(base_path, user_file)
  path = File.join(base_path, user_file)
  File.read(File.expand_path(path, base_path))
  # expand_path with base - safe
end
