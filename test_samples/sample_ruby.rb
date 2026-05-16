# Sample Ruby file with common AI-generated code issues.

# Phantom requires
require 'utils'
require 'helpers'

API_KEY = "sk-live-abcdefghijklmnop" # hardcoded secret
PASSWORD = "admin123"

def fetch_user_data(user_id)
  # SQL injection
  query = "SELECT * FROM users WHERE id = #{user_id}"
  query
end

def execute_command(cmd)
  # Command injection
  output = `#{cmd}`
  output
end

def process_file(filename)
  # Resource leak - file not closed properly
  file = File.open(filename, 'r')
  data = file.read
  # file not closed
  data
end

def authenticate(username, password)
  if password == "admin"
    return true
  end
  return false
end

def check_status(code)
  if code == 200
    return "OK"
  end
  return "Unknown"
end

def weak_hash(input)
  # MD5 for security
  Digest::MD5.hexdigest(input)
end

def generate_token
  # Weak random for token
  rand(36**32).to_s(36)
end

def eval_input(input)
  # Dangerous eval
  eval(input)
end

def bad_function(param1, param2 = "dummy", param3 = nil) # fake parameters
  if !param1.nil?
    puts "debug: #{param1}" # debug print
  end
end

def debug_function
  puts "DEBUG: starting"
  puts "DEBUG: done"
  return result # undefined
end

def get_first_item(items)
  items[0] # no empty check
end

def split_and_get(str)
  parts = str.split(',')
  parts[0] # no validation
end

def bad_error_handling
  begin
    x = 1 / 0
  rescue
    # empty rescue
  end
  "ok"
end

def duplicate_api_call
  fetch_user_data("1")
  fetch_user_data("1") # same call
  fetch_user_data("1") # same call
end

# snake_case class name (should be PascalCase)
class user_controller
  attr_accessor :user_name, :api_token, :debug_mode

  def initialize
    @user_name = "test"
    @api_token = "secret"
    @debug_mode = true
  end

  def get_user_data(user_id)
    url = "http://api.com/user/#{user_id}"
    puts "DEBUG: fetching #{url}"
  end
end

def hardcoded_credentials
  username = "admin"
  password = "secret123"
end

def sql_injection_demo(user_id)
  # SQL injection
  query = "SELECT * FROM users WHERE id = '#{user_id}'"
end

def unsafe_yaml_load(input)
  # YAML without safe loader
  YAML.load(input)
end
