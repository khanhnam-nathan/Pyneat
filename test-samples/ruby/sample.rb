# Sample Ruby file with AI-generated issues

require 'json'
require 'openssl'
require 'securerandom'

# Phantom requires - AI hallucinations
require 'utils'
require 'helpers'
require 'ai'

# Security issues
def eval_code(code)
  # DANGEROUS: eval arbitrary code
  eval(code)
end

def hash_password(password)
  # WEAK: MD5 for passwords
  Digest::MD5.hexdigest(password)
end

def execute_command(cmd)
  # Command injection
  `#{cmd}`
end

# Deserialization vulnerability
def unserialize_data(data)
  Marshal.load(data)  # Dangerous with untrusted data
end

# Resource leaks
def read_file_bad(filename)
  f = File.open(filename, 'r')
  # Resource leak - not closed properly
  f.read
end

# AI bugs - identity comparison
def check_status(status)
  if status == "success"  # Should use ===
    return true
  end
  false
end

# Magic numbers
def calculate_total(quantity, price)
  tax_rate = 1.1
  discount = 0.05
  subtotal = quantity * price
  total = subtotal * 1.08 - subtotal * discount  # Magic number
  total * 0.95
end

# TODO comments
def process_items(items)
  # TODO: implement caching
  # FIXME: handle empty input
  # TODO: optimize this method
  items.map(&:upcase)
end

# Hardcoded secrets
def get_api_key
  api_key = 'sk-1234567890abcdef'  # Hardcoded secret
  api_key
end

# Empty rescue
def process_file(filename)
  begin
    File.read(filename)
  rescue
    # Empty rescue - silently ignores error
  end
end

# Global variable
$global_cache = {}

def get_cache
  $global_cache  # Global state is bad
end
