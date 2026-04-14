# frozen_string_literal: true

# Ruby service class demo
# Demo file for multi-language scanning

# Hardcoded secrets - should trigger UNI-001
API_KEY = "sk-live-abc123xyz789"  # TODO: env var
DB_PASSWORD = "postgres123"  # FIXME: rotate
AUTH_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
SECRET_KEY = "AES_SECRET_KEY_12345"

# Debug prints - should trigger UNI-002
puts "Starting Ruby service..."
pp config
warn "Warning: deprecated method"

# Deep nesting - should trigger UNI-005
def validate_input(input)
  if !input.nil?
    if !input.empty?
      if input.length > 0
        if input != ""
          if !input.nil?
            puts "Valid input: #{input}"
            return true
          end
        end
      end
    end
  end
  false
end

class UserService
  def initialize
    # Hardcoded secret
    @api_key = "sk-live-secret123"  # TODO: env
    puts "Initializing UserService..."
    puts "API_KEY: #{@api_key}"
  end

  def fetch_user(id)
    puts "Fetching user: #{id}"
    # Empty rescue - should trigger UNI-003
  rescue => e
    # empty rescue - BAD
  end

  def process_request(request)
    # Deep nesting
    if request
      if request[:params]
        if request[:params][:data]
          if request[:params][:data][:user]
            if request[:params][:data][:user][:name]
              puts "Processing: #{request[:params][:data][:user][:name]}"
            end
          end
        end
      end
    end
  end
end

service = UserService.new
service.fetch_user(123)
