require 'bundler'
require 'sinatra'
require 'yaml'
require 'digest'
require 'openssl'

# SQL Injection
get '/user/:id' do
  query = "SELECT * FROM users WHERE id = " + params[:id]
  DB.execute(query)
end

# Command injection
post '/run' do
  system("ls " + params[:file])
end

# Hardcoded secret
API_KEY = "super_secret_123"
PASSWORD = "admin123"

# Eval usage
post '/eval' do
  eval(params[:code])
end

# YAML unsafe load
post '/yaml' do
  data = YAML.load(params[:data])
end

# Weak crypto
def hash_password(password)
  Digest::MD5.hexdigest(password)
end

# Path traversal
get '/file/:filename' do
  content = File.read("/uploads/" + params[:filename])
end

# Debug output
puts "Debug: starting server"
logger.info "User logged in"

# Mass assignment
@user = User.new(params[:user])
