"""Sample code for testing naming inconsistency detection.

This file contains examples of code that should trigger naming inconsistency warnings.
AI-generated code often uses mixed naming styles for the same concept.
"""

# BAD: userId vs user_id inconsistency
def create_user():
    userId = generate_id()  # camelCase
    user_name = get_user_name(userId)  # snake_case
    user_email = user_email_lookup(userId)  # snake_case
    return {"id": userId, "name": user_name, "email": user_email}


# BAD: DB config inconsistency
def connect_to_database():
    DBHost = 'localhost'  # PascalCase + camelCase
    db_port = 5432  # snake_case
    DBName = 'mydb'  # PascalCase
    db_user = 'admin'  # snake_case
    return f"{DBHost}:{db_port}/{DBName}"


# BAD: API config inconsistency
def configure_api():
    apiURL = 'https://api.example.com'  # camelCase
    api_key = 'secret123'  # snake_case
    apiToken = 'token456'  # camelCase
    return {"url": apiURL, "key": api_key, "token": apiToken}


# GOOD: Consistent naming
def configure_api_consistent():
    api_url = 'https://api.example.com'
    api_key = 'secret123'
    api_token = 'token456'
    return {"url": api_url, "key": api_key, "token": api_token}


# BAD: Server config inconsistency
def setup_server():
    serverHost = 'localhost'
    server_port = 8080
    serverName = 'production'
    server_url = f'http://{serverHost}:{server_port}'
    return server_url


# BAD: HTTP message inconsistency
def handle_request():
    request_body = get_body()
    responseCode = get_status_code()
    response_data = get_response()
    return {"body": request_body, "code": responseCode, "data": response_data}
