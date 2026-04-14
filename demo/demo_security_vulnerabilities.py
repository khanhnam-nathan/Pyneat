"""
Demo file: PyNEAT Security Vulnerabilities Showcase
Generated for PyNEAT 2.2.0-beta release

This file contains intentionally planted security vulnerabilities
to demonstrate PyNEAT's security scanning capabilities.
"""

import os
import sys
import sqlite3
import pickle
import yaml
import hashlib
import subprocess

# ============================================================================
# CRITICAL VULNERABILITIES (CWE-78, CWE-89, CWE-95)
# ============================================================================

def vulnerable_sql_injection(user_id):
    """SQL Injection vulnerability - CWE-89"""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SECURITY: SQL injection via string concatenation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()


def command_injection():
    """OS Command Injection - CWE-78"""
    filename = input("Enter filename: ")
    # SECURITY: Command injection via shell
    os.system(f"cat {filename}")


def eval_injection(user_input):
    """Eval Injection - CWE-95"""
    # SECURITY: Arbitrary code execution
    result = eval(user_input)
    return result


def pickle_deserialization(data):
    """Pickle Deserialization - CWE-502"""
    # SECURITY: Unsafe deserialization
    obj = pickle.loads(data)
    return obj


def yaml_unsafe_load(config_str):
    """YAML Unsafe Load - CWE-502"""
    # SECURITY: Arbitrary code execution via YAML
    config = yaml.load(config_str)
    return config


# ============================================================================
# HIGH VULNERABILITIES (CWE-798, CWE-327)
# ============================================================================

def hardcoded_secrets():
    """Hardcoded secrets - CWE-798"""
    # SECURITY: Hardcoded credentials
    api_key = "sk_live_abc123xyz789secretkey"
    db_password = "admin123"
    jwt_secret = "my_super_secret_jwt_key_12345"

    return {
        "api_key": api_key,
        "db_password": db_password,
        "jwt_secret": jwt_secret
    }


def weak_crypto():
    """Weak Cryptographic Hash - CWE-327"""
    # SECURITY: MD5 is not suitable for cryptographic purposes
    password = "user_password"
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed


def weak_sha1():
    """Weak SHA1 for security - CWE-327"""
    # SECURITY: SHA1 is deprecated for security purposes
    data = b"sensitive_data"
    hashed = hashlib.sha1(data).hexdigest()
    return hashed


# ============================================================================
# MEDIUM VULNERABILITIES (CWE-79, CWE-918)
# ============================================================================

def xss_vulnerability(user_name):
    """XSS Vulnerability - CWE-79"""
    # SECURITY: Untrusted input in HTML response
    html = f"<h1>Welcome, {user_name}!</h1>"
    return html


def ssrf_vulnerability(url):
    """SSRF Vulnerability - CWE-918"""
    import requests
    # SECURITY: Fetching arbitrary URLs (could access internal services)
    response = requests.get(url)
    return response.text


def open_redirect(url, redirect_to):
    """Open Redirect - CWE-601"""
    # SECURITY: Unvalidated redirect
    return f"{url}?redirect={redirect_to}"


# ============================================================================
# RESOURCE LEAKS (AI-generated common issues)
# ============================================================================

def file_leak():
    """File resource leak - AI common mistake"""
    # SECURITY: open() without context manager
    f = open("config.txt", "r")
    content = f.read()
    # f.close() is missing!
    return content


def network_without_timeout():
    """Network without timeout - AI common mistake"""
    import requests
    # SECURITY: HTTP request without timeout
    response = requests.get("https://api.example.com/data")
    return response.json()


# ============================================================================
# CODE QUALITY ISSUES (AI-generated patterns)
# ============================================================================

def magic_numbers():
    """Magic numbers - AI common pattern"""
    result = calculate(100)  # What does 100 mean?
    percentage = value * 0.15  # Why 0.15?
    timeout = 300  # 5 minutes?
    return result + percentage + timeout


def empty_except():
    """Empty except block - AI common pattern"""
    try:
        risky_operation()
    except:
        pass  # Silently swallow all errors


def mutable_default():
    """Mutable default argument - Python anti-pattern"""
    def add_item(items=[]):  # SECURITY: Mutable default
        items.append(1)
        return items


# ============================================================================
# DEAD CODE (AI-generated unused functions)
# ============================================================================

def unused_helper_function(x):
    """This function is never called"""
    return x * 2


def _private_unused():
    """Private function also unused"""
    pass


def calculate_factor(divisor):
    """Compute magic number factor"""
    return divisor * 42


# ============================================================================
# PERFORMANCE ISSUES
# ============================================================================

def repeated_queries(user_id):
    """N+1 query problem - AI common pattern"""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()

    # SECURITY: N+1 queries (inefficient)
    for user in users:
        cursor.execute(f"SELECT * FROM orders WHERE user_id = {user[0]}")
        orders = cursor.fetchall()

    return users


def redundant_io():
    """Redundant I/O - AI common pattern"""
    # SECURITY: Same file read 3 times
    config1 = open("config.json").read()
    config2 = open("config.json").read()
    config3 = open("config.json").read()
    return config1, config2, config3


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("PyNEAT Security Demo")
    print("Run: pyneat clean demo_security_vulnerabilities.py")
