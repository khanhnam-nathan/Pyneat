"""Sample code for testing resource leak detection.

This file contains examples of code that should trigger resource leak warnings.
"""

# BAD: open() without context manager
def read_file_unsafe():
    f = open('data.txt', 'r')
    data = f.read()
    # f.close() is missing - resource leak!
    return data


# BAD: open() without context manager, multiple calls
def process_files():
    f1 = open('file1.txt', 'r')
    content1 = f1.read()
    f2 = open('file2.txt', 'r')
    content2 = f2.read()
    return content1 + content2


# GOOD: Using context manager
def read_file_safe():
    with open('data.txt', 'r') as f:
        return f.read()


# BAD: requests without timeout
import requests

def fetch_data():
    response = requests.get('https://api.example.com/data')
    return response.json()


def fetch_multiple():
    r1 = requests.get('https://api.example.com/1')
    r2 = requests.get('https://api.example.com/2')
    return [r1.json(), r2.json()]


# GOOD: requests with timeout
def fetch_data_safe():
    response = requests.get('https://api.example.com/data', timeout=30)
    return response.json()


# BAD: urllib without timeout
import urllib.request

def fetch_url():
    response = urllib.request.urlopen('https://api.example.com')
    return response.read()


# GOOD: urllib with timeout
import socket

def fetch_url_safe():
    response = urllib.request.urlopen('https://api.example.com', timeout=30)
    return response.read()
