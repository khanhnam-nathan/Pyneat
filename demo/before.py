# AI-Generated Code Sample
# This file demonstrates common issues that PyNEAT can fix

import os
import json
from typing import List, Dict, Optional

# Issue 1: Magic number
def calculate_discount(price, quantity):
    if price > 100:
        return price * 0.1  # Magic number
    return 0

# Issue 2: Use of != None instead of is not None
def find_user(users, user_id):
    for user in users:
        if user.get("id") != None:
            return user
    return None

# Issue 3: Range(len()) anti-pattern
def process_items(items):
    for i in range(len(items)):
        print(items[i])

# Issue 4: Redundant expression
def check_flag(value):
    if value == True:
        return True
    return False

# Issue 5: Debug print
def calculate_total(items):
    print("Calculating total...")  # Debug artifact
    total = 0
    for item in items:
        total += item["price"]
    return total

# Issue 6: Empty except block
def load_data():
    try:
        with open("data.json", "r") as f:
            return json.load(f)
    except:
        pass

# Issue 7: Unused import
def get_config():
    config = {"debug": True}
    return config

# Issue 8: Inefficient list copy
def copy_list(items):
    new_items = []
    for item in items:
        new_items.append(item)
    return new_items

# Issue 9: Multiple isinstance calls
def validate_input(value):
    if isinstance(value, int) or isinstance(value, float):
        return True
    return False

# Issue 10: type() comparison
def check_type(obj):
    if type(obj) == list:
        return "list"
    return "other"

# Main function (missing type annotation)
def main():
    users = [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]
    user = find_user(users, 1)
    print(user)

if __name__ == "__main__":
    main()
