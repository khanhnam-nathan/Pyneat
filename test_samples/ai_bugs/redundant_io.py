"""Sample code for testing redundant I/O detection.

This file contains examples of code that should trigger redundant I/O warnings.
AI-generated code often makes repeated API calls or file reads.
"""

# BAD: Repeated API call with same URL
def fetch_data_repeatedly():
    data1 = fetch('https://api.example.com/users')
    data2 = fetch('https://api.example.com/users')  # REDUNDANT: same call
    data3 = fetch('https://api.example.com/users')  # REDUNDANT: same call again
    return data1


# BAD: Repeated print calls
def log_message_repeated():
    print("Processing started")
    print("Processing started")  # REDUNDANT
    print("Processing started")  # REDUNDANT
    do_work()
    print("Processing completed")


# BAD: Repeated file reads in same function
def process_with_repeated_reads():
    config = read_config('config.json')
    settings = read_config('config.json')  # REDUNDANT
    prefs = read_config('config.json')  # REDUNDANT
    return merge(config, settings, prefs)


# BAD: Database query in loop
def get_all_users():
    results = []
    user_ids = [1, 2, 3, 4, 5]
    for user_id in user_ids:
        user = db.query(f"SELECT * FROM users WHERE id = {user_id}")  # N+1 query problem
        results.append(user)
    return results


# GOOD: Batch query instead of N+1
def get_all_users_optimized():
    user_ids = [1, 2, 3, 4, 5]
    results = db.query(f"SELECT * FROM users WHERE id IN ({','.join(map(str, user_ids))})")
    return results


# BAD: Repeated validation
def validate_input(data):
    if is_valid(data):
        return is_valid(data)  # REDUNDANT: called twice
    return False
