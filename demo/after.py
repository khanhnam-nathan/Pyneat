# AI-Generated Code Sample
# This file has been cleaned by PyNEAT 2.0.0

from typing import List, Dict, Optional

MAGIC_DISCOUNT_RATE = 0.1
MIN_PRICE_FOR_DISCOUNT = 100

# Fixed: Magic number replaced with constant

def calculate_discount(price: float, quantity: int) -> float:
    if price > MIN_PRICE_FOR_DISCOUNT:
        return price * MAGIC_DISCOUNT_RATE
    return 0

# Fixed: != None replaced with is not None

def find_user(users: List[Dict], user_id: int) -> Optional[Dict]:
    for user in users:
        if user.get("id") is not None:
            return user
    return None

# Fixed: range(len()) replaced with direct iteration

def process_items(items: List) -> None:
    for item in items:
        print(item)

# Fixed: Redundant expression simplified

def check_flag(value: bool) -> bool:
    return value

# Fixed: Debug print removed

def calculate_total(items: List[Dict]) -> float:
    total = 0.0
    for item in items:
        total += item["price"]
    return total

# Fixed: Empty except block - should handle exceptions properly

def load_data() -> Optional[Dict]:
    try:
        with open("data.json", "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

# Fixed: Unused import removed

def get_config() -> Dict[str, bool]:
    return {"debug": True}

# Fixed: List copy replaced with list()

def copy_list(items: List) -> List:
    return list(items)

# Fixed: isinstance simplified

def validate_input(value) -> bool:
    return isinstance(value, (int, float))

# Fixed: type() replaced with isinstance()

def check_type(obj) -> str:
    if isinstance(obj, list):
        return "list"
    return "other"

# Fixed: Type annotation added

def main() -> None:
    users = [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]
    user = find_user(users, 1)
    print(user)

if __name__ == "__main__":
    main()
