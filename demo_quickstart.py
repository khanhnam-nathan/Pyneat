# -*- coding: utf-8 -*-
"""
PyNeat - Hướng dẫn sử dụng cơ bản cho người mới

Cách 1: Clean code từ string
Cách 2: Clean trực tiếp 1 file Python
Cách 3: Chỉ phân tích (không sửa)
"""

from pathlib import Path
from pyneat import clean_code, clean_file, analyze_code

# ============================================================
# CÁCH 1: Clean code từ string (đơn giản nhất)
# ============================================================
print("=" * 60)
print("CÁCH 1: Clean code từ string")
print("=" * 60)

messy_code = """
x == None
print('debug message')
value != None
"""

result = clean_code(messy_code)
print("Input:\n", messy_code)
print("\nOutput:\n", result)

# ============================================================
# CÁCH 2: Clean 1 file Python (chỉ xem kết quả, không sửa gốc)
# ============================================================
print("\n" + "=" * 60)
print("CÁCH 2: Clean 1 file Python (xem trước)")
print("=" * 60)

file_path = Path("test_samples/messy_python3.py")
result = clean_file(file_path)

print(f"File: {file_path}")
print(f"Thành công: {result.success}")
print(f"Số thay đổi: {len(result.changes_made)}")
print("\nCác thay đổi:")
for change in result.changes_made:
    print(f"  - {change}")

print("\n--- CODE SAU KHI CLEAN (xem trước) ---")
print(result.transformed_content[:500], "...\n")

# ============================================================
# CÁCH 3: Clean file và GHI ĐÈ vào file gốc (có backup)
# ============================================================
print("=" * 60)
print("CÁCH 3: Clean và GHI ĐÈ vào file (có backup)")
print("=" * 60)

# Tạo bản backup trước khi sửa
result = clean_file(file_path, in_place=True, backup=True)

print(f"Đã clean và lưu: {file_path}")
print(f"Backup: {file_path}.bak")
print(f"Số thay đổi: {len(result.changes_made)}")

# ============================================================
# CÁCH 4: Chỉ phân tích, KHÔNG sửa
# ============================================================
print("\n" + "=" * 60)
print("CÁCH 4: Chỉ phân tích (không sửa)")
print("=" * 60)

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

report = analyze_code(content, path=file_path)
print(f"File: {file_path}")
print(f"Số vấn đề phát hiện: {report['change_count']}")
print("\nChi tiết:")
for issue in report['issues'][:10]:  # Chỉ show 10 cái đầu
    print(f"  - {issue}")

# ============================================================
# CÁCH 5: Clean với các TÙY CHỌN nâng cao
# ============================================================
print("\n" + "=" * 60)
print("CÁCH 5: Clean với tùy chọn nâng cao")
print("=" * 60)

result = clean_file(
    file_path,
    # Các tùy chọn an toàn (mặc định bật 1 số)
    remove_debug=True,       # Xóa print debug
    fix_is_not_none=True,   # Sửa x != None -> x is not None (mặc định)
    fix_redundant=True,     # Loại bỏ code thừa
    # Các tùy chọn NGHIÊM TRỌNG (phải bật thủ công)
    enable_import_cleaning=True,  # Dọn import
    enable_naming=True,          # Đổi tên class
    enable_refactoring=True,     # Tái cấu trúc
)

print(f"Số thay đổi: {len(result.changes_made)}")
print("\nCác thay đổi:")
for change in result.changes_made[:15]:
    print(f"  - {change}")
