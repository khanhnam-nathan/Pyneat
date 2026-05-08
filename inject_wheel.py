"""Batch add replacement: String::new() after auto_fix_available in Rust files."""
import re
import sys
from pathlib import Path

ROOT = Path(r"d:\pyneat-final\pyneat-rs\src")

# Files that already have replacement added (security.rs done manually)
done_files = {
    "rules/security.rs",
}

for rs_file in sorted(ROOT.rglob("*.rs")):
    rel = rs_file.relative_to(ROOT).as_posix()
    if rel in done_files:
        continue

    content = rs_file.read_text(encoding="utf-8")

    # Only process files that have auto_fix_available:
    if "auto_fix_available:" not in content:
        continue

    original = content

    # Pattern: auto_fix_available: false/true,\n followed by }
    # We want to insert replacement after each occurrence
    content = re.sub(
        r'(auto_fix_available: (false|true),\n)(\s+\})',
        r'\1\3        replacement: String::new(),\n',
        content
    )

    # Handle case where it's the last field before });
    # e.g. auto_fix_available: true,\n                    });
    content = re.sub(
        r'(auto_fix_available: (false|true),)(\n\s+\}\);)',
        r'\1\n                        replacement: String::new(),\3',
        content
    )

    if content != original:
        rs_file.write_text(content, encoding="utf-8")
        print(f"Patched: {rel}")
    else:
        print(f"No change: {rel}")
