"""Batch add replacement: String::new() after auto_fix_available in Rust files."""
import re
from pathlib import Path

ROOT = Path(r"d:\pyneat-final\pyneat-rs\src")

# Skip these files (they use a different Finding structure)
SKIP_FILES = {
    "rules/security.rs",  # Already manually done
    "scanner/base.rs",     # Has LangFinding not Finding
    "scanner/taint_lang_rule.rs",  # Different struct
}

total_patched = 0
total_files = 0

for rs_file in sorted(ROOT.rglob("*.rs")):
    rel = rs_file.relative_to(ROOT).as_posix()
    if rel in SKIP_FILES:
        continue

    content = rs_file.read_text(encoding="utf-8")

    if "auto_fix_available:" not in content:
        continue

    original = content

    # Pattern: auto_fix_available: false/true,\n followed by });
    # We want to insert replacement: String::new(), after each auto_fix_available line
    # when it's not already there
    new_content = re.sub(
        r'(auto_fix_available: (?:false|true),)\n(\s+\}\);)',
        r'\1\n                        replacement: String::new(),\n\2',
        content
    )

    if new_content != original:
        rs_file.write_text(new_content, encoding="utf-8")
        count = len(re.findall(r'replacement: String::new\(\),', new_content)) - len(re.findall(r'replacement: String::new\(\),', original))
        print(f"Patched {rel}: +{count} replacement fields")
        total_patched += count
        total_files += 1

print(f"\nTotal: {total_files} files, {total_patched} replacement fields added")
