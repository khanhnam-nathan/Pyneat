"""Fix all auto_fix_available lines missing replacement - handles dynamic expressions."""
import re
from pathlib import Path

ROOT = Path(r"d:\pyneat-final\pyneat-rs\src")

total_fixed = 0
total_files = 0

for rs_file in sorted(ROOT.rglob("*.rs")):
    content = rs_file.read_text(encoding="utf-8")
    original = content

    lines = content.split('\n')
    new_lines = []
    i = 0
    changed = False

    while i < len(lines):
        line = lines[i]
        new_lines.append(line)

        if 'auto_fix_available:' in line:
            # Check if replacement appears in the next 15 lines
            has_replacement = False
            for j in range(1, 16):
                if i + j < len(lines):
                    if 'replacement:' in lines[i + j]:
                        has_replacement = True
                        break
                    if 'findings.push(Finding' in lines[i + j]:
                        break

            if not has_replacement:
                # Find the "});" that closes this Finding struct
                # It should be at the same or slightly lower indentation than auto_fix_available
                auto_indent = len(line) - len(line.lstrip())

                for j in range(i + 1, min(i + 20, len(lines))):
                    stripped = lines[j].strip()
                    if stripped == '});':
                        line_indent = len(lines[j]) - len(lines[j].lstrip())
                        # The closing should be at similar indentation to auto_fix_available field
                        # Allow some variation (same or slightly less)
                        if line_indent <= auto_indent + 4:
                            # Insert replacement before });
                            repl_indent = auto_indent + 8
                            repl_line = ' ' * repl_indent + 'replacement: String::new(),'
                            # Check it's not already the next line
                            if 'replacement:' not in lines[j - 1]:
                                lines.insert(j, repl_line)
                                changed = True
                                total_fixed += 1
                        break
        i += 1

    if changed:
        rs_file.write_text('\n'.join(lines), encoding='utf-8')
        print(f"Fixed: {rs_file.relative_to(ROOT)}")
        total_files += 1

print(f"\nTotal: {total_files} files, {total_fixed} replacement fields added")
