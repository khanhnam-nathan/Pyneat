"""Pure Python benchmark for comparison."""

import time
import re
from pathlib import Path

PATTERNS = [
    (r"os\.system\s*\(", "SEC-001"),
    (r"subprocess\.run\s*\([^)]*shell\s*=\s*True", "SEC-001"),
    (r"os\.popen\s*\(", "SEC-001"),
    (r"(cursor|db)\.execute\s*\(.*?\+", "SEC-002"),
    (r"\beval\s*\(", "SEC-003"),
    (r"\bexec\s*\(", "SEC-003"),
    (r"pickle\.(loads|load)\s*\(", "SEC-004"),
    (r"yaml\.load\s*\(", "SEC-004"),
    (r"marshal\.loads\s*\(", "SEC-004"),
    (r"shelve\.open", "SEC-004"),
    (r"open\s*\([^)]*(?:user|path|file|filename)[^)]*\)", "SEC-005"),
]

compiled = [(re.compile(p), rid) for p, rid in PATTERNS]

def scan(code: str):
    findings = []
    for pattern, rule_id in compiled:
        for m in pattern.finditer(code):
            findings.append((rule_id, m.start(), m.end()))
    return findings

def main():
    dir_path = Path("d:/pyneat-final")
    files = [f for f in dir_path.rglob("*.py") if f.is_file()]

    contents = []
    for f in files:
        try:
            with open(f, encoding="utf-8", errors="ignore") as fp:
                contents.append(fp.read())
        except:
            pass

    print(f"Files: {len(contents)}")

    # Warmup
    for c in contents[:10]:
        scan(c)

    # Benchmark
    iterations = 3
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        total = 0
        for c in contents:
            total += len(scan(c))
        elapsed = time.perf_counter() - start
        times.append(elapsed)
        print(f"  {elapsed:.3f}s ({total} findings)")

    avg = sum(times) / len(times)
    print(f"\nAverage: {avg:.3f}s")
    print(f"Files/sec: {len(contents) / avg:.1f}")

if __name__ == "__main__":
    main()
