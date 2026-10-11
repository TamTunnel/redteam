# Vulnerable: nested quantifiers — catastrophic backtracking.
import re

CLEANUP_RE = re.compile(r"(a+)+$")
SPLIT_RE = re.compile(r"(\w+\s*)+")
