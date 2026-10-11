# Fixed: linear-time patterns, no nested quantifiers.
import re

USERNAME_RE = re.compile(r"^[a-z0-9_]+$")
