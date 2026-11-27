"""Release identifiers survive registry takedowns and are available offline."""

import math
import re
from difflib import SequenceMatcher

# Long-established Node core libraries. Keep this vocabulary fixed across splits.
CORE = (
    "assert",
    "buffer",
    "crypto",
    "events",
    "http",
    "https",
    "module",
    "path",
    "process",
    "stream",
    "string_decoder",
    "timers",
    "util",
    "zlib",
)
SEMVER = re.compile(
    r"(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})(-[\w.-]+)?(?:\+[\w.-]+)?", re.ASCII
)


def extract(name, version):
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    if not re.fullmatch(r"(?:@[a-z0-9._~-]+/)?[a-z0-9._~-]+", name) or len(name) > 214:
        return None
    match = SEMVER.fullmatch(version)
    if not match:
        return None
    leaf = name.rsplit("/", 1)[-1]
    return {
        "name_length": len(leaf),
        "digit_fraction": sum(c.isdigit() for c in leaf) / len(leaf),
        "separators": sum(leaf.count(c) for c in "-_."),
        "scoped": int(name.startswith("@")),
        "core_similarity": max(SequenceMatcher(None, leaf, core).ratio() for core in CORE),
        "log_major": math.log1p(int(match[1])),
        "log_minor": math.log1p(int(match[2])),
        "log_patch": math.log1p(int(match[3])),
        "prerelease": int(bool(match[4])),
    }
