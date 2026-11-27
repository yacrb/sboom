"""Build research tables from public metadata. No package archives are fetched."""

import hashlib
import json
import re
import subprocess
from collections import defaultdict
from datetime import date
from pathlib import Path

import pandas as pd
import requests

from ml.features import extract

DATA = Path(__file__).with_name("data")
CUTOFF = "2026-09-30"
DATADOG = "72c723be547033c558244520524b117c8d71663b"
INTENT_TREE = "cb873a4e837ca87bd2975dd699c92547229f748a"
OSSF = "e08b53dc1676a30c401bf9956bdfc9b3cf3b287a"
SNAPSHOTS = {
    "npm/cli": [
        ("2024-12-16", "a481f5728046929817e2282cd9e12ee66ce41307"),
        ("2025-04-16", "c561a3307b18f9c208eb7305db0f2a51db61277d"),
        ("2025-07-30", "d006583e20731e8ae55cee94c3b7bd23cbd6f2d0"),
        ("2025-12-09", "6d1db8724b1d0e5457a87bb31e62e43d566348ce"),
        ("2026-04-22", "b9332e6370cb4c3ee32c7b87cfab5847f4657acc"),
        ("2026-09-30", "c276cadf785c1018d82dd287fe7742567055efb9"),
    ],
    "microsoft/vscode": [
        ("2024-12-23", "2e5cbd49c8252d6e1dc44de2ce8f63899a8774f7"),
        ("2025-04-21", "59662ed04538c35239e89553f71cc94b30f6ffb5"),
        ("2025-08-28", "3aac261283e19f341e4becbe760b9272ce0da992"),
        ("2025-12-29", "30d2a293f85a51dbb9187d1bdbaef0c50d964d1a"),
        ("2026-04-30", "ddb2b117c38cca46e722d770e00f1e97907777ef"),
        ("2026-09-30", "f8e3887e499bd98f0144c9114cef098da3e2bddc"),
    ],
}


def fetch(url):
    DATA.mkdir(exist_ok=True)
    path = DATA / (hashlib.sha256(url.encode()).hexdigest() + ".json")
    if not path.exists():
        response = requests.get(url, timeout=(8, 60))
        response.raise_for_status()
        response.json()
        path.write_bytes(response.content)
    return json.loads(path.read_bytes())


def ossf_names():
    repo = DATA / "ossf.git"
    if not repo.exists():
        subprocess.run(["git", "init", "--bare", "-q", repo], check=True)
    if subprocess.run(["git", "-C", repo, "cat-file", "-e", OSSF], capture_output=True).returncode:
        subprocess.run(
            [
                "git",
                "-C",
                repo,
                "fetch",
                "--filter=blob:none",
                "--depth=1",
                "https://github.com/ossf/malicious-packages.git",
                OSSF,
            ],
            check=True,
        )
    paths = subprocess.check_output(
        ["git", "-C", repo, "ls-tree", "-r", "--name-only", OSSF, "osv/malicious/npm"], text=True
    )
    return {p.removeprefix("osv/malicious/npm/").rsplit("/", 1)[0] for p in paths.splitlines()}


def family(name):
    if name.startswith("@"):
        return name.split("/")[0]
    # Coarse campaign proxy for numbered variants and shared hyphenated prefixes.
    return re.sub(r"[\d._-]", "", "-".join(name.split("-")[:2])) or name


def order(item):
    return hashlib.sha256(repr(item).encode()).hexdigest()


def build():
    DATA.mkdir(exist_ok=True)
    blocked = ossf_names() | set(
        fetch(
            f"https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/{DATADOG}/samples/npm/manifest.json"
        )
    )
    tree = fetch(
        "https://api.github.com/repos/DataDog/malicious-software-packages-dataset/"
        f"git/trees/{INTENT_TREE}?recursive=1"
    )
    if tree["truncated"]:
        raise ValueError("Incomplete sample index")
    by_day = defaultdict(list)
    for entry in tree["tree"]:
        path = entry["path"]
        if not path.endswith(".zip") or path.count("/") != 2:
            continue
        name, version, filename = path.split("/")
        if name.startswith("@"):
            name = "@" + name[1:].replace("@", "/", 1)
        day = filename[:10]
        if "2024-12-01" <= day <= CUTOFF and extract(name, version):
            date.fromisoformat(day)
            by_day[day].append((name, version, path))
    rows, groups = [], set()

    def sample(candidates, day, label, limit):
        count = 0
        for name, version, source in sorted(candidates, key=order):
            group = family(name)
            features = extract(name, version)
            if group in groups or not features:
                continue
            groups.add(group)
            rows.append(
                dict(
                    name=name,
                    version=version,
                    observed=day,
                    group=group,
                    label=label,
                    source=source,
                    **features,
                )
            )
            count += 1
            if count == limit:
                break

    for day in sorted(by_day):
        sample(by_day[day], day, 1, 1)
    # Keep a fixed sample per dated snapshot to avoid one lockfile dominating.
    for day, project, commit in sorted(
        (day, repo, sha) for repo, items in SNAPSHOTS.items() for day, sha in items
    ):
        url = f"https://raw.githubusercontent.com/{project}/{commit}/package-lock.json"
        packages = fetch(url)["packages"]
        candidates = []
        for path, package in packages.items():
            name = path.split("node_modules/")[-1]
            if (
                "node_modules/" in path
                and name not in blocked
                and not package.get("link")
                and package.get("resolved", "").startswith("https://registry.npmjs.org/")
                and package.get("integrity")
            ):
                candidates.append((package.get("name", name), package.get("version"), url))
        sample([c for c in candidates if c[0] not in blocked], day, 0, 55)
    frame = pd.DataFrame(rows).sort_values(["observed", "name"]).reset_index(drop=True)
    frame.to_csv(DATA / "releases.csv", index=False)
    return frame


def compromised_probe(used):
    """A positive-only transfer check on a different kind of documented release."""
    tree = fetch(
        "https://api.github.com/repos/DataDog/malicious-software-packages-dataset/"
        "git/trees/fa24c97c54835d563042b73acba6b1985f8a929e?recursive=1"
    )
    if tree["truncated"]:
        raise ValueError("Incomplete compromise index")
    pairs = set()
    for row in tree["tree"]:
        parts = row["path"].split("/")
        if len(parts) != 3 or not parts[2].endswith(".zip") or parts[2][:10] > CUTOFF:
            continue
        name, version = parts[:2]
        if name.startswith("@"):
            name = "@" + name[1:].replace("@", "/", 1)
        if family(name) not in used and extract(name, version):
            pairs.add((name, version))
    return sorted(pairs)


def release_intervals():
    rows = []
    for name in ["express", "chalk", "eslint", "typescript", "rollup", "vite"]:
        registry = fetch(f"https://registry.npmjs.org/{name}")["time"]
        versions = fetch(f"https://api.deps.dev/v3/systems/npm/packages/{name}")["versions"]
        # Confirm timestamps against a second public source. Compare stable releases only.
        times = sorted(
            {
                pd.Timestamp(registry[v["versionKey"]["version"]])
                for v in versions
                if re.fullmatch(r"\d+\.\d+\.\d+", v["versionKey"]["version"])
                and v["versionKey"]["version"] in registry
                and v.get("publishedAt")
                and registry[v["versionKey"]["version"]][:10] <= CUTOFF
                and registry[v["versionKey"]["version"]][:10] == v["publishedAt"][:10]
            }
        )
        for a, b, c, following in zip(times, times[1:], times[2:], times[3:]):
            rows.append(
                dict(
                    name=name,
                    date=c,
                    next_date=following,
                    previous_days=(c - b).total_seconds() / 86400,
                    mean_two_days=(c - a).total_seconds() / 172800,
                    next_days=(following - c).total_seconds() / 86400,
                )
            )
    frame = pd.DataFrame(rows).sort_values("date")
    frame.to_csv(DATA / "intervals.csv", index=False)
    return frame


if __name__ == "__main__":
    print(build().groupby("label").size())
    print("Release intervals:", len(release_intervals()))
