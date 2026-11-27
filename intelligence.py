"""Opt-in OSV lookups, with bounded caches and explicit partial coverage."""

import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import lru_cache
from urllib.parse import quote

import requests

from inventory import ECOSYSTEMS

OSV = "https://api.osv.dev/v1"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@lru_cache(maxsize=512)
def _fetch(url, payload, hour):
    kwargs = dict(timeout=(4, 10), allow_redirects=False)
    if payload:
        response = requests.post(
            url, data=payload, headers={"Content-Type": "application/json"}, **kwargs
        )
    else:
        response = requests.get(url, **kwargs)
    response.raise_for_status()
    return response.json(), datetime.now(timezone.utc).isoformat(timespec="seconds")


def fetch(url, body=None):
    import json

    return _fetch(
        url, json.dumps(body, separators=(",", ":")) if body else "", int(time.time() // 3600)
    )


def advisory(identifier):
    item = dict(
        id=identifier,
        malicious=identifier.startswith("MAL-"),
        severity=None,
        cves=[],
        partial=False,
    )
    try:
        raw, _ = fetch(f"{OSV}/vulns/{quote(identifier, safe='')}")
        aliases = [identifier, *raw.get("aliases", [])]
        item.update(
            malicious=any(a.startswith("MAL-") for a in aliases),
            severity=raw.get("database_specific", {}).get("severity")
            or ", ".join(s["score"] for s in raw.get("severity", []))
            or None,
            cves=sorted({a for a in aliases if re.fullmatch(r"CVE-\d{4}-\d{4,}", a)}),
        )
    except (requests.RequestException, ValueError, KeyError, TypeError):
        item["partial"] = True
    return item


def enrich(report):
    components = report["components"]
    queries = {}
    for c in components:
        key = c["ecosystem"], c["name"], c["version"]
        if key[0] not in ECOSYSTEMS.values() or not key[2]:
            c["intelligence"] = "unsupported"
        else:
            queries.setdefault(key, []).append(c)
    keys = list(queries)
    found, ids = {}, set()
    for start in range(0, len(keys), 100):
        chunk = keys[start : start + 100]
        try:
            body = {
                "queries": [
                    {"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk
                ]
            }
            raw, when = fetch(OSV + "/querybatch", body)
            for key, result in zip(chunk, raw["results"], strict=True):
                found[key] = [a["id"] for a in result.get("vulns", [])]
                ids.update(found[key])
                for c in queries[key]:
                    c.update(
                        intelligence="partial" if result.get("next_page_token") else "checked",
                        checked_at=when,
                    )
        except (requests.RequestException, ValueError, KeyError, TypeError):
            for key in chunk:
                for c in queries[key]:
                    c["intelligence"] = "unavailable"
            # Avoid repeating a failed network request for every remaining chunk.
            for key in keys[start + len(chunk) :]:
                for c in queries[key]:
                    c["intelligence"] = "unavailable"
            break
    with ThreadPoolExecutor(max_workers=6) as pool:
        details = {a["id"]: a for a in pool.map(advisory, sorted(ids)[:100])}
    cves = sorted({cve for a in details.values() for cve in a["cves"]})
    kev, epss = None, {}
    if cves:
        try:
            catalog, _ = fetch(KEV)
            kev = {r["cveID"] for r in catalog["vulnerabilities"]}
        except (requests.RequestException, ValueError, KeyError):
            pass
        for start in range(0, len(cves), 50):
            try:
                data, _ = fetch(
                    "https://api.first.org/data/v1/epss?cve=" + ",".join(cves[start : start + 50])
                )
                epss.update(
                    {r["cve"]: dict(score=float(r["epss"]), date=r["date"]) for r in data["data"]}
                )
            except (requests.RequestException, ValueError, KeyError):
                break
    for key, identifiers in found.items():
        for c in queries[key]:
            for identifier in identifiers:
                detail = details.get(
                    identifier,
                    dict(
                        id=identifier,
                        malicious=identifier.startswith("MAL-"),
                        partial=True,
                        severity=None,
                        cves=[],
                    ),
                )
                c["advisories"].append(
                    dict(
                        detail,
                        exploitation=[
                            dict(cve=v, epss=epss.get(v), kev=v in kev if kev is not None else None)
                            for v in detail["cves"]
                        ],
                    )
                )
                if detail["partial"] and c["intelligence"] == "checked":
                    c["intelligence"] = "partial"
    return report
