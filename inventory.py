"""Read dependency identities and edges without executing project code."""
import json
import os
import shutil
import subprocess
import tempfile
from collections import defaultdict, deque
from pathlib import Path

from packageurl import PackageURL

from ml.predict import predict

LIMIT = 5_000
MAX_BYTES = 12 * 1024 * 1024
ECOSYSTEMS = {"npm":"npm", "pypi":"PyPI", "maven":"Maven", "golang":"Go",
              "cargo":"crates.io", "gem":"RubyGems", "nuget":"NuGet", "composer":"Packagist"}


def read_json(data):
    if len(data) > MAX_BYTES:
        raise ValueError("too_large")
    try:
        return json.loads(data)
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError("invalid_json") from None


def items(value):
    if not isinstance(value, list) or any(not isinstance(i, dict) for i in value):
        raise ValueError("invalid_sbom")
    return value


def strings(value):
    if not isinstance(value, list) or any(not isinstance(i, str) for i in value):
        raise ValueError("invalid_sbom")
    return value


def parse(doc):
    if not isinstance(doc, dict):
        raise ValueError("invalid_sbom")
    components, roots, edges = {}, set(), set()

    def add(raw, ref, purl, hashes):
        name, version, ecosystem = raw.get("name"), raw.get("version", raw.get("versionInfo", "")), "unknown"
        if not isinstance(name, str) or not name or not isinstance(version, str):
            raise ValueError("invalid_sbom")
        if purl:
            try:
                pkg = PackageURL.from_string(purl)
            except (ValueError, TypeError, AttributeError):
                raise ValueError("invalid_sbom") from None
            ecosystem = ECOSYSTEMS.get(pkg.type, pkg.type)
            name = pkg.name
            if pkg.namespace:
                name = pkg.namespace + (":" if pkg.type == "maven" else "/") + name
            if version and pkg.version and pkg.version != version:
                raise ValueError("conflicting_version")
            version = pkg.version or version
        if not isinstance(ref, str) or len(ref) > 2048 or not ref or ref in components:
            raise ValueError("invalid_reference")
        if len(components) >= LIMIT or max(len(name), len(version)) > 1024:
            raise ValueError("too_large")
        digests = {h.get("content", h.get("checksumValue", "")).lower() for h in items(hashes)
                   if str(h.get("alg", h.get("algorithm"))).replace("-", "").upper() == "SHA256"
                   and isinstance(h.get("content", h.get("checksumValue")), str)}
        components[ref] = dict(id=ref, name=name, version=version, ecosystem=ecosystem, depth=None,
                               sha256=sorted(digests), provenance="missing", intelligence="offline",
                               advisories=[], prediction=predict(name, version) if ecosystem == "npm" else None)

    if doc.get("bomFormat") == "CycloneDX" and isinstance(doc.get("specVersion"), str):
        kind = "CycloneDX"
        meta = doc.get("metadata", {})
        if not isinstance(meta, dict) or not isinstance(meta.get("component", {}), dict):
            raise ValueError("invalid_sbom")
        root = meta.get("component", {})
        title = root.get("name") or kind
        if isinstance(root.get("bom-ref"), str):
            roots.add(root["bom-ref"])
        todo = list(reversed(items(doc.get("components", []))))
        while todo:
            raw = todo.pop()
            ref = raw.get("bom-ref", f"#component:{len(components)}")
            add(raw, ref, raw.get("purl"), raw.get("hashes", []))
            todo.extend(reversed(items(raw.get("components", []))))
        for rel in items(doc.get("dependencies", [])):
            if not isinstance(rel.get("ref"), str):
                raise ValueError("invalid_reference")
            edges.update((rel["ref"], target) for target in strings(rel.get("dependsOn", [])))
    elif isinstance(doc.get("spdxVersion"), str) and doc["spdxVersion"].startswith("SPDX-2."):
        kind, title = "SPDX", doc.get("name") or "SPDX"
        roots.update(strings(doc.get("documentDescribes", [])))
        for raw in items(doc.get("packages", [])):
            purl = next((r.get("referenceLocator") for r in items(raw.get("externalRefs", []))
                         if r.get("referenceType") == "purl"), None)
            add(raw, raw.get("SPDXID"), purl, raw.get("checksums", []))
        for rel in items(doc.get("relationships", [])):
            a,b,t = rel.get("spdxElementId"),rel.get("relatedSpdxElement"),rel.get("relationshipType")
            if not all(isinstance(x,str) for x in (a,b,t)):
                raise ValueError("invalid_reference")
            if t == "DESCRIBES" and a == doc.get("SPDXID"):
                roots.add(b)
            elif t == "DESCRIBED_BY" and b == doc.get("SPDXID"):
                roots.add(a)
            elif t == "DEPENDS_ON":
                edges.add((a,b))
            elif t == "DEPENDENCY_OF":
                edges.add((b,a))
    else:
        raise ValueError("unsupported_format")
    if not isinstance(title, str):
        raise ValueError("invalid_sbom")
    valid = components.keys() | roots
    edges = sorted((a,b) for a,b in edges if a in valid and b in valid)
    children = defaultdict(list)
    for a,b in edges:
        children[a].append(b)
    queue = deque((r, 0) for r in roots)
    visited = set()
    while queue:
        node, depth = queue.popleft()
        if node in visited:
            continue
        visited.add(node)
        if node in components:
            components[node]["depth"] = depth
        queue.extend((child, depth+1) for child in children[node] if child not in visited)
    return dict(title=title, format=kind, roots=sorted(roots), edges=edges, components=list(components.values()))


def scan(directory):
    path = Path(directory).resolve()
    if not path.is_dir():
        raise ValueError("invalid_directory")
    if not shutil.which("syft"):
        raise ValueError("syft_missing")
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp, "inventory.json")
        env = dict(os.environ, SYFT_CHECK_FOR_APP_UPDATE="false")
        try:
            proc = subprocess.run(["syft", "scan", f"dir:{path}", "-o", f"cyclonedx-json={output}"],
                                  env=env, cwd=tmp, capture_output=True, timeout=180)
        except subprocess.TimeoutExpired:
            raise ValueError("scan_timeout") from None
        if proc.returncode or not output.exists():
            raise ValueError("scan_failed")
        if output.stat().st_size > MAX_BYTES:
            raise ValueError("too_large")
        return read_json(output.read_bytes())


def compare(old, new):
    def summary(report):
        result = defaultdict(list)
        for c in report["components"]:
            result[(c["ecosystem"], c["name"])].append(dict(version=c["version"],
                score=c["prediction"]["score"] if c["prediction"] else None,
                advisories=sorted(a["id"] for a in c["advisories"]), intelligence=c["intelligence"]))
        return {k: sorted(v, key=lambda r: (r["version"],str(r["advisories"]))) for k,v in result.items()}
    a,b = summary(old),summary(new)
    return [dict(ecosystem=k[0], name=k[1], before=a.get(k, []), after=b.get(k, []))
            for k in sorted(a.keys() | b.keys()) if a.get(k) != b.get(k)]
