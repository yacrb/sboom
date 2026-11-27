import json
from pathlib import Path

import pytest
import requests

import inventory
from app import create_app
from intelligence import enrich
from inventory import compare, parse, read_json
from ml.features import extract
from ml.predict import benchmark, predict
from sboom import main

EXAMPLE = Path(__file__).parents[1] / "web/example.json"


def test_cyclonedx_graph_and_inference():
    report = parse(read_json(EXAMPLE.read_bytes()))
    by_name = {c["name"]: c for c in report["components"]}
    assert by_name["morgan"]["depth"] == 1
    assert by_name["ms"]["depth"] == 3
    prediction = by_name["morgan"]["prediction"]
    assert 0 <= prediction["score"] <= 1
    assert prediction["features"] == extract("morgan", "1.10.0")
    assert all(s["difference"] > 0 for s in prediction["signals"])
    assert all(c["intelligence"] == "offline" for c in by_name.values())


def test_spdx_inverse_edges_and_non_npm():
    doc = dict(spdxVersion="SPDX-2.3", SPDXID="SPDXRef-DOCUMENT", name="test",
               packages=[dict(name="app", SPDXID="app"), dict(name="example", SPDXID="lib",
               externalRefs=[dict(referenceType="purl", referenceLocator="pkg:pypi/example@1.0")])],
               relationships=[dict(spdxElementId="SPDXRef-DOCUMENT", relatedSpdxElement="app", relationshipType="DESCRIBES"),
                              dict(spdxElementId="lib", relatedSpdxElement="app", relationshipType="DEPENDENCY_OF")])
    app, lib = parse(doc)["components"]
    assert app["depth"] == 0 and lib["depth"] == 1
    assert (lib["version"],lib["ecosystem"],lib["prediction"]) == ("1.0","PyPI",None)
    doc["relationships"] = []
    assert all(c["depth"] is None for c in parse(doc)["components"])


@pytest.mark.parametrize("doc", [[], {}, {"bomFormat":"CycloneDX","specVersion":"1.5","components":[False]},
                                  {"spdxVersion":"SPDX-2.3","packages": ["invalid"]}])
def test_invalid_input(doc):
    with pytest.raises(ValueError):
        parse(doc)


def test_duplicates_and_cycles():
    doc = json.loads(EXAMPLE.read_bytes())
    doc["components"].append(doc["components"][0])
    with pytest.raises(ValueError, match="invalid_reference"):
        parse(doc)
    doc["components"].pop()
    doc["dependencies"][0]["dependsOn"].append(doc["dependencies"][0]["ref"])
    assert len(parse(doc)["components"]) == 9


def test_model_abstention_and_benchmark():
    assert predict("test", "latest") is None
    assert predict("../test", "1.0.0") is None
    r = benchmark()
    assert sum(map(sum,r["results"][r["winner"]]["confusion"])) == r["testing"]
    assert r["training"]+r["testing"] == r["positive"]+r["negative"]


def test_changes_preserve_multiple_versions():
    old = parse(json.loads(EXAMPLE.read_bytes()))
    doc = json.loads(EXAMPLE.read_bytes())
    raw = dict(doc["components"][0], version="2.0.2", purl="pkg:npm/basic-auth@2.0.2")
    raw["bom-ref"] += "-second"
    doc["components"].append(raw)
    change, = compare(old,parse(doc))
    assert change["name"] == "basic-auth"
    assert [v["version"] for v in change["after"]] == ["2.0.1","2.0.2"]


def test_outage_and_missing_syft(monkeypatch, tmp_path):
    def down(*args):
        raise requests.Timeout()
    monkeypatch.setattr("intelligence.fetch", down)
    result = enrich(parse(json.loads(EXAMPLE.read_bytes())))
    assert all(c["intelligence"]=="unavailable" for c in result["components"])
    monkeypatch.setattr(inventory.shutil, "which", lambda _: None)
    with pytest.raises(ValueError, match="syft_missing"):
        inventory.scan(tmp_path)


def test_osv_separates_reported_malware_from_cves(monkeypatch):
    def feed(url, body=None):
        if body:
            return {"results":[{"vulns":[{"id":"MAL-2025-1"},{"id":"GHSA-test"}],"next_page_token":"more"}]}, "2025-01-01"
        if url.endswith("GHSA-test"):
            return {"aliases":["CVE-2025-12345"],"database_specific":{"severity":"HIGH"}}, ""
        if "cisa.gov" in url or "first.org" in url:
            raise requests.Timeout()
        return {}, ""
    monkeypatch.setattr("intelligence.fetch",feed)
    d=parse(json.loads(EXAMPLE.read_bytes()))
    d["components"]=d["components"][:1]
    c=enrich(d)["components"][0]
    assert c["intelligence"] == "partial"
    mal, vuln = c["advisories"]
    assert mal["malicious"] and not vuln["malicious"] and vuln["severity"]=="HIGH"
    assert vuln["exploitation"] == [dict(cve="CVE-2025-12345",epss=None,kev=None)]


def test_flask_boundaries_and_cli(tmp_path, capsys):
    client = create_app().test_client()
    h = {"X-SBoom":"local"}
    assert client.get("/").status_code == 200
    assert client.get("/api/model",headers={"Host":"elsewhere.example"}).status_code == 400
    assert client.post("/api/example").status_code == 403
    assert client.post("/api/example",headers={**h,"Origin":"https://elsewhere.example"}).status_code == 403
    assert client.post("/api/analyze",data=b"bad",headers=h).json["error"] == "invalid_json"
    assert client.post("/api/analyze",data=EXAMPLE.read_bytes(),headers=h).json["format"]=="CycloneDX"
    assert client.post("/api/verify",headers=h).json["error"]=="artifact_required"
    assert main(["compare",str(EXAMPLE),str(EXAMPLE)])==0
    assert json.loads(capsys.readouterr().out)==[]
    assert main(["analyze",str(EXAMPLE)])==0
    assert len(json.loads(capsys.readouterr().out)["components"])==9
    assert main(["verify",str(EXAMPLE)])==1
