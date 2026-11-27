import base64
import hashlib
import json
import shutil
import subprocess

import pytest

from security import SLSA, TYPE, verify


@pytest.mark.skipif(not shutil.which("openssl"), reason="OpenSSL unavailable")
def test_real_signatures(tmp_path):
    private, public, file, sig, evidence = [tmp_path / n for n in ["key", "public", "artifact", "sig", "attestation"]]
    subprocess.run(["openssl","genrsa","-out",private,"2048"], capture_output=True, check=True)
    subprocess.run(["openssl","pkey","-in",private,"-pubout","-out",public], capture_output=True,check=True)
    file.write_bytes(b"local verification test")
    sign = ["openssl","dgst","-sha256","-sign",private]
    sig.write_bytes(subprocess.check_output(sign, input=file.read_bytes()))
    assert verify(file, public, signature=sig)["status"] == "verified"
    statement = dict(_type="https://in-toto.io/Statement/v1", predicateType=SLSA,
                     subject=[dict(digest=dict(sha256=hashlib.sha256(file.read_bytes()).hexdigest()))],
                     predicate=dict(buildDefinition=dict(buildType="https://example.org/build"),
                                    runDetails=dict(builder=dict(id="https://example.org/builder"))))
    payload = json.dumps(statement).encode()
    evidence.write_bytes(payload)
    assert verify(file, public, evidence)["status"] == "unsupported"
    pae = f"DSSEv1 {len(TYPE)} {TYPE} {len(payload)} ".encode() + payload
    signature = subprocess.check_output(sign, input=pae)
    envelope = dict(payloadType=TYPE, payload=base64.b64encode(payload).decode(),
                    signatures=[dict(sig=base64.b64encode(signature).decode())])
    evidence.write_text(json.dumps(envelope))
    assert verify(file, public, evidence)["status"] == "verified"
    assert verify(file, attestation=evidence)["status"] == "unsupported"
    file.write_bytes(b"changed")
    assert verify(file, public, evidence)["status"] == "invalid"
    assert verify(file, public, signature=sig)["status"] == "invalid"
    assert verify(file)["status"] == "missing"
