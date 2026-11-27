"""Local SHA-256 artifact binding and trusted-key RSA signature verification."""
import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

TYPE = "application/vnd.in-toto+json"
SLSA = "https://slsa.dev/provenance/v1"


def bounded(path, limit):
    with Path(path).open("rb") as file:
        data = file.read(limit+1)
    if len(data) > limit:
        raise ValueError("too_large")
    return data


def check_signature(digest, signature, key):
    if not key or not shutil.which("openssl"):
        return "unsupported"
    pem = bounded(key, 16384).strip()
    if not pem.startswith(b"-----BEGIN PUBLIC KEY-----"):
        return "unsupported"
    with tempfile.TemporaryDirectory() as tmp:
        pub, sig = Path(tmp, "public.pem"), Path(tmp, "signature")
        pub.write_bytes(pem)
        sig.write_bytes(signature)
        command = ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pub),
                   "-sigfile", str(sig), "-pkeyopt", "digest:sha256", "-pkeyopt", "rsa_padding_mode:pkcs1"]
        result = subprocess.run(command, input=digest, capture_output=True, timeout=10)
        if result.returncode == 0:
            return "verified"
        return "invalid" if b"Signature Verification Failure" in result.stdout else "unsupported"


def verify(artifact, key=None, attestation=None, signature=None):
    with Path(artifact).open("rb") as file:
        digest = hashlib.file_digest(file, "sha256")
    record = dict(sha256=digest.hexdigest(), status="missing", kind="provenance")
    if attestation and signature:
        raise ValueError("choose_evidence")
    if signature:
        return dict(record, kind="signature", status=check_signature(digest.digest(), bounded(signature, 16384), key))
    if not attestation:
        return record
    try:
        envelope = json.loads(bounded(attestation, 2*1024*1024))
        if not isinstance(envelope, dict):
            return dict(record, status="invalid")
        signed = "payload" in envelope
        if signed:
            if envelope.get("payloadType") != TYPE:
                return dict(record, status="unsupported")
            payload = base64.b64decode(envelope["payload"], validate=True)
            statement = json.loads(payload)
        else:
            statement = envelope
        if not isinstance(statement, dict):
            return dict(record, status="invalid")
        if statement.get("predicateType") != SLSA or statement.get("_type") != "https://in-toto.io/Statement/v1":
            return dict(record, status="unsupported")
        predicate = statement["predicate"]
        builder = predicate["runDetails"]["builder"]["id"]
        build_type = predicate["buildDefinition"]["buildType"]
        if not all(isinstance(x, str) and x for x in [builder, build_type]):
            return dict(record, status="invalid")
        record.update(builder=builder, build_type=build_type)
        if not any(s["digest"].get("sha256") == digest.hexdigest() for s in statement["subject"]):
            return dict(record, status="invalid")
        if not signed:
            return dict(record, status="unsupported")
        signatures = envelope["signatures"]
        if not isinstance(signatures, list) or not 1 <= len(signatures) <= 16:
            return dict(record, status="invalid")
        # DSSE pre-authentication encoding uses byte lengths and the original payload bytes.
        pae = b" ".join([b"DSSEv1", str(len(TYPE)).encode(), TYPE.encode(), str(len(payload)).encode(), payload])
        statuses = [check_signature(hashlib.sha256(pae).digest(), base64.b64decode(s["sig"], validate=True), key)
                    for s in signatures]
        return dict(record, status=next((s for s in ["verified","invalid"] if s in statuses), "unsupported"))
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
        return dict(record, status="invalid")
