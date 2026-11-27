"""Loopback dashboard. Browser requests may scan only the operator's chosen directory."""
import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException

from inventory import MAX_BYTES, read_json, scan
from ml.predict import benchmark
from sboom import analyze
from security import verify

WEB = Path(__file__).with_name("web")


def create_app(project=None):
    app = Flask(__name__, static_folder=None)
    app.config.update(MAX_CONTENT_LENGTH=MAX_BYTES, TRUSTED_HOSTS=["localhost", "127.0.0.1", "[::1]"])

    @app.before_request
    def local_request():
        if request.method == "POST":
            origin = request.headers.get("Origin")
            if request.headers.get("X-SBoom") != "local" or (origin and urlsplit(origin).netloc != request.host):
                return jsonify(error="local_only"), 403

    @app.after_request
    def headers(response):
        response.headers.update({"Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
                                 "X-Content-Type-Options": "nosniff", "Referrer-Policy":"no-referrer",
                                 "Cache-Control":"no-store"})
        return response

    @app.errorhandler(ValueError)
    def invalid(exc):
        return jsonify(error=str(exc)), 400

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return jsonify(error="too_large" if exc.code == 413 else "request_failed"), exc.code

    @app.get("/")
    def index():
        return send_from_directory(WEB, "index.html")

    @app.get("/static/<name>")
    def static_asset(name):
        return send_from_directory(WEB, name)

    @app.get("/api/model")
    def model():
        return jsonify(benchmark=benchmark(), project=bool(project))

    @app.post("/api/<action>")
    def run(action):
        online = request.args.get("online") == "1"
        if action == "analyze":
            return jsonify(analyze(read_json(request.get_data()), online))
        if action == "example":
            return jsonify(analyze(read_json((WEB / "example.json").read_bytes()), online))
        if action == "scan" and project:
            return jsonify(analyze(scan(project), online))
        if action == "verify":
            with tempfile.TemporaryDirectory() as tmp:
                files = {}
                for name in ["artifact", "key", "attestation", "signature"]:
                    if name in request.files and request.files[name].filename:
                        path = Path(tmp, name)
                        request.files[name].save(path)
                        files[name] = path
                if "artifact" not in files:
                    raise ValueError("artifact_required")
                return jsonify(verify(**files))
        raise ValueError("request_failed")
    return app


def serve(project=None, port=8765):
    from waitress import serve as run
    host = "0.0.0.0" if os.environ.get("SBOOM_CONTAINER") == "1" else "127.0.0.1"
    print(f"SBoom is listening at http://localhost:{port}", flush=True)
    run(create_app(project), host=host, port=port, threads=4, max_request_body_size=MAX_BYTES)
