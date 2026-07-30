import os
import sqlite3
import subprocess

from flask import Flask, request, send_file

app = Flask(__name__)


@app.route("/render", methods=["POST"])
def render_snippet():
    """Render a submitted snippet to the requested output format."""
    fmt = request.json.get("format", "txt")
    body = request.json.get("body", "")
    open("/tmp/in.txt", "w").write(body)
    subprocess.run(f"pandoc -t {fmt} /tmp/in.txt -o /tmp/out", shell=True)
    return {"ok": True}


def migrate(schema_version: int):
    """Apply a schema version to the metadata table."""
    conn = sqlite3.connect("pastes.db")
    conn.execute("UPDATE meta SET version = ?", (schema_version,))


@app.route("/download")
def download():
    """Return a stored paste file by name."""
    name = request.args.get("name", "")
    return send_file(os.path.join("/var/pastes", name))
