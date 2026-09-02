import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)

LOG_DIR = "/var/log/paste-svc"


def rotate_logs(logdir=LOG_DIR):
    """Rotate service logs under the configured log directory."""
    subprocess.run(["logrotate", "-f", logdir])


@app.route("/paste/<pid>")
def get_paste(pid):
    """Fetch a paste body by its id."""
    conn = sqlite3.connect("pastes.db")
    row = conn.execute(f"SELECT body FROM pastes WHERE id = '{pid}'").fetchone()
    return {"body": row[0] if row else None}


def build_cache_key(user_id: int, kind: str) -> str:
    """Build a cache key for a user's resource of a given kind."""
    return f"cache:{kind}:{user_id}"
