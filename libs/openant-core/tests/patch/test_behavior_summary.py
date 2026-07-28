from pathlib import Path
import sys


from utilities.autopatcher.behavior_summary import BehaviorAnalyzer
from utilities.autopatcher.pipeline import TargetRepoContext


def write_file(p: Path, text: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_behavior_auth_case(tmp_path):
    repo = tmp_path / "repo_auth"
    repo.mkdir()
    auth = repo / "app" / "auth.py"
    write_file(auth, "def authenticate(username, password):\n    return db.query(username)\n")

    diff = """+++ b/app/auth.py
@@ -1,1 +1,3 @@
+def authenticate(username, password):
+    return db.query(username)
"""

    ctx = TargetRepoContext(repo)
    ba = BehaviorAnalyzer()
    r = ba.analyze(diff, repo_context=ctx)

    assert r["function"] == "authenticate"
    assert r["file"] == "app/auth.py"
    assert "authentication" in r["summary"]
    assert any("login" in b for b in r["primary_behaviors"])


def test_behavior_db_case(tmp_path):
    repo = tmp_path / "repo_db"
    repo.mkdir()
    q = repo / "db" / "queries.py"
    write_file(q, "def update_user(u):\n    cursor.execute(\"UPDATE...\")\n")

    diff = """+++ b/db/queries.py
@@ -1,1 +1,3 @@
+def update_user(u):
+    cursor.execute("UPDATE users SET ...")
"""

    ctx = TargetRepoContext(repo)
    ba = BehaviorAnalyzer()
    r = ba.analyze(diff, repo_context=ctx)

    assert r["function"] == "update_user"
    assert r["file"] == "db/queries.py"
    assert "database" in r["summary"] or "database" in " ".join(r["primary_behaviors"])


def test_behavior_fallback(tmp_path):
    repo = tmp_path / "repo_fallback"
    repo.mkdir()
    f = repo / "utils" / "misc.py"
    write_file(f, "# no function here\npass\n")

    diff = """+++ b/utils/misc.py
@@ -1 +1 @@
+some minor change
"""

    ctx = TargetRepoContext(repo)
    ba = BehaviorAnalyzer()
    r = ba.analyze(diff, repo_context=ctx)

    assert r["function"] == ""
    assert r["file"] == "utils/misc.py"
    assert isinstance(r["primary_behaviors"], list)
