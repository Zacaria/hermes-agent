"""Two lifecycle invariants, using real SQLite and a local GitHub HTTP contract."""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli.kanban_db_connect import connect


@pytest.fixture
def github(tmp_path, monkeypatch):
    state = {"conclusion": "success", "head": "a" * 40, "reads": 0, "requests": []}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["requests"].append(self.path)
            sha = state["head"]
            if self.path == "/graphql":
                value = {"data": {"repository": {"pullRequest": {
                    "headRefOid": sha, "baseRefName": "main", "state": "OPEN",
                    "baseRef": {"branchProtectionRule": {"requiredStatusChecks": [
                        {"context": "required", "app": {"databaseId": 1}}] if not state.get("unprotected") else []}}}}}}
            elif "/rules/branches/" in self.path:
                if state.get("rules_error"):
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(state["rules_error"].encode())
                    return
                value = [[]]
            elif "/check-runs" in self.path:
                run = {"id": 42, "name": state.get("check_name", "required"), "head_sha": sha,
                       "app": {"id": state.get("app_id", 1)}, "status": "in_progress" if state["conclusion"] == "pending" else "completed", "conclusion": state["conclusion"],
                       "html_url": "https://github.com/acme/repo/actions/runs/42"}
                if state.get("stale"):
                    run["head_sha"] = "b" * 40
                runs = [] if state.get("missing") else [run]
                value = [{"total_count": 100 + len(runs), "check_runs": [
                    {**run, "id": 1000 + i, "name": "optional", "conclusion": "skipped"}
                    for i in range(100)]}, {"total_count": 100 + len(runs), "check_runs": runs}]
                if state.get("race"):
                    state["race"]()
                if state.get("head_change"):
                    state["head"] = "b" * 40
            elif "/statuses" in self.path:
                value = [[]]
            elif "/pulls/" in self.path:
                value = {"head": {"sha": sha}, "base": {"ref": "main"}, "state": "open"}
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(value).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    shim = tmp_path / "bin"
    shim.mkdir()
    gh = shim / "gh"
    gh.write_text(f"#!{sys.executable}\nimport sys,urllib.request,urllib.error\n"
                  f"u='http://127.0.0.1:{server.server_port}/'+sys.argv[2]\n"
                  "try:\n print(urllib.request.urlopen(u).read().decode())\n"
                  "except urllib.error.HTTPError as e:\n print(e.read().decode() + ' (HTTP ' + str(e.code) + ')', file=sys.stderr); sys.exit(1)\n")
    gh.chmod(0o755)
    monkeypatch.setenv("PATH", str(shim) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    kb.init_db()
    (kb.kanban_db_path().parent / "pr-acceptance-policy.yaml").write_text("kanban: {}\n")
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.platforms("linux")
@pytest.mark.parametrize("backend", ["file", "unsupported-test-backend"])
def test_pinned_board_rejects_caller_selected_policy(github, tmp_path, monkeypatch, backend):
    board = kb.kanban_db_path()
    policy = board.parent / "pr-acceptance-policy.yaml"
    policy.write_text("kanban:\n  pr_required_checks:\n    acme/repo:\n      - context: linux\n        app_id: 1\n")
    spoof = tmp_path / "spoof"
    spoof.mkdir()
    (spoof / "config.yaml").write_text("kanban:\n  pr_required_checks:\n    acme/repo:\n      - context: attacker\n        app_id: 1\n")
    with connect() as conn:
        tid = kb.create_task(conn, title="spoof", completion_contract="acme/repo")
    monkeypatch.setenv("HERMES_KANBAN_DB", str(board))
    monkeypatch.setenv("HERMES_HOME", str(spoof / "profiles" / "caller"))
    monkeypatch.setenv("HOME", str(spoof))
    monkeypatch.setenv("HERMES_CONFIG_BACKEND", backend)
    github.update(rules_error="Upgrade to GitHub Pro or make this repository public to enable this feature.", unprotected=True, check_name="attacker")
    from hermes_cli.config_backend import ConfigBackendUnavailable
    try:
        with connect() as conn:
            assert not kb.complete_task(conn, tid, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7", "pr_required_checks": [{"context": "attacker", "app_id": 1}]})
    except ConfigBackendUnavailable:
        assert backend != "file"
    monkeypatch.setenv("HERMES_CONFIG_BACKEND", "file")
    with connect(board) as conn:
        assert kb.get_task(conn, tid).status != "done"
        row = conn.execute("SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (tid,)).fetchone()
        if row:
            receipt = json.loads(row[0])
            assert receipt["required"] == [{"context": "linux", "app_id": 1}]
            assert receipt["classification"] == "missing"
        else:
            assert backend != "file"


@pytest.mark.platforms("linux")
def test_trusted_check_allows_only_specific_plan_refusal(github, tmp_path, monkeypatch):
    config = kb.kanban_db_path().parent / "pr-acceptance-policy.yaml"
    config.write_text("kanban:\n  pr_required_checks:\n    acme/repo:\n      - context: required\n        app_id: 1\n")
    github.update(rules_error="Upgrade to GitHub Pro or make this repository public to enable this feature.", unprotected=True)
    with connect() as conn:
        for fault in (None, "missing", "stale", "head_change", "failure", "pending"):
            github.update(head="a" * 40, conclusion=fault if fault in ("failure", "pending") else "success")
            if fault in ("missing", "stale", "head_change"):
                github[fault] = True
            tid = kb.create_task(conn, title="trusted", completion_contract="acme/repo")
            assert kb.complete_task(conn, tid, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7"}) is (fault is None)
            if fault in ("missing", "stale", "head_change"):
                github.pop(fault)
        github.update(head="a" * 40, conclusion="success", app_id=2)
        tid = kb.create_task(conn, title="wrong app", completion_contract="acme/repo")
        assert not kb.complete_task(conn, tid, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
        github.pop("app_id")
        github["race"] = lambda: config.write_text("kanban: {}\n")
        tid = kb.create_task(conn, title="policy changed", completion_contract="acme/repo")
        assert not kb.complete_task(conn, tid, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
        github.pop("race")
        github["unprotected"] = False
        config.write_text("kanban:\n  pr_required_checks:\n    acme/repo:\n      - context: different\n        app_id: 1\n")
        tid = kb.create_task(conn, title="both policies apply", completion_contract="acme/repo")
        assert not kb.complete_task(conn, tid, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
        config.write_text("kanban:\n  pr_required_checks:\n    acme/repo:\n      - context: required\n        app_id: 1\n")
        github["rules_error"] = "Resource not accessible by integration"
        tid = kb.create_task(conn, title="denied", completion_contract="acme/repo")
        assert not kb.complete_task(conn, tid, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
        github["rules_error"] = "Upgrade to GitHub Pro or make this repository public to enable this feature."
        config.unlink()
        tid = kb.create_task(conn, title="missing policy", completion_contract="acme/repo")
        assert not kb.complete_task(conn, tid, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
        config.write_text("kanban: {}\n")
        tid = kb.create_task(conn, title="no trusted policy", completion_contract="acme/repo")
        assert not kb.complete_task(conn, tid, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7"})


@pytest.mark.platforms("linux")
def test_pr_completion_requires_current_required_evidence(github):
    with connect() as conn:
        for conclusion in ("failure", "pending", "cancelled", "timed_out", "action_required", "neutral", "skipped", None, "success"):
            github.update(conclusion=conclusion, head="a" * 40)
            tid = kb.create_task(conn, title="Publish", completion_contract="acme/repo")
            ok = kb.complete_task(conn, tid, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
            assert ok is (conclusion == "success")
            task = kb.get_task(conn, tid)
            assert (task.status == "done") is ok
            receipts = [json.loads(r[0]) for r in conn.execute(
                "SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (tid,))]
            assert receipts and receipts[-1]["head_sha"] == "a" * 40
            if not ok:
                assert task.status in {"running", "ready", "blocked", "review"}
                assert "retry" in receipts[-1]["recovery"]
                assert receipts[-1]["checks"][0]["id"] == 42
        for fault in ("missing", "stale", "head_change"):
            github.update(conclusion="success", head="a" * 40)
            github[fault] = True
            tid = kb.create_task(conn, title=fault, completion_contract="acme/repo")
            assert not kb.complete_task(conn, tid, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
            assert kb.get_task(conn, tid).status != "done"
            github.pop(fault)
        # Omission and a sibling repository cannot downgrade the stored declaration.
        tid = kb.create_task(conn, title="publish", completion_contract="acme/repo")
        assert not kb.complete_task(conn, tid, summary="local green")
        assert not kb.complete_task(conn, tid, result="done", metadata={"published_pr": "https://github.com/other/repo/pull/7"})
        before = len(github["requests"])
        local = kb.create_task(conn, title="local", completion_contract="local-only")
        assert kb.complete_task(conn, local, summary="https://github.com/acme/repo/pull/7 is background context")
        assert len(github["requests"]) == before


@pytest.mark.platforms("linux")
def test_acceptance_receipts_and_terminal_write_share_run_ownership(github):
    with connect() as conn:
        for conclusion in ("success", "failure"):
            tid = kb.create_task(conn, title="race", completion_contract="acme/repo")
            owner = kb.claim_task(conn, tid)
            run_id = owner.current_run_id
            def reclaim():
                with connect() as rival:
                    assert kb.block_task(rival, tid, reason="Reassigned during acceptance")
                    assert kb.unblock_task(rival, tid)
                    github["replacement"] = kb.claim_task(rival, tid).current_run_id
            github.update(conclusion=conclusion, race=reclaim)
            assert not kb.complete_task(conn, tid, result="done", expected_run_id=run_id,
                metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
            assert kb.get_task(conn, tid).current_run_id == github["replacement"]
            assert github["replacement"] != run_id
            assert kb.get_task(conn, tid).status != "done"
            assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (tid,)).fetchone()[0] == 0
            github.pop("race")


# --- #122689: acceptance must read the repo as the ASSIGNEE profile's gh login ---

@pytest.mark.platforms("posix")
def test_acceptance_runs_gh_as_the_assignee_profile(tmp_path, monkeypatch):
    """The gh child env carries the assignee's own GH credentials (its .env),
    never the ambient/launch residue, and an invisible repo is classified
    `auth` naming the repository — not a retryable `infra` failure."""
    from pathlib import Path

    launch_home = tmp_path / "home"
    launch_home.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(launch_home))
    assignee_home = launch_home / "profiles" / "b"
    assignee_home.mkdir(parents=True)
    (assignee_home / ".env").write_text("GH_TOKEN=b-token\n", encoding="utf-8")
    # Ambient residue that must NOT decide the login.
    monkeypatch.setenv("GH_TOKEN", "launch-token")
    monkeypatch.setenv("GH_CONFIG_DIR", "/nonexistent/launch/gh")

    env_dump = tmp_path / "gh_env.json"
    shim = tmp_path / "bin"
    shim.mkdir()
    gh = shim / "gh"
    gh.write_text(f"#!{sys.executable}\nimport json, os\n"
                  f"json.dump(dict(os.environ), open({str(env_dump)!r}, 'w'))\n"
                  "print(json.dumps({'data': {'repository': None}}))\n")
    gh.chmod(0o755)
    monkeypatch.setenv("PATH", str(shim) + os.pathsep + os.environ["PATH"])
    kb.init_db()
    with connect() as conn:
        tid = kb.create_task(conn, title="as-b", completion_contract="acme/repo", assignee="b")
        assert not kb.complete_task(conn, tid, result="done",
                                    metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
        assert kb.get_task(conn, tid).status != "done"
        receipts = [json.loads(r[0]) for r in conn.execute(
            "SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (tid,))]
        assert receipts[-1]["classification"] == "auth"
        assert "acme/repo" in receipts[-1]["detail"]
    captured = json.loads(env_dump.read_text())
    assert captured["GH_TOKEN"] == "b-token"
    assert captured.get("GH_CONFIG_DIR") != "/nonexistent/launch/gh"
    assert "credentials" in (kb.get_task(conn, tid).last_failure_error or "")


@pytest.mark.platforms("posix")
def test_assignee_without_own_gh_login_never_falls_through_to_ambient_login(tmp_path, monkeypatch):
    """An assignee profile with no GH_TOKEN/GH_CONFIG_DIR of its own must not inherit the
    launch user's ~/.config/gh (HOME/XDG_CONFIG_HOME stay the launch process's): gh is pinned
    to a profile-owned config dir, its 'not logged in' exit is classified `auth` naming the profile."""
    launch_home = tmp_path / "home"
    launch_home.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(launch_home))
    assignee_home = launch_home / "profiles" / "b"
    assignee_home.mkdir(parents=True)
    (assignee_home / ".env").write_text("", encoding="utf-8")
    monkeypatch.setenv("GH_TOKEN", "launch-token")
    monkeypatch.setenv("GH_CONFIG_DIR", "/nonexistent/launch/gh")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "launch-xdg"))

    env_dump = tmp_path / "gh_env.json"
    shim = tmp_path / "bin"
    shim.mkdir()
    gh = shim / "gh"
    # Real gh: GH_CONFIG_DIR wins; a config dir without hosts.yml means "not logged in" (exit 4).
    gh.write_text(f"#!{sys.executable}\nimport json, os, pathlib, sys\n"
                  f"pathlib.Path({str(env_dump)!r}).write_text(json.dumps(dict(os.environ)), encoding='utf-8')\n"
                  "if 'GH_CONFIG_DIR' in os.environ and not os.path.exists(os.environ['GH_CONFIG_DIR']):\n"
                  "    sys.exit(4)\n"
                  "print(json.dumps({'data': {'repository': None}}))\n")
    gh.chmod(0o755)
    monkeypatch.setenv("PATH", str(shim) + os.pathsep + os.environ["PATH"])
    kb.init_db()
    with connect() as conn:
        tid = kb.create_task(conn, title="as-b", completion_contract="acme/repo", assignee="b")
        assert not kb.complete_task(conn, tid, result="done",
                                    metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
        receipt = json.loads(conn.execute(
            "SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (tid,)).fetchone()[0])
    assert receipt["classification"] == "auth"
    assert "'b'" in receipt["detail"] and "no login" in receipt["detail"]
    captured = json.loads(env_dump.read_text(encoding="utf-8-sig"))
    assert captured["GH_CONFIG_DIR"] == str(assignee_home / "gh")
    assert "GH_TOKEN" not in captured and "GITHUB_TOKEN" not in captured


def test_assigned_card_with_unresolvable_profile_is_auth_not_ambient(tmp_path, monkeypatch):
    """A card assigned to a profile that no longer exists must not run gh as the completing
    process's ambient login: classification `auth` naming the profile, gh never invoked."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))  # any gh spawn would fail as infra
    kb.init_db()
    with connect() as conn:
        tid = kb.create_task(conn, title="as-ghost", completion_contract="acme/repo", assignee="ghost")
        assert not kb.complete_task(conn, tid, result="done",
                                    metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
        receipt = json.loads(conn.execute(
            "SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (tid,)).fetchone()[0])
    assert receipt["classification"] == "auth"
    assert "'ghost'" in receipt["detail"] and "cannot be resolved" in receipt["detail"]
