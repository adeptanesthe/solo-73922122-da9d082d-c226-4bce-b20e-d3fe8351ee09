"""HTTP API 层测试：核查/修复入口的状态码与并发语义。"""
from __future__ import annotations

import os
import sys

import pytest
from fastapi.testclient import TestClient

APP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app"))
TESTS_DIR = os.path.dirname(__file__)
for path in (APP_DIR, TESTS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

import config  # noqa: E402
import coordination  # noqa: E402
import db  # noqa: E402
import firewall  # noqa: E402
import nft  # noqa: E402
from fake_nft import FakeNft  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(config, "RULE_WRITE_LOCK_PATH", str(tmp_path / "l.lock"))
    monkeypatch.setattr(config, "STATE_TOKEN_KEY_PATH", str(tmp_path / "k.key"))
    monkeypatch.setattr(config, "DEMO_INJECTION_ENABLED", True)
    monkeypatch.setattr(config, "CONFIRM_WINDOW_SECONDS", 30.0)
    monkeypatch.setattr(coordination, "_lock_file_handle", None)
    monkeypatch.setattr(coordination, "_lock_file_path", None)

    fake = FakeNft()
    monkeypatch.setattr(nft, "_run_nft", fake.run)

    # main 在 import 时读取配置；确保在 fixture 之后导入
    import main  # noqa: E402
    db.init_db()
    db.set_confirmed_ports([8080, 8090])
    coordination.run_rule_write(lambda: nft.apply_ruleset([8080, 8090]))
    with TestClient(main.app) as c:
        yield c, fake


def test_check_then_repair_flow_over_http(client):
    c, fake = client
    # 注入额外放行
    r = c.post("/api/demo/inject", json={"action": "extra-port", "port": 22})
    assert r.status_code == 200

    r = c.post("/api/audit/check", json={"slow_delay": 0})
    assert r.status_code == 200
    body = r.json()
    assert body["result"] == "drift"
    assert 22 in body["extra_allowed_ports"]
    token = body["token"]

    r = c.post("/api/audit/repair", json={"token": token})
    assert r.status_code == 200
    assert r.json()["verified"] is True

    r = c.post("/api/audit/check", json={})
    assert r.json()["result"] == "in_sync"


def test_repair_returns_409_after_apply(client):
    c, fake = client
    fake.rogue_add_extra_port(22)
    token = c.post("/api/audit/check", json={}).json()["token"]

    # 合法应用推进版本号
    r = c.post("/api/apply", json={"ports": [8080, 8090, 9000]})
    assert r.status_code == 200

    r = c.post("/api/audit/repair", json={"token": token})
    assert r.status_code == 409
    assert "409" in r.json()["detail"] or "拒绝" in r.json()["detail"]


def test_unknown_result_when_nft_unreadable(client, monkeypatch):
    c, _ = client

    class Proc:
        returncode = 1
        stdout = ""
        stderr = "nft: simulated failure"

    import nft as nft_mod
    original = nft_mod._run_nft

    def flaky(args, **kwargs):
        if "list" in args and "table" in args:
            return Proc()
        return original(args, **kwargs)

    monkeypatch.setattr(nft_mod, "_run_nft", flaky)
    body = c.post("/api/audit/check", json={}).json()
    assert body["result"] == "unknown"
    assert body["is_drift"] is False


def test_injection_disabled_returns_403(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(config, "DEMO_INJECTION_ENABLED", False)
    r = c.post("/api/demo/inject", json={"action": "delete-table"})
    assert r.status_code == 403


def test_history_and_status_include_audits(client):
    c, _ = client
    c.post("/api/audit/check", json={})
    r = c.get("/api/audit/history")
    assert r.status_code == 200
    assert r.json()["audits"][0]["kind"] == "check"

    status = c.get("/api/status").json()
    assert "policy_epoch" in status
    assert len(status["recent_audits"]) >= 1


def test_pending_repair_preserves_change_over_http(client):
    c, fake = client
    applied = c.post("/api/apply", json={"ports": [8080, 8090, 443]}).json()
    fake.rogue_add_extra_port(5555)
    check = c.post("/api/audit/check", json={}).json()
    assert check["pending_binding"]["pending_id"] == applied["change_id"]

    repaired = c.post("/api/audit/repair", json={"token": check["token"]}).json()
    assert repaired["pending_id"] == applied["change_id"]
    # pending 仍然存在且截止时间未变
    status = c.get("/api/status").json()
    assert status["pending"]["id"] == applied["change_id"]
    assert abs(status["pending"]["expires_at"] - applied["expires_at"]) < 1e-6
