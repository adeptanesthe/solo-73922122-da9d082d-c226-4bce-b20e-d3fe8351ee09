"""核查/修复端到端测试（假 nft 后端 + 临时 SQLite + 临时锁/密钥文件）。

覆盖需求：
1. 一致状态核查为 in_sync，忽略 handle 与计数器；
2. 额外放行（旁路规则）-> drift，修复后重新读取核实通过；
3. 缺表 -> missing_table，修复重建专用表；
4. 链属性被改（policy accept）-> drift；
5. nft 读取失败 -> unknown；
6. 核查期间发生合法应用 -> 丢弃结果并重查（attempts=2，结论正确）；
7. 修复令牌在应用/确认/回退后返回 409 且不写规则；
8. pending 期间修复保留原变更单与截止时间；
9. 修复不改写已确认基线、不触碰其他表（假后端只有专用表，另验证基线值）；
10. 伪造/篡改令牌被拒绝。
"""
from __future__ import annotations

import os
import sys
import threading
import time

import pytest

# 让测试可以 import 应用模块
APP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app"))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)
TESTS_DIR = os.path.dirname(__file__)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

import config  # noqa: E402
import db  # noqa: E402
import nft  # noqa: E402
import coordination  # noqa: E402
import firewall  # noqa: E402
import audit as audit_mod  # noqa: E402
from fake_nft import FakeNft  # noqa: E402


@pytest.fixture()
def env(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    lock_path = tmp_path / "rule.lock"
    key_path = tmp_path / "token.key"
    monkeypatch.setattr(config, "DB_PATH", str(db_path))
    monkeypatch.setattr(db, "DB_PATH", str(db_path))
    monkeypatch.setattr(config, "RULE_WRITE_LOCK_PATH", str(lock_path))
    monkeypatch.setattr(config, "STATE_TOKEN_KEY_PATH", str(key_path))
    monkeypatch.setattr(config, "AUDIT_SLOW_DELAY_SECONDS", 0.0)
    monkeypatch.setattr(config, "CONFIRM_WINDOW_SECONDS", 30.0)
    # coordination 动态从 config 读路径；重置缓存句柄与路径
    monkeypatch.setattr(coordination, "_lock_file_handle", None)
    monkeypatch.setattr(coordination, "_lock_file_path", None)

    fake = FakeNft()
    monkeypatch.setattr(nft, "_run_nft", fake.run)

    db.init_db()
    # 初始基线 8080/8090 并下发
    db.set_confirmed_ports([8080, 8090])
    coordination.run_rule_write(lambda: nft.apply_ruleset([8080, 8090]))
    return {"fake": fake, "tmp": tmp_path}


def test_in_sync_ignores_handle_and_counter(env):
    result = audit_mod.run_check()
    assert result["result"] == audit_mod.IN_SYNC
    assert result["is_drift"] is False
    assert result["observed_ports"] == [8080, 8090]
    assert result["epoch"] == db.get_policy_epoch()
    assert "token" in result and result["token"]


def test_extra_allow_drift_and_repair(env):
    fake = env["fake"]
    # 旁路脚本追加一条带计数器的额外放行
    fake.rogue_add_extra_port(22)
    result = audit_mod.run_check()
    assert result["result"] == audit_mod.DRIFT
    assert result["is_drift"] is True
    assert 22 in result["extra_allowed_ports"]
    assert result["observed_ports"] == [22, 8080, 8090]
    assert result["structural_diff"]  # 有结构差异
    epoch_before = db.get_policy_epoch()

    # 修复
    out = audit_mod.run_repair(result["token"])
    assert out["ok"] is True and out["changed"] is True
    assert out["restored_ports"] == [8080, 8090]
    assert out["verified"] is True
    assert db.get_policy_epoch() == epoch_before + 1

    # 再核查：一致，且额外放行已消失
    again = audit_mod.run_check()
    assert again["result"] == audit_mod.IN_SYNC
    assert again["observed_ports"] == [8080, 8090]
    # 已确认基线没有被修复动作改写
    assert db.get_confirmed_ports() == [8080, 8090]


def test_missing_table_drift_and_repair(env):
    env["fake"].rogue_delete_table()
    result = audit_mod.run_check()
    assert result["result"] == audit_mod.MISSING_TABLE
    assert result["is_drift"] is True
    assert result["observed_ports"] == []

    out = audit_mod.run_repair(result["token"])
    assert out["ok"] is True and out["changed"] is True
    # 修复后真实表重新存在且结构正确
    snap = nft.read_table_snapshot()
    assert snap is not None
    assert snap["name"] == config.NFT_TABLE_NAME
    assert nft.extract_tcp_accept_ports(snap) == [8080, 8090]
    chain = snap["chains"][0]
    assert chain["policy"] == "drop"
    assert chain["hook"] == "input" and chain["type"] == "filter"


def test_chain_policy_drift_detected(env):
    env["fake"].rogue_change_policy_accept()
    result = audit_mod.run_check()
    assert result["result"] == audit_mod.DRIFT
    drift = result["structural_diff"]["chain_attribute_drifts"]
    assert any(d["attribute"] == "policy" and d["observed"] == "accept"
               for d in drift)


def test_read_failure_reports_unknown(env, monkeypatch):
    env["fake"].make_read_fail(monkeypatch)
    result = audit_mod.run_check()
    assert result["result"] == audit_mod.UNKNOWN
    assert result["is_drift"] is False  # 未知不等于漂移
    # 未知结论的令牌不能用于修复（修复前读取同样失败 -> AuditError 500）
    with pytest.raises(audit_mod.AuditError):
        audit_mod.run_repair(result["token"])


def test_check_discards_and_retries_when_policy_changes(env, monkeypatch):
    # 注入可控慢核查：在第一次读 nft 之前，由另一个线程做一次合法应用
    original_read = nft.read_table_snapshot
    event = threading.Event()

    def slow_read():
        # 只在第一次调用时阻塞，等待并发应用完成
        if not event.is_set():
            event.wait(2.0)
        return original_read()

    monkeypatch.setattr(nft, "read_table_snapshot", slow_read)

    def concurrent_apply():
        # 应用一个合法新白名单（推进 epoch），随后放行核查读取
        firewall.apply_change([8080, 8090, 9000])
        event.set()

    t = threading.Thread(target=concurrent_apply)
    t.start()
    result = audit_mod.run_check(slow_delay=0.0)
    t.join()

    assert result["attempts"] == 2  # 第一次结果被丢弃并重查
    assert result["result"] == audit_mod.IN_SYNC
    # 结论反映的是新策略而不是旧快照
    assert result["expected_ports"] == [8080, 8090, 9000]
    assert result["observed_ports"] == [8080, 8090, 9000]


def test_repair_conflicts_after_apply_confirm_rollback(env):
    # 场景 A：核查后发生“应用” -> 409 且不写规则
    env["fake"].rogue_add_extra_port(22)
    check = audit_mod.run_check()
    assert check["result"] == audit_mod.DRIFT
    firewall.apply_change([8080, 8090, 9000])  # 合法应用，epoch +1
    with pytest.raises(audit_mod.RepairConflict):
        audit_mod.run_repair(check["token"])
    # 修复被拒绝：规则只反映合法应用的结果，修复令牌没有触发任何额外写入
    snap = nft.read_table_snapshot()
    assert nft.extract_tcp_accept_ports(snap) == [8080, 8090, 9000]
    assert db.get_policy_epoch() == check["epoch"] + 1  # 仅 apply 推进过一次

    # 场景 B：核查后发生“确认” -> 409
    env["fake"].rogue_add_extra_port(2222)
    pending = db.get_pending_change()
    check2 = audit_mod.run_check()
    firewall.confirm_change(pending["id"])
    with pytest.raises(audit_mod.RepairConflict):
        audit_mod.run_repair(check2["token"])

    # 场景 C：核查后发生“回退” -> 409
    firewall.apply_change([8080, 8090])  # 再建一个 pending
    env["fake"].rogue_add_extra_port(3333)
    check3 = audit_mod.run_check()
    pending2 = db.get_pending_change()
    # 直接把截止时间改到过去，再由看护逻辑回退
    with db.get_conn() as conn:
        conn.execute("UPDATE changes SET expires_at = ? WHERE id = ?",
                     (time.time() - 1, pending2["id"]))
        conn.commit()
    firewall.rollback_expired()
    with pytest.raises(audit_mod.RepairConflict):
        audit_mod.run_repair(check3["token"])


def test_repair_during_pending_keeps_change_and_deadline(env):
    # 建立 pending：请求白名单 [8080, 8090, 443]
    applied = firewall.apply_change([8080, 8090, 443])
    pending_row = db.get_pending_change()
    original_expires = pending_row["expires_at"]
    original_id = pending_row["id"]

    # 旁路脚本再塞一条额外放行
    env["fake"].rogue_add_extra_port(5555)
    check = audit_mod.run_check()
    assert check["result"] == audit_mod.DRIFT
    # 核查的应生效策略来自 pending 请求（数值排序）
    assert check["expected_ports"] == [443, 8080, 8090]
    assert check["pending_binding"]["pending_id"] == original_id

    out = audit_mod.run_repair(check["token"])
    assert out["pending_id"] == original_id
    assert out["restored_ports"] == [443, 8080, 8090]

    # 原变更单仍为 pending，截止时间未被修复改动
    still_pending = db.get_pending_change()
    assert still_pending is not None
    assert still_pending["id"] == original_id
    assert abs(still_pending["expires_at"] - original_expires) < 1e-9
    # 真实规则恢复为 pending 请求白名单，额外放行消失
    snap = nft.read_table_snapshot()
    assert nft.extract_tcp_accept_ports(snap) == [443, 8080, 8090]


def test_forged_and_tampered_token_rejected(env):
    with pytest.raises(audit_mod.RepairConflict):
        audit_mod.run_repair("not-a-valid-token")
    env["fake"].rogue_add_extra_port(22)
    token = audit_mod.run_check()["token"]
    payload, sig = token.split(".")
    tampered = payload + "." + ("A" * len(sig))
    with pytest.raises(audit_mod.RepairConflict):
        audit_mod.run_repair(tampered)


def test_repair_idempotent_when_already_in_sync(env):
    check = audit_mod.run_check()
    assert check["result"] == audit_mod.IN_SYNC
    out = audit_mod.run_repair(check["token"])
    assert out["changed"] is False  # 无需写入，epoch 不变
    assert out["restored_ports"] == [8080, 8090]
    # 令牌一次性消费：重放同一令牌被拒绝（409 语义）
    with pytest.raises(audit_mod.RepairConflict):
        audit_mod.run_repair(check["token"])


def test_audit_history_persisted(env):
    env["fake"].rogue_add_extra_port(22)
    audit_mod.run_check()
    audit_mod.run_check()
    rows = db.list_recent_audits()
    assert len(rows) >= 2
    assert rows[0]["kind"] == "check"


def test_token_single_use_replay_rejected(env):
    env["fake"].rogue_add_extra_port(22)
    token = audit_mod.run_check()["token"]
    first = audit_mod.run_repair(token)
    assert first["ok"] is True
    # 同一令牌重放：409 且不再写入
    with pytest.raises(audit_mod.RepairConflict):
        audit_mod.run_repair(token)


def test_repair_verify_failure_does_not_report_recovered(env, monkeypatch):
    """写入后重新读取若仍漂移，必须抛 RepairVerifyError，绝不报已恢复。"""
    env["fake"].rogue_add_extra_port(22)
    token = audit_mod.run_check()["token"]

    real_read = nft.read_table_snapshot
    calls = {"n": 0}

    def flaky_verify():
        calls["n"] += 1
        snap = real_read()
        # 修复写入后的那次核实（第 2 次读取：第 1 次是修复前检查）仍返回带漂移的旧结构
        if calls["n"] == 2:
            # 模拟核实读到漂移：手工把额外放行重新塞回再返回
            env["fake"].rogue_add_extra_port(22)
            return real_read()
        return snap

    monkeypatch.setattr(nft, "read_table_snapshot", flaky_verify)
    with pytest.raises(audit_mod.RepairVerifyError):
        audit_mod.run_repair(token)

    # 审计记录中不得出现 repaired 成功结论
    rows = db.list_recent_audits()
    assert all(r["result"] != "repaired" for r in rows if r["kind"] == "repair")
