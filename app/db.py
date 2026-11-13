"""SQLite 持久层。

两类持久数据：
* state：已确认规则（当前白名单），整套服务重启后据此先恢复再开放网页；
* changes：每次“应用”产生的变更单，含应用前快照与完整生命周期状态。
Web 进程与独立看护进程各自打开连接，通过 WAL + BEGIN IMMEDIATE 串行化写入。
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Iterator

from config import DB_PATH

# 变更单状态机
PENDING = "pending"      # 已应用、等待确认
CONFIRMED = "confirmed"  # 已在窗口内确认
EXPIRED = "expired"      # 超时未确认，看护进程已回退
FAILED = "failed"        # 应用失败（规则未生效，旧规则保留）

STATE_CONFIRMED_PORTS = "confirmed_ports"
# 策略版本号：任何合法规则写入（应用/确认/回退/修复）都原子 +1。
# 核查用它检测“读取期间策略是否被合法路径改写”；修复用它绑定核查时状态。
STATE_POLICY_EPOCH = "policy_epoch"


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS state (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS changes (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                requested_ports    TEXT NOT NULL,  -- JSON 数组：本次请求的白名单
                previous_ports     TEXT NOT NULL,  -- JSON 数组：应用前已确认快照
                status             TEXT NOT NULL,
                created_at         REAL NOT NULL,  -- 应用生效时刻（epoch 秒）
                expires_at         REAL NOT NULL,  -- 确认截止时刻
                confirmed_at       REAL,
                finalized_at       REAL,
                detail             TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_changes_status ON changes(status);
            -- 跨进程硬约束：任意时刻最多一张待确认(pending)变更单。
            -- 进程内锁之外的第二道防线：并发应用时后到者直接被数据库拒绝。
            CREATE TRIGGER IF NOT EXISTS trg_changes_one_pending
            BEFORE INSERT ON changes
            WHEN NEW.status = 'pending'
                 AND EXISTS (SELECT 1 FROM changes WHERE status = 'pending')
            BEGIN
                SELECT RAISE(ABORT, 'already has a pending change');
            END;
            CREATE TABLE IF NOT EXISTS audits (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                kind            TEXT NOT NULL,   -- check=核查 / repair=修复
                result          TEXT NOT NULL,   -- in_sync/drift/missing_table/unknown/repaired/conflict/error
                epoch_before    INTEGER,         -- 核查开始时的策略版本号
                epoch_after     INTEGER,         -- 核查完成时的策略版本号
                attempts        INTEGER NOT NULL DEFAULT 1, -- 期间被合法变更打断后的重查次数
                expected_ports  TEXT,            -- 当时“应生效”白名单 JSON
                observed_ports  TEXT,            -- 实际从 nft 读出的放行 TCP 端口 JSON
                detail          TEXT,
                created_at      REAL NOT NULL,
                consumed        INTEGER NOT NULL DEFAULT 0  -- 修复令牌一次性消费标记
            );
            CREATE INDEX IF NOT EXISTS idx_audits_created ON audits(created_at);
            """
        )
        # 旧库升级：补令牌一次性消费标记（列已存在时 ALTER 报错，忽略）
        try:
            conn.execute("ALTER TABLE audits ADD COLUMN consumed INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        conn.commit()


def get_confirmed_ports() -> list[int] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT value FROM state WHERE key = ?", (STATE_CONFIRMED_PORTS,)
        ).fetchone()
    if row is None:
        return None
    return json.loads(row["value"])


def set_confirmed_ports(ports: list[int]) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO state(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (STATE_CONFIRMED_PORTS, json.dumps(sorted(set(ports)))),
        )
        conn.commit()


def get_pending_change() -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM changes WHERE status = ? ORDER BY id DESC LIMIT 1",
            (PENDING,),
        ).fetchone()
    return dict(row) if row else None


def insert_change(
    requested_ports: list[int],
    previous_ports: list[int],
    created_at: float,
    expires_at: float,
    status: str,
    detail: str | None = None,
) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO changes(requested_ports, previous_ports, status, "
            "created_at, expires_at, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (
                json.dumps(sorted(set(requested_ports))),
                json.dumps(sorted(set(previous_ports))),
                status,
                created_at,
                expires_at,
                detail,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def get_change(change_id: int) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM changes WHERE id = ?", (change_id,)
        ).fetchone()
    return dict(row) if row else None


def mark_change_status(
    change_id: int, status: str, when: float | None = None, detail: str | None = None
) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE changes SET status = ?, finalized_at = ?, "
            "detail = COALESCE(?, detail) WHERE id = ?",
            (status, when if when is not None else time.time(), detail, change_id),
        )
        conn.commit()


def mark_expired_if_pending(change_id: int, when: float, detail: str) -> bool:
    """仅当单子仍为 pending 时标记 expired（与确认路径竞争时的安全收口）。

    返回 True 表示本调用赢得了状态机；False 表示单子已被确认，回退方
    必须放弃覆盖，并把 nft 规则恢复为已确认基线。
    """
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT status FROM changes WHERE id = ?", (change_id,)
        ).fetchone()
        if row is None or row["status"] != PENDING:
            conn.rollback()
            return False
        conn.execute(
            "UPDATE changes SET status = ?, finalized_at = ?, detail = ? WHERE id = ?",
            (EXPIRED, when, detail, change_id),
        )
        conn.commit()
        return True


def confirm_change(change_id: int, when: float) -> bool:
    """仅当变更单仍为 pending 时确认成功（行锁内完成，避免与看护进程竞争）。"""
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT status FROM changes WHERE id = ?", (change_id,)
        ).fetchone()
        if row is None or row["status"] != PENDING:
            conn.rollback()
            return False
        conn.execute(
            "UPDATE changes SET status = ?, confirmed_at = ?, finalized_at = ? "
            "WHERE id = ?",
            (CONFIRMED, when, when, change_id),
        )
        conn.commit()
        return True


def list_recent_changes(limit: int = 10) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM changes ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def expire_all_pending(reason: str, when: float) -> list[int]:
    """启动恢复时使用：把所有遗留 pending 单标记为 expired，返回其 id 列表。"""
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            "SELECT id FROM changes WHERE status = ?", (PENDING,)
        ).fetchall()
        ids = [r["id"] for r in rows]
        if ids:
            conn.execute(
                "UPDATE changes SET status = ?, finalized_at = ?, detail = ? "
                "WHERE status = ?",
                (EXPIRED, when, reason, PENDING),
            )
        conn.commit()
    return ids


def get_policy_epoch() -> int:
    """读取当前策略版本号（不存在视为 0）。"""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT value FROM state WHERE key = ?", (STATE_POLICY_EPOCH,)
        ).fetchone()
    return int(row["value"]) if row is not None else 0


def bump_policy_epoch() -> int:
    """原子自增策略版本号并返回新值（所有合法规则写入路径共用）。"""
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT value FROM state WHERE key = ?", (STATE_POLICY_EPOCH,)
        ).fetchone()
        new_epoch = (int(row["value"]) if row is not None else 0) + 1
        conn.execute(
            "INSERT INTO state(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (STATE_POLICY_EPOCH, str(new_epoch)),
        )
        conn.commit()
    return new_epoch


def insert_audit(
    kind: str,
    result: str,
    created_at: float,
    epoch_before: int | None = None,
    epoch_after: int | None = None,
    attempts: int = 1,
    expected_ports: list[int] | None = None,
    observed_ports: list[int] | None = None,
    detail: str | None = None,
) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO audits(kind, result, epoch_before, epoch_after, attempts, "
            "expected_ports, observed_ports, detail, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                kind,
                result,
                epoch_before,
                epoch_after,
                attempts,
                json.dumps(sorted(expected_ports)) if expected_ports is not None else None,
                json.dumps(sorted(observed_ports)) if observed_ports is not None else None,
                detail,
                created_at,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def get_audit(audit_id: int) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM audits WHERE id = ?", (audit_id,)
        ).fetchone()
    return dict(row) if row else None


def list_recent_audits(limit: int = 20) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM audits ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def consume_audit_token(audit_id: int) -> bool:
    """原子地把核查单标记为已消费。

    返回 True 表示本次调用成功占用令牌；False 表示令牌已被消费过（重放）。
    """
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT consumed FROM audits WHERE id = ? AND kind = 'check'",
            (audit_id,),
        ).fetchone()
        if row is None or row["consumed"]:
            conn.rollback()
            return False
        conn.execute(
            "UPDATE audits SET consumed = 1 WHERE id = ?", (audit_id,)
        )
        conn.commit()
    return True
