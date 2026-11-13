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
            """
        )
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
