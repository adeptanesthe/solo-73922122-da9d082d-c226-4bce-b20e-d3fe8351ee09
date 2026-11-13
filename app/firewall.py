"""防火墙变更业务逻辑：应用 / 确认 / 超时回退。

时间一律采用墙钟 epoch 秒，Web 进程与看护进程共用同一判定基准，
确保“生效后 30 秒内确认”在进程重启场景下语义不变。
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any

import db
import nft
from config import CONFIRM_WINDOW_SECONDS
from db import FAILED, PENDING

# 进程内串行化“应用”请求；跨进程的最终一致性由 SQLite 单 pending 约束保证
_apply_lock = threading.Lock()


class ChangeError(RuntimeError):
    """变更被拒绝（业务规则）。"""


@dataclass
class ApplyResult:
    change_id: int
    requested_ports: list[int]
    previous_ports: list[int]
    expires_at: float
    now: float


def _pending_view(row: dict[str, Any], now: float) -> dict[str, Any]:
    return {
        "id": row["id"],
        "requested_ports": json.loads(row["requested_ports"]),
        "previous_ports": json.loads(row["previous_ports"]),
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "remaining_seconds": max(0.0, row["expires_at"] - now),
    }


def apply_change(requested_ports: list[int]) -> ApplyResult:
    """应用一次白名单变更。

    顺序严格满足要求：
    1. 有待确认变更 -> 拒绝新变更；
    2. 先持久化“已确认规则快照 + 本次变更(pending)”；
    3. 再调用 nft 原子生效；
    4. nft 失败 -> 变更单标记 failed，旧规则从未被破坏，直接报错；
    5. 成功后由确认接口或独立看护进程在窗口内/外收口。
    """
    ports = sorted({int(p) for p in requested_ports})
    with _apply_lock:
        if db.get_pending_change() is not None:
            raise ChangeError("存在待确认的变更，请先确认或等待其超时回退后再提交新变更")

        previous = db.get_confirmed_ports() or []
        now = time.time()
        expires_at = now + CONFIRM_WINDOW_SECONDS

        # 2. 先落盘：即使随后 Web 退出，看护进程也能据快照回退。
        # 数据库触发器兜底跨进程并发：已有 pending 时此处抛 IntegrityError
        try:
            change_id = db.insert_change(
                requested_ports=ports,
                previous_ports=previous,
                created_at=now,
                expires_at=expires_at,
                status=PENDING,
            )
        except sqlite3.IntegrityError as exc:
            raise ChangeError(
                "存在待确认的变更（数据库并发约束），请先确认或等待其超时回退"
            ) from exc
        try:
            # 3. 原子生效；nft 批量事务失败时内核保留旧规则
            nft.apply_ruleset(ports)
        except Exception as exc:  # NftError 及其子类
            db.mark_change_status(change_id, FAILED, detail=f"应用失败，旧规则保留: {exc}")
            raise ChangeError(f"防火墙应用失败，已保留旧规则: {exc}") from exc

    return ApplyResult(
        change_id=change_id,
        requested_ports=ports,
        previous_ports=previous,
        expires_at=expires_at,
        now=now,
    )


def confirm_change(change_id: int) -> dict[str, Any]:
    """确认变更。

    * 必须是当前仍 pending 的那张单；过期单、旧单确认一律拒绝；
    * 确认成功才把新白名单写入“已确认规则”，旧单确认不影响当前规则。
    """
    now = time.time()
    row = db.get_change(change_id)
    if row is None:
        raise ChangeError(f"变更单 #{change_id} 不存在")

    pending = db.get_pending_change()
    if pending is None or pending["id"] != change_id:
        # 可能是已确认/已过期/已失败的旧单
        raise ChangeError(
            f"变更单 #{change_id} 不是当前待确认变更（当前状态: {row['status']}），"
            "旧变更/过期变更的确认不会影响当前规则"
        )
    if now >= row["expires_at"]:
        # 窗口已过：交给看护进程（或此处顺手）回退，拒绝确认
        rollback_expired()
        raise ChangeError(
            f"变更单 #{change_id} 已超过确认截止时间，规则已/将回退到旧白名单"
        )

    if not db.confirm_change(change_id, now):
        # 与看护进程竞争落败
        raise ChangeError(
            f"变更单 #{change_id} 已被看护进程超时回退，确认无效，当前规则不受影响"
        )

    new_ports = json.loads(row["requested_ports"])
    db.set_confirmed_ports(new_ports)  # 持久化新的已确认规则
    # 竞争兜底：若看护进程在截止边界已把 nft 回退到旧规则，这里把规则
    # 重新固化为已确认的新白名单，保证数据库状态与 nft 始终一致
    nft.apply_ruleset(new_ports)
    return {
        "change_id": change_id,
        "confirmed_ports": new_ports,
        "confirmed_at": now,
    }


def rollback_expired() -> list[int]:
    """扫描超时 pending 单并回退（看护进程周期调用，Web 确认路径也可复用）。

    回退目标是该单应用前的已确认快照；回退 nft 失败会重试（抛由调用方记录），
    数据库状态仅在 nft 恢复成功后、且单子仍为 pending 时才置为 expired，
    避免“标记过期但规则没恢复”以及与确认路径竞争导致的状态不一致。
    """
    now = time.time()
    pending = db.get_pending_change()
    if pending is None or now < pending["expires_at"]:
        return []

    change_id = pending["id"]
    previous_ports = json.loads(pending["previous_ports"])
    # 恢复旧规则（原子批量；失败则保留现状并抛错，下个轮询周期重试）
    nft.apply_ruleset(previous_ports)

    detail = f"超过 {CONFIRM_WINDOW_SECONDS:.0f}s 未确认，已自动回退到旧白名单"
    won = db.mark_expired_if_pending(change_id, now, detail)
    if not won:
        # 竞争落败：确认路径已赢得状态机并写入新的已确认基线，
        # 放弃回退，把 nft 恢复为当前已确认规则
        current = db.get_confirmed_ports() or previous_ports
        nft.apply_ruleset(current)
        return []
    return [change_id]


def get_status() -> dict[str, Any]:
    now = time.time()
    confirmed = db.get_confirmed_ports()
    pending_row = db.get_pending_change()
    pending = _pending_view(pending_row, now) if pending_row else None
    if pending and now >= pending_row["expires_at"]:
        pending["note"] = "已过期，等待看护进程回退"
    return {
        "now": now,
        "confirm_window_seconds": CONFIRM_WINDOW_SECONDS,
        "confirmed_ports": sorted(confirmed) if confirmed is not None else [],
        "has_confirmed_baseline": confirmed is not None,
        "pending": pending,
        "active_nft_rules": nft.list_active_rules(),
        "recent_changes": db.list_recent_changes(),
    }
