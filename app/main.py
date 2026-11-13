"""FastAPI 管理网页后端。

页面能力（对应需求）：
* 查看当前状态：已确认白名单、待确认变更与倒计时、nft 生效规则、历史变更；
* 应用新的 TCP 端口白名单；
* 在确认窗口内确认本次变更；
* 提供“移除网页端口”的一键演示入口（失联后由看护进程自动回退恢复）。
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

import db
import firewall
import audit
import config
import drift_inject
from config import (
    AUDIT_MAX_SLOW_DELAY,
    CONFIRM_WINDOW_SECONDS,
    ECHO_PORT,
    WEB_PORT,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [web] %(levelname)s %(message)s",
)
log = logging.getLogger("web")

app = FastAPI(title="入站端口白名单变更管理", version="1.0.0")

STATIC_DIR = Path(__file__).resolve().parent / "static"


class ApplyRequest(BaseModel):
    # 用户输入的 TCP 端口白名单
    ports: list[int] = Field(..., description="TCP 端口白名单（1-65535）")

    @field_validator("ports")
    @classmethod
    def _validate(cls, value: list[int]) -> list[int]:
        if not value:
            raise ValueError("白名单至少包含一个 TCP 端口，否则管理面将永久失联")
        bad = [p for p in value if not (1 <= p <= 65535)]
        if bad:
            raise ValueError(f"端口超出 1-65535 范围: {bad}")
        return sorted(set(value))


class ConfirmRequest(BaseModel):
    change_id: int = Field(..., description="待确认变更单 ID")


class RepairRequest(BaseModel):
    # 核查接口返回的状态令牌（绑定核查时的策略版本号与 pending 状态）
    token: str = Field(..., min_length=1, description="核查返回的状态令牌")


class AuditCheckRequest(BaseModel):
    # 演示用：核查读 nft 前的人工延迟（秒），用于演示期间被合法变更打断后重查
    slow_delay: float = Field(
        default=0.0, ge=0.0, le=AUDIT_MAX_SLOW_DELAY,
        description="核查读取前注入的延迟（秒，仅用于演示并发重查）",
    )


class InjectRequest(BaseModel):
    action: str = Field(
        ...,
        description="漂移注入动作：extra-port / delete-table / tamper-policy",
    )
    port: int = Field(default=22, ge=1, le=65535, description="extra-port 的端口")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/config")
def api_config() -> dict:
    return {
        "web_port": WEB_PORT,
        "echo_port": ECHO_PORT,
        "confirm_window_seconds": CONFIRM_WINDOW_SECONDS,
    }


@app.get("/api/status")
def api_status() -> JSONResponse:
    try:
        status = firewall.get_status()
    except Exception as exc:  # nft 读取失败不应让整个状态页不可用
        log.exception("读取状态失败")
        status = {
            "now": time.time(),
            "confirm_window_seconds": CONFIRM_WINDOW_SECONDS,
            "confirmed_ports": db.get_confirmed_ports() or [],
            "has_confirmed_baseline": db.get_confirmed_ports() is not None,
            "pending": None,
            "active_nft_rules": [],
            "recent_changes": db.list_recent_changes(),
            "policy_epoch": db.get_policy_epoch(),
            "recent_audits": db.list_recent_audits(limit=5),
            "status_error": str(exc),
        }
    # JSON 行需要把历史变更里的 JSON 字符串解析后再返回
    for chg in status.get("recent_changes", []):
        chg["requested_ports"] = json.loads(chg["requested_ports"])
        chg["previous_ports"] = json.loads(chg["previous_ports"])
    for aud in status.get("recent_audits", []):
        for key in ("expected_ports", "observed_ports"):
            if aud.get(key):
                aud[key] = json.loads(aud[key])
    return JSONResponse(status)


@app.post("/api/apply")
def api_apply(req: ApplyRequest) -> dict:
    try:
        result = firewall.apply_change(req.ports)
    except firewall.ChangeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    log.warning(
        "变更单 #%s 已应用: %s -> %s，须在 %.0f 秒内确认",
        result.change_id,
        result.previous_ports,
        result.requested_ports,
        CONFIRM_WINDOW_SECONDS,
    )
    return {
        "ok": True,
        "change_id": result.change_id,
        "requested_ports": result.requested_ports,
        "previous_ports": result.previous_ports,
        "expires_at": result.expires_at,
        "now": result.now,
        "confirm_window_seconds": CONFIRM_WINDOW_SECONDS,
        "message": (
            f"规则已生效，变更单 #{result.change_id} 等待确认；"
            f"超过 {CONFIRM_WINDOW_SECONDS:.0f} 秒未确认将自动回退"
        ),
    }


@app.post("/api/confirm")
def api_confirm(req: ConfirmRequest) -> dict:
    try:
        out = firewall.confirm_change(req.change_id)
    except firewall.ChangeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    log.info("变更单 #%s 已确认，白名单固化为 %s", req.change_id, out["confirmed_ports"])
    return {"ok": True, **out}


@app.post("/api/audit/check")
def api_audit_check(req: AuditCheckRequest) -> dict:
    """漂移核查：只读真实 nft 专用表，不阻塞应用/确认/回退。

    结果分类：in_sync（一致）/ drift（结构漂移）/ missing_table（缺表）/
    unknown（读取失败，不臆测）。
    """
    try:
        result = audit.run_check(slow_delay=req.slow_delay)
    except audit.AuditError as exc:
        # 连续重查仍不稳定等：作为 500 未知类失败，不给出可能错误的结论
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    log.warning(
        "漂移核查 #%s 结果=%s 期望=%s 实际放行=%s（尝试 %s 次）",
        result["audit_id"],
        result["result"],
        result["expected_ports"],
        result["observed_ports"],
        result["attempts"],
    )
    return result


@app.get("/api/audit/history")
def api_audit_history() -> dict:
    rows = db.list_recent_audits()
    for row in rows:
        for key in ("expected_ports", "observed_ports"):
            if row.get(key):
                row[key] = json.loads(row[key])
    return {"audits": rows}


@app.post("/api/audit/repair")
def api_audit_repair(req: RepairRequest) -> dict:
    """按核查令牌恢复应生效策略；绑定状态失效一律 409 且不写规则。"""
    try:
        out = audit.run_repair(req.token)
    except audit.RepairConflict as exc:
        log.warning("修复被拒绝（409）：%s", exc)
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except audit.RepairVerifyError as exc:
        # 写入后复核失败：绝不能报已恢复
        log.error("修复复核失败：%s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except audit.AuditError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    log.warning("修复完成：%s", out["message"])
    return out


@app.post("/api/demo/inject")
def api_demo_inject(req: InjectRequest) -> dict:
    """演示入口：模拟其他脚本旁路改写专用表（可通过环境变量关闭）。"""
    if not config.DEMO_INJECTION_ENABLED:
        raise HTTPException(status_code=403, detail="漂移注入演示已被环境变量关闭")
    try:
        if req.action == "extra-port":
            drift_inject.inject_extra_port(req.port)
        elif req.action == "delete-table":
            drift_inject.inject_delete_table()
        elif req.action == "tamper-policy":
            drift_inject.inject_tamper_policy()
        else:
            raise HTTPException(
                status_code=400,
                detail="action 必须是 extra-port / delete-table / tamper-policy",
            )
    except SystemExit as exc:
        raise HTTPException(status_code=500, detail=f"注入失败: {exc}") from exc
    log.warning("演示漂移注入：%s port=%s（未走写锁/版本号）", req.action, req.port)
    return {"ok": True, "action": req.action, "port": req.port,
            "note": "注入不推进策略版本号，请随后执行漂移核查"}


# 静态资源（如有）
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
