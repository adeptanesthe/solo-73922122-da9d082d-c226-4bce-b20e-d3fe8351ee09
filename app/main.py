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
from config import CONFIRM_WINDOW_SECONDS, ECHO_PORT, WEB_PORT

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
            "status_error": str(exc),
        }
    # JSON 行需要把历史变更里的 JSON 字符串解析后再返回
    for chg in status.get("recent_changes", []):
        chg["requested_ports"] = json.loads(chg["requested_ports"])
        chg["previous_ports"] = json.loads(chg["previous_ports"])
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


# 静态资源（如有）
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
