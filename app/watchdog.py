"""独立看护进程（与 Web 进程完全独立，不依赖 FastAPI 存活）。

职责：周期性检查待确认变更，超过确认窗口未确认则把 nftables
规则回退到应用前的已确认快照。

* Web 进程退出/崩溃不影响本进程，回退仍按原期限发生；
* 回退使用与应用相同的原子 nft 批量事务；
* 回退命令失败时保留 pending 状态并在下个周期重试，直到规则真正恢复。
"""
from __future__ import annotations

import logging
import os
import signal
import time

import db
import firewall
from config import WATCHDOG_INTERVAL_SECONDS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [watchdog] %(levelname)s %(message)s",
)
log = logging.getLogger("watchdog")

_running = True


def _stop(signum, _frame) -> None:  # pragma: no cover - 信号路径
    global _running
    _running = False
    log.info("收到信号 %s，准备退出", signum)


def main() -> None:
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    db.init_db()
    log.info(
        "看护进程启动，轮询间隔 %.1fs，确认窗口由数据库时间戳判定",
        WATCHDOG_INTERVAL_SECONDS,
    )

    while _running:
        # 可选的停止文件（运维/测试钩子）：文件出现即干净退出
        stop_file = os.environ.get("WATCHDOG_STOP_FILE")
        if stop_file and os.path.exists(stop_file):
            log.info("检测到停止文件 %s，退出", stop_file)
            break
        try:
            rolled = firewall.rollback_expired()
            for change_id in rolled:
                log.warning("变更单 #%s 超时未确认，已回退到旧白名单", change_id)
        except Exception as exc:  # 永不因单次错误退出看护进程
            log.error("回退检查失败（将在下个周期重试）: %s", exc)
        # 可中断的短睡眠，保证 SIGTERM 及时响应
        deadline = time.time() + WATCHDOG_INTERVAL_SECONDS
        while _running and time.time() < deadline:
            time.sleep(min(0.2, max(0.0, deadline - time.time())))

    log.info("看护进程退出")


if __name__ == "__main__":
    main()
