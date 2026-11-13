"""整套服务启动恢复（entrypoint 在开放网页之前调用）。

恢复顺序：
1. 初始化数据库；
2. 把所有历史遗留的 pending 变更标记为 expired
   （未确认的变更在重启后一律不保留）；
3. 读取已确认规则并先在 nftables 恢复，之后才允许启动 Web。
首次启动（无已确认规则）时写入初始白名单（网页端口 + 回显端口）。
"""
from __future__ import annotations

import logging
import time

import db
import nft
import coordination
from config import INITIAL_PORTS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [bootstrap] %(levelname)s %(message)s",
)
log = logging.getLogger("bootstrap")


def bootstrap() -> list[int]:
    db.init_db()

    when = time.time()
    stale = db.expire_all_pending("服务重启：未确认变更一律作废", when)
    for change_id in stale:
        log.info("遗留待确认变更单 #%s 已标记为 expired", change_id)

    ports = db.get_confirmed_ports()
    if ports is None:
        ports = sorted(INITIAL_PORTS)
        db.set_confirmed_ports(ports)
        log.info("首次启动，写入初始白名单 %s", ports)
    else:
        ports = sorted(ports)
        log.info("恢复已确认规则白名单 %s", ports)

    # 先恢复防火墙，再开放网页：失败则让容器启动失败，避免“裸奔”对外。
    # 走统一跨进程写锁并推进 epoch：重启后所有旧核查令牌自然失效（409）。
    coordination.run_rule_write(lambda: nft.apply_ruleset(ports))
    log.info("nftables 专用表规则已恢复（策略版本号=%s），现在可以启动 Web",
             db.get_policy_epoch())
    return ports


if __name__ == "__main__":
    bootstrap()
