"""集中配置：端口、超时、nftables 表名等均可通过环境变量覆盖。"""
from __future__ import annotations

import os

# 管理网页端口（初始白名单之一，演示时可把它移出白名单以模拟失联）
WEB_PORT = int(os.getenv("WEB_PORT", "8080"))
# 附带的 HTTP 回显服务端口（初始白名单之一）
ECHO_PORT = int(os.getenv("ECHO_PORT", "8090"))

# 确认窗口（秒）：规则生效后必须在该时长内确认，否则看护进程回退
CONFIRM_WINDOW_SECONDS = float(os.getenv("CONFIRM_WINDOW_SECONDS", "30"))
# 看护进程轮询周期
WATCHDOG_INTERVAL_SECONDS = float(os.getenv("WATCHDOG_INTERVAL_SECONDS", "0.5"))

# 容器内专用 nftables 表（只操作这张表，绝不触碰宿主或其他表/链）
NFT_TABLE_FAMILY = "inet"
NFT_TABLE_NAME = os.getenv("NFT_TABLE_NAME", "port_mgmt")
NFT_CHAIN_NAME = "input_filter"
NFT_CHAIN_PRIORITY = 0

DB_PATH = os.getenv("DB_PATH", "/data/mgmt.db")

# 初始放行端口：管理网页 + HTTP 回显服务
INITIAL_PORTS = sorted({WEB_PORT, ECHO_PORT})

MIN_PORT = 1
MAX_PORT = 65535

# 跨进程规则写协调锁文件：Web / 看护 / 修复三条写入路径互斥
RULE_WRITE_LOCK_PATH = os.getenv("RULE_WRITE_LOCK_PATH", "/data/rule_write.lock")

# 状态令牌 HMAC 密钥文件（不存在时自动生成并持久化，重启后旧令牌仍可校验）
STATE_TOKEN_KEY_PATH = os.getenv("STATE_TOKEN_KEY_PATH", "/data/token.key")

# 核查读取 nft 的超时（秒）：读取不得无限期阻塞应用
NFT_READ_TIMEOUT_SECONDS = float(os.getenv("NFT_READ_TIMEOUT_SECONDS", "8"))
# nft 写入超时（秒）
NFT_WRITE_TIMEOUT_SECONDS = float(os.getenv("NFT_WRITE_TIMEOUT_SECONDS", "10"))

# 核查/修复历史最多保留条数
AUDIT_HISTORY_LIMIT = int(os.getenv("AUDIT_HISTORY_LIMIT", "20"))
# 演示用：核查读取 nft 前注入的人工延迟（秒，0 关闭），用于演示
# “核查期间发生合法策略改变 -> 丢弃结果并重查”
AUDIT_SLOW_DELAY_SECONDS = float(os.getenv("AUDIT_SLOW_DELAY_SECONDS", "0"))
AUDIT_MAX_SLOW_DELAY = 30.0

# 演示用漂移注入开关（仅本地演示环境开启；生产应置为 0）
DEMO_INJECTION_ENABLED = os.getenv("DEMO_INJECTION_ENABLED", "1") not in (
    "0",
    "false",
    "False",
    "",
)
