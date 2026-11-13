"""nftables 适配层。

约束：
* 只操作容器内专用表 ``inet port_mgmt``，不使用宿主网络，不触碰其他任何表；
* 整条规则集通过一次 ``nft -f`` 原子批量提交：成功即整体生效，
  失败则旧规则原样保留（内核事务语义），满足“应用失败保留旧规则”；
* 链策略为 drop，白名单之外的非回环入站 TCP（含已有连接）一律被丢弃；
  非 TCP 的已建立/关联连接（如 UDP DNS 应答）放行，保证容器基础网络可用。
"""
from __future__ import annotations

import shutil
import subprocess

from config import (
    NFT_CHAIN_NAME,
    NFT_CHAIN_PRIORITY,
    NFT_TABLE_FAMILY,
    NFT_TABLE_NAME,
)


class NftError(RuntimeError):
    """nftables 命令执行失败。"""


def ensure_nft_available() -> None:
    if shutil.which("nft") is None:
        raise NftError(
            "容器内找不到 nft 可执行文件，请确认镜像已安装 nftables 且以 "
            "NET_ADMIN（及 NET_RAW）能力启动"
        )


def render_ruleset(tcp_ports: list[int]) -> str:
    """根据 TCP 白名单生成原子规则集文本。

    ``destroy`` 与 ``create`` 在同一个批量事务中提交，中间不存在
    “无表”窗口；若批量中任何一句失败，整个事务回滚，旧规则不变。
    """
    lines = [
        f"destroy table {NFT_TABLE_FAMILY} {NFT_TABLE_NAME}",
        f"create table {NFT_TABLE_FAMILY} {NFT_TABLE_NAME}",
        (
            f"create chain {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {NFT_CHAIN_NAME} "
            f"{{ type filter hook input priority {NFT_CHAIN_PRIORITY}; policy drop; }}"
        ),
        # 回环接口全部放行
        f"add rule {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {NFT_CHAIN_NAME} "
        f"iif lo accept comment \"loopback always allowed\"",
        # 非 TCP 的已建立/相关连接放行（UDP/ICMP 应答等，不影响 TCP 过滤语义）
        f"add rule {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {NFT_CHAIN_NAME} "
        f"ct state established,related meta l4proto != tcp accept "
        f"comment \"non-tcp established traffic (e.g. dns replies)\"",
    ]
    for port in sorted(set(tcp_ports)):
        lines.append(
            f"add rule {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {NFT_CHAIN_NAME} "
            f"tcp dport {port} accept comment \"whitelisted tcp {port}\""
        )
    # 链策略 drop 兜底：其余所有非回环入站（含 TCP 已有连接）均被丢弃
    return "\n".join(lines) + "\n"


def apply_ruleset(tcp_ports: list[int]) -> None:
    """原子应用白名单规则；失败抛 NftError，旧规则保持不变。"""
    ensure_nft_available()
    ruleset = render_ruleset(tcp_ports)
    proc = subprocess.run(
        ["nft", "-f", "-"],
        input=ruleset,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise NftError(
            f"nft 应用失败(exit={proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
        )


def list_active_rules() -> list[str]:
    """返回专用表当前生效的规则行（用于状态页展示）。"""
    ensure_nft_available()
    proc = subprocess.run(
        [
            "nft", "-n", "-a",
            "list", "chain",
            NFT_TABLE_FAMILY,
            NFT_TABLE_NAME,
            NFT_CHAIN_NAME,
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        # 表尚不存在时返回非零，视为空规则集
        return []
    rules: list[str] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith(("table ", "chain ", "}")) or not line:
            continue
        rules.append(line)
    return rules


def delete_table() -> None:
    """删除专用表（仅用于清理/测试）。"""
    ensure_nft_available()
    proc = subprocess.run(
        ["nft", "delete", "table", NFT_TABLE_FAMILY, NFT_TABLE_NAME],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0 and "No such file or directory" not in proc.stderr:
        raise NftError(proc.stderr.strip())
