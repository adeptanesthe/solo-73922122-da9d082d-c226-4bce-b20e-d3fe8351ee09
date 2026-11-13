"""漂移注入工具（演示用，模拟“其他脚本”改写专用表）。

安全运维场景里，攻击者/其他脚本可能绕过本系统直接调用 ``nft`` 改写专用表。
本工具仅用于本地演示，**只动专用表 inet port_mgmt**，支持三种注入：

* ``extra-port <port>``：在现有链上追加一条额外的 tcp accept 放行（误放行）；
* ``delete-table``：直接删除整张专用表（缺表漂移）；
* ``tamper-policy``：重建表并把链策略改为 accept（链属性漂移，全放行）。

注意：这些写法都不经过本系统的写锁与 epoch，因此核查能通过
“真实表结构 vs 应生效策略”的比对发现漂移。
"""
from __future__ import annotations

import sys

from config import (
    NFT_CHAIN_NAME,
    NFT_CHAIN_PRIORITY,
    NFT_TABLE_FAMILY,
    NFT_TABLE_NAME,
)
import nft


def _run(ruleset: str) -> None:
    proc = nft._run_nft(  # 复用统一入口（含超时/可执行检查，测试可替换）
        ["-f", "-"],
        input_text=ruleset,
        timeout=nft.NFT_WRITE_TIMEOUT_SECONDS,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"漂移注入失败(exit={proc.returncode}): "
            f"{proc.stderr.strip() or proc.stdout.strip()}"
        )


def inject_extra_port(port: int) -> None:
    # 表必须已存在（由本系统 bootstrap 建立）；仅追加规则，模拟旁路误放行
    rule = (
        f"add rule {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {NFT_CHAIN_NAME} "
        f"tcp dport {int(port)} accept comment \"rogue extra allow {port}\""
    )
    _run(rule + "\n")
    print(f"[drift-inject] 已在专用表追加额外放行：tcp dport {port} accept")


def inject_delete_table() -> None:
    nft.delete_table()
    print("[drift-inject] 已删除专用表 inet port_mgmt（缺表漂移）")


def inject_tamper_policy() -> None:
    # 重建表但链策略改为 accept：链属性漂移，策略变为全放行
    ruleset = "\n".join(
        [
            f"destroy table {NFT_TABLE_FAMILY} {NFT_TABLE_NAME}",
            f"create table {NFT_TABLE_FAMILY} {NFT_TABLE_NAME}",
            (
                f"create chain {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {NFT_CHAIN_NAME} "
                f"{{ type filter hook input priority {NFT_CHAIN_PRIORITY}; policy accept; }}"
            ),
            (
                f"add rule {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {NFT_CHAIN_NAME} "
                f"iif lo accept comment \"rogue policy accept\""
            ),
        ]
    ) + "\n"
    _run(ruleset)
    print("[drift-inject] 已重建专用表并把链策略改为 accept（链属性漂移）")


def main(argv: list[str]) -> None:
    if len(argv) < 2:
        print(
            "用法: python drift_inject.py {extra-port <port>|delete-table|tamper-policy}",
            file=sys.stderr,
        )
        raise SystemExit(2)
    action = argv[1]
    if action == "extra-port":
        if len(argv) != 3:
            raise SystemExit("用法: python drift_inject.py extra-port <port>")
        inject_extra_port(int(argv[2]))
    elif action == "delete-table":
        inject_delete_table()
    elif action == "tamper-policy":
        inject_tamper_policy()
    else:
        raise SystemExit(f"未知动作: {action}")


if __name__ == "__main__":
    main(sys.argv)
