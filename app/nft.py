"""nftables 适配层。

约束：
* 只操作容器内专用表 ``inet port_mgmt``，不使用宿主网络，不触碰其他任何表；
* 整条规则集通过一次 ``nft -f`` 原子批量提交：成功即整体生效，
  失败则旧规则原样保留（内核事务语义），满足“应用失败保留旧规则”；
* 链策略为 drop，白名单之外的非回环入站 TCP（含已有连接）一律被丢弃；
  非 TCP 的已建立/关联连接（如 UDP DNS 应答）放行，保证容器基础网络可用。

核查相关只读能力：
* :func:`read_table_snapshot` 以 ``nft -j`` 读取真实专用表的结构化 JSON，
  表不存在返回 ``None``，其他读取失败抛 :class:`NftError`（上层报“未知”）；
* :func:`canonicalize_snapshot` 把 JSON 归一成可比较的结构，
  递归剔除 handle 与计数器计数值（packets/bytes），只保留链属性与规则结构；
* :func:`expected_snapshot` 用与实际下发规则同源的内置模板构造“应生效”
  规则结构（跨 nft 版本确定）；``nft --check --echo`` 路径保留用于测试交叉验证。
"""
from __future__ import annotations

import copy
import json
import shutil
import subprocess

from config import (
    NFT_CHAIN_NAME,
    NFT_CHAIN_PRIORITY,
    NFT_READ_TIMEOUT_SECONDS,
    NFT_TABLE_FAMILY,
    NFT_TABLE_NAME,
    NFT_WRITE_TIMEOUT_SECONDS,
)

# 缺表时 nft 报错的典型片段（跨版本兼容匹配，小写比较）
_MISSING_TABLE_MARKERS = (
    "no such file or directory",
    "no such table",
    "does not exist",
    "could not fetch table",
)


class NftError(RuntimeError):
    """nftables 命令执行失败（读取失败时上层应判为“未知”，而不是漂移）。"""


class NftTableMissing(NftError):
    """专用表不存在（结构漂移的一种：缺表）。"""


def ensure_nft_available() -> None:
    if shutil.which("nft") is None:
        raise NftError(
            "容器内找不到 nft 可执行文件，请确认镜像已安装 nftables 且以 "
            "NET_ADMIN（及 NET_RAW）能力启动"
        )


def _run_nft(
    args: list[str],
    *,
    input_text: str | None = None,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    ensure_nft_available()
    try:
        return subprocess.run(
            ["nft", *args],
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise NftError(f"nft 执行超时（>{timeout:.0f}s），本次读取/写入结果未知") from exc
    except OSError as exc:  # 可执行文件缺失等
        raise NftError(f"nft 无法执行: {exc}") from exc


def render_ruleset(tcp_ports: list[int], table_name: str = NFT_TABLE_NAME) -> str:
    """根据 TCP 白名单生成原子规则集文本。

    ``destroy`` 与 ``create`` 在同一个批量事务中提交，中间不存在
    “无表”窗口；若批量中任何一句失败，整个事务回滚，旧规则不变。
    ``table_name`` 可替换为临时表名（仅供 ``nft --check`` 构造期望结构）。
    """
    lines = [
        f"destroy table {NFT_TABLE_FAMILY} {table_name}",
        f"create table {NFT_TABLE_FAMILY} {table_name}",
        (
            f"create chain {NFT_TABLE_FAMILY} {table_name} {NFT_CHAIN_NAME} "
            f"{{ type filter hook input priority {NFT_CHAIN_PRIORITY}; policy drop; }}"
        ),
        # 回环接口全部放行
        f"add rule {NFT_TABLE_FAMILY} {table_name} {NFT_CHAIN_NAME} "
        f"iif lo accept comment \"loopback always allowed\"",
        # 非 TCP 的已建立/相关连接放行（UDP/ICMP 应答等，不影响 TCP 过滤语义）
        f"add rule {NFT_TABLE_FAMILY} {table_name} {NFT_CHAIN_NAME} "
        f"ct state established,related meta l4proto != tcp accept "
        f"comment \"non-tcp established traffic (e.g. dns replies)\"",
    ]
    for port in sorted(set(tcp_ports)):
        lines.append(
            f"add rule {NFT_TABLE_FAMILY} {table_name} {NFT_CHAIN_NAME} "
            f"tcp dport {port} accept comment \"whitelisted tcp {port}\""
        )
    # 链策略 drop 兜底：其余所有非回环入站（含 TCP 已有连接）均被丢弃
    return "\n".join(lines) + "\n"


def _check_only_ruleset(tcp_ports: list[int], scratch_table: str) -> str:
    """只含 create/add 的规则集（无 destroy），供 nft --check 解析期望结构。"""
    lines = [
        f"create table {NFT_TABLE_FAMILY} {scratch_table}",
        (
            f"create chain {NFT_TABLE_FAMILY} {scratch_table} {NFT_CHAIN_NAME} "
            f"{{ type filter hook input priority {NFT_CHAIN_PRIORITY}; policy drop; }}"
        ),
        f"add rule {NFT_TABLE_FAMILY} {scratch_table} {NFT_CHAIN_NAME} iif lo accept",
        (
            f"add rule {NFT_TABLE_FAMILY} {scratch_table} {NFT_CHAIN_NAME} "
            f"ct state established,related meta l4proto != tcp accept"
        ),
    ]
    for port in sorted(set(tcp_ports)):
        lines.append(
            f"add rule {NFT_TABLE_FAMILY} {scratch_table} {NFT_CHAIN_NAME} "
            f"tcp dport {port} accept"
        )
    return "\n".join(lines) + "\n"


def apply_ruleset(tcp_ports: list[int]) -> None:
    """原子应用白名单规则；失败抛 NftError，旧规则保持不变。

    调用方（firewall/audit/bootstrap）负责在跨进程写锁内调用并推进 epoch。
    """
    ruleset = render_ruleset(tcp_ports)
    proc = _run_nft(
        ["-f", "-"], input_text=ruleset, timeout=NFT_WRITE_TIMEOUT_SECONDS
    )
    if proc.returncode != 0:
        raise NftError(
            f"nft 应用失败(exit={proc.returncode}): "
            f"{proc.stderr.strip() or proc.stdout.strip()}"
        )


# ---------------------------------------------------------------------------
# 结构化读取与归一
# ---------------------------------------------------------------------------

def _clean_node(node):
    """递归剔除句柄与计数器计数值。

    * 任何层级的 ``handle`` 都删掉（规则/表/链句柄随每次重建变化，无结构意义）；
    * ``counter`` 只保留“存在计数器”这一结构事实，删除 packets/bytes 计数值；
    * 其余键原样保留，从而比较完整的表达式结构与链属性。
    """
    if isinstance(node, dict):
        cleaned = {}
        for key, value in node.items():
            if key == "handle":
                continue
            if key == "counter" and isinstance(value, dict):
                cleaned[key] = {}  # 忽略 packets/bytes，仅保留计数器结构本身
                continue
            cleaned[key] = _clean_node(value)
        return cleaned
    if isinstance(node, list):
        return [_clean_node(item) for item in node]
    return node


# 归一后链对象保留的属性（链结构比较范围）
_CHAIN_ATTRS = ("name", "type", "hook", "priority", "policy", "family", "table")


def canonicalize_snapshot(nf_json: dict) -> dict:
    """把 ``nft -j list table`` 的原始 JSON 归一成可比较的稳定结构。

    返回::

        {"family", "name",
         "chains": [{"name","type","hook","priority","policy",
                     "rules": [<归一后的 expr 列表>, ...]}, ...]}

    表/链按名字排序；规则保持内核中的顺序（顺序即规则结构的一部分）；
    注释不参与结构比较（不影响放行语义）。
    """
    items = nf_json.get("nftables", [])
    table_info = None
    chains: dict[str, dict] = {}

    for item in items:
        if "table" in item and table_info is None:
            t = _clean_node(item["table"])
            table_info = {"family": t.get("family"), "name": t.get("name")}
        elif "chain" in item:
            c = _clean_node(item["chain"])
            name = c.get("name")
            chains[name] = {
                attr: c.get(attr)
                for attr in _CHAIN_ATTRS
                if attr in c and attr not in ("family", "table")
            } | {"rules": []}
        elif "rule" in item:
            r = _clean_node(item["rule"])
            chain_name = r.get("chain")
            chains.setdefault(
                chain_name, {"name": chain_name, "rules": []}
            )["rules"].append(copy.deepcopy(r.get("expr", [])))

    if table_info is None:  # 兼容只有 chain/rule 的异常输出
        table_info = {"family": NFT_TABLE_FAMILY, "name": NFT_TABLE_NAME}

    return {
        "family": table_info["family"],
        "name": table_info["name"],
        "chains": [chains[key] for key in sorted(chains)],
    }


def read_table_snapshot() -> dict | None:
    """读取真实专用表的归一结构。

    * 表不存在 -> 返回 ``None``（上层判定为“缺表漂移”）；
    * nft 执行失败/超时/JSON 解析失败 -> 抛 :class:`NftError`（上层判定“未知”）；
    * 成功 -> 返回归一后的结构（已剔除 handle 与计数器计数值）。
    """
    proc = _run_nft(
        ["-j", "list", "table", NFT_TABLE_FAMILY, NFT_TABLE_NAME],
        timeout=NFT_READ_TIMEOUT_SECONDS,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").lower()
        if any(marker in err for marker in _MISSING_TABLE_MARKERS):
            return None
        raise NftError(
            f"nft 读取失败(exit={proc.returncode}): "
            f"{proc.stderr.strip() or proc.stdout.strip()}"
        )
    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise NftError(f"nft 输出不是合法 JSON，无法核查: {exc}") from exc
    return canonicalize_snapshot(raw)


def _expected_from_nft_check(tcp_ports: list[int]) -> dict | None:
    """通过 nft --check --echo -j 构造期望结构（只读检查，不提交内核）。"""
    scratch = f"__nft_audit_check_{NFT_TABLE_NAME}"
    proc = _run_nft(
        ["-j", "--echo", "--check", "-f", "-"],
        input_text=_check_only_ruleset(tcp_ports, scratch),
        timeout=NFT_WRITE_TIMEOUT_SECONDS,
    )
    if proc.returncode != 0:
        return None
    try:
        snap = canonicalize_snapshot(json.loads(proc.stdout))
    except json.JSONDecodeError:
        return None
    # 临时表名替换回真实表名（结构与表名无关，归一后统一名称）
    snap["name"] = NFT_TABLE_NAME
    for chain in snap["chains"]:
        chain.pop("family", None)
        chain.pop("table", None)
    return snap


def _expected_from_templates(tcp_ports: list[int]) -> dict:
    """内置期望模板：与 render_ruleset 生成的三条基础规则逐一对齐。

    表达式结构按 nftables JSON 词法手工构造，再经过同一套归一逻辑，
    作为 ``nft --check --echo`` 不可用时的回退。
    """
    def rule_loopback() -> list:
        return [
            {
                "match": {
                    "op": "==",
                    "left": {"meta": {"key": "iifname"}},
                    "right": "lo",
                }
            },
            {"accept": None},
        ]

    def rule_non_tcp_established() -> list:
        return [
            {
                "match": {
                    "op": "==",
                    "left": {"ct": {"key": "state"}},
                    "right": [{"ct": "established"}, {"ct": "related"}],
                }
            },
            {
                "match": {
                    "op": "!=",
                    "left": {"meta": {"key": "l4proto"}},
                    "right": "tcp",
                }
            },
            {"accept": None},
        ]

    def rule_tcp_accept(port: int) -> list:
        return [
            {
                "match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": port,
                }
            },
            {"accept": None},
        ]

    rules = [rule_loopback(), rule_non_tcp_established()]
    rules.extend(rule_tcp_accept(p) for p in sorted(set(tcp_ports)))
    pseudo = {
        "nftables": [
            {"table": {"family": NFT_TABLE_FAMILY, "name": NFT_TABLE_NAME, "handle": 0}},
            {
                "chain": {
                    "family": NFT_TABLE_FAMILY,
                    "table": NFT_TABLE_NAME,
                    "name": NFT_CHAIN_NAME,
                    "handle": 0,
                    "type": "filter",
                    "hook": "input",
                    "priority": NFT_CHAIN_PRIORITY,
                    "policy": "drop",
                }
            },
            *[
                {
                    "rule": {
                        "family": NFT_TABLE_FAMILY,
                        "table": NFT_TABLE_NAME,
                        "chain": NFT_CHAIN_NAME,
                        "handle": idx + 1,
                        "expr": expr,
                    }
                }
                for idx, expr in enumerate(rules)
            ],
        ]
    }
    return canonicalize_snapshot(pseudo)


def expected_snapshot(tcp_ports: list[int]) -> dict:
    """构造白名单 ``tcp_ports`` 对应的期望归一结构。

    以内置模板为权威来源：它与 :func:`render_ruleset` 实际下发的规则同源、
    跨 nft 版本确定，避免 ``--check --echo`` 与 ``list table`` 两种输出
    词法差异导致的误判。``nft --check`` 路径保留在测试中用于交叉验证
    两套构造逻辑的等价性。
    """
    return _expected_from_templates(tcp_ports)


def extract_tcp_accept_ports(snapshot: dict) -> list[int]:
    """从归一结构中提取所有 ``tcp dport N accept`` 规则的端口（实际放行集）。"""
    ports: set[int] = set()
    for chain in snapshot.get("chains", []):
        for expr in chain.get("rules", []):
            port = _match_tcp_dport_accept(expr)
            if port is not None:
                ports.add(port)
    return sorted(ports)


def _match_tcp_dport_accept(expr: list) -> int | None:
    has_accept = False
    port = None
    for node in expr:
        if isinstance(node, dict) and "accept" in node:
            has_accept = True
        if isinstance(node, dict) and "match" in node:
            m = node["match"]
            left = m.get("left") if isinstance(m, dict) else None
            if (
                isinstance(left, dict)
                and isinstance(left.get("payload"), dict)
                and left["payload"].get("protocol") == "tcp"
                and left["payload"].get("field") == "dport"
                and m.get("op") == "=="
                and isinstance(m.get("right"), int)
            ):
                port = int(m["right"])
    return port if has_accept and port is not None else None


def diff_snapshots(expected: dict, observed: dict) -> dict:
    """比较两个归一结构，返回结构化差异（空差异表示一致）。"""
    diffs: dict[str, list] = {
        "missing_chains": [],
        "unexpected_chains": [],
        "chain_attribute_drifts": [],
        "missing_rules": [],
        "unexpected_rules": [],
    }
    exp_chains = {c["name"]: c for c in expected.get("chains", [])}
    obs_chains = {c["name"]: c for c in observed.get("chains", [])}

    for name in exp_chains.keys() - obs_chains.keys():
        diffs["missing_chains"].append(name)
    for name in obs_chains.keys() - exp_chains.keys():
        diffs["unexpected_chains"].append(name)

    for name in exp_chains.keys() & obs_chains.keys():
        exp_c, obs_c = exp_chains[name], obs_chains[name]
        for attr in ("type", "hook", "priority", "policy"):
            if exp_c.get(attr) != obs_c.get(attr):
                diffs["chain_attribute_drifts"].append(
                    {
                        "chain": name,
                        "attribute": attr,
                        "expected": exp_c.get(attr),
                        "observed": obs_c.get(attr),
                    }
                )
        exp_rules = [json.dumps(r, sort_keys=True) for r in exp_c.get("rules", [])]
        obs_rules = [json.dumps(r, sort_keys=True) for r in obs_c.get("rules", [])]
        # 多重集比较：同一结构规则出现次数不同也算漂移
        exp_counts = {r: exp_rules.count(r) for r in set(exp_rules)}
        obs_counts = {r: obs_rules.count(r) for r in set(obs_rules)}
        for rule, cnt in exp_counts.items():
            extra = cnt - obs_counts.get(rule, 0)
            for _ in range(max(0, extra)):
                diffs["missing_rules"].append(json.loads(rule))
        for rule, cnt in obs_counts.items():
            extra = cnt - exp_counts.get(rule, 0)
            for _ in range(max(0, extra)):
                diffs["unexpected_rules"].append(json.loads(rule))

    return {k: v for k, v in diffs.items() if v}


def list_active_rules() -> list[str]:
    """返回专用表当前生效的规则行（用于状态页展示）。"""
    proc = _run_nft(
        ["-n", "-a", "list", "chain", NFT_TABLE_FAMILY, NFT_TABLE_NAME, NFT_CHAIN_NAME],
        timeout=NFT_READ_TIMEOUT_SECONDS,
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
    """删除专用表（仅用于清理/测试/演示缺表场景）。"""
    ensure_nft_available()
    proc = _run_nft(
        ["delete", "table", NFT_TABLE_FAMILY, NFT_TABLE_NAME],
        timeout=NFT_WRITE_TIMEOUT_SECONDS,
    )
    if proc.returncode != 0 and "No such file or directory" not in proc.stderr:
        raise NftError(proc.stderr.strip())
