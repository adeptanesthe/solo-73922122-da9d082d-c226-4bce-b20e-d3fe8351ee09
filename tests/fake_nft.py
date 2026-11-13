"""内存假 nft 后端：仅用于单元/集成测试，不触碰真实内核。

通过 monkeypatch 替换 ``nft._run_nft``，模拟一个仅含专用表的 nftables
状态机，支持：
* ``-f -`` 规则集文本提交（destroy/create table/chain、add rule）；
* ``-j list table`` 结构化 JSON 读取（表不存在按真实 nft 报错）；
* ``-n -a list chain`` 文本读取；
* ``delete table``；
* ``-j --echo --check -f -`` 期望结构回显（不修改状态）；
以及测试专用的“旁路漂移注入”（不经过锁/epoch，模拟其他脚本）。
"""
from __future__ import annotations

import copy
import json
import subprocess

import nft
from config import NFT_CHAIN_NAME, NFT_CHAIN_PRIORITY, NFT_TABLE_FAMILY, NFT_TABLE_NAME


class FakeNftError(RuntimeError):
    pass


class FakeNft:
    def __init__(self) -> None:
        # tables: name -> {"chain": {"policy","type","hook","priority",
        #                            "rules": [expr_list]}}
        self.tables: dict[str, dict] = {}
        self._handle = 0

    # -- 表达式构造（与 nftables JSON 词法对齐） ---------------------------
    @staticmethod
    def _expr_loopback() -> list:
        return [
            {"match": {"op": "==",
                       "left": {"meta": {"key": "iifname"}}, "right": "lo"}},
            {"accept": None},
        ]

    @staticmethod
    def _expr_non_tcp_established() -> list:
        return [
            {"match": {"op": "==",
                       "left": {"ct": {"key": "state"}},
                       "right": [{"ct": "established"}, {"ct": "related"}]}},
            {"match": {"op": "!=",
                       "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}},
            {"accept": None},
        ]

    @staticmethod
    def _expr_tcp_accept(port: int) -> list:
        return [
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                       "right": int(port)}},
            {"accept": None},
        ]

    def _next_handle(self) -> int:
        self._handle += 1
        return self._handle

    # -- 规则集文本解析（仅支持本系统生成的固定句式） ----------------------
    def _apply_ruleset_text(self, text: str) -> None:
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            tokens = line.split()
            if tokens[:2] == ["destroy", "table"]:
                self.tables.pop(tokens[3], None)
            elif tokens[:2] == ["create", "table"]:
                family, name = tokens[2], tokens[3]
                self.tables[name] = {"family": family, "chain": None}
            elif tokens[:2] == ["create", "chain"]:
                # create chain inet <table> <chain> { type filter hook input priority 0; policy drop; }
                tbl = tokens[3]
                chain_name = tokens[4]
                policy = "drop"
                if "policy accept" in line:
                    policy = "accept"
                self.tables[tbl]["chain"] = {
                    "name": chain_name,
                    "type": "filter",
                    "hook": "input",
                    "priority": NFT_CHAIN_PRIORITY,
                    "policy": policy,
                    "rules": [],
                }
            elif tokens[:2] == ["add", "rule"]:
                tbl = tokens[3]
                chain_name = tokens[4]
                rest = tokens[5:]
                expr = self._parse_rule_expr(rest)
                self.tables[tbl]["chain"]["rules"].append(expr)
            elif tokens[:2] == ["delete", "table"]:
                self.tables.pop(tokens[3], None)
            else:
                raise FakeNftError(f"假后端不支持的语句: {line}")

    def _parse_rule_expr(self, rest: list[str]) -> list:
        text = " ".join(rest)
        if text.startswith("iif lo accept"):
            return self._expr_loopback()
        if text.startswith("ct state established,related meta l4proto != tcp accept"):
            return self._expr_non_tcp_established()
        if text.startswith("tcp dport"):
            port = int(rest[2])
            return self._expr_tcp_accept(port)
        raise FakeNftError(f"假后端不支持的规则: {text}")

    # -- 序列化 -------------------------------------------------------------
    def _table_json(self, name: str, *, echo_style: bool = False) -> dict:
        tbl = self.tables[name]
        chain = tbl["chain"]
        out = [
            {"table": {"family": tbl["family"], "name": name,
                       "handle": self._next_handle()}},
            {"chain": {"family": tbl["family"], "table": name,
                       "name": chain["name"], "handle": self._next_handle(),
                       "type": chain["type"], "hook": chain["hook"],
                       "priority": chain["priority"], "policy": chain["policy"]}},
        ]
        for expr in chain["rules"]:
            out.append({"rule": {"family": tbl["family"], "table": name,
                                 "chain": chain["name"],
                                 "handle": self._next_handle(),
                                 "expr": copy.deepcopy(expr)}})
        return {"nftables": out}

    # -- subprocess 入口 ----------------------------------------------------
    def run(self, args, input_text=None, timeout=None, **_kw):
        args = list(args)
        json_mode = "-j" in args

        def completed(stdout="", stderr="", code=0):
            if json_mode and stdout:
                stdout = json.dumps(stdout)
            return subprocess.CompletedProcess(args, code, stdout, stderr)

        # 结构化读取：nft -j list table <family> <name>
        if "list" in args and "table" in args and json_mode:
            name = args[args.index("table") + 2]
            if name not in self.tables:
                return completed(
                    stderr=f"Error: Could not fetch table: {name}: "
                           "No such file or directory", code=1)
            return completed(self._table_json(name))

        # 文本读取（状态页）
        if "list" in args and "chain" in args:
            if NFT_TABLE_NAME not in self.tables:
                return completed(stderr="No such file or directory", code=1)
            return completed(stdout=self._text_chain_listing())

        # delete table
        if args[:2] == ["delete", "table"]:
            self.tables.pop(args[3], None)
            return completed()

        # 规则集提交 / check
        if "-f" in args and "-" in args:
            is_check = "--check" in args
            if is_check:
                # 回显期望结构但不落盘：用临时表模拟后丢弃
                scratch = "__nft_audit_check_" + NFT_TABLE_NAME
                saved = copy.deepcopy(self.tables)
                try:
                    self._apply_ruleset_text(input_text)
                    echo = self._table_json(scratch)
                finally:
                    self.tables = saved
                return completed(echo)
            self._apply_ruleset_text(input_text)
            return completed()

        return completed(stderr=f"假后端不支持的参数: {args}", code=1)

    def _text_chain_listing(self) -> str:
        tbl = self.tables[NFT_TABLE_NAME]
        chain = tbl["chain"]
        lines = [f"table {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {{",
                 f"  chain {chain['name']} {{",
                 f"    type filter hook input priority {NFT_CHAIN_PRIORITY}; "
                 f"policy {chain['policy']};"]
        for idx, _expr in enumerate(chain["rules"], start=1):
            lines.append(f"    rule ... # handle {idx}")
        lines.append("  }")
        lines.append("}")
        return "\n".join(lines) + "\n"

    # -- 测试专用旁路注入（模拟其他脚本，不走锁/epoch） ---------------------
    def rogue_add_extra_port(self, port: int) -> None:
        chain = self.tables[NFT_TABLE_NAME]["chain"]
        # 带计数器，验证归一会忽略 packets/bytes
        chain["rules"].append([
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                       "right": int(port)}},
            {"counter": {"packets": 12345, "bytes": 67890}},
            {"accept": None},
        ])

    def rogue_delete_table(self) -> None:
        self.tables.pop(NFT_TABLE_NAME, None)

    def rogue_change_policy_accept(self) -> None:
        self.tables[NFT_TABLE_NAME]["chain"]["policy"] = "accept"

    def make_read_fail(self, monkeypatch, message: str = "simulated nft failure"):
        """让后续真实读取调用抛 NftError（模拟读取失败 -> 未知）。"""
        original = self.run

        def flaky(args, **kwargs):
            if "list" in args and "table" in args:
                class Proc:
                    returncode = 1
                    stdout = ""
                    stderr = message
                return Proc()
            return original(args, **kwargs)

        monkeypatch.setattr(nft, "_run_nft", flaky)
