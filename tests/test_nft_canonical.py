"""nft 结构归一/差异比较的单元测试（不依赖数据库与写锁）。"""
from __future__ import annotations

import os
import sys

import pytest

APP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app"))
TESTS_DIR = os.path.dirname(__file__)
for path in (APP_DIR, TESTS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

import nft  # noqa: E402
from config import NFT_CHAIN_NAME, NFT_TABLE_FAMILY, NFT_TABLE_NAME  # noqa: E402
from fake_nft import FakeNft  # noqa: E402


def _raw_json(rules_expr, policy="drop"):
    return {
        "nftables": [
            {"table": {"family": NFT_TABLE_FAMILY, "name": NFT_TABLE_NAME,
                       "handle": 7}},
            {"chain": {"family": NFT_TABLE_FAMILY, "table": NFT_TABLE_NAME,
                       "name": NFT_CHAIN_NAME, "handle": 8, "type": "filter",
                       "hook": "input", "priority": 0, "policy": policy}},
            *[
                {"rule": {"family": NFT_TABLE_FAMILY, "table": NFT_TABLE_NAME,
                          "chain": NFT_CHAIN_NAME, "handle": 100 + idx,
                          "expr": expr,
                          "comment": f"rule {idx}"}}
                for idx, expr in enumerate(rules_expr)
            ],
        ]
    }


def test_canonicalize_ignores_handle_counter_and_comment():
    expr_with_counter = [
        {"match": {"op": "==",
                   "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                   "right": 22}},
        {"counter": {"packets": 999, "bytes": 8888}},
        {"accept": None},
    ]
    snap = nft.canonicalize_snapshot(_raw_json([expr_with_counter]))
    chain = snap["chains"][0]
    rule = chain["rules"][0]
    # handle 已剔除；counter 的 packets/bytes 已剔除，只保留空计数器结构
    assert all("handle" not in str(node) for node in rule)
    counter_node = next(n for n in rule if isinstance(n, dict) and "counter" in n)
    assert counter_node == {"counter": {}}
    # comment 不进入归一结构
    assert "comment" not in str(rule)
    # 链属性保留
    assert chain["policy"] == "drop" and chain["hook"] == "input"


def test_handle_difference_alone_is_in_sync():
    expr = FakeNft._expr_tcp_accept(8080)
    snap_a = nft.canonicalize_snapshot(_raw_json([expr]))
    snap_b = nft.canonicalize_snapshot(_raw_json([expr]))  # 重建后句柄不同
    assert nft.diff_snapshots(snap_a, snap_b) == {}


def test_extra_rule_and_missing_rule_detected():
    expected = nft.canonicalize_snapshot(_raw_json([
        FakeNft._expr_loopback(),
        FakeNft._expr_non_tcp_established(),
        FakeNft._expr_tcp_accept(8080),
    ]))
    observed = nft.canonicalize_snapshot(_raw_json([
        FakeNft._expr_loopback(),
        FakeNft._expr_non_tcp_established(),
        FakeNft._expr_tcp_accept(8080),
        FakeNft._expr_tcp_accept(22),  # 额外放行
    ]))
    diff = nft.diff_snapshots(expected, observed)
    assert len(diff["unexpected_rules"]) == 1
    assert diff["unexpected_rules"][0] == FakeNft._expr_tcp_accept(22)

    observed_missing = nft.canonicalize_snapshot(_raw_json([
        FakeNft._expr_loopback(),
        FakeNft._expr_tcp_accept(8080),  # 缺少 non-tcp established 规则
    ]))
    diff2 = nft.diff_snapshots(expected, observed_missing)
    assert len(diff2["missing_rules"]) == 1
    assert diff2["missing_rules"][0] == FakeNft._expr_non_tcp_established()


def test_chain_policy_attribute_drift():
    expected = nft.canonicalize_snapshot(
        _raw_json([FakeNft._expr_loopback()], policy="drop"))
    observed = nft.canonicalize_snapshot(
        _raw_json([FakeNft._expr_loopback()], policy="accept"))
    diff = nft.diff_snapshots(expected, observed)
    assert diff["chain_attribute_drifts"] == [
        {"chain": NFT_CHAIN_NAME, "attribute": "policy",
         "expected": "drop", "observed": "accept"}
    ]


def test_expected_template_matches_nft_check_path(monkeypatch):
    # --check --echo 路径（假后端）与内置模板回退必须产出同一归一结构
    fake = FakeNft()
    monkeypatch.setattr(nft, "_run_nft", fake.run)
    ports = [8080, 8090, 443]
    via_check = nft._expected_from_nft_check(ports)
    via_template = nft._expected_from_templates(ports)
    assert via_check is not None
    assert nft.diff_snapshots(via_check, via_template) == {}
    # expected_snapshot 对外结果同样一致
    assert nft.diff_snapshots(nft.expected_snapshot(ports), via_template) == {}


def test_template_fallback_when_check_unsupported(monkeypatch):
    # 模拟 nft --check 不可用（返回非零）：静默回退内置模板
    def failing_run(args, input_text=None, timeout=None, **_kw):
        class Proc:
            returncode = 1
            stdout = ""
            stderr = "check not supported"
        return Proc()

    monkeypatch.setattr(nft, "_run_nft", failing_run)
    snap = nft.expected_snapshot([8080])
    chain = snap["chains"][0]
    assert chain["policy"] == "drop"
    assert nft.extract_tcp_accept_ports(snap) == [8080]


def test_extract_tcp_accept_ports_ignores_non_accept_rules():
    # 带 counter 的放行规则仍能识别端口；非 tcp 规则不产生端口
    snap = nft.canonicalize_snapshot(_raw_json([
        FakeNft._expr_loopback(),
        FakeNft._expr_non_tcp_established(),
        [
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                       "right": 2222}},
            {"counter": {"packets": 1, "bytes": 2}},
            {"accept": None},
        ],
    ]))
    assert nft.extract_tcp_accept_ports(snap) == [2222]
