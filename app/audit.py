"""防火墙漂移核查与修复业务逻辑。

设计要点（对应安全语义）：

核查（:func:`run_check`）
* 只读，不获取规则写锁，因此**不会阻塞应用 / 确认 / 回退**；
* 读取**真实 nft 专用表**，比较链属性（type/hook/priority/policy）与
  **完整规则表达式结构**，忽略每条规则的 handle 与计数器计数值；
* 专用表缺失 -> ``missing_table``（漂移）；结构与期望不同 -> ``drift``（漂移）；
  nft 读取失败/超时/JSON 非法 -> ``unknown``（未知，不臆测）；
* 读取 nft 前后各读一次策略版本号 epoch，期间任何合法写入（应用/确认/
  回退/修复）都会使 epoch 变化，此时**丢弃本次结果并重查**，最多若干次，
  避免把“合法变更进行中”的瞬时不一致误判为漂移；
* 返回带 HMAC 签名的状态令牌，绑定核查时的 epoch 与 pending 状态。

修复（:func:`run_repair`）
* 必须携带核查返回的令牌；进入跨进程规则写锁后重新校验：
  epoch 变化、pending 状态变化（发生过应用/确认/回退）一律 **409 且不写规则**；
* 未变化才把规则恢复为“应生效策略”：
  - 无 pending：恢复已确认基线；
  - 有 pending：恢复该单请求的规则，**保留原变更单与原截止时间**；
* 写入后重新读取真实表核实，核实不过**绝不报已恢复**（返回 error）；
* 只重建专用表 ``inet port_mgmt``，不触碰其他表，也不改写已确认基线数据。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Any

import coordination
import db
import nft
import config

# 核查期间检测到合法变更后的最大重查次数（避免活锁无限循环）
MAX_CHECK_ATTEMPTS = 5


class AuditError(RuntimeError):
    """核查/修复失败（读取类，结果为未知或内部错误）。"""


class RepairConflict(RuntimeError):
    """修复绑定的策略状态已失效（对应 HTTP 409），不写任何规则。"""


class RepairVerifyError(RuntimeError):
    """规则已写入但重新读取核实失败（不得报已恢复）。"""


# 核查结果常量
IN_SYNC = "in_sync"
DRIFT = "drift"
MISSING_TABLE = "missing_table"
UNKNOWN = "unknown"


@dataclass
class ExpectedPolicy:
    """某个时刻“应生效”的策略。"""

    ports: list[int]
    # 绑定的 pending 变更单 id（无 pending 为 None）
    pending_id: int | None
    pending_expires_at: float | None
    # 人类可读来源
    source: str


def _load_token_key() -> bytes:
    """加载（或首次生成并持久化）状态令牌 HMAC 密钥。"""
    key_path = config.STATE_TOKEN_KEY_PATH
    os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
    if os.path.exists(key_path):
        with open(key_path, "rb") as fh:
            key = fh.read()
        if key:
            return key
    key = os.urandom(32)
    # 0600：仅运行用户可读写
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


def _sign(payload_b64: str) -> str:
    sig = hmac.new(_load_token_key(), payload_b64.encode("ascii"), hashlib.sha256)
    return base64.urlsafe_b64encode(sig.digest()).decode("ascii").rstrip("=")


def issue_token(claims: dict[str, Any]) -> str:
    """签发状态令牌：base64(claims).HMAC-SHA256（无状态、可验真、防篡改）。"""
    raw = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"{payload}.{_sign(payload)}"


def verify_token(token: str) -> dict[str, Any]:
    """验签并还原令牌 claims；非法/过期格式抛 :class:`RepairConflict`。"""
    try:
        payload_b64, sig = token.split(".", 1)
    except (ValueError, AttributeError) as exc:
        raise RepairConflict("状态令牌格式非法，请重新核查后再修复") from exc
    expected_sig = _sign(payload_b64)
    if not hmac.compare_digest(sig, expected_sig):
        raise RepairConflict("状态令牌签名无效（可能被篡改），请重新核查后再修复")
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    try:
        claims = json.loads(base64.b64decode(padded))
    except Exception as exc:
        raise RepairConflict("状态令牌内容无法解析，请重新核查") from exc
    return claims


def _binding_fingerprint(pending_row: dict[str, Any] | None) -> dict[str, Any]:
    """pending 绑定指纹：用于检测核查与修复之间是否发生过应用/确认/回退。"""
    if pending_row is None:
        return {"pending_id": None}
    return {
        "pending_id": pending_row["id"],
        "expires_at": pending_row["expires_at"],
        "requested_ports": json.loads(pending_row["requested_ports"]),
        "previous_ports": json.loads(pending_row["previous_ports"]),
    }


def _current_expected_policy() -> ExpectedPolicy:
    """计算当前“应生效”白名单及其绑定来源。"""
    pending = db.get_pending_change()
    if pending is not None:
        return ExpectedPolicy(
            ports=sorted(json.loads(pending["requested_ports"])),
            pending_id=pending["id"],
            pending_expires_at=pending["expires_at"],
            source=f"pending 变更单 #{pending['id']} 的请求白名单",
        )
    confirmed = db.get_confirmed_ports() or []
    return ExpectedPolicy(
        ports=sorted(confirmed),
        pending_id=None,
        pending_expires_at=None,
        source="已确认基线",
    )


def _slow_delay(slow_delay: float) -> None:
    """演示钩子：核查读 nft 前的人工可控延迟（默认关闭）。"""
    delay = min(max(0.0, slow_delay), config.AUDIT_MAX_SLOW_DELAY)
    if delay > 0:
        time.sleep(delay)


def run_check(slow_delay: float | None = None) -> dict[str, Any]:
    """执行一次漂移核查（只读、不持写锁、不阻塞写入路径）。

    返回完整核查结论，含可用于修复的 ``token``。
    """
    if slow_delay is None:
        slow_delay = config.AUDIT_SLOW_DELAY_SECONDS
    slow_delay = min(max(0.0, float(slow_delay)), config.AUDIT_MAX_SLOW_DELAY)
    attempts = 1
    started_at = time.time()
    epoch_before = coordination.current_epoch()

    while True:
        policy = _current_expected_policy()
        pending_row = db.get_pending_change()
        binding = _binding_fingerprint(pending_row)
        expected = nft.expected_snapshot(policy.ports)

        # 演示用可控延迟：放大“读取期间策略被合法改写”的时间窗
        _slow_delay(slow_delay)

        observed = None
        read_error: str | None = None
        try:
            observed = nft.read_table_snapshot()
        except nft.NftError as exc:
            read_error = str(exc)

        epoch_after = coordination.current_epoch()

        # 读取期间发生了合法策略改变（应用/确认/回退/修复）：
        # 丢弃本次结果，用新 epoch 重新核查
        if epoch_after != epoch_before:
            if attempts >= MAX_CHECK_ATTEMPTS:
                raise AuditError(
                    f"核查期间策略连续变化，已重查 {attempts} 次仍无法获得稳定快照，"
                    "请稍后再试"
                )
            attempts += 1
            epoch_before = epoch_after
            continue

        now = time.time()
        common = {
            "checked_at": now,
            "duration_ms": round((now - started_at) * 1000, 1),
            "attempts": attempts,
            "epoch": epoch_after,
            "expected_ports": policy.ports,
            "expected_source": policy.source,
            "pending_binding": binding,
        }

        if read_error is not None:
            result = UNKNOWN
            detail = f"真实 nft 表读取失败，无法判定是否漂移：{read_error}"
            observed_ports: list[int] = []
            diff: dict[str, Any] = {}
        elif observed is None:
            result = MISSING_TABLE
            detail = (
                f"专用表 inet port_mgmt 缺失（应含链 {nft.NFT_CHAIN_NAME}，"
                f"应放行 {policy.ports}）"
            )
            observed_ports = []
            diff = {"table_missing": True}
        else:
            observed_ports = nft.extract_tcp_accept_ports(observed)
            diff = nft.diff_snapshots(expected, observed)
            if diff:
                result = DRIFT
                extra = sorted(set(observed_ports) - set(policy.ports))
                missing = sorted(set(policy.ports) - set(observed_ports))
                detail = (
                    "真实规则结构与应生效策略不一致："
                    f"额外放行 TCP {extra or '无'}；缺少放行 TCP {missing or '无'}；"
                    f"结构差异 {len(json.dumps(diff, ensure_ascii=False))} 字符"
                )
            else:
                result = IN_SYNC
                detail = "专用表链属性与完整规则结构均与应生效策略一致"

        audit_id = db.insert_audit(
            kind="check",
            result=result,
            created_at=now,
            epoch_before=epoch_before,
            epoch_after=epoch_after,
            attempts=attempts,
            expected_ports=policy.ports,
            observed_ports=observed_ports,
            detail=detail,
        )

        token = issue_token(
            {
                "audit_id": audit_id,
                "epoch": epoch_after,
                "binding": binding,
                "expected_ports": policy.ports,
                "issued_at": now,
            }
        )
        return {
            **common,
            "audit_id": audit_id,
            "result": result,
            "is_drift": result in (DRIFT, MISSING_TABLE),
            "detail": detail,
            "observed_ports": observed_ports,
            "extra_allowed_ports": sorted(
                set(observed_ports) - set(policy.ports)
            ),
            "missing_allowed_ports": sorted(
                set(policy.ports) - set(observed_ports)
            ),
            "structural_diff": diff,
            "token": token,
        }


def run_repair(token: str) -> dict[str, Any]:
    """按核查令牌绑定的状态恢复应生效策略。

    任何绑定失效都抛 :class:`RepairConflict`（HTTP 409），且不写规则。
    """
    claims = verify_token(token)
    bound_epoch = claims.get("epoch")
    bound_binding = claims.get("binding")
    bound_ports = claims.get("expected_ports")
    audit_id = claims.get("audit_id")
    if not isinstance(bound_epoch, int) or not isinstance(bound_binding, dict):
        raise RepairConflict("状态令牌缺少绑定信息，请重新核查后再修复")

    with coordination.rule_write_lock():
        # 1. 策略版本号必须与核查时一致：任何应用/确认/回退/修复都会推进它
        current_epoch = coordination.current_epoch()
        if current_epoch != bound_epoch:
            raise RepairConflict(
                f"核查后策略已被合法路径改变（版本号 {bound_epoch} -> "
                f"{current_epoch}），为避免覆盖新策略，本次修复拒绝写入（409）。"
                "请重新核查后再修复"
            )

        # 2. pending 绑定必须一致（应用/确认/回退都会改变它）
        pending_row = db.get_pending_change()
        current_binding = _binding_fingerprint(pending_row)
        if current_binding != bound_binding:
            raise RepairConflict(
                "核查后待确认变更状态已变化（发生过应用、确认或回退），"
                "本次修复拒绝写入（409）。请重新核查后再修复"
            )

        # 2.5 令牌一次性消费：同一核查结果只能触发一次修复，防止重放
        if not db.consume_audit_token(audit_id):
            raise RepairConflict(
                "该核查令牌已被使用或不存在，修复令牌仅可消费一次（409）。"
                "请重新核查后再修复"
            )

        policy = _current_expected_policy()
        if sorted(policy.ports) != sorted(bound_ports):
            # 理论上 epoch 不变时不会发生，作为防御性兜底
            raise RepairConflict(
                "应生效策略与核查时不一致，本次修复拒绝写入（409），请重新核查"
            )

        # 3. 先再读一次真实表：若已经是期望结构，则无需写规则
        try:
            current_snapshot = nft.read_table_snapshot()
        except nft.NftError as exc:
            raise AuditError(f"修复前读取真实表失败，已放弃写入：{exc}") from exc

        expected_snapshot = nft.expected_snapshot(policy.ports)
        if (
            current_snapshot is not None
            and not nft.diff_snapshots(expected_snapshot, current_snapshot)
        ):
            now = time.time()
            db.insert_audit(
                kind="repair",
                result=IN_SYNC,
                created_at=now,
                epoch_before=current_epoch,
                epoch_after=current_epoch,
                expected_ports=policy.ports,
                observed_ports=nft.extract_tcp_accept_ports(current_snapshot),
                detail="修复前真实表已与应生效策略一致，无需写入",
            )
            return {
                "ok": True,
                "changed": False,
                "restored_ports": policy.ports,
                "pending_id": policy.pending_id,
                "pending_expires_at": policy.pending_expires_at,
                "epoch": current_epoch,
                "message": "真实规则已是应生效策略，无需修复",
            }

        # 4. 原子重建专用表（只动 inet port_mgmt，不触碰其他表/已确认基线）。
        # run_rule_write 与外层 rule_write_lock 基于可重入 RLock + 同进程
        # 可重入 flock：写入成功后才在同一临界区推进 epoch。
        def _write() -> None:
            nft.apply_ruleset(policy.ports)

        write_epoch = coordination.run_rule_write(_write)

        # 5. 写入后重新读取真实表核实；失败不得报已恢复
        try:
            verified_snapshot = nft.read_table_snapshot()
        except nft.NftError as exc:
            db.insert_audit(
                kind="repair",
                result="error",
                created_at=time.time(),
                epoch_before=current_epoch,
                epoch_after=write_epoch,
                expected_ports=policy.ports,
                observed_ports=[],
                detail=f"写入后重新读取核实失败，不能确认已恢复：{exc}",
            )
            raise RepairVerifyError(
                f"规则已下发但重新读取核实失败，不能确认已恢复：{exc}"
            ) from exc
        if verified_snapshot is None or nft.diff_snapshots(
            expected_snapshot, verified_snapshot
        ):
            db.insert_audit(
                kind="repair",
                result="error",
                created_at=time.time(),
                epoch_before=current_epoch,
                epoch_after=write_epoch,
                expected_ports=policy.ports,
                observed_ports=(
                    [] if verified_snapshot is None
                    else nft.extract_tcp_accept_ports(verified_snapshot)
                ),
                detail="写入后重新读取的结构与应生效策略仍不一致，不视为成功，需人工核查",
            )
            raise RepairVerifyError(
                "规则已下发但重新读取的结构与应生效策略仍不一致，"
                "本次修复不视为成功，请人工检查专用表"
            )

        now = time.time()
        observed_ports = nft.extract_tcp_accept_ports(verified_snapshot)
        db.insert_audit(
            kind="repair",
            result="repaired",
            created_at=now,
            epoch_before=current_epoch,
            epoch_after=write_epoch,
            expected_ports=policy.ports,
            observed_ports=observed_ports,
            detail=(
                f"已恢复应生效策略（来源：{policy.source}），写入后重新读取核实通过；"
                + (
                    f"保留 pending 变更单 #{policy.pending_id} 及原截止时间"
                    if policy.pending_id is not None
                    else "当前无待确认变更，恢复的是已确认基线"
                )
            ),
        )
        return {
            "ok": True,
            "changed": True,
            "restored_ports": policy.ports,
            "pending_id": policy.pending_id,
            "pending_expires_at": policy.pending_expires_at,
            "epoch": write_epoch,
            "verified": True,
            "message": (
                f"已恢复应生效策略 {policy.ports} 并经真实表复核通过；"
                + (
                    f"待确认变更单 #{policy.pending_id} 与原截止时间保持不变"
                    if policy.pending_id is not None
                    else "已确认基线未被改写"
                )
            ),
        }
