"""规则写入的跨进程协调与策略版本号管理。

三条会写 nft 规则的路径共用同一条互斥通道：

1. Web 的“应用 / 确认”（firewall.py）；
2. 独立看护进程的超时“回退”（firewall.rollback_expired，watchdog 调用）；
3. 新增的“漂移修复”（audit.py）。

协调手段：

* ``fcntl.flock`` 排他文件锁——跨 Web / 看护两个 OS 进程互斥，
  锁文件放在持久化数据目录；同一进程内也用可重入 ``threading.RLock``
  串行化，避免线程间交错。
* 每次成功的规则写入都把 SQLite 中的策略版本号（epoch）原子 +1。
  核查在读取 nft 前后各读一次 epoch：读取期间任何合法写入都会让
  epoch 变化，核查结果即作废并重查。
* 修复持锁后再次比对 epoch 与 pending 绑定，状态已变则 409 且不写规则。

锁只保护“规则写入 + epoch 推进”这一临界区；nft 的只读核查不持写锁，
因此核查不会阻塞应用/确认/回退。
"""
from __future__ import annotations

import contextlib
import fcntl
import os
import threading
from collections.abc import Iterator
from typing import Callable, TypeVar

import db
import config

T = TypeVar("T")

# 进程内可重入锁：同一线程可嵌套（如 confirm 内部的竞争兜底路径）
_in_process_lock = threading.RLock()
_lock_file_handle = None
_lock_file_path: str | None = None


def _ensure_lock_file():
    """惰性打开锁文件；路径变化（测试场景）时重新打开。"""
    global _lock_file_handle, _lock_file_path
    path = config.RULE_WRITE_LOCK_PATH
    if _lock_file_handle is None or _lock_file_path != path:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        # 以追加方式打开并保持句柄，flock 生命周期跟随句柄
        _lock_file_handle = open(path, "a+")
        _lock_file_path = path
    return _lock_file_handle


@contextlib.contextmanager
def rule_write_lock() -> Iterator[None]:
    """获取跨进程排他规则写锁（阻塞获取，锁内操作应尽量短）。"""
    with _in_process_lock:
        fh = _ensure_lock_file()
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def current_epoch() -> int:
    return db.get_policy_epoch()


def bump_epoch() -> int:
    return db.bump_policy_epoch()


def run_rule_write(write_fn: Callable[[], T]) -> T:
    """在跨进程写锁内执行 nft 写入；写入成功后推进策略版本号。

    ``write_fn`` 抛错时不推进 epoch（规则未被本路径改变），异常原样上抛。
    """
    with rule_write_lock():
        result = write_fn()
        bump_epoch()
        return result
