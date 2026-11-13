#!/bin/sh
# 容器入口：四个角色协同
#   1) bootstrap：先恢复已确认规则（首次启动写初始白名单），再开放网页
#   2) watchdog：独立于 Web 的看护进程，超时未确认即回退；Web 退出后仍存活
#   3) echo    ：附带的 HTTP 回显服务
#   4) uvicorn ：FastAPI 管理网页
# 不使用 set -e：后台子进程的 wait 退出码需要逐个处理，避免误杀 PID 1。

echo "[entrypoint] 启动恢复：先恢复已确认 nftables 规则…"
python -u bootstrap.py || {
  echo "[entrypoint] 启动恢复失败，为避免无防火墙裸奔，容器终止" >&2
  exit 1
}

echo "[entrypoint] 启动独立看护进程 watchdog…"
python -u watchdog.py &
WD_PID=$!

echo "[entrypoint] 启动 HTTP 回显服务（端口 ${ECHO_PORT:-8090}）…"
python -u echo_server.py &
ECHO_PID=$!

echo "[entrypoint] 启动 FastAPI 管理网页（端口 ${WEB_PORT:-8080}）…"
python -u -m uvicorn main:app --host 0.0.0.0 --port "${WEB_PORT:-8080}" &
WEB_PID=$!

STOPPING=0
shutdown() {
  STOPPING=1
  echo "[entrypoint] 收到停止信号，终止全部子进程…"
  kill "$WEB_PID" "$ECHO_PID" "$WD_PID" 2>/dev/null
}
trap shutdown TERM INT

# 可中断睡眠：sleep 放后台，wait 会被 SIGTERM/SIGINT 打断并执行 trap
interruptible_sleep() {
  sleep "$1" &
  SP=$!
  wait "$SP" 2>/dev/null
}

# 关键语义：Web 退出（含崩溃）后不结束容器——独立看护进程仍须按原期限
# 完成超时回退，以完整演示“网页失联 -> 自动恢复”；docker stop 由 trap 收口。
WEB_EXITED=0
while [ "$STOPPING" -eq 0 ]; do
  if [ "$WEB_EXITED" -eq 0 ] && ! kill -0 "$WEB_PID" 2>/dev/null; then
    WEB_EXITED=1
    wait "$WEB_PID" 2>/dev/null
    echo "[entrypoint] Web 进程已退出（code=$?），watchdog 继续值守以保证超时回退（docker stop 可结束容器）"
  fi
  # 仅对已退出的子进程执行 wait 以回收僵尸（kill -0 先确认，避免阻塞）
  if ! kill -0 "$ECHO_PID" 2>/dev/null; then wait "$ECHO_PID" 2>/dev/null; fi
  if ! kill -0 "$WD_PID" 2>/dev/null; then wait "$WD_PID" 2>/dev/null; fi
  interruptible_sleep 1
done

shutdown
interruptible_sleep 1
exit 0
