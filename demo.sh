#!/usr/bin/env bash
# 端到端演示脚本（在能访问已发布端口的机器上运行，容器宿主即可）
# 用法: ./demo.sh
set -u
WEB="${WEB:-http://127.0.0.1:8080}"
ECHO="${ECHO:-http://127.0.0.1:8090}"
WINDOW="${WINDOW:-30}"

hr() { printf '\n========== %s ==========\n' "$1"; }

hr "0. 初始状态：网页与回显服务均在白名单内"
curl -s "$WEB/api/config"; echo
curl -s "$WEB/api/status" | python3 -m json.tool | sed -n '1,20p'
curl -s "$ECHO/hello" | head -5

hr "1. 应用新白名单（仅回显端口 8090，移除网页端口 8080）——模拟误封管理网页"
APPLY=$(curl -s -X POST "$WEB/api/apply" -H 'Content-Type: application/json' -d '{"ports":[8090]}')
echo "$APPLY" | python3 -m json.tool
CID=$(echo "$APPLY" | python3 -c 'import sys,json;print(json.load(sys.stdin)["change_id"])')

hr "2. 规则已生效：网页失联（2 秒超时即失败），回显服务仍可通"
curl -s --max-time 2 "$WEB/api/status" && echo "网页仍可访问（异常）" || echo ">>> 网页已失联（预期行为）"
curl -s --max-time 3 "$ECHO/hello" | head -3

hr "3. 等待看护进程在 ${WINDOW}s 窗口到期后自动回退（多等 3 秒）…"
sleep $((WINDOW + 3))

hr "4. 网页自动恢复访问，白名单回到应用前快照"
curl -s "$WEB/api/status" | python3 -m json.tool | sed -n '1,12p'

hr "5. 再来一次并在窗口内确认（演示确认保留）"
APPLY=$(curl -s -X POST "$WEB/api/apply" -H 'Content-Type: application/json' -d '{"ports":[8080,8090,9000]}')
CID=$(echo "$APPLY" | python3 -c 'import sys,json;print(json.load(sys.stdin)["change_id"])')
echo "变更单 #$CID 已应用，立即确认："
curl -s -X POST "$WEB/api/confirm" -H 'Content-Type: application/json' \
  -d "{\"change_id\":$CID}" | python3 -m json.tool

hr "6. 待确认期间拒绝新变更 / 旧单确认无效 的校验"
curl -s -X POST "$WEB/api/apply" -H 'Content-Type: application/json' -d '{"ports":[22]}' | python3 -m json.tool
curl -s -X POST "$WEB/api/confirm" -H 'Content-Type: application/json' -d "{\"change_id\":$CID}" | python3 -m json.tool

hr "完成。浏览器打开 $WEB 可使用图形界面重复以上流程。"
