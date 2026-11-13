#!/usr/bin/env bash
# 漂移核查/修复端到端演示（在能访问已发布端口的机器上运行，容器宿主即可）
# 覆盖三个要求场景：
#   A. 缺表漂移      —— 其他脚本删除专用表 -> 核查 missing_table -> 修复重建
#   B. 额外放行漂移  —— 旁路追加 tcp dport 22 accept -> 核查 drift -> 修复清除
#   C. 可控慢核查    —— 核查期间发生合法应用 -> 结果被丢弃并重查（attempts=2）
# 另含修复 409 语义：核查后发生应用/确认/回退，修复拒绝写入。
set -u
WEB="${WEB:-http://127.0.0.1:8080}"
WINDOW="${WINDOW:-30}"
PY="${PYTHON:-python3}"

jget() { "$PY" -c "import sys,json;d=json.load(sys.stdin);print(eval('d$1'))"; }
hr() { printf '\n========== %s ==========\n' "$1"; }

hr "0. 初始状态：策略版本号与已确认白名单"
curl -s "$WEB/api/status" | "$PY" -m json.tool | sed -n '1,14p'

# ---------------------------------------------------------------------------
hr "场景 A：缺表漂移 —— 其他脚本删除专用表"
curl -s -X POST "$WEB/api/demo/inject" -H 'Content-Type: application/json' \
  -d '{"action":"delete-table"}' | "$PY" -m json.tool
CHECK_A=$(curl -s -X POST "$WEB/api/audit/check" -H 'Content-Type: application/json' -d '{"slow_delay":0}')
echo "$CHECK_A" | "$PY" -m json.tool | sed -n '1,12p'
echo "$CHECK_A" | jget "['result']" | grep -q missing_table \
  && echo ">>> 正确识别为缺表漂移" || echo "!!! 未识别缺表"
TOKEN_A=$(echo "$CHECK_A" | jget "['token']")
curl -s -X POST "$WEB/api/audit/repair" -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN_A\"}" | "$PY" -m json.tool
curl -s -X POST "$WEB/api/audit/check" -H 'Content-Type: application/json' -d '{}' \
  | jget "['result']" | grep -q in_sync && echo ">>> 修复后复核一致"

# ---------------------------------------------------------------------------
hr "场景 B：额外放行漂移 —— 旁路追加 tcp dport 22 accept（误放行）"
curl -s -X POST "$WEB/api/demo/inject" -H 'Content-Type: application/json' \
  -d '{"action":"extra-port","port":22}' | "$PY" -m json.tool
CHECK_B=$(curl -s -X POST "$WEB/api/audit/check" -H 'Content-Type: application/json' -d '{}')
echo "$CHECK_B" | "$PY" -m json.tool | sed -n '1,16p'
echo "$CHECK_B" | jget "['result']" | grep -q drift && echo ">>> 正确识别为结构漂移"
echo "$CHECK_B" | jget "['extra_allowed_ports']" | grep -q 22 && echo ">>> 正确定位额外放行 TCP 22"
TOKEN_B=$(echo "$CHECK_B" | jget "['token']")
curl -s -X POST "$WEB/api/audit/repair" -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN_B\"}" | "$PY" -m json.tool
CHECK_B2=$(curl -s -X POST "$WEB/api/audit/check" -H 'Content-Type: application/json' -d '{}')
echo "$CHECK_B2" | jget "['result']" | grep -q in_sync && echo ">>> 修复后误放行已清除且复核一致"

# ---------------------------------------------------------------------------
hr "场景 C：可控慢核查 —— 读取期间发生合法应用，结果丢弃并重查"
# 先制造一个漂移，慢核查给 6 秒窗口；在第 2 秒由合法路径应用新白名单（会推进版本号）
curl -s -X POST "$WEB/api/demo/inject" -H 'Content-Type: application/json' \
  -d '{"action":"extra-port","port":2222}' >/dev/null
(
  sleep 2
  echo ">>> 慢核查进行中，提交一次合法应用（推进策略版本号）…"
  curl -s -X POST "$WEB/api/apply" -H 'Content-Type: application/json' \
    -d '{"ports":[8080,8090,9000]}' | "$PY" -m json.tool | sed -n '1,8p'
) &
APPLY_BG=$!
CHECK_C=$(curl -s -X POST "$WEB/api/audit/check" -H 'Content-Type: application/json' \
  -d '{"slow_delay":6}')
wait "$APPLY_BG"
echo "$CHECK_C" | "$PY" -m json.tool | sed -n '1,14p'
ATTEMPTS=$(echo "$CHECK_C" | jget "['attempts']")
[ "$ATTEMPTS" = "2" ] && echo ">>> 第一次结果被丢弃，自动重查（attempts=$ATTEMPTS），结论反映新策略" \
  || echo "!!! 重查次数异常: $ATTEMPTS"
# 清理 pending：立即确认，避免影响后续演示
CID=$(curl -s "$WEB/api/status" | jget "['pending']['id']")
curl -s -X POST "$WEB/api/confirm" -H 'Content-Type: application/json' \
  -d "{\"change_id\":$CID}" | "$PY" -m json.tool | sed -n '1,6p'

# ---------------------------------------------------------------------------
hr "场景 D：修复绑定状态失效 —— 核查后发生应用，修复返回 409 且不写规则"
curl -s -X POST "$WEB/api/demo/inject" -H 'Content-Type: application/json' \
  -d '{"action":"extra-port","port":3333}' >/dev/null
TOKEN_D=$(curl -s -X POST "$WEB/api/audit/check" -H 'Content-Type: application/json' -d '{}' \
  | jget "['token']")
curl -s -X POST "$WEB/api/apply" -H 'Content-Type: application/json' \
  -d '{"ports":[8080,8090,7000]}' >/dev/null
echo "--- 对过期令牌发起修复（预期 HTTP 409）："
curl -s -o /tmp/repair_409.json -w "HTTP %{http_code}\n" -X POST \
  "$WEB/api/audit/repair" -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN_D\"}"
cat /tmp/repair_409.json | "$PY" -m json.tool
# 等待自动回退，恢复演示前白名单
echo ">>> 等待 ${WINDOW}s 确认窗口到期由看护进程回退…"
sleep $((WINDOW + 3))
curl -s "$WEB/api/status" | jget "['confirmed_ports']"

hr "完成。浏览器打开 $WEB 可在“防火墙漂移核查与修复”卡片重复以上全部操作。"
