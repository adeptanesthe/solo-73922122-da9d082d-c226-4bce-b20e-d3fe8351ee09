# 入站端口白名单变更管理（FastAPI + SQLite + nftables）

面向远程运维场景：调整入站端口白名单时，如果误封了管理网页自身，系统会在确认窗口
（默认 30 秒）到期后由**独立于 Web 的看护进程**自动恢复旧规则，无需登录宿主操作。

此外提供**防火墙漂移核查与修复**：安全运维人员可发现“其他脚本”旁路改写专用表造成的
误放行/缺表/链属性篡改，并在网页上把规则恢复为应生效策略。

## 架构与边界

```
容器（独立网络命名空间，不使用 network_mode: host）
├── bootstrap.py     入口恢复：先恢复“已确认规则”，再开放网页
├── nft.py           nftables 适配：仅操作专用表 inet port_mgmt，原子批量提交；
│                    nft -j 结构化读取、归一（忽略 handle/计数器）、结构差异比较
├── coordination.py  跨进程规则写锁（flock）+ 策略版本号 epoch
├── firewall.py      变更业务：应用 / 确认 / 超时回退
├── audit.py         漂移核查（只读）与修复（绑定核查状态、409、写后复核）
├── drift_inject.py  演示用：模拟其他脚本旁路改写专用表（额外放行/缺表/改策略）
├── db.py            SQLite 持久层（WAL）：已确认规则、变更单、核查记录、epoch
├── watchdog.py      独立看护进程：超时未确认即回退，Web 退出后仍值守
├── main.py          FastAPI 管理网页（应用、确认、核查、修复、状态查看）
├── echo_server.py   附带的 HTTP 回显服务
└── /data/mgmt.db    命名卷持久化（含写锁文件与令牌 HMAC 密钥）
```

* **只修改容器内专用表** `inet port_mgmt`（链 `input_filter`，策略 `drop`），
  不触碰宿主网络命名空间或其他任何 nftables 表；Compose 仅授予 `NET_ADMIN`/`NET_RAW`。
* **过滤所有非回环入站流量**：回环接口显式放行；白名单 TCP 端口放行，
  其余入站（含白名单外 TCP 的**已有连接**）一律丢弃。非 TCP 的
  established/related（如 UDP DNS 应答）放行，保证容器基础网络可用。
* **原子生效**：每次变更通过一次 `nft -f -` 批量事务（destroy + create 同批）提交，
  内核要么整体生效、要么整体回滚——**应用失败时旧规则原样保留**。
* **先持久化后生效**：应用前先把“已确认规则快照 + pending 变更单”写入 SQLite，
  再调用 nft；因此 Web 在生效后任意时刻退出，看护进程都能据快照回退。

## 确认窗口状态机（关键安全语义）

1. 有待确认（pending）变更时，**拒绝任何新变更**（HTTP 409）。
2. 变更生效后 **30 秒内**在页面点“确认”：白名单固化为已确认规则并持久化。
3. 30 秒内未确认：独立看护进程自动把 nft 规则恢复为应用前快照，变更单标记 `expired`。
4. **过期单 / 旧变更单的确认一律拒绝**，不会影响当前规则。
5. Web 进程退出不影响回退（看护进程是独立 OS 进程，按数据库中的截止时间判定）。
6. 整套服务重启：遗留 pending 单全部作废，**先恢复已确认规则，再开放网页**。

## 漂移核查与修复（新增能力）

### 核查语义

* **读取真实 nft 专用表**：使用 `nft -j list table inet port_mgmt` 获取结构化 JSON，
  与“应生效策略”的期望结构比较：
  - 链属性：`type` / `hook` / `priority` / `policy`；
  - 完整规则表达式结构（match/ct/payload/accept 等逐节点比较，规则顺序、重复条数均参与）；
  - **忽略每条规则的 handle 与计数器 packets/bytes 计数值**（它们随重建自然变化，不代表漂移）。
* 结论分四类：

  | 结果 | 含义 |
  |---|---|
  | `in_sync` | 链属性与规则结构均与应生效策略一致 |
  | `drift` | 表存在但结构不同（如额外放行、缺规则、链策略被改） |
  | `missing_table` | 专用表缺失（漂移的一种） |
  | `unknown` | nft 读取失败/超时/JSON 非法——**不臆测，不允许据此修复** |

* **只读且不阻塞**：核查不获取规则写锁，应用 / 确认 / 回退不会被核查卡住。
* **并发一致性**：每次合法规则写入都把 SQLite 中的策略版本号 `epoch` 原子 +1。
  核查在读取 nft 前后各读一次 epoch，**读取期间发生合法策略改变即丢弃本次结果并重查**
  （最多 5 次），避免把“合法变更进行中”的瞬时不一致误判为漂移。

### 修复语义

* 修复请求必须携带核查返回的 **HMAC 签名状态令牌**，令牌绑定核查时的 epoch 与
  pending 状态指纹，并在数据库中**一次性消费**（不可重放）。
* 进入跨进程写锁后重新校验，以下情况一律 **HTTP 409 且不写任何规则**：
  - 核查后发生过应用 / 确认 / 回退 / 修复（epoch 变化）；
  - pending 变更状态变化（新单、被确认、被回退）；
  - 令牌已被使用、伪造或篡改。
* 状态未变化才恢复“应生效策略”：
  - 无 pending：恢复**已确认基线**（基线数据本身不被改写）；
  - 有 pending：恢复该变更单请求的规则，**保留原变更单与原确认截止时间**。
* **写入后重新读取真实表核实**，结构不一致或读取失败时返回错误，**绝不报已恢复**。
* 只重建专用表 `inet port_mgmt`，不触碰其他 nft 表，也不修改已确认基线。

### 写入协调

Web（应用/确认）、独立看护（回退）、修复三条写规则路径共用一把跨进程 `flock`
写锁（`/data/rule_write.lock`）与同一 epoch 计数；核查只读不持锁。
30 秒确认窗口与“Web 退出后看护独立回退”的原有语义保持不变。

### 本地演示（缺表 / 额外放行 / 可控慢核查）

一键脚本（容器启动后在宿主执行）：

```bash
./demo_audit.sh
```

浏览器手动演示（http://localhost:8080/ 的“防火墙漂移核查与修复”卡片）：

1. 点击 **注入额外放行（TCP 22）** / **删除专用表（缺表）** / **链策略改 accept**；
2. 点击 **开始核查**，页面显示漂移类型、额外放行端口与结构差异；
3. 点击 **按核查结果修复**，后端写入并重新读取核实，页面自动再核查确认一致；
4. **可控慢核查**：把“演示慢核查延迟”设为 6 秒后开始核查，在另一个标签页立即
   应用一次合法白名单，可看到核查 `attempts=2`（第一次结果被丢弃并重查）。

命令行等价注入（容器内）：

```bash
docker compose exec port-mgmt python drift_inject.py extra-port 22
docker compose exec port-mgmt python drift_inject.py delete-table
docker compose exec port-mgmt python drift_inject.py tamper-policy
```

## 快速启动

```bash
docker compose up --build
```

浏览器入口：

| 服务 | 地址 | 说明 |
|---|---|---|
| 管理网页 | http://localhost:8080/ | 应用 / 确认 / 状态查看 |
| HTTP 回显 | http://localhost:8090/ | 验证端口连通性，返回请求 JSON 回显 |

初始白名单为 `8080`（网页）+ `8090`（回显），首次启动时写入 SQLite 并下发 nft。

## 演示：误封网页后自动恢复

1. 打开 http://localhost:8080/ ，点击 **“演示：移除网页端口（模拟误封失联）”**
   （或手动输入仅含 `8090` 的白名单并应用）。
2. 规则立即生效：网页端口 8080 被丢弃，页面进入失联重试状态；
   回显服务 http://localhost:8090/ 仍可正常访问。
3. 不要点确认。等待 30 秒：看护进程自动回退到旧白名单，
   页面自动恢复访问，变更记录中该单显示“已过期回退”。

命令行端到端演示：

```bash
./demo.sh
```

容器内查看实际 nft 规则（只读）：

```bash
docker compose exec port-mgmt nft list table inet port_mgmt
```

## HTTP API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/config` | 端口与确认窗口配置 |
| GET | `/api/status` | 已确认白名单、pending 倒计时、生效规则、历史变更、epoch、最近核查 |
| POST | `/api/apply` | body `{"ports":[8080,8090]}` 应用新白名单（pending 时 409） |
| POST | `/api/confirm` | body `{"change_id":1}` 窗口内确认（过期/旧单 409） |
| POST | `/api/audit/check` | body `{"slow_delay":0}` 漂移核查，返回结论与修复令牌 |
| POST | `/api/audit/repair` | body `{"token":"..."}` 按令牌修复；状态失效/重放返回 409，复核失败返回 500 |
| GET | `/api/audit/history` | 最近核查/修复记录 |
| POST | `/api/demo/inject` | 演示漂移注入 `{"action":"extra-port|delete-table|tamper-policy","port":22}`（可关闭） |

核查结果字段：`result`（in_sync/drift/missing_table/unknown）、`is_drift`、
`expected_ports`、`observed_ports`、`extra_allowed_ports`、`missing_allowed_ports`、
`structural_diff`、`attempts`、`epoch`、`token`。

## 配置（环境变量，见 docker-compose.yml）

| 变量 | 默认 | 说明 |
|---|---|---|
| `WEB_PORT` | 8080 | 管理网页端口（初始白名单） |
| `ECHO_PORT` | 8090 | HTTP 回显端口（初始白名单） |
| `CONFIRM_WINDOW_SECONDS` | 30 | 确认窗口时长 |
| `WATCHDOG_INTERVAL_SECONDS` | 0.5 | 看护进程轮询周期 |
| `NFT_TABLE_NAME` | port_mgmt | 容器内专用 nft 表名 |
| `DB_PATH` | /data/mgmt.db | SQLite 路径（命名卷持久化） |
| `NFT_READ_TIMEOUT_SECONDS` | 8 | 核查读 nft 超时（避免无限阻塞应用） |
| `NFT_WRITE_TIMEOUT_SECONDS` | 10 | nft 写入超时 |
| `RULE_WRITE_LOCK_PATH` | /data/rule_write.lock | 跨进程规则写锁文件 |
| `STATE_TOKEN_KEY_PATH` | /data/token.key | 修复令牌 HMAC 密钥（自动生成，0600） |
| `DEMO_INJECTION_ENABLED` | 1 | 漂移注入演示开关，生产置 `0` 关闭 `/api/demo/inject` |
| `AUDIT_SLOW_DELAY_SECONDS` | 0 | 核查人工延迟（演示并发重查，也可 API 传入） |

## 测试

测试使用内存假 nft 后端（不触碰内核），覆盖核查分类、结构归一（忽略 handle/计数器）、
慢核查重查、修复 409、pending 保留、令牌防重放、API 状态码等：

```bash
python -m pytest tests/ -q
```

## 说明与注意事项

* 能力要求：容器需 `NET_ADMIN`（配置 nft 规则）与 `NET_RAW`；
  宿主内核需支持 nftables（现代 Docker Desktop / Linux 发行版默认支持）。
* 回退 nft 命令本身失败时，看护进程不会把变更单标记过期，而是在下个轮询周期
  重试，直到规则真正恢复，避免“状态显示回退但规则未恢复”。
* 健康检查走容器回环接口（回环永远放行），因此网页端口被封时健康检查仍可工作。
* 页面强制白名单至少保留一个端口，避免提交空规则导致永久失联。
