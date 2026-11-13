# 入站端口白名单变更管理（FastAPI + SQLite + nftables）

面向远程运维场景：调整入站端口白名单时，如果误封了管理网页自身，系统会在确认窗口
（默认 30 秒）到期后由**独立于 Web 的看护进程**自动恢复旧规则，无需登录宿主操作。

## 架构与边界

```
容器（独立网络命名空间，不使用 network_mode: host）
├── bootstrap.py   入口恢复：先恢复“已确认规则”，再开放网页
├── nft.py         nftables 适配：仅操作专用表 inet port_mgmt，原子批量提交
├── firewall.py    变更业务：应用 / 确认 / 超时回退
├── db.py          SQLite 持久层（WAL）：已确认规则 + 全部变更单
├── watchdog.py    独立看护进程：超时未确认即回退，Web 退出后仍值守
├── main.py        FastAPI 管理网页（应用、确认、状态查看）
├── echo_server.py 附带的 HTTP 回显服务
└── /data/mgmt.db  命名卷持久化
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
| GET | `/api/status` | 已确认白名单、pending 倒计时、生效规则、历史变更 |
| POST | `/api/apply` | body `{"ports":[8080,8090]}` 应用新白名单（pending 时 409） |
| POST | `/api/confirm` | body `{"change_id":1}` 窗口内确认（过期/旧单 409） |

## 配置（环境变量，见 docker-compose.yml）

| 变量 | 默认 | 说明 |
|---|---|---|
| `WEB_PORT` | 8080 | 管理网页端口（初始白名单） |
| `ECHO_PORT` | 8090 | HTTP 回显端口（初始白名单） |
| `CONFIRM_WINDOW_SECONDS` | 30 | 确认窗口时长 |
| `WATCHDOG_INTERVAL_SECONDS` | 0.5 | 看护进程轮询周期 |
| `NFT_TABLE_NAME` | port_mgmt | 容器内专用 nft 表名 |
| `DB_PATH` | /data/mgmt.db | SQLite 路径（命名卷持久化） |

## 说明与注意事项

* 能力要求：容器需 `NET_ADMIN`（配置 nft 规则）与 `NET_RAW`；
  宿主内核需支持 nftables（现代 Docker Desktop / Linux 发行版默认支持）。
* 回退 nft 命令本身失败时，看护进程不会把变更单标记过期，而是在下个轮询周期
  重试，直到规则真正恢复，避免“状态显示回退但规则未恢复”。
* 健康检查走容器回环接口（回环永远放行），因此网页端口被封时健康检查仍可工作。
* 页面强制白名单至少保留一个端口，避免提交空规则导致永久失联。
