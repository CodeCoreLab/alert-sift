# alert-sift — 告警降噪网关

**Alertmanager 兼容的告警降噪网关**：接收 vmalert / Alertmanager webhook 告警，
经「去重 → 静默 → 抑制 → 聚合 → 分级 → 通知」七阶段流水线处理后按项目路由推送，
并内置 **AI 运维护栏（MCP）**——让 AI 安全地管理你的告警系统。

> 源自生产环境日均千级告警的实战沉淀，替代 "Alertmanager + 一堆脚本" 的松散组合。

## 为什么不用 Alertmanager 直连 webhook

| 痛点 | alert-sift 的解法 |
|---|---|
| 同一故障风暴刷屏几十条 | L2 指纹去重 + L5 窗口聚合，风暴折叠为计数卡 |
| 维护窗口静默要手动配 Alertmanager | L3 静默走 YAML/API，支持时间窗 + 标签匹配 |
| 父告警 firing 时子告警照推 | L4 抑制：主机宕机压制其上全部子告警 |
| 机器人被限流 45009 打满配额 | per-robot 令牌桶限流，P0 不节流保可达 |
| P0-P4 不分级全量推送 | L6 分级 + severity 路由树（P0 自动双发值班群） |
| 让 AI 改配置怕删库 | guard 护栏：RBAC + 高危审批闭环 + 审计 + dry_run 默认 |

## 快速开始

```bash
pip install -r requirements.txt
export WECOM_BOT_APP="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=<你的key>"

# 启动（REST 控制面 + MCP 同进程）
uvicorn app.main:app --host 0.0.0.0 --port 9999

# 模拟一条告警
curl -X POST http://127.0.0.1:9999/api/v2/alerts -H 'Content-Type: application/json' -d '{
  "alerts": [{
    "status": "firing",
    "labels": {"alertname": "SYS|Host|P2|CpuHigh", "project": "SYS",
               "severity": "P2", "type": "host", "instance": "10.0.0.8"},
    "annotations": {"summary": "CPU 使用率 92%"},
    "startsAt": "2026-01-01T00:00:00Z"
  }]
}'
```

vmalert / Alertmanager 侧指向本服务即可（AM webhook v2 协议兼容）：

```
vmalert -notifier.url=http://alert-sift:9999   # 自动追加 /api/v2/alerts
```

## 流水线

```
Alertmanager webhook (POST /api/v2/alerts)
  └─> L2 dedup       指纹去重：短窗冷却 / 长窗折叠 / P0 豁免 / 风暴折叠
  └─> L3 silence     静默：维护时间窗 + 标签匹配（silences.yaml / API 动态改）
  └─> L4 inhibit     抑制：父告警压制子告警（inhibits.yaml）
  └─> L5 aggregate   聚合：窗口内同组合并为单条通知，防刷屏
  └─> L6 classify    分级：P0-P4 + 分组标签归一（groups 配置驱动）
  └─> L7 notify      通知：多机器人路由 + Jinja2 渲染 + 重试 + 令牌桶限流
  └─> L8 store       状态与历史持久化（SQLite，可选 MySQL）
```

## AI 运维护栏（MCP Server）—— 核心差异化

内置 MCP Server（16 个工具），AI 助手可直接查询与操作告警系统；
`guard.py` 为 AI 写操作提供三层护栏：

1. **RBAC**：`ai` 角色仅放行读类与预览动作，`human` 全开（`configs/guard.yaml`）
2. **高危审批**：静默/抑制/规则/路由写操作须先 `request_approval`，人 `approve` 后放行
3. **审计留痕**：每次写操作记录 actor/action/params/ok 到 SQLite，配合 dry_run 预览与 .bak 回滚

```bash
# 独立进程部署（9998 端口）或与 REST 同进程（/mcp/mcp，streamable-http）
python app/mcp_server.py --transport http --port 9998
```

对接 WorkBuddy / Claude Desktop / 任意 MCP 客户端后，AI 即可安全执行
「查活跃告警 → 建静默 → 改规则」全流程——高危步骤自动拦截等人审批。

## 管理 API

启动后访问 `http://localhost:9999/docs` 查看 OpenAPI。常用：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /admin/alerts | 活跃告警（可按 project/severity 过滤） |
| POST | /admin/alerts/{fp}/ack | 确认告警 |
| GET/PUT/DELETE | /admin/silences | 静默 CRUD（`?dry_run=true` 预览） |
| GET/PUT/DELETE | /admin/inhibits | 抑制 CRUD |
| GET/PUT | /admin/rules | vmalert 规则读写（30s 热加载） |
| GET | /admin/history/export | 历史导出 CSV |

## 配置

全部声明式 YAML（`config/` + `configs/`），样例即文档：

| 文件 | 职责 |
|---|---|
| `config/config.yaml` | 主配置：业务分组 / 项目路由 / 通知 / 去重窗口 |
| `config/silences.yaml` | 静默规则（API 动态写入的覆盖源） |
| `config/inhibits.yaml` | 抑制规则 |
| `config/notifiers.yaml` | 通知路由（存在即覆盖主配置同名段） |
| `configs/guard.yaml` | AI 护栏：RBAC 角色与高危动作清单 |
| `configs/instance_ip_map.yaml` | 主机名 ↔ IP 映射（展示增强） |

安全约定：机器人 webhook key 一律 `${WECOM_BOT_*}` 环境变量引用，禁止明文入仓。

## 部署

```bash
# Docker
docker build -t alert-sift .
docker run -d -p 9999:9999 \
  -e WECOM_BOT_SYS="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx" \
  -v ./config:/app/config alert-sift
```

环境变量：`ALERT_SIFT_CONFIG`（主配置路径）、`ALERT_SIFT_ROOT`（配置根目录）、
`ALERT_SIFT_VMALERT_URL`（vmalert 地址，用于活跃告警 reconcile）、
`ALERT_SIFT_WECOM_RATE_PER_MIN`（出站限流，默认 15）、`ALERT_SIFT_HTTP_TIMEOUT`（默认 10s）。

## 测试

```bash
cd app && python -m unittest test_pipeline -v   # 48 用例：classify/dedup/silence/inhibit/notify/aggregate + e2e
```

## 路线图

- [x] 七阶段降噪流水线 + 状态持久化
- [x] MCP Server + guard 护栏
- [ ] `NotifierChannel` 插件接口与钉钉 / Slack / Telegram 适配器（当前内置企微 webhook，其余渠道可仿 `pipeline/notify.py` 扩展）
- [ ] Prometheus rules 模板库

## License

MIT
