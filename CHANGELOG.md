# 变更日志 — 告警降噪网关（alert-sift）

本文件记录本项目的变更。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

### 变更

- 产品页 hero 区「快速开始」按钮改为「下载源码包」：走 fetch 流式下载并显示进度，
  文件名取 `Content-Disposition`（缺失时回退 URL 末段），失败给出可读原因 +
  「重试」+「直接下载」兜底

### 修复

- `state_store` 未定义导致启动即 NameError（`app/main.py`）
  —— 变量被误重命名为 `_unused_bind`，启动期 meta 清理与退出期
  DB 关闭均引用旧名。改回 `state_store`，并把启动清理的兜底
  捕获收窄为 `sqlite3.Error` / `OSError`，不再吞掉编程错误。
- 默认部署路径下 lifespan 完全未挂载，四个后台任务全部不启动
  （`app/main.py`）—— fastmcp 是可选 extra，Dockerfile 与 CI 只装基础依赖，
  默认走 `else` 分支的 `app_kwargs = {}`。改为 else 分支同样挂载 `_lifespan`，
  meta 清理 / 源侧对账 / 升级引擎 / 指标推送恢复运行。
- 企微 webhook 密钥（URL query 里的 `key=`）明文进日志
  （`app/pipeline/notify.py`、`app/pipeline/escalation.py`）
  —— 统一走新增的 `_safe_url()` 脱敏（只保留 scheme+host+path），
  异常文本另经 `_scrub()` 处理（httpx 部分异常会把请求 URL 写进 str(exc)）。
- 管理面与入站 webhook 鉴权 fail-open（`app/main.py`）
  —— 未配置令牌时整个鉴权判断被短路跳过，`/admin/*`（含写 vmalert 规则文件、
  改静默、改机器人路由）与 `/mcp` 完全无鉴权即可访问，而容器默认对外暴露。
  改为 fail-closed：未配置 → 503 并给出明确提示，已配置但不符 → 401。
  入站侧 `/api/v2/alerts` 同样改为 fail-closed，迁移期可用
  `ALERT_SIFT_ALLOW_ANON_PUSH=1` 临时保留匿名入站。
  另修复 `/api/v1/alerts` 兼容入口绕过鉴权与限流的旁路。
- 升级通知与业务通知共用同一组企微机器人（`app/main.py`）
  —— 升级引擎优先使用 `WECOM_BOT_ESCALATION_<PROJECT>`，
  未配置时回退 `WECOM_BOT_<PROJECT>`（向后兼容，行为不变）。
- Jinja2 模板未开自动转义（`app/pipeline/notify.py`）
  —— annotations 来自上游 Alertmanager webhook（外部可控），
  `description` / `llm_advice` / `runbook` 原样输出可注入 HTML 与伪造链接。
  开启 autoescape；runbook 作为 markdown 链接目标改用 `md_link_url`
  过滤器（保留查询串结构、拦截伪协议），避免 `&` 被转成 `&amp;` 破坏链接。
- 生产镜像携带单元测试（`Dockerfile` + 新增 `.dockerignore`）
  —— 改用精确 COPY 并排除测试文件与缓存；`app/test_pipeline.py` 保留在仓库
  供 CI 使用。
- 入站限流异常时降级放行不可观测（`app/main.py`）
  —— 保留 fail-open（可用性优先，刻意取舍）但日志级别提到 warning，
  并新增 `alert_sift_rate_limit_degraded_total` 计数指标。
- `guard.py` 用 `print` 记审计/审批写入失败（`app/guard.py`）
  —— print 不走 logging 体系，采集侧抓不到。改用 `logger.error`；
  审计查询失败也从"静默返回空列表"改为记 error 后返回空列表。
- 版本号三处分裂（`app/main.py` vs `app/__init__.py`）
  —— FastAPI 的 `version` 改为从 `app/__init__.py` 的 `__version__` 读取，
  消除第二份硬编码副本。
- 同源 `_unused_bind` 误改名残留（静态检查 F821 扫出，2026-10-30 追加修复）
  —— `app/pipeline/notify.py` 的 `_fetch_host_context` 中 `vm` / `now` 被误改名，
  引用处仍用旧名，主机上下文增强必抛 NameError 且被静默吞掉，改回原名；
  同函数死变量 `normal_group`（全仓无引用）删除。
  `app/test_pipeline.py` 两处 `old` 被误改名导致 2 个去重测试必挂，改回原名。
  `app/mcp_server.py` 的 `FastMCP` 类型注解在 fastmcp 未安装时 F821，
  改用 `TYPE_CHECKING` 守卫导入（运行时 fastmcp 仍是可选依赖）。

## [0.1.0] - 2026-10-27

### 新增

- 首个开源版本：七阶段告警降噪流水线
  （去重 / 静默 / 抑制 / 聚合 / 分级 / 通知 / 持久化）
- AI 运维护栏：MCP Server（16 工具）+ guard
  （RBAC / 高危审批 / 审计 / dry_run）
- Alertmanager webhook v2 兼容入口；vmalert reconcile
- per-robot 令牌桶限流 + 推送健康观测 + 失败落盘审计
- 48 项用例全绿，CI 三版本矩阵

### 变更

- 业务词配置化：`groups.project_names` / `prefixes` / `ip_prefixes`
  （原生产硬编码移除）
- 全局改名 `alert-core` → `alert-sift`（含 metrics 前缀与环境变量前缀）
