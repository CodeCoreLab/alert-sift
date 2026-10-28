# Changelog

Format: Keep a Changelog. Versions follow semver.

## [0.1.0] - 2026-10-27
### Added
- 首个开源版本：七阶段告警降噪流水线（去重/静默/抑制/聚合/分级/通知/持久化）
- AI 运维护栏：MCP Server（19 工具）+ guard（RBAC/高危审批/审计/dry_run）
- Alertmanager webhook v2 兼容入口；vmalert reconcile
- 业务词配置化：groups.project_names / prefixes / ip_prefixes（原生产硬编码移除）
- per-robot 令牌桶限流 + 推送健康观测 + 失败落盘审计
