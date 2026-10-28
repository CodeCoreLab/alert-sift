# 变更日志 — 告警降噪网关（alert-sift）

本文件记录本项目的变更。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

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
