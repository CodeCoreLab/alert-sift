# -*- coding: utf-8 -*-
"""MCP Server —— 让 AI（WorkBuddy 等）可直接操作 alert-sift 全部模块

共享 core.AppContext，提供与 /admin REST 一致的管理能力：
  告警查询/确认、静默/抑制 CRUD、规则读写、通知路由、配置热重载、历史导出。

运行方式：
  独立进程:  python mcp_server.py --transport stdio   （stdio，供本地 MCP 客户端）
            python mcp_server.py --transport http     （streamable-http，端口 9998）
  FastAPI 挂载: main.py 中 app.mount("/mcp", mcp_app) （与 REST 同端口）
"""
from __future__ import annotations

import argparse
import logging
import os
from typing import TYPE_CHECKING

from core import AppContext

if TYPE_CHECKING:
    from fastmcp import FastMCP  # noqa: F401 —— 仅注解用，运行时 fastmcp 是可选依赖
from guard import guarded, list_approvals, approve, reject

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("alert-sift.mcp")

CONFIG_PATH = os.getenv("ALERT_SIFT_CONFIG", "config/config.yaml")
DB_PATH = os.getenv("ALERT_SIFT_DB", "data/alert_sift.db")

# 模块级单例（独立运行时用）；FastAPI 挂载时由 build_server(ctx) 注入共享 ctx。
# 惰性创建：避免 import 本模块即初始化 DB/配置（FastAPI 挂载模式下无谓副作用）
_ctx: AppContext | None = None


def _default_ctx() -> AppContext:
    global _ctx
    if _ctx is None:
        _ctx = AppContext(CONFIG_PATH, DB_PATH)
    return _ctx


def build_server(ctx: AppContext | None = None) -> FastMCP:
    """构建 MCP Server。ctx 可注入（与 REST 共享同一内存态），缺省用模块级 ctx。"""
    from fastmcp import FastMCP
    ctx = ctx or _default_ctx()

    mcp = FastMCP("alert-sift", instructions=(
        "alert-sift 告警中枢管理接口。修改类操作可传 dry_run=True 预览，"
        "确认无误后 dry_run=False 提交生效（写操作自动备份 .bak）。"))

    # ---------------- 告警 ----------------
    @mcp.tool()
    def alert_list(project: str = "", severity: str = "") -> list[dict]:
        """查询当前活跃告警。project/severity 可选过滤。"""
        return ctx.list_active_alerts(project=project or None, severity=severity or None)

    @mcp.tool()
    def alert_ack(fingerprint: str) -> dict:
        """确认某条活跃告警（fingerprint 必填），状态置 ack。"""
        return {"ack": ctx.ack_alert(fingerprint), "fingerprint": fingerprint}

    # ---------------- 静默 ----------------
    @mcp.tool()
    def silence_list() -> list[dict]:
        """列出全部静默规则。"""
        return ctx.list_silences()

    @mcp.tool()
    @guarded("silence_create", global_check=lambda k: not k.get("matchers"))
    def silence_create(matchers: dict, starts_at: str = "", ends_at: str = "",
                       dry_run: bool = False) -> dict:
        """新增/更新静默规则。matchers 为标签匹配（如 {"project":"SYS","severity":"P2"}），
        starts_at/ends_at 为 RFC3339 UTC，留空=永久。dry_run=True 仅校验。"""
        return ctx.upsert_silence({
            "matchers": matchers,
            **({"starts_at": starts_at} if starts_at else {}),
            **({"ends_at": ends_at} if ends_at else {}),
        }, dry_run=dry_run)

    @mcp.tool()
    @guarded("silence_delete", global_check=lambda k: not k.get("matchers"))
    def silence_delete(matchers: dict, dry_run: bool = False) -> dict:
        """按 matchers 删除静默规则。"""
        return ctx.delete_silence(matchers, dry_run=dry_run)

    # ---------------- 抑制 ----------------
    @mcp.tool()
    def inhibit_list() -> list[dict]:
        """列出全部抑制规则。"""
        return ctx.list_inhibits()

    @mcp.tool()
    @guarded("inhibit_create")
    def inhibit_create(source_matchers: dict, target_matchers: dict,
                       equal: list[str] | None = None,
                       dry_run: bool = False) -> dict:
        """新增/更新抑制规则：source_matchers 命中=子告警，target_matchers 命中=父告警，
        equal 为两告警须共享的标签（如 instance）。"""
        return ctx.upsert_inhibit({
            "source_matchers": source_matchers,
            "target_matchers": target_matchers,
            "equal": equal or [],
        }, dry_run=dry_run)

    @mcp.tool()
    @guarded("inhibit_delete", global_check=lambda k: not k.get("target_matchers"))
    def inhibit_delete(target_matchers: dict, dry_run: bool = False) -> dict:
        """按 target_matchers 删除抑制规则。"""
        return ctx.delete_inhibit(target_matchers, dry_run=dry_run)

    # ---------------- vmalert 规则 ----------------
    @mcp.tool()
    def rule_list() -> list[dict]:
        """列出 rules/ 下全部 vmalert 告警规则（只读）。"""
        return ctx.list_rules()

    @mcp.tool()
    @guarded("rule_upsert", high_risk=True)
    def rule_upsert(file: str, alert: str, expr: str, for_: str = "5m",
                    labels: dict | None = None, annotations: dict | None = None,
                    dry_run: bool = False) -> dict:
        """在指定 rules 文件新增/更新规则（按 alert 名定位），vmalert 30s 自动热加载。"""
        return ctx.upsert_rule(file, {
            "alert": alert, "expr": expr, "for": for_,
            "labels": labels or {}, "annotations": annotations or {},
        }, dry_run=dry_run)

    # ---------------- 通知路由 ----------------
    @mcp.tool()
    def notifier_list() -> dict:
        """查看机器人路由（各 project 及来源 env/config）。"""
        return ctx.list_notifier_routes()

    @mcp.tool()
    @guarded("notifier_update", high_risk=True)
    def notifier_update(project: str, url: str = "", dry_run: bool = False) -> dict:
        """更新项目机器人路由；url 留空=删除该路由。"""
        return ctx.update_notifier_route(project, url or None, dry_run=dry_run)

    # ---------------- 配置 ----------------
    @mcp.tool()
    def config_diff() -> dict:
        """查看内存配置与磁盘配置的差异（不生效）。"""
        return ctx.config_diff()

    @mcp.tool()
    @guarded("config_reload", high_risk=True)
    def config_reload(confirm: bool = False) -> dict:
        """热重载磁盘配置（confirm=true 才生效，预览模式需显式确认）。"""
        if not confirm:
            return {"error": "需 confirm=true 确认后才生效"}
        return ctx.reload_config()

    # ---------------- 历史/存储 ----------------
    @mcp.tool()
    def db_stats() -> dict:
        """查看存储统计（活跃告警数/历史数/DB 路径）。"""
        return ctx.db_stats()

    @mcp.tool()
    def history_export(out: str = "", limit: int = 10000) -> dict:
        """导出告警历史为 CSV，返回文件路径。"""
        return {"csv": ctx.export_history_csv(out_path=out or None, limit=limit)}

    # ---------------- 审批流 (P2-7) ----------------
    @mcp.tool()
    def approval_list(status: str = "pending") -> list:
        """列出审批单 (status: pending/approved/rejected, 留空=全部)。"""
        return list_approvals(status or None)

    @mcp.tool()
    @guarded("approval_approve")
    def approval_approve(id: str) -> dict:
        """批准审批单 (id 必填)。仅 human 角色可执行；ai 角色调用返回 RBAC denied（防自批绕过，P1-① 修复）。
        人工审批通道：REST POST /admin/approvals/{id}/approve（X-Admin-Token 鉴权即 human 身份）。"""
        return {"ok": approve(id), "id": id}

    @mcp.tool()
    @guarded("approval_reject")
    def approval_reject(id: str) -> dict:
        """拒绝审批单 (id 必填)。仅 human 角色可执行；ai 角色调用返回 RBAC denied（防自批绕过，P1-① 修复）。
        人工通道：REST POST /admin/approvals/{id}/reject。"""
        return {"ok": reject(id), "id": id}

    return mcp


def create_mcp_app(ctx: AppContext | None = None):
    """生成可挂载到 FastAPI 的 ASGI 应用（与 REST 共享 ctx 内存态）。
    用法：app.mount("/mcp", create_mcp_app(app.state.ctx))
    注：fastmcp>=3 用 http_app()（streamable-http 默认路径 /mcp）；旧版回退 streamable_http_app。
    """
    server = build_server(ctx)
    for attr in ("http_app", "streamable_http_app"):
        fn = getattr(server, attr, None)
        if fn is not None:
            return fn()
    raise RuntimeError("当前 fastmcp 版本不支持挂载 ASGI 应用")


def main():
    ap = argparse.ArgumentParser(description="alert-sift MCP Server")
    ap.add_argument("--transport", default="stdio", choices=["stdio", "http", "sse"])
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9998)
    args = ap.parse_args()

    mcp = build_server()  # 惰性初始化默认 ctx
    if args.transport == "stdio":
        mcp.run(transport="stdio")
    elif args.transport == "sse":
        mcp.run(transport="sse", host=args.host, port=args.port)
    else:
        mcp.run(transport="streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()