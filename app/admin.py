# -*- coding: utf-8 -*-
"""管理 API（REST 全套 CRUD）—— 控制面可编程

挂载于 /admin 前缀，与 MCP Server 共享 core.AppContext。

重构（2026-08-15）：
  * 提取 VALID_PROJECTS 常量
  * _parse_matchers 提取为独立方法（消除重复 try/except）
  * 增加空 fingerprint 检查
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from core import AppContext
from guard import (approve as _guard_approve,
                   reject as _guard_reject,
                   list_approvals as _guard_list_approvals)



logger = logging.getLogger("alert-sift.admin")

router = APIRouter(prefix="/admin", tags=["admin"])

# 有效项目列表
VALID_PROJECTS = ("SYS", "APP", "OPS")  # 机器人路由键（示例；按你的环境改）


# ================= 请求/响应模型 =================
class SilenceIn(BaseModel):
    matchers: dict
    starts_at: str | None = None
    ends_at: str | None = None
    schedule: dict | None = None   # 周期维护窗口: {timezone?, weekdays?, start, end}


class InhibitIn(BaseModel):
    source_matchers: dict
    target_matchers: dict
    equal: list[str] = Field(default_factory=list)


class RuleIn(BaseModel):
    alert: str
    expr: str
    for_: str = Field(default="5m", alias="for")
    labels: dict = Field(default_factory=dict)
    annotations: dict = Field(default_factory=dict)


class RouteIn(BaseModel):
    url: str | None = None


def _ctx(request: Request) -> AppContext:
    return request.app.state.ctx


def _parse_matchers(key: str) -> dict:
    """解析 JSON 格式的 matchers 字符串。"""
    try:
        return json.loads(key)
    except Exception:  # noqa: BLE001
        raise HTTPException(400, 'key 需为 JSON 格式的 matchers，如 {"rule_name":"Noise"}')


# ================= 健康/状态 =================
@router.get("/health")
async def health(request: Request):
    ctx = _ctx(request)
    return {"status": "ok", "db": ctx.db_stats()}


# ================= 告警查询/确认 =================
@router.get("/alerts")
async def list_alerts(request: Request, project: str | None = None,
                      severity: str | None = None):
    return _ctx(request).list_active_alerts(project=project, severity=severity)


@router.post("/alerts/{fingerprint}/ack")
async def ack_alert(fingerprint: str, request: Request):
    if not fingerprint:
        raise HTTPException(400, "fingerprint 不能为空")
    ok = _ctx(request).ack_alert(fingerprint)
    if not ok:
        raise HTTPException(404, f"fingerprint={fingerprint} 未找到活跃告警")
    return {"ack": True, "fingerprint": fingerprint}


# ================= 配置 =================
@router.get("/config/diff")
async def config_diff(request: Request):
    return _ctx(request).config_diff()


@router.post("/config/reload")
async def config_reload(request: Request, confirm: bool = Query(False)):
    if not confirm:
        raise HTTPException(400, "需 confirm=true 确认后才生效（预览模式）")
    return _ctx(request).reload_config()


# ================= 静默 CRUD =================
@router.get("/silences")
async def list_silences(request: Request):
    return _ctx(request).list_silences()


@router.put("/silences")
async def upsert_silence(item: SilenceIn, request: Request, dry_run: bool = False):
    return _ctx(request).upsert_silence(item.model_dump(), dry_run=dry_run)


@router.delete("/silences")
async def delete_silence(request: Request, key: str, dry_run: bool = False):
    matchers = _parse_matchers(key)
    return _ctx(request).delete_silence(matchers, dry_run=dry_run)


# ================= 抑制 CRUD =================
@router.get("/inhibits")
async def list_inhibits(request: Request):
    return _ctx(request).list_inhibits()


@router.put("/inhibits")
async def upsert_inhibit(item: InhibitIn, request: Request, dry_run: bool = False):
    return _ctx(request).upsert_inhibit(item.model_dump(), dry_run=dry_run)


@router.delete("/inhibits")
async def delete_inhibit(request: Request, key: str, dry_run: bool = False):
    target = _parse_matchers(key)
    return _ctx(request).delete_inhibit(target, dry_run=dry_run)


# ================= 通知渠道 =================
@router.get("/notifiers")
async def list_notifiers(request: Request):
    return _ctx(request).list_notifier_routes()


@router.put("/notifiers/{project}")
async def update_route(project: str, item: RouteIn, request: Request,
                       dry_run: bool = False):
    if project not in VALID_PROJECTS:
        raise HTTPException(400, f"project 仅支持 {','.join(VALID_PROJECTS)}")
    return _ctx(request).update_notifier_route(project, item.url, dry_run=dry_run)


# ================= vmalert 规则 =================
@router.get("/rules")
async def list_rules(request: Request):
    return _ctx(request).list_rules()


@router.put("/rules/{file}")
async def upsert_rule(file: str, item: RuleIn, request: Request,
                      dry_run: bool = False):
    rule = {
        "alert": item.alert,
        "expr": item.expr,
        "for": item.for_,
        "labels": item.labels,
        "annotations": item.annotations,
    }
    try:
        return _ctx(request).upsert_rule(file, rule, dry_run=dry_run)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc))


# ================= 审批流 (P2-7, 2026-08-25 加固) =================
# human 审批通道：MCP 的 approval_approve/approval_reject 已挂 guarded 仅限 human 角色
# （ai 角色被 RBAC 拒绝，防自批绕过 P1-①）；因 MCP 无法传角色参数，
# 人工审批在此 REST 端点完成（X-Admin-Token 鉴权即 human 身份）。
@router.get("/approvals")
async def list_approvals_api(request: Request, status: str | None = None):
    return _guard_list_approvals(status)


@router.post("/approvals/{aid}/approve")
async def approve_approval(aid: str, request: Request):
    if not aid or not _guard_approve(aid):
        raise HTTPException(404, f"审批单 {aid} 不存在或已处理")
    return {"ok": True, "id": aid}


@router.post("/approvals/{aid}/reject")
async def reject_approval(aid: str, request: Request):
    if not aid or not _guard_reject(aid):
        raise HTTPException(404, f"审批单 {aid} 不存在或已处理")
    return {"ok": True, "id": aid}


# ================= 历史/存储 =================
@router.get("/history/export")
async def export_history(request: Request, out: str | None = None,
                         limit: int = 10000):
    try:
        return {"csv": _ctx(request).export_history_csv(out_path=out, limit=limit)}
    except ValueError as exc:
        raise HTTPException(422, str(exc))
