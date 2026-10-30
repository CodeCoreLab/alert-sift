#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
guard.py - alert-sift 执行层护栏 (P2-7)
为 MCP Server 的写操作提供: 审计日志 / RBAC / 高危审批 / 回滚辅助。
设计原则: 非破坏式接入, 保留原有 dry_run 机制; 仅对 AI 角色(mcp 调用方)施加限制。

组件:
  - record_audit(): 每次写操作记 actor/action/params/dry_run/ok/result 到 SQLite(操作证据)
  - check_rbac(role, action): 角色→允许动作 (ai 角色受限, human 全开)
  - request_approval()/list_approvals()/approve()/reject(): 高危操作审批闭环
  - guarded(): 装饰器, 包裹 MCP 写工具, 串联 RBAC+审批+审计
  - rollback_rule(): 基于 core 写操作的 .bak 备份做回滚
"""
import json
import logging
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from functools import wraps

_HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.path.join(_HERE, "..", "data"))
AUDIT_DB = os.path.join(DATA_DIR, "audit.db")
APPROVAL_FILE = os.path.join(DATA_DIR, "approvals.jsonl")

# P1-7 修复（2026-10-05）：RBAC/HIGH_RISK 外部化到 configs/guard.yaml
# 原问题：硬编码在代码中，改角色/高危清单需改代码重新部署。
# 改造：进程启动时从配置文件加载；文件缺失或解析失败时回退到内置默认值。


def _load_guard_config():
    """加载 guard 配置（P1-6 收口：委托 config_loader.load_guard_config）。"""
    from config_loader import load_guard_config
    return load_guard_config()


_GUARD_CFG = _load_guard_config()
RBAC = _GUARD_CFG["RBAC"]
DEFAULT_ROLE = _GUARD_CFG["DEFAULT_ROLE"]
HIGH_RISK = _GUARD_CFG["HIGH_RISK"]
APPROVAL_VALID_SECONDS = _GUARD_CFG["APPROVAL_VALID_SECONDS"]

logger = logging.getLogger("alert-sift.guard")


def check_rbac(role: str, action: str) -> bool:
    allow = RBAC.get(role, RBAC.get(DEFAULT_ROLE, set()))
    if allow is None:
        return True
    return action in allow


# ── 审计日志 (SQLite) ──
def _audit_conn():
    os.makedirs(DATA_DIR, exist_ok=True)
    con = sqlite3.connect(AUDIT_DB)
    con.execute("""CREATE TABLE IF NOT EXISTS audit(
        id INTEGER PRIMARY KEY, ts TEXT, actor TEXT, action TEXT,
        params TEXT, dry_run INTEGER, ok INTEGER, result TEXT)""")
    con.commit()
    return con


def record_audit(action, params, dry_run, ok, actor="ai", result=""):
    try:
        con = _audit_conn()
        con.execute(
            "INSERT INTO audit(ts,actor,action,params,dry_run,ok,result) "
            "VALUES(?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), actor,
             action, json.dumps(params, ensure_ascii=False)[:2000],
             int(bool(dry_run)), int(bool(ok)), str(result)[:500]))
        con.commit()
        con.close()
    except Exception as e:
        # 当前行为：用 print 记审计写入失败 —— print 不走 logging 体系，
        # 没有级别/时间戳/logger 名，日志采集侧抓不到，审计链断裂完全不可见。
        # 改法：改用本模块已有的 logger（alert-sift.guard）以 error 级别记录。
        logger.error("审计日志写入失败 action=%s: %s", action, e)


def audit_query(action=None, limit=50):
    try:
        con = _audit_conn()
        if action:
            rows = con.execute(
                "SELECT ts,actor,action,params,dry_run,ok FROM audit "
                "WHERE action=? ORDER BY id DESC LIMIT ?", (action, limit)).fetchall()
        else:
            rows = con.execute(
                "SELECT ts,actor,action,params,dry_run,ok FROM audit "
                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        con.close()
        return [dict(zip(("ts", "actor", "action", "params", "dry_run", "ok"), r)) for r in rows]
    except Exception as e:
        # 当前行为：except Exception 直接 return []，查询失败与"没有审计记录"
        # 在调用方看来完全一样 —— 审计不可用被伪装成空结果，无人察觉。
        # 改法：记 error 日志后再返回 []（保持返回类型不变，不影响调用方逻辑），
        # 让"审计查询失败"这件事本身变得可观测。
        logger.error("审计日志查询失败 action=%s: %s", action, e)
        return []


# ── 审批队列 (JSONL) ──
def request_approval(action, params, actor="ai"):
    # P3-⑫（2026-08-25）：id 加随机后缀，防同毫秒并发调用生成相同 id
    # （原实现 ap_{int(time.time()*1000)} 在并发时碰撞，_set_approval 按 id
    #   匹配会批量误改多个审批单）。
    rec = {
        "id": f"ap_{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}",
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "actor": actor, "action": action,
        "params": params, "status": "pending",
    }
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(APPROVAL_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        # 当前行为：用 print 记审批单写入失败 —— 同 record_audit 的问题：
        # 不走 logging 体系，审批链断裂完全不可见（且 print 与业务日志格式不一致）。
        # 改法：改用 logger 以 error 级别记录。
        logger.error("审批单写入失败 action=%s: %s", action, e)
    return rec["id"]


def list_approvals(status=None):
    out = []
    if not os.path.exists(APPROVAL_FILE):
        return out
    bad_lines = 0
    with open(APPROVAL_FILE, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except (json.JSONDecodeError, ValueError) as e:
                # 原为静默 continue，审批记录损坏时无人知晓（P0-15 漏网，由新测试发现）
                logger.warning(
                    "审批记录存在无法解析的行（已跳过）file=%s line=%d err=%s",
                    APPROVAL_FILE, lineno, e,
                )
                bad_lines += 1
                continue
            if status is None or r.get("status") == status:
                out.append(r)
    if bad_lines:
        logger.warning(
            "审批记录读取完成，共跳过 %d 行损坏数据 file=%s 有效=%d",
            bad_lines, APPROVAL_FILE, len(out),
        )
    return out


def _set_approval(aid, status):
    if not os.path.exists(APPROVAL_FILE):
        return False
    rows, found = [], False
    with open(APPROVAL_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                rows.append(line + "\n")
                continue
            if r.get("id") == aid:
                r["status"] = status
                found = True
            rows.append(json.dumps(r, ensure_ascii=False) + "\n")
    if found:
        with open(APPROVAL_FILE, "w", encoding="utf-8") as f:
            f.writelines(rows)
    return found


def approve(aid):
    return _set_approval(aid, "approved")


def reject(aid):
    return _set_approval(aid, "rejected")


def is_approved(action, params=None):
    """判断该 action 是否有仍有效的 approved 审批单。

    P3-⑪（2026-08-25）：
      * 按 action 维度粗匹配（params 逐字段比对会让审批单因参数微差而过期，
        暂保持宽松；如需严格化可后续引入 params 哈希匹配）；
      * 增加时效校验：approved 单超过 APPROVAL_VALID_SECONDS(默认24h) 不再放行，
        防止"一次批准、永久放行"的长期授权面。
    """
    now = time.time()
    for r in list_approvals("approved"):
        if r.get("action") != action:
            continue
        ts = r.get("ts")
        try:
            t = datetime.fromisoformat(ts).timestamp()
        except (TypeError, ValueError):
            t = 0
        if now - t <= APPROVAL_VALID_SECONDS:
            return True
    return False


def guarded(action, high_risk=None, global_check=None):
    """装饰器: 包裹 MCP 写工具, 串联 RBAC + 审批 + 审计。
    global_check(kwargs)->bool: 用于运行期判定"全局影响"(如空 matchers=全局静默)。
    """
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            role = kwargs.pop("__role", DEFAULT_ROLE)
            if not check_rbac(role, action):
                record_audit(action, kwargs, kwargs.get("dry_run", False),
                             False, role, "RBAC denied")
                return {"error": f"RBAC denied: role={role} action={action}"}
            dry = kwargs.get("dry_run", False)
            # P1-7 修复：high_risk=None 时从 HIGH_RISK 配置查询（支持配置化）
            is_high_risk = action in HIGH_RISK if high_risk is None else bool(high_risk)
            glob = bool(global_check(kwargs)) if global_check else False
            if (is_high_risk or glob) and not dry:
                # P3-⑪（2026-08-25）：审批闭环真正接通 ——
                # 存在 24h 内 approved 单则放行执行，否则生成审批单待人工批准。
                # （原实现永不检查 is_approved，导致人工 approve 后 AI 重试
                #  仍被拒，审批闭环不可达。）
                if is_approved(action, kwargs):
                    pass
                else:
                    aid = request_approval(action, kwargs, role)
                    return {"error": "NEEDS_APPROVAL", "approval_id": aid,
                            "msg": f"高危操作 [{action}] 已生成审批单 {aid}; "
                                   f"需人工 approve 后重试(dry_run=False)"}
            res = fn(*args, **kwargs)
            ok = bool(res and not (isinstance(res, dict) and res.get("error")))
            record_audit(action, kwargs, dry, ok, role, str(res)[:200])
            return res
        return wrapper
    return deco


if __name__ == "__main__":
    # 自测
    record_audit("self_test", {"x": 1}, True, True, "ai", "ok")
    print("audit rows:", len(audit_query(limit=5)))
    aid = request_approval("rule_upsert", {"file": "group_host.yaml"})
    print("approval id:", aid, "approve:", approve(aid))
    print("is_approved:", is_approved("rule_upsert"))
    print("GUARD SELF-TEST OK")
