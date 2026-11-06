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
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
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


# ── 审批队列 (JSONL 追加式事件日志) ──
#
# 【A14 修复】原实现：request_approval 用 "a" 追加，_set_approval 读整个文件、
# 改一行、再用 open(..., "w") 截断重写。三处问题：
#   (a) 无任何文件锁 —— _set_approval 的截断重写会把并发追加的记录覆盖掉；
#   (b) "w" 先截断再写，中途异常留下半截文件；
#   (c) 写入非原子。
# 改为「只追加」的事件日志：
#   * 所有写操作只往文件尾部追加新行，永不截断重写 → 并发写不会互相覆盖；
#   * 同一 id 允许有多条记录，list_approvals 折叠后以最后一条为准
#     （先 pending、后 approved/rejected 的语义由此自然表达）；
#   * 追加用 O_APPEND + 单次 write + fsync；若发现文件尾部残留上次崩溃留下的
#     半截行，先用「临时文件 + os.replace」原子修复，再追加；
#   * 跨进程用 fcntl.flock / msvcrt.locking 串行化，进程内再用线程锁兜底；
#     平台不支持文件锁时退化为「仅进程内锁」并告警。
_APPROVAL_THREAD_LOCK = threading.RLock()
# 记录当前线程已持有的审批文件锁深度，避免同一线程重复获取跨进程锁时自锁。
_APPROVAL_LOCK_DEPTH = threading.local()


def _stable_repr(obj):
    """对象的稳定 repr：抹掉内存地址，保证跨进程/跨次运行可比。"""
    try:
        r = repr(obj)
    except Exception:  # noqa: BLE001
        r = "<unreprable %s>" % type(obj).__name__
    return re.sub(r"0x[0-9a-fA-F]+", "0x?", r)


@contextmanager
def _approval_lock():
    """串行化审批文件的读写：进程内线程锁 + 跨进程文件锁。

    跨进程锁用独立的 .lock 文件：
      * POSIX   → fcntl.flock(LOCK_EX)
      * Windows → msvcrt.locking(LK_LOCK)
    两者都拿不到时退化为「仅进程内锁」，并留下告警（不静默降级）。
    同一线程重入时只加线程锁、不重复加跨进程锁，避免自锁。
    """
    with _APPROVAL_THREAD_LOCK:
        depth = getattr(_APPROVAL_LOCK_DEPTH, "n", 0)
        if depth:
            _APPROVAL_LOCK_DEPTH.n = depth + 1
            try:
                yield
            finally:
                _APPROVAL_LOCK_DEPTH.n = depth
            return
        fh = None
        try:
            d = os.path.dirname(APPROVAL_FILE)
            if d:
                os.makedirs(d, exist_ok=True)
            fh = open(APPROVAL_FILE + ".lock", "a+b")
            if fh.seek(0, os.SEEK_END) == 0:
                fh.write(b"\0")
                fh.flush()
            fh.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        except Exception as e:  # noqa: BLE001
            # 退化路径：拿不到跨进程锁时只靠进程内线程锁，仍能挡同进程并发，
            # 但跨进程并发不受保护 —— 必须留下告警，不能静默降级。
            logger.warning("审批文件锁不可用，退化为仅进程内锁: %s", e)
            if fh is not None:
                try:
                    fh.close()
                except OSError:
                    pass
                fh = None
        _APPROVAL_LOCK_DEPTH.n = 1
        try:
            yield
        finally:
            _APPROVAL_LOCK_DEPTH.n = 0
            if fh is not None:
                try:
                    fh.seek(0)
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except Exception as e:  # noqa: BLE001
                    logger.warning("释放审批文件锁失败: %s", e)
                finally:
                    fh.close()


def _repair_torn_tail():
    """原子修复审批文件尾部残留的半截行（上次崩溃留下的）。

    用「临时文件 + os.replace」保证修复过程中读到的永远是完整文件。
    """
    try:
        with open(APPROVAL_FILE, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return
    if not data or data.endswith(b"\n"):
        return
    idx = data.rfind(b"\n")
    keep = data[: idx + 1] if idx >= 0 else b""
    d = os.path.dirname(APPROVAL_FILE) or "."
    tmp = os.path.join(d, os.path.basename(APPROVAL_FILE) + ".repair")
    with open(tmp, "wb") as f:
        f.write(keep)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, APPROVAL_FILE)
    logger.warning("审批文件尾部存在半截行，已原子修复（丢弃 %d 字节）",
                   len(data) - len(keep))


def _append_approval_records(records):
    """把若干条审批记录追加到审批文件（追加语义，非读改写）。"""
    payload = "".join(
        json.dumps(r, ensure_ascii=False, default=_stable_repr) + "\n"
        for r in records
    ).encode("utf-8")
    d = os.path.dirname(APPROVAL_FILE)
    if d:
        os.makedirs(d, exist_ok=True)
    _repair_torn_tail()
    fd = os.open(APPROVAL_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        off = 0
        while off < len(payload):
            off += os.write(fd, payload[off:])
        os.fsync(fd)
    finally:
        os.close(fd)


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
        with _approval_lock():
            _append_approval_records([rec])
    except Exception as e:
        # 【A13 修复】原来这里只 logger.error 然后照样 return rec["id"]，
        # 调用方拿到一个根本没落盘的 id，误以为审批已提交（审批链断裂且
        # 现象是「审批丢失」而非「审批失败」，排障方向被误导）。
        # 现在：记录日志后向上抛错，由调用方明确感知「审批提交失败」。
        logger.error("审批单写入失败 action=%s: %s", action, e)
        raise
    return rec["id"]


def _read_approval_records():
    """读取审批记录原始列表（不折叠；损坏行跳过并告警）。"""
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
            out.append(r)
    if bad_lines:
        logger.warning(
            "审批记录读取完成，共跳过 %d 行损坏数据 file=%s 有效=%d",
            bad_lines, APPROVAL_FILE, len(out),
        )
    return out


def list_approvals(status=None):
    """列出审批单（同一 id 折叠为最后一条记录）。

    折叠是追加式日志的必要一步：pending → approved/rejected 表现为同一 id
    的多条记录，最终状态以最后一条为准。
    """
    with _approval_lock():
        rows = _read_approval_records()
    folded = {}
    order = []
    for r in rows:
        rid = r.get("id")
        if rid is None:
            # 无 id 的记录无法折叠，逐条独立保留
            order.append(("__noid__", len(order)))
            folded[order[-1]] = r
            continue
        if rid not in folded:
            order.append(rid)
        folded[rid] = r
    out = [folded[k] for k in order]
    if status is not None:
        out = [r for r in out if r.get("status") == status]
    return out


def _set_approval(aid, status):
    """变更审批单状态：追加一条新记录（不截断重写整个文件）。"""
    with _approval_lock():
        target = None
        for r in _read_approval_records():
            if r.get("id") == aid:
                target = r
        if target is None:
            return False
        new = dict(target)
        new["status"] = status
        _append_approval_records([new])
        return True


def approve(aid):
    return _set_approval(aid, "approved")


def reject(aid):
    return _set_approval(aid, "rejected")


def _params_fingerprint(params):
    """把 params 规范化成可比较的指纹。

    规则：
      * None / 空字典 → 空指纹（表示「不约束参数」）；
      * 字典 → 按键排序后序列化，保证参数顺序不影响比较；
      * 无法规范化的对象 → 稳定 repr（抹掉内存地址）。
    dry_run 只决定「是否走审批闸门」，不改变操作目标，故不参与指纹。
    """
    if params is None:
        return ""
    if isinstance(params, dict):
        params = {k: v for k, v in params.items() if k != "dry_run"}
        if not params:
            return ""
    try:
        return json.dumps(params, sort_keys=True, ensure_ascii=False,
                          default=_stable_repr)
    except (TypeError, ValueError):
        return _stable_repr(params)


def is_approved(action, params=None):
    """判断该 action 是否存在仍有效、且参数匹配的 approved 审批单。

    【A15 修复】原来只比较 action，参数被完全忽略 —— 一次批准即对同 action
    的任意参数组合在有效期内放行，参数级审批形同虚设。现在：
      * action 必须相同；
      * params 指纹必须相同（规范化后比较，见 _params_fingerprint）；
      * 存量审批记录（无 params 字段，或 params 为空）指纹为空，只与「不约束
        参数」的调用匹配，不会放行任何带具体参数的调用 —— 即不匹配任何具体
        参数，符合「存量记录不隐式授权具体参数目标」的兼容策略；
      * 时效校验不变：approved 单超过 APPROVAL_VALID_SECONDS(默认24h) 不放行。
    """
    now = time.time()
    want = _params_fingerprint(params)
    for r in list_approvals("approved"):
        if r.get("action") != action:
            continue
        ts = r.get("ts")
        try:
            t = datetime.fromisoformat(ts).timestamp()
        except (TypeError, ValueError):
            t = 0
        if now - t <= APPROVAL_VALID_SECONDS:
            if _params_fingerprint(r.get("params")) == want:
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
    # A15：审批匹配含 params —— 同参数放行，不同参数不放行
    print("is_approved(same params):",
          is_approved("rule_upsert", {"file": "group_host.yaml"}))
    print("is_approved(other params):",
          is_approved("rule_upsert", {"file": "other.yaml"}))
    print("GUARD SELF-TEST OK")
