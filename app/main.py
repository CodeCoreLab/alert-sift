# -*- coding: utf-8 -*-
"""alert-sift 告警中枢入口 —— 替代旧版告警中心的核心服务

职责：接收 vmalert 推送的 Alertmanager Webhook 告警事件，
     经 去重→静默→抑制→聚合→分类→通知 流水线处理后，按项目路由推送企微。

控制面（可编程）：
  * /admin/*    —— REST 管理 API（配置/静默/抑制/规则/通知/存储 CRUD）
  * /mcp        —— MCP Server（AI 可直接操作，与 REST 共享同一核心）

对接：
  vmalert -notifier.url=http://127.0.0.1:9999/api/v2/alerts

重构（2026-08-15）：
  * 提取所有配置常量为模块级命名常量（消除魔法数字）
  * TokenBucket 增加 _refill 方法提取（消除重复计算）
  * _estimate_alert_count 增加 body 空值检查
  * _reconcile_loop 增加空结果快速返回
  * 增加 _validate_config 辅助函数
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import os
import sqlite3
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

import httpx

# 保证 uvicorn 从任意 cwd 启动都能导入兄弟模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

import metrics
from core import AppContext
from models import AlertBatch, parse_am_payload
from pipeline import run_pipeline, PipelineResult
from pipeline.aggregate import Aggregator
from pipeline.notify import _safe_url
from utils import setup_logging


def _app_version() -> str:
    """读取权威版本号（唯一真相源：app/__init__.py 的 __version__）。

    当前行为：main.py 里 FastAPI(version="0.2.0") 是第二份硬编码副本，
    与 app/__init__.py 的 __version__（registry.yaml 指定的权威源）分裂，
    改一处漏一处，OpenAPI 文档暴露的版本会与包版本不一致。

    改法：统一从 app/__init__.py 读取，消除第二份副本。

    实现说明：优先 `from app import __version__`（uvicorn app.main:app 启动时
    仓库根在 sys.path 上，可用）；但 main.py 顶部把 app/ 目录本身插进了
    sys.path（兄弟模块用 `from core import ...` 扁平导入），当以
    `python app/main.py` 方式直接运行时仓库根不在 sys.path，
    `import app` 会 ImportError —— 故回退到按文件路径加载 __init__.py。
    """
    try:
        from app import __version__ as _pkg_version  # noqa: PLC0415
        return str(_pkg_version)
    except Exception:  # noqa: BLE001 —— 扁平导入路径下 app 包不可见，走文件加载
        init_path = Path(__file__).resolve().parent / "__init__.py"
        try:
            spec = importlib.util.spec_from_file_location("_alert_sift_version", init_path)
            if spec is None or spec.loader is None:
                return "0.0.0"
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return str(getattr(module, "__version__", "0.0.0"))
        except Exception as exc:  # noqa: BLE001 —— 读不到版本号不应阻断启动
            logger.warning("读取 app/__init__.py 版本号失败: %s", exc)
            return "0.0.0"


def _to_int(value, ctx=""):
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"非法整数{(' ' + ctx) if ctx else ''}: {value!r}") from exc


def _to_float(value, ctx=""):
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"非法浮点数{(' ' + ctx) if ctx else ''}: {value!r}") from exc

logger = logging.getLogger("alert-sift")

# ================= 配置 =================
CONFIG_PATH = os.getenv("ALERT_SIFT_CONFIG", "config/config.yaml")
DB_PATH = os.getenv("ALERT_SIFT_DB", "data/alert_sift.db")

# meta 清理间隔（秒）
META_CLEANUP_INTERVAL = _to_int(os.getenv("ALERT_SIFT_META_CLEANUP_SECONDS", "3600"))

# 源侧对账
VMALERT_URL = os.getenv("ALERT_SIFT_VMALERT_URL", "http://127.0.0.1:8880")
RECONCILE_INTERVAL = _to_int(os.getenv("ALERT_SIFT_RECONCILE_SECONDS", "60"))

# 入站限流
RATE_LIMIT_RATE = _to_float(os.getenv("ALERT_SIFT_RATE_LIMIT_RATE", "50"))
RATE_LIMIT_BURST = _to_int(os.getenv("ALERT_SIFT_RATE_LIMIT_BURST", "1000"))

# 升级引擎（P1-⑧，2026-08-22）
ESCALATION_INTERVAL = _to_int(os.getenv("ALERT_SIFT_ESCALATION_SECONDS", "30"))
_ACK_GRACE_SECONDS = 1800  # ack 后宽限期 30min 不升级

# 自观测指标主动推送 VictoriaMetrics（P0-③：VM 无 promscrape 抓取，
# 由 alert-sift 主动 POST import/prometheus，零改动 VM 配置）
VM_IMPORT_URL = os.getenv("ALERT_SIFT_VM_IMPORT_URL",
                          "http://127.0.0.1:9090/api/v1/import/prometheus")
METRICS_PUSH_INTERVAL = _to_int(os.getenv("ALERT_SIFT_METRICS_PUSH_SECONDS", "15"))


# ================= 令牌桶 =================
class TokenBucket:
    """asyncio 令牌桶：take(n) 需 n 个令牌，不足返回 False（不阻塞）。"""

    def __init__(self, rate: float, capacity: int):
        self._rate = rate
        self._capacity = _to_float(capacity)
        self._tokens = _to_float(capacity)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def take(self, n: int = 1) -> bool:
        async with self._lock:
            self._refill()
            if self._tokens >= n:
                self._tokens -= n
                return True
            return False

    def _refill(self) -> None:
        """补充令牌（调用前必须先持有 _lock）。"""
        now = time.monotonic()
        elapsed = now - self._updated
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._updated = now


_bucket = TokenBucket(RATE_LIMIT_RATE, RATE_LIMIT_BURST)


# ================= 后台任务 =================
async def _meta_cleanup_loop(ctx: AppContext, interval: int = META_CLEANUP_INTERVAL) -> None:
    """后台循环：定期清理过期 meta 键。"""
    while True:
        try:
            removed = ctx.store.cleanup_expired_meta()
            if removed:
                logger.info("清理过期 meta %d 条", removed)
        except Exception as exc:  # noqa: BLE001
            logger.warning("meta 清理失败（跳过）: %s", exc)
        await asyncio.sleep(interval)


def _fetch_vmalert_fingerprints() -> set[str]:
    """拉取 vmalert 当前活跃告警 stable_fingerprint 集合。

    P0-1 修复（2026-10-05）：改用 stable_fingerprint，避免 labels 变化导致对账误判。
    """
    from models import Alert
    with httpx.Client(timeout=10) as client:
        resp = client.get(f"{VMALERT_URL}/api/v1/alerts")
        resp.raise_for_status()

    alerts = resp.json().get("data", {}).get("alerts", [])
    fps: set[str] = set()
    for a in alerts:
        if a.get("state") != "firing":
            continue
        labels = {str(k): str(v) for k, v in a.get("labels", {}).items()}
        alert = Alert(rule_name=labels.get("alertname", "unknown"), labels=labels)
        from models import compute_stable_fingerprint
        fps.add(compute_stable_fingerprint(alert))
    return fps


async def _reconcile_loop(state, interval: int = RECONCILE_INTERVAL) -> None:
    """源侧对账循环：清理僵尸 firing 并推送 resolved 通知。

    当前行为：形参是整个 FastAPI app 对象，内部再取 app.state。
    改为直接接收 app.state（State 对象），使 lifespan 不必把 app 透传给后台任务
    （P0-2：lifespan 需要在 MCP 分支与原生分支下都能独立挂载）。
    """
    ctx = state.ctx
    while True:
        try:
            source = await asyncio.to_thread(_fetch_vmalert_fingerprints)
            if source:
                resolved_alerts = ctx.reconcile_active_alerts(source, stale_seconds=600)
            else:
                resolved_alerts = ctx.reconcile_active_alerts(set(), stale_seconds=600)

            if resolved_alerts:
                logger.info("源侧对账生成 %d 条 resolved 告警，送入流水线", len(resolved_alerts))
                for alert in resolved_alerts:
                    result = await run_pipeline(alert, state)
                    await flush_aggregator(state, [result])
        except Exception as exc:  # noqa: BLE001
            logger.warning("源侧对账失败（跳过）: %s", exc)
        await asyncio.sleep(interval)


async def _escalation_loop(state, interval: int = ESCALATION_INTERVAL) -> None:
    """升级策略引擎（P1-1 修复，2026-10-05）。

    从 main.py 内嵌逻辑重构到 pipeline.escalation.EscalationEngine：
      * 使用 stable_fingerprint 做 meta key（P0-1 联动）
      * ack 宽限期可配置（config escalation.ack_grace_seconds）
      * 升级消息复用 notify._friendly_name 友好化
      * 失败不写 meta，下轮自动重试

    当前行为：形参是整个 FastAPI app 对象；改为接收 app.state（同 _reconcile_loop），
    与 lifespan 解耦。
    """
    from pipeline.escalation import EscalationEngine

    ctx = state.ctx
    cfg = ctx.cfg
    esc_cfg = cfg.get("escalation", {})
    if not esc_cfg.get("enabled", False):
        logger.info("升级引擎未启用（config escalation.enabled=false）")
        return

    # 机器人 URL 解析（环境变量优先，与 notify 一致）
    #
    # 当前行为：升级通知与业务通知复用同一组 WECOM_BOT_<PROJ> 机器人，
    # 值班群无法区分消息来源（业务告警 vs 升级提醒），也无法把升级通知
    # 单独路由到专用机器人。
    # 改为：升级引擎优先使用独立机器人 WECOM_BOT_ESCALATION_<PROJ>，
    # 未配置时回退 WECOM_BOT_<PROJ>（保持向后兼容：未配置独立 key 时行为不变）。
    resolved_robots: dict[str, str] = {}
    cfg_robots = (cfg.get("notifiers", {}) or {}).get("wecom", {}).get("robots", {}) or {}
    # 独立升级机器人可覆盖配置中不存在的 project
    # （例如只配 WECOM_BOT_ESCALATION_SYS，不在 notifiers.wecom.robots 里）
    for env_key, env_val in os.environ.items():
        if env_key.startswith("WECOM_BOT_ESCALATION_") and env_val:
            resolved_robots[env_key[len("WECOM_BOT_ESCALATION_"):].upper()] = env_val
    for proj, cfg_url in cfg_robots.items():
        url = os.getenv(f"WECOM_BOT_ESCALATION_{proj.upper()}", "")
        if not url:
            url = os.getenv(f"WECOM_BOT_{proj.upper()}", "")
        if not url and cfg_url:
            url = os.path.expandvars(cfg_url)
        if url and not url.startswith("${"):
            # 同时登记原始 key 与大写 key：原始 key 保持旧行为不变，
            # 大写 key 让 escalation 策略里的 notify:[SYS] 之类匹配稳定。
            resolved_robots[proj] = url
            resolved_robots.setdefault(proj.upper(), url)
    # 日志只打印脱敏后的 URL（企微 webhook key 在 query 里，明文入日志即凭据泄露）
    for proj in sorted(set(resolved_robots)):
        logger.debug("升级通知机器人 project=%s url=%s",
                     proj, _safe_url(resolved_robots[proj]))

    engine = EscalationEngine(cfg, resolved_robots)

    while True:
        try:
            n = await engine.run_once(ctx)
            if n:
                logger.info("升级引擎本轮推送 %d 条升级通知", n)
        except Exception as exc:  # noqa: BLE001
            logger.warning("升级引擎异常（跳过）: %s", exc)
        await asyncio.sleep(interval)


def _parse_ts_meta(ctx, key: str) -> float | None:
    """读取 meta 时间戳；脏数据/None 安全。"""
    try:
        raw = ctx.store.get_meta(key)
        if raw is None:
            return None
        return float(raw)
    except (TypeError, ValueError):
        return None


def _fmt_ts(iso_str: str) -> str:
    """ISO 时间 → MM-DD HH:MM（升级通知用）。"""
    if not iso_str:
        return "N/A"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.astimezone().strftime("%m-%d %H:%M")
    except Exception:  # noqa: BLE001
        return iso_str[:16].replace("T", " ")


async def _metrics_push_loop(state,
                             interval: int = METRICS_PUSH_INTERVAL) -> None:
    """自观测指标主动推送（P0-③）：把 /metrics 文本 POST 到 VM import/prometheus。

    VictoriaMetrics 容器无 promscrape 抓取（数据全走 remoteWrite/import），
    故由 alert-sift 主动推送自身指标，Grafana 可直接查询 alert_sift_* 系列。
    失败静默（下次重试），不影响告警主链路。

    当前行为：形参是整个 FastAPI app 对象，但函数体实际并不使用它。
    改为接收 app.state（与 _reconcile_loop / _escalation_loop 一致），
    与 lifespan 解耦。
    """
    while True:
        try:
            text = metrics.render()
            if not text:
                await asyncio.sleep(interval)
                continue
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(
                    VM_IMPORT_URL, content=text,
                    headers={"Content-Type": "text/plain"})
            ok = resp.status_code == 204 or resp.status_code == 200
            metrics.inc("alert_sift_metrics_push_total", ok=str(ok).lower())
            if not ok:
                logger.warning("自监控指标推送 VM 失败 status=%s", resp.status_code)
        except Exception as exc:  # noqa: BLE001 —— 推送失败不影响主链路
            logger.debug("自监控指标推送异常（跳过）: %s", exc)
        await asyncio.sleep(interval)


# ================= 鉴权/限流工具 =================
def _token_ok(got: str, want: str) -> bool:
    """恒定时间比较，防时序侧信道。"""
    import hmac
    return bool(got) and bool(want) and hmac.compare_digest(got, want)


def _bearer_token(request: Request) -> str:
    """从 Authorization: Bearer <token> 中提取凭证。

    P0-6（2026-09-30）：vmalert 改用 -notifier.bearerTokenFile 传凭据，
    使 token 不再出现在命令行（/proc/<pid>/cmdline）与 journal 中。
    解析失败返回空串，交由 _token_ok 判定为未授权。
    """
    auth = request.headers.get("Authorization", "")
    prefix = "Bearer "
    if auth.startswith(prefix):
        return auth[len(prefix):].strip()
    return ""


def _estimate_alert_count(body: bytes) -> int:
    """粗略估算批次告警条数。"""
    if not body:
        return 1
    try:
        data = json.loads(body)
        if isinstance(data, list):
            return max(len(data), 1)
        if isinstance(data, dict) and isinstance(data.get("alerts"), list):
            return max(len(data["alerts"]), 1)
    except Exception as _exc:  # noqa: BLE001
        logger.debug("忽略预期内异常（降级路径）: %s", _exc)
    return 1


# ================= 应用工厂 =================
def create_app() -> FastAPI:
    ctx = AppContext(CONFIG_PATH, DB_PATH)
    # 当前行为：这一行原本写成 `_unused_bind = ctx.store`，把 store 绑定到了
    # 一个用不到的名字上，而下方 _lifespan 里的 `state_store.cleanup_expired_meta()`
    # 与 `state_store.close()` 仍引用旧名 state_store —— 模块级根本没有这个名字，
    # 运行到启动清理时抛 NameError（启动清理在 try 里被 except Exception 吞掉，
    # 退出时的 state_store.close() 在 finally 里则直接抛 NameError）。
    # 改法：把绑定名改回 state_store，与下方引用一致。
    state_store = ctx.store

    @asynccontextmanager
    async def _lifespan(_app: FastAPI | None = None):
        # 当前行为：_lifespan 形参写死为 app（FastAPI 实例），但 FastAPI 原生
        # lifespan 协议与 MCP lifespan 协议签名不同，导致非 MCP 分支无法直接复用；
        # 且下方原实现从 else 分支完全没挂载过 lifespan（见 create_app 末尾）。
        # 改法：形参改为可选；取 app 时优先用传入值，缺省回退到闭包里的 app
        # （create_app 末尾赋值），从而两种挂载方式行为完全一致。
        # 注意：闭包里的 app 在 create_app 返回前已赋值，lifespan 只在服务启动时执行。
        the_app = _app if _app is not None else app
        state = the_app.state

        setup_logging(ctx.cfg.get("log_level", "INFO"))
        logger.info("alert-sift 启动完成，config=%s", CONFIG_PATH)

        # 启动清理存量过期 meta
        # P2-8（2026-10-30）：当前行为是用 `except Exception` + debug 日志兜底，
        # 会把 NameError 这类真 bug 一并吞掉 —— 启动清理实际从未生效且完全不可见。
        # 改法：只捕获存储层异常（sqlite3.Error / OSError），其余异常（如
        # NameError / AttributeError）直接抛出，让真 bug 立刻暴露而不是静默降级。
        try:
            removed = state_store.cleanup_expired_meta()
            if removed:
                logger.info("启动清理过期 meta %d 条", removed)
        except (sqlite3.Error, OSError) as _exc:
            logger.warning("启动清理过期 meta 失败（跳过，不阻断启动）: %s", _exc)

        # 启动后台任务（轻量版 2026-09-04：外部化聚合循环已删除——
        # external_state 生产恒 false，单实例进程内窗口足够）
        cleanup_task = asyncio.create_task(_meta_cleanup_loop(ctx))
        reconcile_task = asyncio.create_task(_reconcile_loop(state))
        # P1-⑧ 升级引擎 + P0-③ 自监控指标推送（2026-08-22）
        escalation_task = asyncio.create_task(_escalation_loop(state))
        metrics_push_task = asyncio.create_task(_metrics_push_loop(state))

        try:
            yield
        finally:
            cleanup_task.cancel()
            reconcile_task.cancel()
            escalation_task.cancel()
            metrics_push_task.cancel()
            state_store.close()

    # MCP 挂载（可选：缺 fastmcp 时降级为纯 REST，不影响告警主链路）
    mcp_http_app = None
    try:
        from mcp_server import create_mcp_app
        mcp_http_app = create_mcp_app(ctx)
    except ImportError as exc:
        logger.warning('MCP Server 不可用（pip install "alert-sift[mcp]" 启用）: %s', exc)

    if mcp_http_app is not None:
        @asynccontextmanager
        async def _combined_life(_app: FastAPI | None = None):
            # 与 _lifespan 同样的解析方式：优先用传入的 app，缺省回退闭包 app，
            # 保证 MCP 分支与原生分支拿到的是同一个 FastAPI 实例。
            the_app = _app if _app is not None else app
            async with mcp_http_app.lifespan(the_app):
                async with _lifespan(the_app):
                    yield
        app_kwargs = {"lifespan": _combined_life}
    else:
        # 当前行为（缺陷）：else 分支是 app_kwargs = {}，_lifespan 从未被挂载。
        # 而 requirements.txt 里 fastmcp 只是可选 extra，Dockerfile 与 ci.yml
        # 都只装基础依赖 —— 默认部署路径就是 else 分支，
        # 于是 _meta_cleanup_loop / _reconcile_loop / _escalation_loop /
        # _metrics_push_loop 四个后台任务一个都不启动（meta 永不清理、
        # 僵尸 firing 永不回收、升级引擎永不触发、自监控指标永不推送）。
        # 改法：else 分支同样挂载 _lifespan，两个分支行为一致。
        app_kwargs = {"lifespan": _lifespan}

    # 版本号唯一真相源是 app/__init__.py 的 __version__（registry.yaml 指定）。
    # 当前行为：这里硬编码了第二份副本 version="0.2.0"，与 __init__.py 的
    # "0.1.0" 分裂，改一处漏一处。改法：统一从 app/__init__.py 导入。
    app = FastAPI(title="alert-sift", version=_app_version(), **app_kwargs)
    app.state.ctx = ctx
    app.state.cfg = ctx.cfg
    app.state.store = ctx.store
    app.state._aggregator_lock = asyncio.Lock()
    app.state.aggregator = None

    # 守卫中间件
    @app.middleware("http")
    async def _guard_middleware(request: Request, call_next):
        path = request.url.path
        # vmalert/Alertmanager 兼容: /api/v1/alerts → /api/v2/alerts
        #
        # 当前行为：只改了 request.scope["path"]，本地 path 变量仍是 "/api/v1/alerts"，
        # 于是下面按 path 判断的鉴权（elif path == "/api/v2/alerts"）与限流
        # （if path == "/api/v2/alerts"）对 v1 兼容入口全部不生效 ——
        # /api/v1/alerts 是一条完全无鉴权、无限流的旁路。
        # 改法：本地 path 一并归一，后续鉴权/限流判断与路由实际落点保持一致。
        if path == "/api/v1/alerts":
            request.scope["path"] = "/api/v2/alerts"
            path = "/api/v2/alerts"

        # 1) 鉴权
        #
        # 【行为变更说明 —— 2026-10-30 起由 fail-open 改为 fail-closed】
        # 当前行为（修复前）：`if want and not _token_ok(...)` —— 当
        # ALERT_SIFT_ADMIN_TOKEN 未配置时 want 为空串，整个鉴权 if 被短路跳过，
        # /admin/* 与 /mcp 完全无鉴权即可访问。而 /admin 下挂着
        # config_reload / upsert_rule（写 vmalert 规则文件）/
        # update_notifier_route / delete_silence 等高危写操作，
        # Dockerfile 又是 --host 0.0.0.0 对外暴露 ⇒ 任何人可改规则/静默/机器人路由。
        # 修复后语义（fail-closed）：
        #   * env 未配置      → 503 "ALERT_SIFT_ADMIN_TOKEN 未配置，管理面已禁用"
        #     （不返回 401 是因为这不是"凭证错了"，而是"服务未就绪"；
        #       503 让编排/探针能明确区分"配置缺失"与"鉴权失败"）
        #   * env 已配置但不符 → 401
        if path.startswith("/admin") or path.startswith("/mcp"):
            want = os.getenv("ALERT_SIFT_ADMIN_TOKEN", "")
            if not want:
                # fail-closed：未配置管理令牌 = 管理面禁用，绝不匿名放行
                logger.error(
                    "管理面请求被拒：ALERT_SIFT_ADMIN_TOKEN 未配置，管理面已禁用 path=%s",
                    path)
                return JSONResponse(
                    status_code=503,
                    content={"detail": "ALERT_SIFT_ADMIN_TOKEN 未配置，管理面已禁用"})
            if not _token_ok(request.headers.get("X-Admin-Token", ""), want):
                return JSONResponse(status_code=401,
                                    content={"detail": "invalid or missing admin token"})
        elif path == "/api/v2/alerts":
            want = os.getenv("ALERT_SIFT_PUSH_TOKEN", "")
            # P0-6: 支持 Bearer（vmalert bearerTokenFile）与 X-Push-Token（向后兼容）
            _got = _bearer_token(request) or request.headers.get("X-Push-Token", "")
            if not want:
                # 【行为变更 —— fail-closed】当前行为是 `if want and not _token_ok(...)`，
                # 未配置 ALERT_SIFT_PUSH_TOKEN 时入站 webhook 完全匿名 —— 任何能访问
                # 9999 端口的人都能伪造告警（污染去重/静默状态、刷企微机器人配额、
                # 甚至配合畸形 payload 打内存/CPU）。修复后：未配置令牌 = 入站拒绝。
                # 迁移开关：ALERT_SIFT_ALLOW_ANON_PUSH=1 可临时保留匿名入站
                # （仅用于存量部署灰度迁移；开启时会打 WARNING 日志提醒尽快配置令牌）。
                if os.getenv("ALERT_SIFT_ALLOW_ANON_PUSH", "") == "1":
                    logger.warning(
                        "ALERT_SIFT_ALLOW_ANON_PUSH=1 已开启：入站 webhook 处于匿名模式，"
                        "任何能访问本端口的客户端都可伪造告警，请尽快配置 "
                        "ALERT_SIFT_PUSH_TOKEN")
                else:
                    logger.error(
                        "入站告警被拒：ALERT_SIFT_PUSH_TOKEN 未配置，入站已禁用 path=%s",
                        path)
                    return JSONResponse(
                        status_code=503,
                        content={"detail": "ALERT_SIFT_PUSH_TOKEN 未配置，入站推送已禁用"})
            elif not _token_ok(_got, want):
                return JSONResponse(status_code=401,
                                    content={"detail": "invalid or missing push token"})

        # 2) 入站限流
        if path == "/api/v2/alerts":
            try:
                body = await request.body()
                n = _estimate_alert_count(body)
                if not await _bucket.take(max(n, 1)):
                    metrics.inc("alert_sift_rate_limited_total", path="api_v2_alerts")
                    logger.warning("入站限流触发 n=%d", n)
                    return JSONResponse(status_code=429,
                                        content={"detail": "rate limit exceeded"})
            except Exception as e:  # noqa: BLE001
                # 当前行为：限流器自身异常时降级放行（可用性优先，告警不能因限流器
                # 故障而全丢），但日志级别是 error —— 与"真的限流触发"混在一起，
                # 且没有任何计数器，降级多少次完全不可观测。
                # 改法：级别提到 warning（仍高于 info，运维能发现但不再伪装成致命错误），
                # 并加降级计数指标，让"限流器坏了"的次数可被 Grafana/日志观测。
                # 取舍说明：此处刻意保留 fail-open —— 限流是保护措施而非业务正确性
                # 依赖，宁可放过少量流量也不能让告警链路整体失效。
                metrics.inc("alert_sift_rate_limit_degraded_total", path=path)
                logger.warning("入站限流异常, 降级放行（fail-open 有意保留）path=%s: %s",
                               path, e)

        # 3) 响应 + 指标
        resp = await call_next(request)
        metrics.inc("alert_sift_http_requests_total", path=path, code=str(resp.status_code))
        return resp

    # 控制面
    from admin import router as admin_router
    app.include_router(admin_router)
    if mcp_http_app is not None:
        app.mount("/mcp", mcp_http_app)

    # 数据面
    @app.get("/healthz")
    async def healthz():
        # P1-2（2026-10-15）：透出 per-robot 推送健康摘要
        push_health = {}
        try:
            # Notifier 实例在 Aggregator 内（state.aggregator 惰性创建），
            # 尚未创建时 push_health 为空属正常（进程启动后首批推送即出现）
            agg = getattr(app.state, "aggregator", None)
            notifier = getattr(agg, "notifier", None) if agg is not None else None
            if notifier is not None and getattr(notifier, "_health", None):
                for proj, h in notifier._health.items():
                    push_health[proj] = {
                        "ok": h.last_error == "",
                        "consecutive_failures": h.consecutive_failures,
                        "last_ok_age_s": round(
                            time.time() - h.last_ok_ts, 1) if h.last_ok_ts else None,
                        "last_error": h.last_error,
                    }
        except Exception as _exc:  # noqa: BLE001 —— 健康摘要失败不影响 healthz 主应答
            logger.debug("忽略预期内异常（降级路径）: %s", _exc)
        return {"status": "ok", "push_health": push_health, **ctx.db_stats()}

    @app.get("/metrics")
    async def metrics_endpoint():
        metrics.record_uptime()
        try:
            metrics.set_gauge("alert_sift_active_alerts",
                              ctx.store.conn.execute(
                                  "SELECT COUNT(*) FROM active_alerts WHERE status='firing'"
                              ).fetchone()[0])
        except Exception as _exc:  # noqa: BLE001
            logger.debug("忽略预期内异常（降级路径）: %s", _exc)
        # P0-③：failed_push 存量 gauge（待补推/审计的失败批次数）
        try:
            from pipeline.notify import FAILED_PUSH_DIR
            pending = len(list(Path(FAILED_PUSH_DIR).glob("failed_*.json")))
            metrics.set_gauge("alert_sift_failed_push_pending", pending)
        except Exception as _exc:  # noqa: BLE001
            logger.debug("忽略预期内异常（降级路径）: %s", _exc)
        return PlainTextResponse(metrics.render())

    @app.post("/api/v2/alerts")
    async def receive_alerts(req: Request):
        try:
            payload = await req.json()
            batch: AlertBatch = parse_am_payload(payload)
        except Exception as exc:  # noqa: BLE001
            logger.error("解析告警载荷失败: %s", exc)
            return JSONResponse(status_code=400, content={"detail": f"bad payload: {exc}"})

        # P0-2 同类修复（2026-10-30）：ack 宽限期分支要构造 ack 状态的 Alert，
        # 但本模块顶层只导入了 AlertBatch / parse_am_payload，没有 Alert ——
        # 命中 ack 宽限分支时必抛 NameError（被外层 try 吞掉后整批告警丢失）。
        from models import Alert
        results: list[PipelineResult] = []
        for alert in batch.alerts:
            metrics.inc("alert_sift_alerts_received_total", status=alert.status)

            if alert.status == "resolved":
                app.state.store.remove_active(alert.fingerprint)
            else:
                # P1-③（2026-08-25）：ack 宽限期(30min)内 vmalert 重推时，
                # 保留 ack 状态（不覆盖回 firing）且不进通知链路（不重复轰炸）。
                # starts_at 保留首次触发时间，供升级引擎按"已持续时长"继续评估。
                acked = app.state.store.get_meta(f"acked:{alert.stable_fingerprint}")  # P0-1 修复：用稳定指纹
                if acked is not None:
                    prev = app.state.store.conn.execute(
                        "SELECT payload FROM active_alerts WHERE fingerprint=?",
                        (alert.fingerprint,)).fetchone()
                    prev_payload = json.loads(prev["payload"]) if prev else None
                    app.state.store.upsert_active(Alert(
                        rule_name=alert.rule_name, labels=alert.labels,
                        annotations=alert.annotations, status="ack",
                        severity=alert.severity, project=alert.project,
                        starts_at=(prev_payload or {}).get("starts_at") or alert.starts_at,
                        fingerprint=alert.fingerprint,
                        times_fired=alert.times_fired,
                    ))
                    metrics.inc("alert_sift_ack_grace_skip_total",
                                project=alert.project,
                                severity=alert.severity or "P3")
                    continue  # 宽限期内不通知，不进流水线
                app.state.store.upsert_active(alert)

            result = await run_pipeline(alert, app.state)
            results.append(result)

            if alert.status != "resolved" and result.actions:
                app.state.store.upsert_active(alert)

        app.state.store.add_history_batch(batch.alerts)
        await flush_aggregator(app.state, results)
        return {"received": len(results), "status": "ok"}

    return app


async def flush_aggregator(state, results: list[PipelineResult]) -> None:
    """将流水线结果送入聚合器（惰性创建，进程内窗口）。"""
    agg: Aggregator | None = state.aggregator
    if agg is None:
        agg = Aggregator(
            window=state.cfg.get("aggregate", {}).get("window_seconds", 30),
            notifier_cfg=state.cfg.get("notifiers", {}),
            cfg=state.cfg,
            store=getattr(state, "store", None),  # P0-2：快照持久化
        )
        state.aggregator = agg
        # P0-2：首次创建时恢复上次崩溃残留的聚合队列
        await agg.recover()
    await agg.push_many(results)


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=_to_int(os.getenv("ALERT_SIFT_PORT", "9999")),
        reload=False,
    )
