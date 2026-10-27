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
import json
import logging
import os
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
from utils import setup_logging


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


async def _reconcile_loop(app: FastAPI, interval: int = RECONCILE_INTERVAL) -> None:
    """源侧对账循环：清理僵尸 firing 并推送 resolved 通知。"""
    ctx = app.state.ctx
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
                    result = await run_pipeline(alert, app.state)
                    await flush_aggregator(app.state, [result])
        except Exception as exc:  # noqa: BLE001
            logger.warning("源侧对账失败（跳过）: %s", exc)
        await asyncio.sleep(interval)


async def _escalation_loop(app: FastAPI, interval: int = ESCALATION_INTERVAL) -> None:
    """升级策略引擎（P1-1 修复，2026-10-05）。

    从 main.py 内嵌逻辑重构到 pipeline.escalation.EscalationEngine：
      * 使用 stable_fingerprint 做 meta key（P0-1 联动）
      * ack 宽限期可配置（config escalation.ack_grace_seconds）
      * 升级消息复用 notify._friendly_name 友好化
      * 失败不写 meta，下轮自动重试
    """
    from pipeline.escalation import EscalationEngine

    ctx = app.state.ctx
    cfg = ctx.cfg
    esc_cfg = cfg.get("escalation", {})
    if not esc_cfg.get("enabled", False):
        logger.info("升级引擎未启用（config escalation.enabled=false）")
        return

    # 机器人 URL 解析（环境变量优先，与 notify 一致）
    resolved_robots: dict[str, str] = {}
    for proj, cfg_url in cfg.get("notifiers", {}).get("wecom", {}).get("robots", {}).items():
        url = os.getenv(f"WECOM_BOT_{proj.upper()}", "")
        if not url and cfg_url:
            url = os.path.expandvars(cfg_url)
        if url and not url.startswith("${"):
            resolved_robots[proj] = url

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


async def _metrics_push_loop(app: FastAPI,
                             interval: int = METRICS_PUSH_INTERVAL) -> None:
    """自观测指标主动推送（P0-③）：把 /metrics 文本 POST 到 VM import/prometheus。

    VictoriaMetrics 容器无 promscrape 抓取（数据全走 remoteWrite/import），
    故由 alert-sift 主动推送自身指标，Grafana 可直接查询 alert_sift_* 系列。
    失败静默（下次重试），不影响告警主链路。
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
    _unused_bind = ctx.store  # noqa: F841 —— 原变量 state_store

    @asynccontextmanager
    async def _lifespan(app: FastAPI):
        setup_logging(ctx.cfg.get("log_level", "INFO"))
        logger.info("alert-sift 启动完成，config=%s", CONFIG_PATH)

        # 启动清理存量过期 meta
        try:
            removed = state_store.cleanup_expired_meta()
            if removed:
                logger.info("启动清理过期 meta %d 条", removed)
        except Exception as _exc:  # noqa: BLE001
            logger.debug("忽略预期内异常（降级路径）: %s", _exc)

        # 启动后台任务（轻量版 2026-09-04：外部化聚合循环已删除——
        # external_state 生产恒 false，单实例进程内窗口足够）
        cleanup_task = asyncio.create_task(_meta_cleanup_loop(ctx))
        reconcile_task = asyncio.create_task(_reconcile_loop(app))
        # P1-⑧ 升级引擎 + P0-③ 自监控指标推送（2026-08-22）
        escalation_task = asyncio.create_task(_escalation_loop(app))
        metrics_push_task = asyncio.create_task(_metrics_push_loop(app))

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
        async def _combined_life(app: FastAPI):
            async with mcp_http_app.lifespan(app):
                async with _lifespan(app):
                    yield
        app_kwargs = {"lifespan": _combined_life}
    else:
        app_kwargs = {}

    app = FastAPI(title="alert-sift", version="0.2.0", **app_kwargs)
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
        if path == "/api/v1/alerts":
            request.scope["path"] = "/api/v2/alerts"

        # 1) 鉴权
        if path.startswith("/admin") or path.startswith("/mcp"):
            want = os.getenv("ALERT_SIFT_ADMIN_TOKEN", "")
            if want and not _token_ok(request.headers.get("X-Admin-Token", ""), want):
                return JSONResponse(status_code=401,
                                    content={"detail": "invalid or missing admin token"})
        elif path == "/api/v2/alerts":
            want = os.getenv("ALERT_SIFT_PUSH_TOKEN", "")
            # P0-6: 支持 Bearer（vmalert bearerTokenFile）与 X-Push-Token（向后兼容）
            _got = _bearer_token(request) or request.headers.get("X-Push-Token", "")
            if want and not _token_ok(_got, want):
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
                logger.error("入站限流异常, 降级放行 path=%s: %s", path, e)

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
