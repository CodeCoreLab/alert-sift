# -*- coding: utf-8 -*-
"""L7 通知 —— Webhook 多机器人路由 + Jinja2 渲染 + 重试 + per-robot 出站限流

配置（config/notifiers.yaml）：
  notifiers:
    wecom:
      robots:
        APP:  https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=<你的key>
        OPS:  https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=<你的key>
  retry: {max_attempts: 3, backoff: [1, 3, 5]}

per-robot 出站限流（2026-08-22 新增）：
  企微 webhook 官方限流 20 条/分钟/机器人。notify 层加令牌桶
  （默认 15 条/min，env ALERT_SIFT_WECOM_RATE_PER_MIN 覆盖），
  风暴时超限批降级落盘审计（同 failed_push），避免 45009 打满配额
  抢占 P0 推送。P0 告警不节流（最高优先级必须可达）。

阶段 2.2（降级方案，2026-08-13）：推送最终失败时告警批次落盘
  data/failed_push/（JSON 文件），供人工补推/审计；不做自动重投队列。

重构（2026-08-15）：
  * 提取 WECOM_MAX_BYTES / FAILED_PUSH_DIR 为模块常量（消除魔法值）
  * 新增 _validate_payload 方法，校验渲染结果完整性
  * _resolve_robots 增加空 URL 过滤
  * _post_with_retry 增加超时可配置
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from jinja2 import Environment, FileSystemLoader, select_autoescape

from models import Alert
from severity import is_p0 as _is_p0


_SECONDS_PER_MINUTE = 60


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

logger = logging.getLogger("alert-sift.notify")

# ---------- 常量 ----------
TEMPLATE_DIR = Path(__file__).parent.parent / "templates"

# 企微 markdown 消息体上限 4096 字节（UTF-8，中文 3 字节/字）
WECOM_MAX_BYTES = 4096

# 失败落盘目录：环境变量可配置，默认项目 data/failed_push
FAILED_PUSH_DIR = Path(os.getenv("ALERT_SIFT_FAILED_PUSH_DIR", "data/failed_push"))

# 默认 HTTP 超时（秒）
_DEFAULT_HTTP_TIMEOUT = 10

# 秒级上下文最多查询的主机数（防风暴期间放大对 VM 的查询）
MAX_HOST_CONTEXT = 3

# 默认重试配置
_DEFAULT_RETRY = {"max_attempts": 3, "backoff": [1, 3, 5]}

# 企微 webhook 官方限流 20 条/min/机器人，本层默认 15 条/min 预留余量
_DEFAULT_RATE_PER_MIN = 15

# 业务时窗（2026-08-14 由 alert_feedback_loop 迁移）：固定敏感时段，
# 命中时在企微推送中标注，提示评估业务影响。start 闭 / end 开。
BUSINESS_WINDOWS = [
    ("09:15", "09:30", "开盘集合竞价"),
    ("15:00", "15:30", "收盘清算"),
]

# P1-2（2026-10-15）：per-robot 推送健康状态机（借鉴 OpenOcta BaseRuntimeImpl
# 连接状态机「断连不静默」）。内存态即可：
#   * gauge 经 main._metrics_push_loop 每 15s 推 VM，Grafana 可直接配
#     consecutive_failures>=3 告警（对齐自动化任务规约「连续 3 次才告警」）；
#   * 连续失败≥3 时本地 logger.error 一次性高声告警（冷却 10min，防刷屏）。
_PUSH_HEALTH_COOLDOWN = 600  # 连续失败高声告警冷却（秒）


class _PushHealth:
    """per-robot 推送健康状态：last_ok_ts / last_error / consecutive_failures。"""

    def __init__(self) -> None:
        self.last_ok_ts: float = 0.0
        self.last_error: str = ""
        self.consecutive_failures: int = 0
        self._last_shout_ts: float = 0.0

    def record_ok(self, project: str) -> None:
        self.last_ok_ts = time.time()
        self.last_error = ""
        self.consecutive_failures = 0
        self._emit(project)
        self._last_shout_ts = 0.0  # 恢复后重置冷却

    def record_fail(self, project: str, err: str) -> None:
        self.last_error = (err or "unknown")[:200]
        self.consecutive_failures += 1
        self._emit(project)
        # 连续失败≥3 且未在冷却期 → logger.error 高声一次
        now = time.time()
        if (self.consecutive_failures >= 3
                and now - self._last_shout_ts >= _PUSH_HEALTH_COOLDOWN):
            logger.error(
                "【推送通道异常】project=%s 连续失败 %d 次，last_error=%s"
                "（Grafana 告警项：alert_sift_wecom_robot_failures>=3）",
                project, self.consecutive_failures, self.last_error)
            self._last_shout_ts = now

    def _emit(self, project: str) -> None:
        """打点 gauge：ok/failures/last_ok_age。打点失败不阻断推送。"""
        try:
            import metrics as _m
            _m.set_gauge("alert_sift_wecom_robot_ok",
                         1.0 if self.last_error == "" else 0.0, project=project)
            _m.set_gauge("alert_sift_wecom_robot_failures",
                         float(self.consecutive_failures), project=project)
            age = (time.time() - self.last_ok_ts) if self.last_ok_ts else -1
            _m.set_gauge("alert_sift_wecom_robot_last_ok_age_seconds",
                         round(age, 1), project=project)
        except Exception:  # noqa: BLE001 —— 打点失败不影响推送主链路
            logger.debug("推送健康打点失败 project=%s", project, exc_info=True)


class _RobotBucket:
    """per-robot 令牌桶：take(n) 不足返回 False（不阻塞）。

    与入站限流 TokenBucket 同构，独立实现避免跨模块耦合。
    支持持久化：进程重启后从文件恢复令牌数，防止重启期间超限流。
    """

    def __init__(self, rate_per_sec: float, capacity: int, persist_path: str = ""):
        self._rate = rate_per_sec
        self._capacity = _to_float(capacity)
        # P1-2 修复（2026-10-05）：默认禁用持久化（内存令牌足够，重启归零可接受）。
        # 保留接口便于未来重启保令牌场景启用；调用方传 persist_path="" 即内存模式。
        self._persist_path = ""  # 强制内存模式，忽略外部传入
        self._tokens = _to_float(self._capacity)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    def _load(self) -> float:
        """从持久化文件恢复令牌数；失败回退满桶。"""
        if not self._persist_path:
            return _to_float(self._capacity)
        try:
            import json as _json
            with open(self._persist_path, "r", encoding="utf-8") as f:
                data = _json.load(f)
            saved = float(data.get("tokens", self._capacity))
            return min(saved, self._capacity)
        except Exception:
            return float(self._capacity)

    def _save(self) -> None:
        """持久化当前令牌数；失败静默（不影响主流程）。"""
        if not self._persist_path:
            return
        try:
            import json as _json
            import os as _os
            _os.makedirs(_os.path.dirname(self._persist_path), exist_ok=True)
            tmp = self._persist_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                _json.dump({"tokens": self._tokens, "updated": time.time()}, f)
            _os.replace(tmp, self._persist_path)
        except Exception as exc:
            # 落盘失败 → 进程重启后令牌数归零、限流窗口重置（易触发上游 45009）
            logger.warning("限流令牌持久化失败 path=%s: %s",
                           self._persist_path, exc, exc_info=True)

    async def take(self, n: int = 1) -> bool:
        async with self._lock:
            now = time.monotonic()
            self._tokens = min(self._capacity,
                               self._tokens + (now - self._updated) * self._rate)
            self._updated = now
            if self._tokens >= n:
                self._tokens -= n
                self._save()
                return True
            return False


# ---------- 业务时窗工具 ----------
def get_active_business_window(now: datetime | None = None) -> str | None:
    """返回当前命中的业务时窗标签；无命中返回 None。零依赖、零网络。"""
    if not BUSINESS_WINDOWS:
        return None
    now = now or datetime.now()
    cur = now.hour * _SECONDS_PER_MINUTE + now.minute
    for start, end, label in BUSINESS_WINDOWS:
        try:
            sh, sm = (int(x) for x in start.split(":"))
            eh, em = (int(x) for x in end.split(":"))
        except (ValueError, AttributeError):
            logger.warning("业务时窗配置格式错误，跳过: %s", (start, end, label))
            continue
        if sh * _SECONDS_PER_MINUTE + sm <= cur < eh * _SECONDS_PER_MINUTE + em:  # start 闭、end 开
            return label


def _business_window_tip() -> str:
    """业务时窗提示段：命中时返回一行，否则空串。"""
    label = get_active_business_window()
    if not label:
        return ""
    return f"\n> 当前处于「{label}」敏感时段，请评估该告警对交易业务的影响优先级\n"


# ---------- 消息处理工具 ----------
def _safe_url(url: str) -> str:
    """脱敏 webhook URL：只保留 scheme+host+path，抹掉 query string。

    背景（2026-10-30 安全修复）：企微机器人 webhook 形如
        https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=<SECRET>
    其中 `key=` 就是机器人凭据本身。当前行为是通知失败时把完整 URL 直接
    打进日志（notify.py 三处 + escalation.py），日志落盘/被采集后即等于
    凭据泄露，可被直接用于向任意群发消息。

    改法：所有涉及 webhook URL 的日志统一走本函数，保留 scheme://host/path
    便于定位是哪个群/哪个端点，query string 整体丢弃。

    Args:
        url: 原始 webhook URL（可能为空、可能不是合法 URL）。

    Returns:
        脱敏后的 URL；无法解析时返回占位串，绝不回显原始 query。
    """
    if not url:
        return "<empty-url>"
    try:
        parts = urlsplit(url)
    except ValueError:
        # URL 本身非法（极端输入）：连 host/path 都不保证安全，直接占位
        return "<invalid-url>"
    if not parts.scheme or not parts.netloc:
        return "<invalid-url>"
    path = parts.path or "/"
    return f"{parts.scheme}://{parts.netloc}{path}"


def _scrub(text: str, url: str) -> str:
    """把文本中出现的原始 webhook URL 替换成脱敏形式。

    httpx 的部分异常（InvalidURL / UnsupportedProtocol / 重定向类）会把
    请求 URL 原文写进 str(exc)，日志里打印 exc 就等于间接把 key= 凭据打出去。
    故凡是要记录 webhook URL 相关异常的日志，都先用本函数过一遍。

    Args:
        text: 待脱敏文本（通常是 str(exc)）。
        url: 对应的 webhook URL（用于定位需要替换的原文）。

    Returns:
        脱敏后的文本；url 为空或文本中不含该 URL 时原样返回。
    """
    if not url or not text:
        return text
    return text.replace(url, _safe_url(url))


def _md_code(value: str) -> str:
    """把值渲染成可安全嵌入 markdown 行内代码（`...`）的形态。

    当前行为：模板把主机名/IP 用反引号包进行内代码展示（`{{ host_display }}`），
    而 host / ip 来自上游 Alertmanager 的 labels（外部可控）。
    autoescape 不会转义反引号 —— 标签里带一个反引号就能提前闭合代码段，
    再往消息里塞伪造的 markdown 链接/图片。

    改法：去掉值里的反引号（代码段内容里本就不该出现反引号），
    并交给 autoescape 继续处理 HTML 特殊字符。

    Args:
        value: 待处理的标签值（主机名 / IP 等）。

    Returns:
        已剔除反引号的文本。
    """
    return str(value or "").replace("`", "")


def _md_link_url(value: str) -> str:
    """把 URL 渲染成可安全嵌入 markdown 链接目标的形态（配合模板内 |safe 使用）。

    当前行为：模板直接输出 {{ a.annotations.runbook }}。P2-5 开启 autoescape 后，
    '&' 会被 HTML 转义成 '&amp;'，markdown 链接目标里的查询串参数就断了；
    且 annotations 来自外部（上游 Alertmanager webhook），其中可含 ')'
    提前闭合链接再插入伪造的 markdown 链接。

    改法：
      1) 只允许 http/https 方案（挡掉 javascript: 之类伪协议）；
      2) 去掉控制字符（非打印字符）；空白字符改为 percent-encode（%20）——
         直接删空白会改变 URL 语义，而 markdown 链接目标里的裸空白
         会被多数 markdown 解析器当作链接结束符；
      3) 只 percent-encode 会破坏 markdown 链接语法的字符
         （空格、圆括号、尖括号、引号、反引号），
         保留 & = ? / : # 等 URL 结构字符，查询串不被破坏。

    返回值已是安全形态，模板里用 |safe 包裹，避免被 autoescape 二次 HTML 转义。
    """
    raw = (value or "").strip()
    if not raw:
        return ""
    # 去控制字符（非打印）；空白保留 —— 交给下面的 quote 做 %20 编码
    raw = "".join(ch for ch in raw if ch.isprintable())
    try:
        parts = urlsplit(raw)
    except ValueError:
        return ""
    if parts.scheme and parts.scheme.lower() not in ("http", "https"):
        return ""
    # safe 白名单：URL 结构字符全部保留（查询串不坏），
    # 其余（空格 () <> " ` 等）由 quote 做 percent-encode
    return quote(raw, safe=":/?#[]@!$&'*+,;=%")


def _byte_truncate(s: str, limit: int) -> str:
    """按字节安全截断（不切断 UTF-8 多字节字符）。"""
    if len(s.encode("utf-8")) <= limit:
        return s
    truncated = s.encode("utf-8")[:limit].decode("utf-8", errors="ignore")
    return truncated + "…"


def _strip_ai_summary(alerts: list[Alert]) -> list[Alert]:
    """降级用：去掉逐条 ai_summary（保留聚类块），压缩消息体积。"""
    return [
        replace(a, annotations={
            k: v for k, v in a.annotations.items() if k != "ai_summary"
        })
        for a in alerts
    ]


# ---------- Jinja2 过滤器 ----------
_SEVERITY_EMOJI_MAP = {"P0": "🚨", "P1": "🔥", "P2": "⚠️", "P3": "📌", "P4": "ℹ️"}
_SEVERITY_LABEL_MAP = {"P0": "紧急", "P1": "严重", "P2": "警告", "P3": "提示", "P4": "信息"}
_PROJECT_CN_MAP: dict[str, str] = {}  # 由 config.yaml groups.project_names 注入（见 set_project_names）


def set_project_names(names: dict[str, str]) -> None:
    """注入项目代号 → 中文显示名映射（Notifier 初始化时从 groups.project_names 调用）。"""
    _PROJECT_CN_MAP.clear()
    _PROJECT_CN_MAP.update({str(k): str(v) for k, v in (names or {}).items()})


def _severity_emoji(severity: str) -> str:
    """P0-P4 → emoji（firing 场景）。"""
    return _SEVERITY_EMOJI_MAP.get(severity.upper(), "🔔")


def _severity_label(severity: str) -> str:
    """P0-P4 → 中文分级标签。"""
    return _SEVERITY_LABEL_MAP.get(severity.upper(), "未知")


def _project_cn(project: str) -> str:
    """项目代号 → 中文显示名（未知代号原样返回）。"""
    return _PROJECT_CN_MAP.get((project or "").upper(), project or "")


def _friendly_name(rule_name: str) -> str:
    """SYS|Host|P3|MemLeak → MemLeak（去掉 SYS|Host| 前缀和 |P3| 严重度段）。

    用于告警主标题展示：rule_cn 为空时，从技术 ID 提取可读名称。
    过滤常见元信息前缀（SYS/Host/Service 等）和严重度段（P0-P4）。
    """
    if not rule_name:
        return "未知规则"
    parts = [p.strip() for p in rule_name.split("|") if p.strip()]
    if not parts:
        return rule_name
    keep = []
    for p in parts:
        up = p.upper()
        if up in ("SYS", "HOST", "SERVICE", "BIZ", "APP", "INFRA"):
            continue
        if len(p) == 2 and p[0] == "P" and p[1].isdigit():
            continue
        keep.append(p)
    return " ".join(keep) if keep else rule_name


def _fmt_time(iso_str: str) -> str:
    """ISO 时间 → MM-DD HH:MM（本地时区，容错）。"""
    if not iso_str:
        return "N/A"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.astimezone().strftime("%m-%d %H:%M")
    except Exception:  # noqa: BLE001 —— 时间解析失败不阻断
        return iso_str[:16].replace("T", " ")


def _fmt_duration(iso_str: str) -> str:
    """ISO 开始时间 → 持续时长（P0-④ 通知富化，starts_at → now）。

    格式：<1分 → "X秒"；<1时 → "X分Y秒"；≥1时 → "X小时Y分"；解析失败返回 "N/A"。
    """
    if not iso_str:
        return "N/A"
    try:
        start = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        # 容忍未来时间（时钟偏移），钳位为 0
        seconds = max(int((datetime.now().astimezone() - start.astimezone()).total_seconds()), 0)
    except Exception:  # noqa: BLE001 —— 时间解析失败不阻断
        return "N/A"
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, _SECONDS_PER_MINUTE)
    if h:
        return f"{h}小时{m}分"
    if m:
        return f"{m}分{s}秒"
    return f"{s}秒"


# ---------- 核心类 ----------
class Notifier:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        # 项目中文名（groups.project_names，替代原硬编码映射）
        set_project_names((cfg.get("groups", {}) or {}).get("project_names", {}))
        # P2-5（2026-10-30 安全修复）：Jinja2 自动转义。
        # 当前行为：autoescape=select_autoescape(default=False) —— 转义关闭，
        # 模板里 {{ a.annotations.description }} / {{ a.annotations.llm_advice }} /
        # {{ a.annotations.runbook }} 直接原样输出。这些 annotations 来自上游
        # Alertmanager webhook（外部可控），可以注入 HTML/JS 或伪造 markdown 链接
        # 到企微消息里（消息注入 / 钓鱼）。
        # 改法：开启 autoescape（default=True 且把 .j2 纳入 enabled_extensions，
        # 否则 .j2 模板仍会走 default 分支不被转义）。
        # 说明：转义会把 & < > " ' 变成 HTML 实体；模板中 markdown 链接等
        # 需要保留原样结构的字段已按需处理（见下方 filters 注册与模板内 |safe 用法）。
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(
                default=True, enabled_extensions=("html", "xml", "j2")),
        )
        # 注册 Jinja2 过滤器
        self._env.filters["severity_emoji"] = _severity_emoji
        self._env.filters["severity_label"] = _severity_label
        self._env.filters["fmt_time"] = _fmt_time
        self._env.filters["fmt_duration"] = _fmt_duration
        self._env.filters["friendly_name"] = _friendly_name
        self._env.filters["project_cn"] = _project_cn
        # P2-5：markdown 链接目标专用过滤器（URL 结构字符保留 + 伪协议拦截），
        # 模板里配合 |safe 使用，避免 autoescape 把查询串的 & 转成 &amp;
        self._env.filters["md_link_url"] = _md_link_url
        # P2-5：markdown 行内代码内容过滤器（剔除反引号，防闭合代码段后注入伪造 markdown）
        self._env.filters["md_code"] = _md_code

        # P1-3 修复（2026-10-05）：模板预加载（避免热路径每次 get_template 查盘）
        self._template = self._env.get_template("wecom_markdown.j2")

        # 解析机器人路由
        self._robots = self._resolve_robots(cfg.get("wecom", {}).get("robots", {}))

        # 重试配置
        self._retry = cfg.get("retry", _DEFAULT_RETRY)

        # HTTP 超时
        self._timeout = _to_float(os.getenv("ALERT_SIFT_HTTP_TIMEOUT", str(_DEFAULT_HTTP_TIMEOUT)))

        # per-robot 出站限流（企微 20/min 上限，本层 15/min 预留余量）
        rate_per_min = _to_float(os.getenv("ALERT_SIFT_WECOM_RATE_PER_MIN",
                                       str(_DEFAULT_RATE_PER_MIN)))
        self._rate_per_sec = rate_per_min / _SECONDS_PER_MINUTE
        self._rate_capacity = max(_to_int(rate_per_min), 1)
        self._buckets: dict[str, _RobotBucket] = {}
        # P1-2：per-robot 推送健康状态（project 标签维度）
        self._health: dict[str, _PushHealth] = {}

    @staticmethod
    def _resolve_robots(cfg_robots: dict) -> dict:
        """企微机器人路由解析：环境变量 WECOM_BOT_<PROJECT> 优先于配置文件。

        配置中的 ${VAR} 占位符也会被环境变量展开。
        空 URL 或纯占位符的机器人自动跳过。
        """
        resolved: dict[str, str] = {}
        for project, cfg_url in cfg_robots.items():
            # 环境变量优先
            url = os.getenv(f"WECOM_BOT_{project.upper()}", "")
            if not url and cfg_url:
                url = os.path.expandvars(cfg_url)  # 展开 ${VAR}
            # 过滤空值 / 未展开的占位符
            if url and not url.startswith("${"):
                resolved[project] = url
            else:
                logger.warning("project=%s 机器人 URL 未配置或为占位符，跳过", project)
        return resolved

    # ================= 对外接口 =================
    async def send_batch(self, alerts: list[Alert]) -> bool:
        """按 project 分组渲染企微 Markdown 并推送；失败批次落盘审计。

        断线降级（2026-09-14 新增）：
          企微 webhook 连续 3 次失败 -> 自动切备用通道（WECOM_BOT_FALLBACK 或邮件）。
          P0 告警必须可达：降级通道也失败时，告警仍落盘审计。

        P1-⑤ 路由树（2026-08-22）：severity 级路由覆盖。
          config routing.severity_extra_robots（如 {P0: [SYS]}）：
          P0 告警除本 project 机器人外，额外双发到指定值班群机器人。
          其余 severity 仅推本 project 机器人（默认兜底 SYS）。

        Returns:
            True=全部成功，False=至少一组失败。
        """
        if not alerts:
            return True

        # 幂等过滤（QoS 1 语义：至少一次送达 + 业务幂等）
        # 推送前查 meta pushed:{fingerprint}，已成功且未过期则跳过
        # 推送后写入 meta，覆盖 dedup 窗口（2h）
        alerts = self._filter_already_pushed(alerts)

        # 路由树配置：severity → 额外推送的机器人（project 键）
        extra_robots_cfg = (self.cfg.get("routing", {})
                            .get("severity_extra_robots", {}))
        # P0 默认双发 SYS 值班群（无配置时也生效，P0 必须双通道可达）
        extra_robots = {sev.upper(): list(robots)
                        for sev, robots in extra_robots_cfg.items()}
        extra_robots.setdefault("P0", list(extra_robots.get("P0", ["SYS"])))

        # 按 project 分组
        by_project: dict[str, list[Alert]] = {}
        for a in alerts:
            by_project.setdefault(a.project, []).append(a)

        all_ok = True
        failed_groups: list[tuple[str, list[Alert]]] = []

        for project, group in by_project.items():
            url = self._robots.get(project) or self._robots.get("SYS")
            if not url:
                logger.warning("project=%s 无机器人配置，跳过", project)
                failed_groups.append((project, group))
                continue

            # 路由树拆分：P0 双发额外群，其余走主群
            p0_group = [a for a in group if _is_p0(a)]  # P0-3 修复：统一判定
            # （原 normal_group 变量全仓无引用处，属死代码，已删除 —— 2026-10-30）

            # 主群推送（含 P0 主发 + 常规告警）
            if group:
                ok = await self._send_group(url, project, group, p0_only=False)
                all_ok = all_ok and ok
                if not ok:
                    failed_groups.append((project, group))

            # P0 额外双发值班群（路由树）
            if p0_group:
                for extra_proj in extra_robots.get("P0", []):
                    extra_url = self._robots.get(extra_proj)
                    if not extra_url or extra_url == url:
                        continue
                    ok = await self._send_group(
                        extra_url, f"{project}+{extra_proj}", p0_group,
                        p0_only=True)
                    all_ok = all_ok and ok
                    if not ok:
                        failed_groups.append((f"{project}+{extra_proj}", p0_group))

        # 断线降级：企微连续失败 -> 切备用通道（P0 必须可达）
        if failed_groups:
            fallback_ok = await self._fallback_send(failed_groups)
            if fallback_ok:
                # fallback 成功：此后主群幂等记录仍标记 all_ok 保留，但落盘不从失败组触发
                logger.info("降级通道补推成功，%d 个失败组", len(failed_groups))
            else:
                logger.error("降级通道也失败，告警落盘审计")

        # 阶段 2.2：最终失败批次落盘。
        # P2-修复（2026-09-27）：仅当降级通道也失败时落盘（避免 fallback 成功仍误记"失败"），
        # 且落盘内容为「失败组的去重告警」而非整批（便于按失败组追溯审计）。
        if failed_groups and not fallback_ok:
            failed_only = _dedup_alerts(
                _alerts_of_groups(failed_groups))
            _dump_failed(failed_only, failed_groups)

        # 幂等记录：推送成功的告警写入 meta，下次同 fingerprint 跳过。
        # 有失败组时 all_ok=False 不记录（保守：失败组下轮重试）；
        # 记录的是参与推送的整批，已成功的组因指纹相同仍会跳过，不重复推送。
        if all_ok:
            self._record_pushed(alerts)

        return all_ok

    def _filter_already_pushed(self, alerts: list[Alert]) -> list[Alert]:
        """幂等过滤：跳过已推送且未过期的告警。

        meta 键 pushed:{fingerprint} = 推送时间戳
        TTL 2h（覆盖 dedup 长窗口，防重复推送）
        """
        try:
            store = self._get_store()
            now = time.time()
            ttl = 7200  # 2h
            result = []
            for a in alerts:
                key = "pushed:" + a.fingerprint
                val = store.get_meta(key)
                if val:
                    try:
                        last_ts = float(val)
                        if now - last_ts < ttl:
                            logger.debug("幂等跳过 fingerprint=%s (已推送 %.0fs 前)",
                                         a.fingerprint, now - last_ts)
                            continue
                    except (ValueError, TypeError) as exc:
                        # 元数据损坏 → 视为未推送（宁重复不丢告警），但必须留痕
                        logger.warning("幂等元数据损坏 fingerprint=%s value=%r: %s",
                                       a.fingerprint, val, exc)
                result.append(a)
            if len(result) < len(alerts):
                logger.info("幂等过滤：%d -> %d 条（跳过 %d 条已推送）",
                            len(alerts), len(result), len(alerts) - len(result))
            return result
        except Exception as exc:
            # 幂等检查失败不阻断推送（保守：宁可重复推送也不丢告警）
            logger.warning("幂等过滤失败（已跳过）: %s", exc)
            return alerts

    def _record_pushed(self, alerts: list[Alert]) -> None:
        """记录推送成功：写入 meta pushed:{fingerprint} = ts。

        TTL 2h，覆盖 dedup 长窗口。
        """
        try:
            store = self._get_store()
            now = time.time()
            for a in alerts:
                key = "pushed:" + a.fingerprint
                store.set_meta(key, str(now), ttl=7200)
            logger.debug("幂等记录：%d 条告警", len(alerts))
        except Exception as exc:
            # 记录失败不阻断（下次可能重复推送，但不丢告警）
            logger.warning("幂等记录失败（已跳过）: %s", exc)

    async def _fallback_send(self, failed_groups: list[tuple[str, list[Alert]]]) -> bool:
        """降级通道：企微失败时切备用 webhook 或邮件。

        备用通道优先级：
          1. WECOM_BOT_FALLBACK 环境变量（另一群 webhook）
          2. SMTP 邮件（SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASS/SMTP_TO）
          3. 无备用通道 -> 返回 False（仅落盘审计）

        Returns:
            True=降级成功，False=降级也失败
        """
        fallback_url = os.getenv("WECOM_BOT_FALLBACK", "")
        if fallback_url:
            logger.warning("企微推送失败，切换备用 webhook 通道")
            all_ok = True
            for project, group in failed_groups:
                ok = await self._send_group(fallback_url, f"fallback:{project}", group)
                if not ok:
                    all_ok = False
            return all_ok

        # 尝试邮件通道
        smtp_host = os.getenv("SMTP_HOST", "")
        if smtp_host:
            logger.warning("企微推送失败，切换邮件通道")
            return await self._send_via_email(failed_groups)

        logger.error("无备用通道配置（WECOM_BOT_FALLBACK/SMTP_HOST 均未设置）")
        return False

    async def _send_via_email(self, failed_groups: list[tuple[str, list[Alert]]]) -> bool:
        """邮件降级通道。"""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            smtp_port = int(os.getenv("SMTP_PORT", "465"))
            smtp_user = os.getenv("SMTP_USER", "")
            smtp_pass = os.getenv("SMTP_PASS", "")
            smtp_to = os.getenv("SMTP_TO", "")

            if not all([smtp_user, smtp_pass, smtp_to]):
                logger.error("邮件配置不完整（SMTP_USER/SMTP_PASS/SMTP_TO）")
                return False

            msg = MIMEMultipart()
            msg["From"] = smtp_user
            msg["To"] = smtp_to
            msg["Subject"] = "[alert-sift 降级] 企微推送失败，共 {} 组告警".format(
                sum(len(g) for _, g in failed_groups))

            body = "企微推送失败，以下告警通过邮件降级送达：\n\n"
            for project, group in failed_groups:
                body += "=== {} 项目 ({} 条) ===\n".format(project, len(group))
                for a in group:
                    body += "- {} [{}] {}\n".format(
                        a.severity, a.status, a.rule_name)
                body += "\n"

            msg.attach(MIMEText(body, "plain", "utf-8"))

            if smtp_port == 465:
                server = smtplib.SMTP_SSL(os.getenv("SMTP_HOST", ""), smtp_port, timeout=10)
            else:
                server = smtplib.SMTP(os.getenv("SMTP_HOST", ""), smtp_port, timeout=10)
                server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, [smtp_to], msg.as_string())
            server.quit()

            logger.info("邮件降级推送成功，收件人 %s", smtp_to)
            return True

        except Exception as exc:
            logger.error("邮件降级推送失败: %s", exc)
            return False

    def _get_store(self):
        """获取全局 SQLiteStore 实例（从 main.py 的 app.state.ctx 读取）。"""
        from main import app
        return app.state.ctx.store

    def _health_of(self, project: str) -> _PushHealth:
        """取（或建）project 维度的推送健康状态。"""
        return self._health.setdefault(project, _PushHealth())

    async def _send_group(self, url: str, label: str, group: list[Alert],
                          p0_only: bool = False) -> bool:
        """向单个机器人推送一组告警（含出站限流与打点）。"""
        # per-robot 出站限流：P0 不节流，其余超限降级落盘审计
        # （防风暴打爆企微 45009，低级别告警抢占 P0 配额）
        if not p0_only:
            # P1-2 修复：改为内存令牌桶（重启归零可接受，避免每推送写文件 IO）
            bucket = self._buckets.setdefault(
                url, _RobotBucket(self._rate_per_sec, self._rate_capacity))
            if not await bucket.take(len(group)):
                try:
                    import metrics as _m
                    _m.inc("alert_sift_wecom_rate_limited_total",
                           project=label)
                except Exception:  # noqa: BLE001 —— 打点失败不阻断推送
                    logger.debug("限流打点失败 project=%s", label, exc_info=True)
                logger.warning(
                    "project=%s 出站限流(>%s/min) 告警%d条 降级落盘",
                    label, self._rate_capacity, len(group))
                return False

        payload = await self._render_wecom_payload(group)
        # P0-5 修复：批次含 P0 时启用快通道，单次失败即触发 fallback
        p0_fast = p0_only or any(_is_p0(a) for a in group)
        ok = await self._post_with_retry(url, payload, p0_fast=p0_fast)

        # P1-2：推送健康状态机记账（url 作为状态键，project 作为打点标签；
        # P0 双发时 label 形如 "APP+SYS"，fallback 时形如 "fallback:APP"）
        health = self._health_of(label)
        if ok:
            health.record_ok(label)
        else:
            health.record_fail(label, "push failed (see journal for detail)")

        # 推送打点（P0-③）
        try:
            import metrics as _m
            _m.inc("alert_sift_wecom_send_total",
                   ok=str(ok).lower(), project=label)
        except Exception:  # noqa: BLE001 —— 打点失败不阻断推送
            logger.debug("推送打点失败 project=%s ok=%s", label, ok, exc_info=True)
        return ok

    # ================= 渲染 =================
    async def _fetch_host_context(self, hostname: str) -> str | None:
        """从 VictoriaMetrics 拉取主机近 5 分钟 CPU/内存趋势（尽力而为，失败返回 None）。

        原秒级上下文数据源已下线（2026-08-24），
        改为查 VM 的 host:* recording rule（15s 聚合）补全告警上下文。
        """
        # P0-2 同类修复（2026-10-30）：原变量 vm / now 被误改名为 _unused_bind，
        # 下方 _trend 仍引用旧名 vm / now —— 运行到此处必抛 NameError
        # （外层 except Exception 会吞掉并静默 return None，主机上下文永远为空）。
        # 改回原变量名，与引用处一致。
        vm = "http://127.0.0.1:9090"
        try:
            now = int(time.time())
            async with httpx.AsyncClient(timeout=3) as client:
                async def _trend(query: str) -> list[float]:
                    r = await client.get(
                        f"{vm}/api/v1/query_range",
                        params={"query": query, "start": now - 300, "end": now, "step": "60"})
                    if r.status_code != 200:
                        return []
                    res = r.json().get("data", {}).get("result", [])
                    if not res:
                        return []
                    return [float(v[1]) for v in res[0].get("values", [])
                            if v[1] not in (None, "")]
                cpus = await _trend(f'host:cpu_usage_percent{{host="{hostname}"}}')
                mems = await _trend(f'host:mem_used_percent{{host="{hostname}"}}')
                if not cpus:
                    return None
                parts = [f"CPU {min(cpus):.0f}→{cpus[-1]:.0f}%（峰 {max(cpus):.0f}%）"]
                if mems:
                    parts.append(f"内存 {min(mems):.0f}→{mems[-1]:.0f}%")
                return " | ".join(parts)
        except Exception:  # noqa: BLE001 —— 上下文增强失败不阻断推送
            return None

    async def _render_wecom_payload(self, alerts: list[Alert]) -> dict:
        """渲染企微 Markdown payload，处理 4096B 上限降级。"""
        firing = [a for a in alerts if a.status == "firing"]
        # LLM 智能建议分支已随 llm_advisor.py 删除（2026-10-14 裁剪：
        # 生产 llm.enabled=false 恒关，为死代码；如需恢复从 .backup 取回）
        resolved = [a for a in alerts if a.status == "resolved"]
        # 业务时窗提示已移入模板（tips 变量），由 _render_sections 注入
        content = self._render_sections(firing, resolved)

        # 秒级上下文增强（2026-08-24）：仅 firing 告警，按 host 查 VM 趋势
        # （改查 VM host:* recording rule，label 由 instance 改为 host）
        hosts = sorted({a.labels.get("host", "") for a in firing
                        if a.labels.get("host")})
        if hosts:
            results = await asyncio.gather(
                *[self._fetch_host_context(h) for h in hosts[:MAX_HOST_CONTEXT]])
            ctx_parts = [f"{h}: {s}"
                         for h, s in zip(hosts[:MAX_HOST_CONTEXT], results) if s]
            if ctx_parts:
                content += "\n\n**秒级上下文**\n"
                for part in ctx_parts:
                    content += f"> {part}\n"

        # 4096B 上限降级：先去 ai_summary，再字节截断
        if len(content.encode("utf-8")) > WECOM_MAX_BYTES:
            content = self._render_sections(
                _strip_ai_summary(firing), _strip_ai_summary(resolved))
            if len(content.encode("utf-8")) > WECOM_MAX_BYTES:
                content = _byte_truncate(content, WECOM_MAX_BYTES)
                logger.warning("企微消息超 4096B，已降级截断（去 ai_summary + 字节截断）")

        payload = {
            "msgtype": "markdown",
            "markdown": {"content": content},
        }
        # 完整性校验
        self._validate_payload(payload)
        return payload

    @staticmethod
    def _validate_payload(payload: dict) -> None:
        """校验 payload 完整性。"""
        if not isinstance(payload, dict):
            raise ValueError("payload 必须是 dict")
        if "markdown" not in payload:
            raise ValueError("payload 缺少 markdown 字段")
        if "content" not in payload.get("markdown", {}):
            raise ValueError("payload 缺少 markdown.content 字段")

    def _render_sections(self, firing: list[Alert], resolved: list[Alert]) -> str:
        """渲染 firing/resolved 两个 section。

        业务时窗提示（tips）只在 firing 渲染时传入模板，
        resolved section 传空串，避免提示重复出现。
        """
        template = self._template  # P1-3 修复：使用预加载模板
        sections = []
        tips = _business_window_tip()  # 业务时窗提示，由模板在标题行下渲染
        if firing:
            sections.append(template.render(alerts=firing, title="告警触发", emoji="🔴", tips=tips))
        if resolved:
            sections.append(template.render(alerts=resolved, title="告警恢复", emoji="🟢", tips=""))
        return "\n\n".join(sections)

    # ================= 发送（带重试） =================
    async def _post_with_retry(self, url: str, payload: dict,
                                p0_fast: bool = False) -> bool:
        """发送企微消息，带指数退避重试。

        网络层不可达（ConnectError/ConnectTimeout）只报一次不重试。
        业务失败（errcode != 0）也不重试（重试无意义）。
        其他异常走重试。
        """
        max_attempts = self._retry.get("max_attempts", 3)
        backoff = self._retry.get("backoff", [1, 3, 5])
        # P0-5 修复：P0 快通道 - 含 P0 告警的批次首次失败立即返回，
        # 由上层 send_batch 触发 fallback（避免 3 次重试 + backoff 浪费 ~44s）
        if p0_fast:
            max_attempts = 1
        last_exc: Exception | None = None

        for attempt in range(max_attempts):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(url, json=payload)

                if resp.status_code == 200:
                    result = resp.json()
                    if result.get("errcode") == 0:
                        return True
                    # 业务失败：不重试
                    logger.error("企微推送业务失败 status=%s body=%s",
                                 resp.status_code, resp.text[:300])
                    return False

                # HTTP 5xx 是瞬时故障，走重试；4xx 是权限/参数错误，不重试
                if 500 <= resp.status_code < 600:
                    last_exc = Exception(f"HTTP {resp.status_code}: {resp.text[:200]}")
                    if attempt < max_attempts - 1:
                        sleep_time = backoff[min(attempt, len(backoff) - 1)]
                        logger.warning("企微 5xx 瞬时故障(重试 %d/%d) status=%s",
                                       attempt + 1, max_attempts - 1, resp.status_code)
                        await asyncio.sleep(sleep_time)
                        continue
                else:
                    logger.error("企微推送业务失败 status=%s body=%s",
                                 resp.status_code, resp.text[:300])
                    return False

            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                # 网络层不可达：只报一次不重试
                # 当前行为：把完整 webhook URL（含 key= 凭据）打进日志。
                # 改法：URL 统一走 _safe_url 脱敏，保留 scheme+host+path 便于定位；
                # 异常文本也过 _scrub（httpx 某些异常会把请求 URL 原文写进 str(exc)）。
                logger.error("网络不可达 url=%s err=%s",
                             _safe_url(url), _scrub(str(exc), url))
                return False
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if attempt < max_attempts - 1:
                    sleep_time = backoff[min(attempt, len(backoff) - 1)]
                    logger.warning("推送异常(重试 %d/%d) url=%s err=%s",
                                   attempt + 1, max_attempts - 1, _safe_url(url),
                                   _scrub(str(exc), url))
                    await asyncio.sleep(sleep_time)

        # 当前行为：把完整 webhook URL（含 key= 凭据）打进日志。
        # 改法：URL 统一走 _safe_url 脱敏；末次异常同样过 _scrub。
        logger.error("推送最终失败 url=%s err=%s", _safe_url(url),
                     _scrub(str(last_exc), url) if last_exc else None)
        return False


def _alerts_of_groups(failed_groups: list[tuple[str, list[Alert]]]) -> list[Alert]:
    """展平失败分组为告警列表。"""
    out: list[Alert] = []
    for _, group in failed_groups:
        out.extend(group)
    return out


def _dedup_alerts(alerts: list[Alert]) -> list[Alert]:
    """按 fingerprint 去重（同一告警可能同时在主群与 P0 双发群失败）。"""
    seen: set[str] = set()
    out: list[Alert] = []
    for a in alerts:
        if a.fingerprint in seen:
            continue
        seen.add(a.fingerprint)
        out.append(a)
    return out


def _dump_failed(alerts: list[Alert], failed_groups: list[tuple[str, list[Alert]]]) -> None:
    """推送最终失败的批次落盘（阶段 2.2 降级方案）。

    文件：data/failed_push/failed_<ts>_<uuid8>.json，含失败告警与失败分组。
    失败不阻断（落盘本身出错只记日志）。
    """
    try:
        dir_path = Path(FAILED_PUSH_DIR)
        dir_path.mkdir(parents=True, exist_ok=True)
        fname = f"failed_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}.json"
        record = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "reason": "wecom push failed",
            "failed_projects": [p for p, _ in failed_groups],
            "alerts": [a.to_dict() for a in alerts],
        }
        path = dir_path / fname
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2),
                        encoding="utf-8")
        logger.error("推送失败已落盘 %s（告警 %d 条）", path, len(alerts))
    except Exception as exc:  # noqa: BLE001 —— 落盘失败不阻断主流程
        logger.error("失败落盘异常: %s", exc)
