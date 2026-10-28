# -*- coding: utf-8 -*-
"""数据模型：Alert / AlertBatch / 载荷解析"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Alert:
    """统一告警模型（对齐 Alerta 生命周期：firing→ack→resolved）"""

    rule_name: str
    labels: dict[str, str]
    annotations: dict[str, str] = field(default_factory=dict)
    status: str = "firing"          # firing | resolved | ack | suppressed
    severity: str = ""              # P0-P4（空=未显式指定，classify 按 type 兜底）
    project: str = "SYS"            # 机器人路由键（自定义项目代号，如 APP/OPS）
    starts_at: str = field(default_factory=_now_utc)
    ends_at: str | None = None
    times_fired: int = 1
    fingerprint: str = ""
    generator_url: str = ""
    rule_cn: str = ""            # 中文规则名（展示用，不影响去重指纹）
    # P0-1 修复（2026-10-05）：新增 stable_fingerprint —— 基于稳定语义维度
    # （alertname + 稳定实例标识 ip/node/host/instance），不受其他 labels 变化影响。
    # 原 fingerprint 保留向后兼容（历史数据、对账、旧客户端）。
    # 所有新判断（dedup/对账/acked 元数据）改用 stable_fingerprint。
    stable_fingerprint: str = ""

    def __post_init__(self):
        # 从 labels 提取约定字段
        self.project = self.labels.get("project", self.project)
        self.severity = self.labels.get("severity", self.severity)
        # 指纹 = sha256(rule_name + 排序后的 labels) —— 去重/聚合键
        if not self.fingerprint:
            stable = json.dumps(dict(sorted(self.labels.items())), ensure_ascii=False)
            self.fingerprint = hashlib.sha256(
                f"{self.rule_name}|{stable}".encode()
            ).hexdigest()[:16]
        # 稳定实例标识优先级：ip > node > host > instance（易变标签被排除）
        # 2026-10-23：补 host —— 四条规则用 host 标签，缺它会导致指纹塌陷
        if not self.stable_fingerprint:
            self.stable_fingerprint = compute_stable_fingerprint(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_name": self.rule_name,
            "status": self.status,
            "severity": self.severity,
            "project": self.project,
            "labels": self.labels,
            "annotations": self.annotations,
            "starts_at": self.starts_at,
            "ends_at": self.ends_at,
            "times_fired": self.times_fired,
            "generator_url": self.generator_url,
            "stable_fingerprint": self.stable_fingerprint,
        }


def compute_stable_fingerprint(alert) -> str:
    """基于稳定语义维度的指纹（P0-1 修复）。

    仅使用 alertname + 稳定实例标识，避免 labels 变化导致指纹漂移。
    稳定实例标识优先级：ip > node > host > instance（2026-10-23 补 host）。
    alert 支持 Alert 对象或 dict 两种形态。
    """
    if isinstance(alert, dict):
        rule_name = alert.get("rule_name", "") or alert.get("labels", {}).get("alertname", "")
        labels = alert.get("labels", {}) or {}
    else:
        rule_name = getattr(alert, "rule_name", "") or ""
        labels = getattr(alert, "labels", {}) or {}
    # 2026-10-23 P1 修复：补 host —— 原实现只认 ip/node/instance，
    # 而 SYS|Host|P3|LoadSpike / TcpConnSpike / FdWarn、SYS|Disk|P2|WriteRateHigh
    # 四条规则输出的是 host 标签 → 取不到实例 → 全主机塌陷成同一指纹
    # （实测多台不同实例均折叠为同一指纹）。
    # 后果：reconcile 的 dict 互相覆盖产生永久僵尸 + 跨主机 dedup/ack 误抑制。
    # 2026-10-23 审查修复：补 target/collector 兜底 —— Blackbox 类告警用
    # target（Loki/nginx 等探测目标），Collector 类用 collector，labels 里
    # 无 ip/node/host/instance → 不同实例塌陷（实测 target=Loki 与
    # target=nginx 同指纹 2737662d，CollectorDown 两 collector 同指纹）。
    # 塌陷后果：dedup:{stable_fp} 互相抑制通知（dedup.py:127-128）→ 漏报。
    instance = (labels.get("ip") or labels.get("node")
                or labels.get("host") or labels.get("target")
                or labels.get("collector") or labels.get("instance") or "")
    key = f"{rule_name}|{instance}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _alert_from_raw(raw: dict) -> Alert:
    """单条标准告警（Alertmanager/vmalert 风格）→ Alert。"""
    labels = {str(k): str(v) for k, v in (raw.get("labels") or {}).items()}
    annotations = {str(k): str(v) for k, v in (raw.get("annotations") or {}).items()}
    status = raw.get("status", "firing")
    return Alert(
        rule_name=labels.get("alertname", "unknown"),
        labels=labels,
        annotations=annotations,
        status="resolved" if status == "resolved" else "firing",
        starts_at=raw.get("startsAt", _now_utc()),
        ends_at=raw.get("endsAt"),
        generator_url=raw.get("generatorURL", ""),
    )


# 通用 severity → P0-P4 映射（P0-2 异构入站标准化，2026-10-15）
_GENERIC_SEVERITY_MAP: dict[str, str] = {
    "critical": "P1", "crit": "P1",
    "error": "P2", "high": "P2",
    "warning": "P3", "warn": "P3", "medium": "P3",
    "info": "P3", "notice": "P3", "low": "P4", "debug": "P4",
}


def _map_generic_severity(value) -> str:
    """异构 severity 值 → P0-P4；无法映射返回空串（classify 按 type 兜底）。"""
    v = str(value or "").strip().lower()
    if v in _GENERIC_SEVERITY_MAP:
        return _GENERIC_SEVERITY_MAP[v]
    if v.startswith("p") and len(v) == 2 and v[1].isdigit():
        return v.upper()
    return ""


def _normalize_generic_alert(payload: dict) -> Alert | None:
    """通用/异构单条告警标准化（P0-2，2026-10-15，借鉴 OpenOcta hooksPayloadAlert）。

    兼容两类非批量载荷（顶层无 alerts 键的 JSON 对象）：
      ① 单条 AM 风格（labels 为 dict）→ 按单条标准解析，不影响原有语义；
      ② 通用 schema {alertId,title,message,severity,source,data} 或任意
         JSON 对象 → 字段映射构造 Alert；无 message 时整包 JSON 原文
         降级为 description（原文回退），任何合法 JSON 告警体都能进流水线；
         原始包截断后写入 annotations["raw_payload"] 供 LLM 分析与审计。
    """
    try:
        raw_json = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        raw_json = str(payload)

    # ① 单条 AM 风格（labels 为 dict）
    if isinstance(payload.get("labels"), dict):
        alert = _alert_from_raw(payload)
        alert.annotations.setdefault("source_format", "am_single")
        return alert

    # ② 通用 schema / 任意 JSON 对象
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}

    labels: dict[str, str] = {}
    nested = data.get("labels")
    if isinstance(nested, dict):
        # data 内嵌原始 labels（部分异构源会携带），合并后可正常路由/去重
        labels.update({str(k): str(v) for k, v in nested.items()})
    for k in ("ip", "node", "instance", "hostname", "project"):
        if data.get(k) is not None:
            labels.setdefault(k, str(data[k]))

    title = str(payload.get("title") or "").strip()
    source = str(payload.get("source") or "").strip()
    alert_id = str(payload.get("alertId") or "").strip()
    message = str(payload.get("message") or "").strip()
    if not message:
        message = raw_json  # 原文回退

    rule_name = title or source or "unknown"
    labels["alertname"] = rule_name
    sev = _map_generic_severity(payload.get("severity"))
    if not sev and isinstance(data.get("severity"), str):
        sev = _map_generic_severity(data["severity"])
    if sev:
        labels["severity"] = sev  # 空=未映射，classify 按 type 兜底

    status = str(payload.get("status") or data.get("status") or "firing").strip().lower()
    starts_at = str(payload.get("startsAt") or payload.get("starts_at")
                    or data.get("startsAt") or _now_utc())

    annotations = {
        "summary": title,
        "description": message[:4000],
        "source_format": "generic",
        "raw_payload": raw_json[:4000],
    }
    if source:
        annotations["source"] = source
    if alert_id:
        annotations["alertId"] = alert_id

    return Alert(
        rule_name=rule_name,
        labels=labels,
        annotations=annotations,
        status="resolved" if status == "resolved" else "firing",
        starts_at=starts_at,
    )


@dataclass
class AlertBatch:
    alerts: list[Alert]
    version: str = "4"
    group_key: str = ""
    receiver: str = ""
    external_url: str = ""


def parse_am_payload(payload) -> AlertBatch:
    """解析告警载荷，兼容多种来源格式（P0-2 异构入站标准化，2026-10-15）：
    1. Alertmanager Webhook v2：{"alerts":[...], "version":"4", ...}
    2. vmalert 直发（-notifier.url 指向本服务）：[ {...}, {...} ]（顶层为 list）
    3. 通用/异构单条告警 JSON（无 alerts 键的 dict）：
       - 单条 AM 风格 {labels, annotations, status, startsAt, ...}
       - 通用 schema {alertId, title, message, severity, source, data}
       - 任意 JSON 对象 → 整包原文降级为 message（原文回退），
         保证任何合法 JSON 告警体都能进入流水线（借鉴 OpenOcta /hooks/alert）
    注：1/2 为生产热路径，行为逐字节不变；仅新增 3。
    """
    if isinstance(payload, list):
        raw_alerts = payload
        meta: dict = {}
    elif isinstance(payload, dict):
        if "alerts" not in payload:
            # 异构单条告警：标准化为单元素批次，不抛 400
            alert = _normalize_generic_alert(payload)
            if alert is None:
                raise TypeError(f"不支持的载荷类型: {type(payload)}")
            return AlertBatch(alerts=[alert])
        meta = payload
        raw_alerts = payload.get("alerts", [])
    else:
        raise TypeError(f"不支持的载荷类型: {type(payload)}")

    alerts: list[Alert] = []
    for raw in raw_alerts:
        if isinstance(raw, dict) and not (raw.get("labels") or {}).get("alertname") \
                and (raw.get("message") or raw.get("title")):
            # 批量内混入通用格式条目（如 netdata 风格）同样走标准化
            alert = _normalize_generic_alert(raw)
            if alert is not None:
                alerts.append(alert)
                continue
        labels = {str(k): str(v) for k, v in raw.get("labels", {}).items()}
        annotations = {str(k): str(v) for k, v in raw.get("annotations", {}).items()}
        status = raw.get("status", "firing")
        alerts.append(
            Alert(
                rule_name=labels.get("alertname", "unknown"),
                labels=labels,
                annotations=annotations,
                status="resolved" if status == "resolved" else "firing",
                starts_at=raw.get("startsAt", _now_utc()),
                ends_at=raw.get("endsAt"),
                generator_url=raw.get("generatorURL", ""),
            )
        )
    return AlertBatch(
        alerts=alerts,
        version=meta.get("version", "4"),
        group_key=meta.get("groupKey", ""),
        receiver=meta.get("receiver", ""),
        external_url=meta.get("externalURL", ""),
    )
