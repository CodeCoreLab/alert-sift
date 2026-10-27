# -*- coding: utf-8 -*-
"""L6 分类 —— P0-P4 分级 + 业务标签归一（轻量版 2026-09-04）

分级规则（对齐运营习惯）：
  P0 核心业务中断 → 立即 + 升级
  P1 严重（主机宕机/磁盘满/DB 不可用）→ 立即
  P2 警告（CPU>90 持续/内存高）→ 窗口内推送
  P3 提示（常规波动）
  P4 信息（巡检类）

业务词配置化（开源版 2026-10-27）：
  * 项目中文名、分组前缀、IP 网段兜底 → config.yaml groups 段
    （原硬编码的项目代号与中文映射已全部移除）

轻量化（2026-09-04）：
  * 删除 LLM 摘要分支（llm.enabled=false 生产恒关；llm_utils.py 随之废弃）
  * instance_ip_map 路径改为环境变量可配 + 惰性加载（原 import 时硬编码
    /opt 路径读盘，Windows 本地测试/非默认部署路径直接失效）
"""
from __future__ import annotations

import logging
import re
from typing import Any


from models import Alert

logger = logging.getLogger("alert-sift.classify")

SEVERITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}

# instance 主机名 -> IP 地址映射（惰性加载）
_INSTANCE_IP_MAP: dict[str, str] | None = None
# IP -> 主机名 反向映射（由 instance_ip_map 派生，惰性加载）
_HOST_BY_IP: dict[str, str] | None = None

# 业务分组前缀（hostname 形如 APP-search-09 → 分组 APP）。
# 默认通用于按大写前缀命名的环境；可经 config.yaml groups.prefixes 覆盖。
_DEFAULT_GROUP_PREFIXES = ("APP", "OPS")
_GROUP_PREFIXES: tuple[str, ...] | None = None

# 项目代号 → 中文显示名。默认为空（未知代号原样返回）；
# 可经 config.yaml groups.project_names 覆盖（如 {APP: "搜索业务"}）。
_PROJECT_CN: dict[str, str] = {}
_PROJECT_CN_OVERRIDDEN = False

# IP 网段 → 分组 兜底映射。可经 config.yaml groups.ip_prefixes 覆盖
# （如 {"10.70.0.": "APP"}）。
_IP_GROUP_PREFIXES: dict[str, str] = {}
_IP_GROUP_LOADED = False

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _looks_like_ip(s: str) -> bool:
    """判断字符串是否为 IPv4 地址。"""
    return bool(_IP_RE.match(s or ""))


def _instance_ip_map() -> dict[str, str]:
    """惰性加载 instance->IP 映射（P1-6 收口：委托 config_loader）。"""
    global _INSTANCE_IP_MAP
    if _INSTANCE_IP_MAP is None:
        from config_loader import load_instance_ip_map
        _INSTANCE_IP_MAP = load_instance_ip_map()
    return _INSTANCE_IP_MAP

def _ip_to_hostname(ip: str) -> str:
    """IP → 主机名 反向查表（基于 instance_ip_map 的值→键）。"""
    global _HOST_BY_IP
    if _HOST_BY_IP is None:
        _HOST_BY_IP = {v: k for k, v in _instance_ip_map().items()}
    return _HOST_BY_IP.get(ip, "")


# type → 默认 severity 映射（兜底，规则未显式给 severity 时使用）
_TYPE_SEVERITY_MAP: dict[str, str] = {
    "host": "P2",
    "disk": "P1",
    "db": "P1",
    "net": "P2",
    "biz": "P0",
    "process": "P2",
}

# rule_name（alertname = PROJECT|TYPE|SEVERITY|EVENT）中文翻译
# （原 _PROJECT_CN 硬编码已上移至 groups.project_names 可配置项，见文件头）
_TYPE_CN: dict[str, str] = {
    "Host": "主机", "Disk": "磁盘", "Biz": "业务", "DB": "数据库", "Net": "网络",
    "Process": "进程", "Collector": "采集器", "Probe": "拨测",
    "Blackbox": "外部探测", "Service": "服务",
    "Docker": "容器", "Redis": "Redis",
}
_EVENT_CN: dict[str, str] = {
    "CpuHigh": "CPU使用率过高", "MemHigh": "内存使用率过高", "SpaceLow": "空间不足",
    "HostDown": "心跳中断", "InstanceDown": "失联",
    "HeartbeatLost": "心跳丢失", "LatencyHigh": "交易延迟过高",
    "ErrorRateHigh": "接口错误率过高", "ConnPoolExhausted": "数据库连接池耗尽",
    "IoWaitHigh": "IO等待过高",
    "MemLeak": "内存泄漏", "SwapHigh": "Swap使用过高",
    "ProcessDown": "进程退出", "PortDown": "端口不可达",
    # 2026-10-23 补齐：rules/*.yaml 全部 24 个 EVENT 中文名（原缺 10 个，
    # LoadSpike 等未映射时卡片主标题回退显示英文 ID）
    "CpuWarn": "CPU使用率预警", "MemWarn": "内存使用率预警",
    "SpaceWarn": "磁盘空间预警", "InodeWarn": "inode使用率过高",
    "SpaceForecast": "磁盘空间耗尽预测", "WriteRateHigh": "磁盘写入速率过高",
    "LoadSpike": "系统负载突发", "TcpConnSpike": "TCP连接数突增",
    "FdWarn": "文件句柄使用率过高",
    "CollectorDown": "采集器离线", "CollectorSilent": "采集器心跳中断",
    "ProbeFail": "HTTP拨测不可达",
    "BlackboxProbeFail": "外部探测失败", "BlackboxProbeError": "外部探测异常",
    "BlackboxSilent": "外部探测静默",
    "TestMachineServiceDown": "测试机服务不可用", "TestMachineDiskHigh": "测试机磁盘使用率过高",
    "WecomPushDown": "企微推送服务不可用",
    # 2026-10-27 补齐：10-23 晚新落 8 条规则的事件名
    "ReadRateHigh": "磁盘读取速率过高",
    "OomKill": "OOM进程被杀",
    "MonitoredProcDown": "关键进程存活中断",
    "NetTrafficSpike": "网卡流量突增",
    "SwapUsed": "Swap使用持续增长",
    "RedisBlocked": "Redis阻塞客户端过多",
    "RedisFragHigh": "Redis内存碎片率过高",
    "ContainerdDown": "容器引擎中断",
}


def _rule_cn(rule_name: str) -> str:
    """把 SYS|Host|P1|MemHigh 这类 alertname 翻译为中文。

    2026-10-27：裸名（无四段前缀，如 MonitoredProcDown）不再原样返回英文 ID，
    改为查 _EVENT_CN 单段映射；仍未登记则返回空串，由模板回退到中文 summary
    （wecom_markdown.j2: rule_cn or summary or friendly_name），
    保证卡片主标题永不出现英文告警 ID。
    """
    if not rule_name:
        return ""
    if "|" not in rule_name:
        return _EVENT_CN.get(rule_name, "")
    parts = rule_name.split("|")
    if len(parts) < 4:
        return _EVENT_CN.get(parts[-1], "")
    proj, typ, _sev, event = parts[0], parts[1], parts[2], "|".join(parts[3:])
    event_cn = _EVENT_CN.get(event)
    if not event_cn:
        return ""
    return f"{_PROJECT_CN.get(proj, proj)}·{_TYPE_CN.get(typ, typ)}·{event_cn}"


def _groups_cfg(state: dict[str, Any] | None) -> dict[str, Any]:
    """从 state.cfg 取 groups 配置段（兼容 dict 与 Starlette State）。"""
    if not state:
        return {}
    cfg = state.get("cfg") if isinstance(state, dict) else getattr(state, "cfg", {})
    if not isinstance(cfg, dict):
        return {}
    g = cfg.get("groups")
    return g if isinstance(g, dict) else {}


def _load_groups(state: dict[str, Any] | None) -> None:
    """按 config.yaml groups 段加载业务分组配置（每进程一次）。

    groups:
      prefixes: [APP, OPS]            # hostname 前缀 → 分组
      project_names: {APP: 搜索业务}  # 项目代号 → 中文显示名
      ip_prefixes: {"10.70.0.": APP}  # IP 网段前缀 → 分组（兜底）
    """
    global _GROUP_PREFIXES, _PROJECT_CN, _IP_GROUP_PREFIXES
    global _PROJECT_CN_OVERRIDDEN, _IP_GROUP_LOADED
    g = _groups_cfg(state)
    if isinstance(g.get("prefixes"), list) and g["prefixes"]:
        _GROUP_PREFIXES = tuple(str(x) for x in g["prefixes"])
    if isinstance(g.get("project_names"), dict) and g["project_names"]:
        _PROJECT_CN = {str(k): str(v) for k, v in g["project_names"].items()}
        _PROJECT_CN_OVERRIDDEN = True
    if isinstance(g.get("ip_prefixes"), dict) and g["ip_prefixes"]:
        _IP_GROUP_PREFIXES = {str(k): str(v) for k, v in g["ip_prefixes"].items()}
        _IP_GROUP_LOADED = True


def apply(alert: Alert, state: dict[str, Any]) -> None:
    """对告警做分级 + 项目路由（原地修改 alert 对象）。

    流程：
      1. 注入 IP 标签（instance → IP 映射）
      2. 生成中文规则名（不影响去重指纹）
      3. severity 为空或非 P0-P4 → 按 type 兜底
      4. project=SYS → 按 IP 前缀映射（project_mapping 配置）
    """
    _load_groups(state)
    _inject_ip(alert)
    _inject_group(alert)
    alert.rule_cn = _rule_cn(alert.rule_name)

    if not alert.severity or alert.severity not in SEVERITY_ORDER:
        alert.severity = _default_severity(alert.labels.get("type", ""))
        alert.labels["severity"] = alert.severity

    if alert.project == "SYS":
        mapped = _map_project(alert, state)
        if mapped:
            alert.project = mapped


def _inject_ip(alert: Alert) -> None:
    """从 instance / node label 注入 ip 与 hostname。

    fleet 采集的 node 即 IP（如 10.55.65.48），直接作为 ip；
    instance 为主机名时需查 instance_ip_map 得到 IP。
    同时反向查表注入 hostname（IP→主机名），供模板展示分组。
    """
    if "ip" in alert.labels and "hostname" in alert.labels:
        return

    # 候选来源：node（fleet 现命名）/ instance（旧命名）
    raw = alert.labels.get("node", "") or alert.labels.get("instance", "")
    if not raw:
        return

    # 注入 ip
    if "ip" not in alert.labels:
        if _looks_like_ip(raw):
            alert.labels["ip"] = raw
        else:
            mapped = _instance_ip_map().get(raw)
            if mapped:
                alert.labels["ip"] = mapped

    # 注入 hostname（IP→主机名 反查，失败不阻断）
    if "hostname" not in alert.labels:
        ip_for_lookup = alert.labels.get("ip", raw)
        host = _ip_to_hostname(ip_for_lookup)
        if host:
            alert.labels["hostname"] = host


def _inject_group(alert: Alert) -> None:
    """按主机名前缀提取业务分组（由 groups.prefixes 配置，默认 APP/OPS）。

    补充系统级告警缺失的分组标签，便于定位责任域。
    不影响 project 路由（SYS 仍推 SYS 机器人）。
    """
    if "group" in alert.labels:
        return
    prefixes = _GROUP_PREFIXES if _GROUP_PREFIXES is not None else _DEFAULT_GROUP_PREFIXES
    host = alert.labels.get("hostname", "")
    for g in prefixes:
        if host.startswith(g):
            alert.labels["group"] = g
            return
    # IP 网段兜底：由 groups.ip_prefixes 配置（如 {"10.70.0.": "APP"}）
    ip = alert.labels.get("ip", "")
    for prefix, g in _IP_GROUP_PREFIXES.items():
        if ip.startswith(prefix):
            alert.labels["group"] = g
            return


def _default_severity(alert_type: str) -> str:
    """根据告警 type 返回默认 severity。"""
    return _TYPE_SEVERITY_MAP.get(alert_type, "P3")


def _map_project(alert: Alert, state: dict[str, Any]) -> str:
    """按 IP 前缀映射项目；未命中返回 SYS。"""
    ip = alert.labels.get("ip") or alert.labels.get("instance", "")
    if not ip:
        return "SYS"

    rules = state.get("cfg", {}).get("project_mapping", [])
    for rule in rules:
        for prefix in rule.get("ip_prefixes", []):
            if ip.startswith(prefix):
                return rule["project"]
    return "SYS"
