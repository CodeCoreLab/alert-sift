# -*- coding: utf-8 -*-
"""统一配置加载入口（P1-6 修复，2026-10-05）

原问题：配置加载散落多处 ——
  * utils.load_config        : config.yaml + silences/inhibits/notifiers 叠加
  * pipeline/classify.py     : instance_ip_map.yaml 惰性加载（硬编码路径 + env）
  * guard.py                 : guard.yaml 加载（内置默认回退）
改后：全部收口到本模块，utils/guard/classify 仅做委托，规则一处改全局生效。
文件本身不合并（silences/inhibits 由管理 API 动态写入，保持独立文件是特性）。
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("alert-sift.config_loader")

# 项目默认根：优先 env；缺省取仓库根（本文件位于 <root>/app/ 下），
# 兼容自定义部署根（env 显式指定 ALERT_SIFT_ROOT 即可）。
_DEFAULT_ROOT = os.getenv(
    "ALERT_SIFT_ROOT",
    str(Path(__file__).resolve().parent.parent))


def load_main(path: str) -> dict[str, Any]:
    """加载主配置 config.yaml，并叠加动态子配置文件。

    叠加规则：
      * silences.yaml / inhibits.yaml : 存在即覆盖 config.yaml 同名键
      * notifiers.yaml                : 通知路由可编程权威源，存在即覆盖
    文件缺失或解析失败时降级为空结构，不阻断主链路。
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning("配置文件不存在 path=%s", path)
        return {}
    except Exception as exc:  # noqa: BLE001
        logger.error("配置文件加载失败 path=%s: %s", path, exc)
        return {}

    cfg_dir = Path(path).resolve().parent
    for key, filename in (("silences", "silences.yaml"),
                          ("inhibits", "inhibits.yaml"),
                          ("notifiers", "notifiers.yaml")):
        if key not in cfg or filename == "notifiers.yaml":
            cfg_file = cfg_dir / filename
            if cfg_file.exists():
                try:
                    with open(cfg_file, "r", encoding="utf-8") as f:
                        loaded = yaml.safe_load(f)
                    cfg[key] = loaded if loaded is not None                         else ({} if key == "notifiers" else [])
                except Exception as exc:  # noqa: BLE001
                    logger.warning("加载 %s 失败: %s", filename, exc)
                    cfg[key] = {} if key == "notifiers" else []
            elif key not in cfg:
                cfg[key] = {} if key == "notifiers" else []
    return cfg


def load_instance_ip_map(path: str | None = None) -> dict[str, str]:
    """加载 instance->IP 映射（instance_ip_map.yaml 的 hosts 键）。

    失败返回空表 —— 映射缺失只影响友好名展示，不阻断主链路。
    """
    p = path or os.getenv(
        "ALERT_SIFT_INSTANCE_IP_MAP",
        os.path.join(_DEFAULT_ROOT, "configs", "instance_ip_map.yaml"))
    try:
        fp = Path(p)
        if not fp.exists():
            return {}
        data = yaml.safe_load(fp.read_text(encoding="utf-8")) or {}
        hosts = data.get("hosts", {}) or {}
        if hosts:
            logger.info("加载 instance->IP 映射 %d 条", len(hosts))
        return hosts
    except Exception as exc:  # noqa: BLE001
        logger.warning("加载 instance->IP 映射失败: %s", exc)
        return {}


_GUARD_DEFAULTS: dict[str, Any] = {
    "roles": {
        "ai": {
            "alert_list", "alert_ack", "silence_list", "silence_create",
            "inhibit_list", "inhibit_create", "rule_list", "rule_upsert",
            "notifier_list", "config_diff", "db_stats", "history_export",
        },
        "human": None,
    },
    "default_role": "ai",
    "high_risk": {
        "notifier_update", "config_reload", "silence_delete",
        "inhibit_delete", "rule_upsert",
    },
    "approval_valid_seconds": 86400,
}


def load_guard_config(path: str | None = None) -> dict[str, Any]:
    """加载 guard.yaml（RBAC/高危清单），失败回退内置默认。

    返回键：RBAC / DEFAULT_ROLE / HIGH_RISK / APPROVAL_VALID_SECONDS。
    """
    p = path or os.path.join(_DEFAULT_ROOT, "configs", "guard.yaml")
    try:
        with open(p, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        roles_raw = raw.get("roles", _GUARD_DEFAULTS["roles"])
        roles: dict[str, Any] = {}
        for k, v in roles_raw.items():
            roles[k] = set(v) if v is not None else None
        high_risk_raw = raw.get("high_risk", _GUARD_DEFAULTS["high_risk"])
        high_risk = set(high_risk_raw) if isinstance(high_risk_raw, (list, set))             else set(high_risk_raw)
        return {
            "RBAC": roles,
            "DEFAULT_ROLE": raw.get("default_role", _GUARD_DEFAULTS["default_role"]),
            "HIGH_RISK": high_risk,
            "APPROVAL_VALID_SECONDS": int(
                raw.get("approval_valid_seconds",
                        os.getenv("ALERT_SIFT_APPROVAL_VALID_SECONDS", 86400))),
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("guard 配置加载失败，使用内置默认: %s", exc)
        return _GUARD_DEFAULTS
