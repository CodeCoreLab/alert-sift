# -*- coding: utf-8 -*-
"""核心服务层 AppContext —— main.py / admin.py / mcp_server.py 三方共享

统一持有：配置(cfg)、存储(store)、文件路径；提供全部管理操作（CRUD）。

重构（2026-08-15）：
  * 提取 _BAK_SUFFIX 常量
  * _write_yaml 增加写入后校验
  * list_active_alerts 增加类型兼容处理
  * ack_alert 增加 fingerprint 空值保护
  * reconcile_active_alerts 增加空输入快速返回
  * upsert_rule 增加文件名白名单校验（防路径穿越增强）
"""
from __future__ import annotations

import csv
import json
import logging
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from models import Alert
from utils import load_config
from store.sqlite_store import SQLiteStore


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

logger = logging.getLogger("alert-sift.core")

_SEVERITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
_BAK_SUFFIX = ".bak"


class AppContext:
    def __init__(self, config_path: str, db_path: str):
        self.config_path = Path(config_path)
        self.db_path = db_path
        self._config_dir = self.config_path.resolve().parent
        self._project_root = self._config_dir.parent
        self._rules_dir = self._project_root / "rules"
        self._data_dir = self._project_root / "data"
        self.cfg = load_config(str(self.config_path))
        self.store = SQLiteStore(db_path)
        self.store.init()
        self._rules_cache: tuple[float, list[dict]] | None = None

    # ================= 配置 =================
    def reload_config(self) -> dict:
        """热重载：重新读取配置，返回变更摘要。"""
        old = dict(self.cfg)
        new = load_config(str(self.config_path))
        changed = {
            k: (old.get(k), new.get(k))
            for k in set(old) | set(new)
            if old.get(k) != new.get(k)
        }
        # 2026-10-21 修复：必须 in-place 更新，禁止重新赋值。
        # 原因：main.py:334 `app.state.cfg = ctx.cfg` 持有的是本对象的引用快照，
        # `self.cfg = new` 会让 state.cfg 继续指向旧 dict，导致流水线
        # (pipeline/__init__.py:49-52 读 state.cfg) 永远读不到新配置。
        # 表现为：reload 返回 changed_keys 看似成功，但 silence/inhibit 等配置全部不生效。
        self.cfg.clear()
        self.cfg.update(new)
        return {
            "changed_keys": list(changed.keys()),
            "reloaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    def config_diff(self) -> dict:
        """仅返回内存 cfg 与磁盘文件的差异。"""
        on_disk = load_config(str(self.config_path))
        diff = {
            k: (self.cfg.get(k), on_disk.get(k))
            for k in set(self.cfg) | set(on_disk)
            if self.cfg.get(k) != on_disk.get(k)
        }
        return {"diff_keys": list(diff.keys())}

    def _write_yaml(self, path: Path, data: Any) -> None:
        """写 YAML 前先备份，再原子写入。"""
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            shutil.copy2(path, str(path) + f"{_BAK_SUFFIX}.{_to_int(time.time())}")
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
        os.replace(tmp, path)  # 原子替换

    # ================= 告警查询/确认 =================
    def list_active_alerts(self, project: str | None = None,
                           severity: str | None = None) -> list[dict]:
        alerts = []
        for row in self.store.get_active_alerts():
            a = row if isinstance(row, dict) else row.to_dict()
            if project and a.get("project") != project:
                continue
            if severity and a.get("severity") != severity:
                continue
            alerts.append(a)
        return alerts

    def ack_alert(self, fingerprint: str) -> bool:
        """确认告警：状态 firing → ack。

        P1-⑧（2026-08-22）：ack 时记录 meta `acked:{fp}`（30min 宽限期），
        升级引擎在宽限期内跳过该告警，避免「已确认处理中」的告警被升级轰炸。
        """
        if not fingerprint:
            return False

        for row in self.store.get_active_alerts():
            a = row if isinstance(row, dict) else row.to_dict()
            if a.get("fingerprint") == fingerprint:
                a["status"] = "ack"
                self.store.upsert_active(Alert(
                    rule_name=a.get("rule_name", ""),
                    labels=a.get("labels", {}),
                    annotations=a.get("annotations", {}),
                    status="ack",
                    severity=a.get("severity", "P3"),
                    project=a.get("project", "SYS"),
                    starts_at=a.get("starts_at", ""),
                    fingerprint=fingerprint,
                    times_fired=_to_int(a.get("times_fired", 1) or 1),
                ))
                try:
                    self.store.set_meta(
                        f"acked:{a.get('stable_fingerprint') or fingerprint}", str(time.time()), ttl=1800)  # P0-1: stable fp
                except Exception as _exc:  # noqa: BLE001 —— meta 失败不阻断 ack
                    logger.debug("忽略预期内异常（降级路径）: %s", _exc)
                return True
        return False

    def get_firing_alerts(self) -> list[dict]:
        """获取全部活跃告警（firing + ack），供升级引擎扫描。"""
        out = []
        for row in self.store.get_active_alerts():
            a = row if isinstance(row, dict) else row.to_dict()
            if a.get("status") in ("firing", "ack"):
                out.append(a)
        return out

    def reconcile_active_alerts(self, source_fingerprints: set[str],
                                stale_seconds: int = 600) -> list[Alert]:
        """源侧对账：清理本地 firing 但源侧已消失的僵尸告警。

        P0-6 修复（2026-10-05）：改用 stable_fingerprint 做差集。
        原逻辑用旧 fingerprint（含 labels 全量哈希）导致 vmalert 侧 labels
        微调即触发僵尸误判。现改为基于稳定语义维度（alertname + ip/node/instance）。

        双通道清理：
          * 源侧非空：差集清理（按 stable_fingerprint）
          * 源侧为空：stale 兜底（updated_at 超过 stale_seconds 未更新）

        Args:
            source_fingerprints: vmalert 当前 firing 告警的 stable_fingerprint 集合
            stale_seconds: stale 兜底秒数

        Returns:
            list[Alert]: 被 resolve 的告警对象列表。空列表=无清理或已跳过。
        """
        from models import compute_stable_fingerprint

        rows = self.store.conn.execute(
            "SELECT fingerprint, payload, updated_at "
            "FROM active_alerts WHERE status IN ('firing','ack')").fetchall()
        if not rows:
            return []

        # 反查每条本地记录的 stable_fingerprint（P0-6 修复核心）
        local_stable_map: dict[str, tuple] = {}
        for r in rows:
            try:
                a = json.loads(r["payload"])
            except (ValueError, TypeError) as e:
                logger.warning("payload 解析失败 fp=%s: %s", r["fingerprint"], e)
                continue
            stable_fp = a.get("stable_fingerprint") or compute_stable_fingerprint(a)
            local_stable_map[stable_fp] = (r["fingerprint"], a, r["updated_at"])

        local_stable_fps = set(local_stable_map.keys())

        if source_fingerprints and not (local_stable_fps & source_fingerprints):
            logger.warning(
                "源侧对账交集为空（本地 %d / 源侧 %d），跳过清理防误杀",
                len(local_stable_fps), len(source_fingerprints))
            return []

        now = time.time()
        cut = now - stale_seconds
        resolved_alerts: list[Alert] = []

        for stable_fp, (orig_fp, a, updated_at) in local_stable_map.items():
            if source_fingerprints:
                if stable_fp in source_fingerprints:
                    continue
            else:
                if updated_at >= cut:
                    continue

            resolved = Alert(
                rule_name=a.get("rule_name", "unknown"),
                labels=a.get("labels", {}),
                annotations=a.get("annotations", {}),
                status="resolved",
                severity=a.get("severity", "P3"),
                project=a.get("project", "SYS"),
                starts_at=a.get("starts_at", ""),
                ends_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                fingerprint=orig_fp,
                times_fired=_to_int(a.get("times_fired", 1) or 1),
            )
            self.store.remove_active(orig_fp)
            resolved_alerts.append(resolved)

        # 2026-10-23：reconcile 统一走 add_history_batch，与其他入库路径共用去重。
        # 原实现逐条 add_history —— 绕过 (fingerprint,status) 窗口去重，
        # 僵尸告警每分钟产生一条 resolved 入库（同指纹 1h 16 条，24h 153 条噪音）。
        if resolved_alerts:
            self.store.add_history_batch(resolved_alerts)
            logger.info("源侧对账清理僵尸告警 %d 条（本地 %d / 源侧 %d / stale>%ds）",
                        len(resolved_alerts), len(local_stable_fps), len(source_fingerprints),
                        stale_seconds)
        return resolved_alerts

    # ================= 静默 CRUD =================
    def _silences_path(self) -> Path:
        return self._config_dir / "silences.yaml"

    def list_silences(self) -> list[dict]:
        return list(self.cfg.get("silences", []))

    def upsert_silence(self, silence: dict, dry_run: bool = False) -> dict:
        silences = self.list_silences()
        idx = next(
            (i for i, s in enumerate(silences)
             if s.get("matchers") == silence.get("matchers")), None)
        action = "update" if idx is not None else "create"
        if idx is not None:
            silences[idx] = silence
        else:
            silences.append(silence)
        if not dry_run:
            self._write_yaml(self._silences_path(), silences)
            self.cfg["silences"] = silences
        return {"action": action, "silence": silence, "dry_run": dry_run}

    def delete_silence(self, matchers: dict, dry_run: bool = False) -> dict:
        silences = [s for s in self.list_silences()
                    if s.get("matchers") != matchers]
        removed = len(self.list_silences()) - len(silences)
        if removed and not dry_run:
            self._write_yaml(self._silences_path(), silences)
            self.cfg["silences"] = silences
        return {"removed": removed, "dry_run": dry_run}

    # ================= 抑制 CRUD =================
    def list_inhibits(self) -> list[dict]:
        return list(self.cfg.get("inhibits", []))

    def upsert_inhibit(self, inhibit: dict, dry_run: bool = False) -> dict:
        inhibits = self.list_inhibits()
        idx = next(
            (i for i, r in enumerate(inhibits)
             if r.get("target_matchers") == inhibit.get("target_matchers")
             and r.get("source_matchers") == inhibit.get("source_matchers")), None)
        action = "update" if idx is not None else "create"
        if idx is not None:
            inhibits[idx] = inhibit
        else:
            inhibits.append(inhibit)
        if not dry_run:
            self._write_yaml(self._config_dir / "inhibits.yaml", inhibits)
            self.cfg["inhibits"] = inhibits
        return {"action": action, "inhibit": inhibit, "dry_run": dry_run}

    def delete_inhibit(self, target_matchers: dict, dry_run: bool = False) -> dict:
        inhibits = [r for r in self.list_inhibits()
                    if r.get("target_matchers") != target_matchers]
        removed = len(self.list_inhibits()) - len(inhibits)
        if removed and not dry_run:
            self._write_yaml(self._config_dir / "inhibits.yaml", inhibits)
            self.cfg["inhibits"] = inhibits
        return {"removed": removed, "dry_run": dry_run}

    # ================= 通知渠道 =================
    def list_notifier_routes(self) -> dict:
        robots = {}
        for project in ("SYS", "APP", "OPS"):
            env_key = f"WECOM_BOT_{project}"
            val = os.getenv(env_key)
            if val:
                robots[project] = {"source": "env", "url": val}
            else:
                cfg_val = self.cfg.get("notifiers", {}).get("wecom", {}).get("robots", {}).get(project)
                robots[project] = {"source": "config", "url": cfg_val or None}
        return robots

    def update_notifier_route(self, project: str, url: str | None,
                              dry_run: bool = False) -> dict:
        cfg = self.cfg.get("notifiers", {}).get("wecom", {}).get("robots", {})
        if url:
            cfg[project] = url
        else:
            cfg.pop(project, None)
        self.cfg["notifiers"] = self.cfg.get("notifiers", {})
        self.cfg["notifiers"]["wecom"] = {"robots": cfg}
        if not dry_run:
            self._write_yaml(self._config_dir / "notifiers.yaml",
                             {"wecom": {"robots": cfg}})
        return {"project": project, "url": url or "(deleted)", "dry_run": dry_run}

    # ================= vmalert 规则 =================
    RULES_CACHE_TTL = _to_float(os.getenv("ALERT_SIFT_RULES_CACHE_TTL", "5"))

    def list_rules(self) -> list[dict]:
        """读取 rules/*.yaml 返回规则清单（只读，5s 缓存）。"""
        now = time.time()
        if self._rules_cache:
            cache_ts, cached = self._rules_cache
            if now - cache_ts < self.RULES_CACHE_TTL:
                return cached

        rules_dir = self._rules_dir
        out = []
        if rules_dir.exists():
            for f in sorted(rules_dir.glob("*.yaml")):
                doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
                for g in doc.get("groups", []):
                    for r in g.get("rules", []):
                        out.append({
                            "file": f.name,
                            "group": g.get("name"),
                            "alert": r.get("alert"),
                            "expr": r.get("expr"),
                            "for": r.get("for"),
                            "labels": r.get("labels"),
                        })
        self._rules_cache = (now, out)
        return out

    def upsert_rule(self, file: str, rule: dict, dry_run: bool = False) -> dict:
        """在指定 rules 文件中新增/更新规则。"""
        # 防路径穿越：仅允许纯文件名
        if not file or any(ch in file for ch in ("/", "\\", "..")):
            raise ValueError(f"非法规则文件名: {file!r}")
        path = self._rules_dir / file
        if not path.exists():
            raise FileNotFoundError(f"rules 文件不存在: {file}")

        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {"groups": []}
        group = doc["groups"][0]
        rules = group.get("rules", [])
        idx = next((i for i, r in enumerate(rules)
                    if r.get("alert") == rule.get("alert")), None)
        action = "update" if idx is not None else "create"
        if idx is not None:
            rules[idx] = rule
        else:
            rules.append(rule)

        if not dry_run:
            self._write_yaml(path, doc)
            self._rules_cache = None
            self._git_commit_rules(file)

        return {"action": action, "file": file, "alert": rule.get("alert"),
                "dry_run": dry_run,
                "note": "vmalert -configCheckInterval=30s 自动热加载"}

    def _git_commit_rules(self, file: str) -> bool:
        """规则 Git 版本化：rules/ 为 git 仓库时自动 commit。"""
        try:
            rules_dir = self._rules_dir
            if not (rules_dir / ".git").exists():
                return False
            for cmd in (
                ["git", "-C", str(rules_dir), "add", file],
                ["git", "-C", str(rules_dir), "commit", "-m",
                 f"rule: {file} updated via admin api"],
            ):
                proc = subprocess.run(cmd, capture_output=True, timeout=15)
                if proc.returncode not in (0, 1):
                    logger.warning("规则 git 操作失败: %s",
                                   proc.stderr.decode(errors="ignore")[:200])
                    return False
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("规则 git 版本化跳过: %s", exc)
            return False

    # ================= 历史导出 / 存储 =================
    def export_history_csv(self, out_path: str | None = None,
                           limit: int = 10000) -> str:
        # 防路径穿越
        if out_path:
            p = Path(out_path)
            if not p.is_absolute():
                p = self._data_dir / p
            out = str(p)
            if not Path(out).resolve().is_relative_to(self._data_dir.resolve()):
                raise ValueError(f"out_path 必须位于 {self._data_dir} 目录内")
        else:
            out = str(self._data_dir / f"alert_history_{datetime.now():%Y%m%d_%H%M%S}.csv")

        Path(out).parent.mkdir(parents=True, exist_ok=True)
        conn = self.store.conn
        rows = conn.execute(
            "SELECT fingerprint,rule_name,project,severity,status,created_at "
            "FROM alert_history ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

        with open(out, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["fingerprint", "rule_name", "project", "severity",
                        "status", "created_at"])
            w.writerows(rows)
        return out

    def db_stats(self) -> dict:
        conn = self.store.conn
        active = conn.execute(
            "SELECT COUNT(*) FROM active_alerts").fetchone()[0]
        history = conn.execute(
            "SELECT COUNT(*) FROM alert_history").fetchone()[0]
        return {"db": self.db_path, "active_alerts": active,
                "alert_history": history}
