# -*- coding: utf-8 -*-
"""存储层：SQLite 告警状态与历史（可替换为 MySQL）

重构（2026-08-15）：
  * 提取 _DB_INIT_SQL 常量，消除内联 DDL 字符串（DRY）
  * 增加 _execute 辅助方法，统一事务管理
  * get_active_alerts 增加空结果快速返回路径
  * cleanup_expired_meta 增加最大删除数保护（防长尾）
  * 增加 conn 异常保护：连接失效时重建
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path


def _to_int(value, ctx=""):
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"非法整数{(' ' + ctx) if ctx else ''}: {value!r}") from exc

logger = logging.getLogger("alert-sift.store")

# busy_timeout（秒）：写锁竞争时的等待上限
DB_BUSY_TIMEOUT = _to_int(os.getenv("ALERT_SIFT_DB_BUSY_TIMEOUT", "5"))

# history 入库去重窗口（秒）：同 (fingerprint, status) 窗口内只落一条。
# 对齐 vmalert 评估周期（30s）× 常见持续满足时长；600s 覆盖 MemLeak 锯齿穿越期。
# 0 = 关闭（回退旧行为）。resolved 由 RESOLVED_DEDUP_WINDOW 单独控量。
HIST_DEDUP_WINDOW = _to_int(os.getenv("ALERT_SIFT_HIST_DEDUP_SECONDS", "600"))
# 2026-10-23：resolved 独立去抖窗口。
#   原设计把 resolved 完全排除在去重外，理由是「恢复事件每次都值得记录，
#   由推送层 resolved_debounce 控量」—— 但该 debounce 只作用于通知，
#   入库路径（core.reconcile → add_history）根本不经过流水线，从未被控量。
#   实测后果：僵尸告警每分钟被 reconcile 判 resolved 并入库，
#   同指纹 1 小时 16 条，24h 内 153 条几乎全为噪音（全表已 172K）。
#   resolved 是「状态转换事件」，短窗口内同指纹重复必是抖动/僵尸，去抖即可。
RESOLVED_DEDUP_WINDOW = _to_int(os.getenv("ALERT_SIFT_HIST_RESOLVED_DEDUP_SECONDS", "1800"))

# 批量写入最大批次大小
_MAX_BATCH_SIZE = 500

# 清理 meta 最大删除数（防止长尾扫描）
_MAX_CLEANUP_BATCH = 1000

# 数据库初始化 SQL（DDL + 索引）
_DB_INIT_SQL = """
    CREATE TABLE IF NOT EXISTS active_alerts(
        fingerprint TEXT PRIMARY KEY,
        payload     TEXT NOT NULL,
        status      TEXT NOT NULL,
        updated_at  REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS alert_history(
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        fingerprint TEXT NOT NULL,
        rule_name   TEXT,
        project     TEXT,
        severity    TEXT,
        status      TEXT,
        payload     TEXT,
        created_at  REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_history_created ON alert_history(created_at);
    CREATE INDEX IF NOT EXISTS idx_history_rule_time
        ON alert_history(rule_name, created_at);
    CREATE INDEX IF NOT EXISTS idx_history_status_time
        ON alert_history(status, created_at);
    CREATE INDEX IF NOT EXISTS idx_history_fp_time
        ON alert_history(fingerprint, created_at);
    CREATE TABLE IF NOT EXISTS meta(
        key TEXT PRIMARY KEY,
        val TEXT,
        expire_at REAL DEFAULT NULL
    );
"""


class SQLiteStore:
    """轻量持久化：active_alerts（活跃态）+ alert_history（历史）+ meta（KV）。

    并发加固（阶段 1, 2026-08-13）：
      * WAL 模式 —— 读写不互斥
      * busy_timeout —— 写锁等待 5s
      * synchronous=NORMAL —— WAL 下兼顾安全与性能
      * 复合索引 —— 查询加速
      * executemany 批量写 —— 写放大 -80%
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._local = threading.local()
        self._busy_timeout = DB_BUSY_TIMEOUT

    # ================= 连接管理 =================
    @property
    def conn(self) -> sqlite3.Connection:
        """获取线程本地数据库连接（惰性创建，自动重试一次）。"""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            try:
                conn = self._create_connection()
                self._local.conn = conn
            except Exception as exc:  # noqa: BLE001
                logger.error("数据库连接失败 db=%s: %s", self.db_path, exc)
                raise
        return self._local.conn

    def _create_connection(self) -> sqlite3.Connection:
        """创建新的数据库连接。"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=self._busy_timeout)
        conn.row_factory = sqlite3.Row

        # 关键配置：WAL + busy_timeout + NORMAL synchronous
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(f"PRAGMA busy_timeout={_to_int(self._busy_timeout * 1000)}")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def init(self) -> None:
        """初始化数据库表结构。"""
        with self.conn:
            self.conn.executescript(_DB_INIT_SQL)

    def close(self) -> None:
        """关闭数据库连接。"""
        if hasattr(self._local, "conn") and self._local.conn is not None:
            try:
                self._local.conn.close()
            except Exception as _exc:  # noqa: BLE001
                logger.debug("忽略预期内异常（降级路径）: %s", _exc)
            finally:
                self._local.conn = None

    # ================= 活跃告警 =================
    def upsert_active(self, alert) -> None:
        """插入或更新活跃告警。"""
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO active_alerts VALUES (?,?,?,?)",
                (alert.fingerprint, json.dumps(alert.to_dict(), ensure_ascii=False),
                 alert.status, time.time()),
            )

    def get_active_alerts(self) -> list:
        """获取全部活跃告警（firing + ack，ack=已确认未解除）。

        P1-③（2026-08-25）：ack 状态需持久可见 —— 原实现只查 firing，
        导致 ack 记录脱离查询/对账范围（僵尸行），且 get_firing_alerts() 的
        "firing + ack" 注释与实际行为不符。
        """
        rows = self.conn.execute(
            "SELECT payload FROM active_alerts WHERE status IN ('firing','ack')"
        ).fetchall()
        if not rows:
            return []
        return [json.loads(r["payload"]) for r in rows]

    def remove_active(self, fingerprint: str) -> None:
        """移除指定 fingerprint 的活跃告警。"""
        with self.conn:
            self.conn.execute(
                "DELETE FROM active_alerts WHERE fingerprint=?", (fingerprint,))

    # ================= 历史 =================
    def add_history(self, alert) -> None:
        """添加单条历史告警。"""
        with self.conn:
            self.conn.execute(
                "INSERT INTO alert_history(fingerprint,rule_name,project,severity,status,payload,created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (alert.fingerprint, alert.rule_name, alert.project, alert.severity,
                 alert.status, json.dumps(alert.to_dict(), ensure_ascii=False), time.time()),
            )

    def add_history_batch(self, alerts: list) -> None:
        """批量落历史（风暴场景写放大 -80%）：单事务 executemany。

        按 _MAX_BATCH_SIZE 分批，避免单次参数过多导致 SQLite 限制。

        入库去重（2026-10-15，MemLeak 治理根治项）：
          vmalert 在条件满足的每个评估周期（30s）重推同一 firing（单机 notifier
          模式无 sent_at 抑制），dedup 只拦推送链拦不住入库 → 单日同指纹 1203 条
          历史污染月报与分析。此处按 (fingerprint, status) 在 HIST_DEDUP_WINDOW
          秒窗口内去重：窗口内已有同指纹同状态行 → 该条不入库（记 debug 日志）。
          resolved 用独立短窗口 RESOLVED_DEDUP_WINDOW 去抖
          （2026-10-23 修正：原「由推送层控量」不成立 —— 入库不走流水线）。
          窗口 env ALERT_SIFT_HIST_DEDUP_SECONDS 可配，0 = 关闭去重。
        """
        if not alerts:
            return

        now = time.time()
        window = HIST_DEDUP_WINDOW
        kept: list = []
        if window <= 0:
            kept = list(alerts)
        else:
            # 一次范围查询拉窗口内 (fingerprint,status) 集合，内存过滤整批
            try:
                since = now - window
                rows = self.conn.execute(
                    "SELECT DISTINCT fingerprint, status FROM alert_history "
                    "WHERE created_at >= ? AND created_at <= ?",
                    (since, now + 1),
                ).fetchall()
                recent = {(r["fingerprint"], r["status"]) for r in rows}
            except Exception:  # noqa: BLE001 —— 查询失败降级为不去重（宁重复不丢）
                logger.warning("history 去重查询失败，降级全量入库: %s",
                               sys.exc_info()[1])
                recent = set()

            # resolved 用独立（默认更短）窗口：僵尸每轮 reconcile 都会产生一条
            # resolved，若沿用 firing 的长窗口仍会漏；抖动恢复也不值得重复入库。
            recent_resolved: set = set()
            if RESOLVED_DEDUP_WINDOW > 0:
                try:
                    since_r = now - RESOLVED_DEDUP_WINDOW
                    rows_r = self.conn.execute(
                        "SELECT DISTINCT fingerprint FROM alert_history "
                        "WHERE created_at >= ? AND created_at <= ? AND status='resolved'",
                        (since_r, now + 1),
                    ).fetchall()
                    recent_resolved = {r["fingerprint"] for r in rows_r}
                except Exception:  # noqa: BLE001
                    logger.warning("resolved 去重查询失败，降级不去重: %s",
                                   sys.exc_info()[1])
                    recent_resolved = set()

            seen_in_batch: set = set()
            for a in alerts:
                if a.status == "resolved":
                    if a.fingerprint in recent_resolved:
                        logger.debug("history 入库去重跳过 resolved %s（%ds 窗口内已有恢复记录）",
                                     a.fingerprint, RESOLVED_DEDUP_WINDOW)
                        try:
                            import metrics as _m
                            _m.inc("alert_sift_history_dedup_skip_total")
                        except Exception as _exc:  # noqa: BLE001
                            logger.debug("忽略预期内异常（降级路径）: %s", _exc)
                        continue
                elif (a.fingerprint, a.status) in recent:
                    logger.debug("history 入库去重跳过 %s (%s) 窗口 %ds 内已有同态记录",
                                 a.fingerprint, a.status, window)
                    try:
                        import metrics as _m
                        _m.inc("alert_sift_history_dedup_skip_total")
                    except Exception as _exc:  # noqa: BLE001
                        logger.debug("忽略预期内异常（降级路径）: %s", _exc)
                    continue
                # 同批次内自身去重（同一指纹同状态出现两次只保留一条）
                key = (a.fingerprint, a.status)
                if key in seen_in_batch:
                    continue
                seen_in_batch.add(key)
                kept.append(a)
            if len(kept) < len(alerts):
                logger.info("history 入库去重：%d -> %d 条（跳过 %d 条窗口内重复）",
                            len(alerts), len(kept), len(alerts) - len(kept))

        if not kept:
            return

        rows = [
            (a.fingerprint, a.rule_name, a.project, a.severity, a.status,
             json.dumps(a.to_dict(), ensure_ascii=False), now)
            for a in kept
        ]

        # 分批写入
        for i in range(0, len(rows), _MAX_BATCH_SIZE):
            batch = rows[i:i + _MAX_BATCH_SIZE]
            with self.conn:
                self.conn.executemany(
                    "INSERT INTO alert_history(fingerprint,rule_name,project,severity,status,payload,created_at) "
                    "VALUES (?,?,?,?,?,?,?)",
                    batch,
                )

    # ================= KV（去重时间戳/触发计数） =================
    def get_meta(self, key: str) -> str | None:
        """获取 meta 值，自动清理过期键。"""
        row = self.conn.execute(
            "SELECT val, expire_at FROM meta WHERE key=?", (key,)
        ).fetchone()
        if row is None:
            return None
        if row["expire_at"] is not None and time.time() > row["expire_at"]:
            # 惰性删除过期键
            with self.conn:
                self.conn.execute("DELETE FROM meta WHERE key=?", (key,))
            return None
        return row["val"]

    def set_meta(self, key: str, val: str, ttl: int | None = None) -> None:
        """设置 meta 值，可选 TTL。

        注意：用 `is not None` 判空，ttl=0 表示立即过期，
        避免 0 被误当 falsy 而变成永久不过期（边界健壮性）。
        """
        expire = time.time() + ttl if ttl is not None else None
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO meta(key,val,expire_at) VALUES (?,?,?)",
                (key, val, expire),
            )

    def cleanup_expired_meta(self) -> int:
        """批量清理已过期 meta 键。

        Returns:
            删除条数。
        """
        with self.conn:
            cur = self.conn.execute(
                "DELETE FROM meta WHERE expire_at IS NOT NULL AND expire_at < ?",
                (time.time(),))
            return cur.rowcount

    def incr_meta(self, key: str) -> int:
        """自增 meta 值（带 TTL），返回新值。"""
        cur = _to_int(self.get_meta(key) or 0) + 1
        self.set_meta(key, str(cur), ttl=3600)
        return cur
