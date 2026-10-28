#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""构建 alert-sift 产品页的发布产物（工具站二级目录形态）。

用法：
    python web/build.py --out <输出目录> [--slug alert-sift] [--site-url https://<站点>/]

产物形态（满足 deploy.sh 硬性要求）：
    <输出目录>/index.html      单文件页面（内联样式与脚本，无外部资源依赖）

设计约束：
  * 站点地址**不写在源码里**，由 --site-url 注入 —— 源码可安全进公开仓库，
    构建产物仍带「返回工具站」导航。
  * 不做根绝对引用（deploy.sh 会拒绝），站内跳转一律用页内锚点。
  * 构建期做敏感信息自检，命中即失败，避免带病发布。
"""
from __future__ import annotations

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "index.html")

# 敏感信息自检规则：命中即构建失败
# （不依赖行首正则，避免"注释里出现"与"真值"混淆）
SENSITIVE_RULES = [
    ("内网 IP", re.compile(r"\b(?:10|172|192)\.(?:\d{1,3}\.){2}\d{1,3}\b")),
    ("公网主机名", re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\.[a-z]{2,}\b")),
    ("内部域名", re.compile(r"\b[a-z0-9.-]*\.gf\.com\.cn\b")),
    ("凭据赋值", re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\s*=\s*[\"'][^\"']{6,}")),
    ("webhook 明文 key", re.compile(r"webhook/send\?key=[A-Za-z0-9_\-]{8,}")),
    ("SSH 私钥", re.compile(r"BEGIN [A-Z ]*PRIVATE KEY")),
]

BACK_LINK_TPL = (
    '      <a href="{site}" class="hide-sm back-site" rel="noopener">\n'
    "        <svg width=\"12\" height=\"12\" viewBox=\"0 0 24 24\" fill=\"none\" aria-hidden=\"true\">\n"
    "          <path d=\"M15 6l-6 6 6 6\" stroke=\"currentColor\" stroke-width=\"2\"\n"
    "                stroke-linecap=\"round\" stroke-linejoin=\"round\"/>\n"
    "        </svg>\n"
    "        工具列表\n"
    "      </a>\n"
)

BACK_CSS = """
/* 「返回工具站」链接：构建期注入，站点地址不入源码 */
.nav-links .back-site{display:inline-flex;align-items:center;gap:.28rem}
@media (max-width:920px){.nav-links .back-site{display:none}}
"""


def check_sensitive(html: str) -> list[str]:
    """返回命中的敏感项描述列表（空列表 = 通过）。"""
    hits = []
    for label, pattern in SENSITIVE_RULES:
        for m in pattern.finditer(html):
            hits.append(f"{label}: {m.group(0)[:60]}")
    return hits


def check_root_absolute(html: str, slug: str) -> list[str]:
    """根绝对引用检查（deploy.sh 会拒绝非 /<slug>/ 前缀的引用）。"""
    refs = re.findall(r'(?:src|href)="(/[^"]*)"', html)
    return [r for r in refs if not r.startswith(f"/{slug}/")]


def main() -> int:
    ap = argparse.ArgumentParser(description="构建 alert-sift 产品页发布产物")
    ap.add_argument("--out", required=True, help="输出目录")
    ap.add_argument("--slug", default="alert-sift", help="工具 slug（默认 alert-sift）")
    ap.add_argument("--site-url", default=os.getenv("XMTOOLDEV_SITE_URL", ""),
                    help="站点根 URL（如 https://example.com/），"
                         "用于注入「工具列表」返回链接；留空则不注入")
    ap.add_argument("--allow-sensitive", action="store_true",
                    help="跳过敏感信息自检（仅用于本地排障，不用于发布）")
    args = ap.parse_args()

    if not os.path.exists(SOURCE):
        print(f"✗ 源文件不存在: {SOURCE}")
        return 1

    html = open(SOURCE, encoding="utf-8").read()
    print("=" * 58)
    print(f"  构建 alert-sift 产品页  (slug={args.slug})")
    print("=" * 58)
    print(f"  源文件: {SOURCE}  ({len(html):,} 字符)")

    # ---- 1) 敏感信息自检 ----
    hits = check_sensitive(html)
    if hits and not args.allow_sensitive:
        print("\n  ✗ 敏感信息自检未通过：")
        for h in hits[:10]:
            print("     ", h)
        print("  请在源码中脱敏后重建，或改用占位/示例值")
        return 1
    print(f"  敏感信息自检：{'PASS' if not hits else 'SKIPPED(--allow-sensitive)'}")

    # ---- 2) 注入「返回工具站」导航 ----
    if args.site_url:
        site = args.site_url.rstrip("/") + "/"
        if "back-site" in html:
            print("  返回链接已存在，跳过注入")
        else:
            m = re.search(r"(<nav class=\"nav-links\">\s*)", html)
            if not m:
                print("  ✗ 未找到 <nav class=\"nav-links\">，无法注入返回链接")
                return 1
            html = html[:m.end()] + BACK_LINK_TPL.format(site=site) + html[m.end():]
            html = html.replace("</style>", BACK_CSS + "</style>", 1)
            print(f"  已注入「工具列表」返回链接 -> {site}")
    else:
        print("  未指定 --site-url，跳过返回链接注入（产物无站点回链）")

    # ---- 3) 根绝对引用检查 ----
    bad = check_root_absolute(html, args.slug)
    if bad:
        print(f"\n  ✗ 存在非 /{args.slug}/ 前缀的根绝对引用（deploy.sh 会拒绝）：")
        for b in bad[:8]:
            print("     ", b)
        return 1
    print("  根绝对引用：PASS")

    # ---- 4) 落盘 ----
    os.makedirs(args.out, exist_ok=True)
    out_file = os.path.join(args.out, "index.html")
    with open(out_file, "w", encoding="utf-8", newline="\n") as f:
        f.write(html)
    size = os.path.getsize(out_file)
    print(f"\n  产物: {out_file}  ({size:,} 字节)")

    print("\n  发布目录清单：")
    total = 0
    for root, _d, fs in os.walk(args.out):
        for f in sorted(fs):
            full = os.path.join(root, f)
            rel = os.path.relpath(full, args.out).replace("\\", "/")
            sz = os.path.getsize(full)
            total += sz
            print(f"    {sz:>10,}  {rel}")
    print(f"    {total:>10,}  合计")
    print("=" * 58)
    return 0


if __name__ == "__main__":
    sys.exit(main())
