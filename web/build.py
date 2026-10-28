#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""构建 alert-sift 产品页的发布产物（工具站二级目录形态）。

用法：
    python web/build.py --out <输出目录> [--slug alert-sift] [--site-url https://<站点>/]
                         [--version v0.1.0] [--no-package]

产物形态（满足 deploy.sh 硬性要求）：
    <输出目录>/index.html                       单文件页面（内联样式与脚本）
    <输出目录>/assets/<name>-<version>-src.zip  源码包（页面下载入口）

设计约束：
  * 站点地址**不写在源码里**，由 --site-url 注入 —— 源码可安全进公开仓库，
    构建产物仍带「返回工具站」导航。
  * 源码包内容取自 git 已跟踪文件，包内做敏感信息自检（见 make_dist.py）。
  * 下载链接写相对路径 assets/<file>.zip（二级目录部署必须），文件名用 ASCII。
  * 构建期做敏感信息自检，命中即失败，避免带病发布。
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "index.html")

# 页面里的下载占位符（由构建期替换为真实文件名/大小）
DL_FILE_PLACEHOLDER = "__DL_FILE__"
DL_SIZE_PLACEHOLDER = "__DL_SIZE__"

# 敏感信息自检规则：命中即构建失败
# （不依赖行首正则，避免"注释里出现"与"真值"混淆）
#
# 示例值白名单：RFC 5737 文档专用网段（192.0.2.0/24、198.51.100.0/24、
# 203.0.113.0/24）—— 业界标准保留段，用作示例天然自证非真实地址，
# 且与真实内网段不会混淆。
EXAMPLE_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")

SENSITIVE_RULES = [
    ("内网 IP", re.compile(r"\b(?:10|172|192|198|203)\.(?:\d{1,3}\.){2}\d{1,3}\b")),
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
    """返回命中的敏感项描述列表（空列表 = 通过）。

    RFC 5737 文档专用网段视为示例值，不算命中。
    """
    hits = []
    for label, pattern in SENSITIVE_RULES:
        for m in pattern.finditer(html):
            value = m.group(0)
            if label == "内网 IP" and value.startswith(EXAMPLE_NETS):
                continue  # RFC 5737 示例段，跳过
            hits.append(f"{label}: {value[:60]}")
    return hits


def check_root_absolute(html: str, slug: str) -> list[str]:
    """根绝对引用检查（deploy.sh 会拒绝非 /<slug>/ 前缀的引用）。"""
    refs = re.findall(r'(?:src|href)="(/[^"]*)"', html)
    return [r for r in refs if not r.startswith(f"/{slug}/")]


def human_size(num: int) -> str:
    """字节数 → 人类可读（KB/MB）。"""
    if num < 1024:
        return f"{num} B"
    if num < 1024 * 1024:
        return f"{num / 1024:.0f} KB"
    return f"{num / 1024 / 1024:.1f} MB"


def build_package(out_dir: str, version: str, name: str) -> tuple[str, int] | None:
    """调用 make_dist.py 打源码包，拷进 assets/，返回 (文件名, 字节数)。

    失败返回 None（调用方决定是否中止）。
    """
    import shutil

    stage = os.path.join(out_dir, "_pkg")
    if os.path.isdir(stage):
        shutil.rmtree(stage)
    cmd = [sys.executable, os.path.join(HERE, "make_dist.py"),
           "--out", stage, "--version", version, "--name", name]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace")
    if proc.returncode != 0:
        print("  ✗ 源码包打包失败：")
        for line in (proc.stdout + proc.stderr).splitlines()[:12]:
            print("     ", line)
        shutil.rmtree(stage, ignore_errors=True)
        return None

    zip_name = f"{name}-{version}-src.zip"
    src_zip = os.path.join(stage, zip_name)
    if not os.path.exists(src_zip):
        print(f"  ✗ 未找到预期产物: {zip_name}")
        shutil.rmtree(stage, ignore_errors=True)
        return None

    assets_dir = os.path.join(out_dir, "assets")
    os.makedirs(assets_dir, exist_ok=True)
    dst = os.path.join(assets_dir, zip_name)
    shutil.copy2(src_zip, dst)
    size = os.path.getsize(dst)
    shutil.rmtree(stage, ignore_errors=True)
    print(f"  源码包：assets/{zip_name}  ({size:,} 字节 / {human_size(size)})")
    return zip_name, size


def main() -> int:
    ap = argparse.ArgumentParser(description="构建 alert-sift 产品页发布产物")
    ap.add_argument("--out", required=True, help="输出目录")
    ap.add_argument("--slug", default="alert-sift", help="工具 slug（默认 alert-sift）")
    ap.add_argument("--site-url", default=os.getenv("XMTOOLDEV_SITE_URL", ""),
                    help="站点根 URL（如 https://example.com/），"
                         "用于注入「工具列表」返回链接；留空则不注入")
    ap.add_argument("--allow-sensitive", action="store_true",
                    help="跳过敏感信息自检（仅用于本地排障，不用于发布）")
    ap.add_argument("--version", default="v0.1.0", help="源码包版本号")
    ap.add_argument("--name", default="alert-sift", help="源码包名前缀")
    ap.add_argument("--no-package", action="store_true",
                    help="不打包源码包（页面下载入口将不生成）")
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

    # ---- 4) 打包源码包并回填下载入口 ----
    if args.no_package:
        print("  已指定 --no-package，跳过源码包")
        if DL_FILE_PLACEHOLDER in html:
            print("  ! 页面仍含下载占位符，下载入口不可用")
    else:
        pkg = build_package(args.out, args.version, args.name)
        if pkg is None:
            print("\n  ✗ 源码包构建失败，终止构建")
            return 1
        zip_name, size = pkg
        if DL_FILE_PLACEHOLDER not in html:
            print(f"  ! 页面未找到 {DL_FILE_PLACEHOLDER} 占位符，下载入口未回填")
        else:
            html = html.replace(DL_FILE_PLACEHOLDER, zip_name)
            html = html.replace(DL_SIZE_PLACEHOLDER, human_size(size))
            print(f"  下载入口已回填：assets/{zip_name}（{human_size(size)}）")

    # ---- 5) 落盘 ----
    os.makedirs(args.out, exist_ok=True)
    out_file = os.path.join(args.out, "index.html")
    with open(out_file, "w", encoding="utf-8", newline="\n") as f:
        f.write(html)
    size = os.path.getsize(out_file)
    print(f"\n  产物: {out_file}  ({size:,} 字节)")

    # ---- 6) 下载链接可达性自检 ----
    refs = re.findall(r'href="(assets/[^"]+)"', html)
    for rel in refs:
        target = os.path.join(args.out, rel)
        if not os.path.exists(target):
            print(f"  ✗ 下载链接指向不存在的文件: {rel}")
            return 1
    if refs:
        print(f"  下载链接可达性：PASS（{len(refs)} 处）")

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
