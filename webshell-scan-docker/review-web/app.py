#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Local review portal for webshell scan findings.

The app is intentionally dependency-light: stdlib HTTP + SQLite, with optional
openpyxl/yara support when they are installed in the scanner environment.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import mimetypes
import os
import posixpath
import re
import secrets
import shutil
import sqlite3
import sys
import textwrap
import time
import urllib.parse
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from http.cookies import SimpleCookie
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath

try:
    import openpyxl
except Exception:  # pragma: no cover - optional runtime dependency
    openpyxl = None

try:
    import yara
except Exception:  # pragma: no cover - optional runtime dependency
    yara = None


APP_DIR = Path(__file__).resolve().parent
SCANNER_DIR = APP_DIR.parent
DATA_DIR = APP_DIR / "data"
DB_PATH = DATA_DIR / "review.db"
CONFIG_PATH = DATA_DIR / "config.json"
MAX_UPLOAD_BYTES = 512 * 1024 * 1024
MAX_VIEW_BYTES = 2 * 1024 * 1024
YARA_TIMEOUT_SECONDS = 20
FINDING_FILE_EXTENSIONS = (".csv", ".xlsx", ".xlsm")
SESSION_COOKIE = "review_session"
ADMIN_COOKIE = "review_admin"
SESSION_TTL_SECONDS = 8 * 60 * 60
VALID_STATUSES = ("pending", "reviewing", "confirmed", "benign", "remediated")

sys.path.insert(0, str(SCANNER_DIR))

try:
    from libs.deobfuscate import iter_deobfuscated_layers, should_deobfuscate
except Exception:  # pragma: no cover - scanner tree may be incomplete
    iter_deobfuscated_layers = None
    should_deobfuscate = None

try:
    from libs.review_bundle import (
        ReviewBundleError,
        bundle_passphrase,
        decrypt_review_bundle_bytes,
    )
except Exception:  # pragma: no cover - scanner tree may be incomplete
    ReviewBundleError = RuntimeError
    bundle_passphrase = None
    decrypt_review_bundle_bytes = None


@dataclass
class UploadedPart:
    name: str
    filename: str | None
    content_type: str
    data: bytes


def now_ts() -> int:
    return int(time.time())


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / "cases").mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(
            json.dumps({"admin_key": secrets.token_urlsafe(32)}, indent=2),
            encoding="utf-8",
        )


def get_admin_key() -> str:
    env_key = os.environ.get("REVIEW_ADMIN_KEY", "").strip()
    if env_key:
        return env_key
    return str(read_json(CONFIG_PATH, {}).get("admin_key", ""))


@contextmanager
def connect_db() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with connect_db() as conn:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                share_key TEXT NOT NULL UNIQUE,
                viewer_key TEXT UNIQUE,
                created_at INTEGER NOT NULL,
                source_zip_name TEXT,
                finding_count INTEGER NOT NULL DEFAULT 0,
                source_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                sha256 TEXT,
                score INTEGER,
                scan_time TEXT,
                description TEXT,
                extension TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                reviewer_note TEXT NOT NULL DEFAULT '',
                local_relpath TEXT,
                has_source INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(id)
            );
            CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id);
            CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(case_id, status);
            CREATE TABLE IF NOT EXISTS layers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                relpath TEXT NOT NULL,
                size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                UNIQUE(finding_id, name),
                FOREIGN KEY(finding_id) REFERENCES findings(id)
            );
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                layer_name TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                string_id TEXT,
                start_offset INTEGER,
                end_offset INTEGER,
                matched_text TEXT,
                score INTEGER,
                description TEXT,
                reference TEXT,
                author TEXT,
                FOREIGN KEY(finding_id) REFERENCES findings(id)
            );
            CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                finding_id INTEGER,
                action TEXT NOT NULL,
                detail TEXT,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                case_id INTEGER NOT NULL,
                role TEXT NOT NULL DEFAULT 'reviewer',
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(id)
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_case ON sessions(case_id);
            CREATE TABLE IF NOT EXISTS admin_sessions (
                token TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            """
        )
        ensure_column(conn, "cases", "viewer_key", "TEXT")
        ensure_column(conn, "sessions", "role", "TEXT NOT NULL DEFAULT 'reviewer'")
        for row in conn.execute("SELECT id FROM cases WHERE viewer_key IS NULL OR viewer_key=''", ()):
            conn.execute("UPDATE cases SET viewer_key=? WHERE id=?", (secrets.token_urlsafe(24), row["id"]))
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_cases_viewer_key ON cases(viewer_key)")


def ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def scanner_policy() -> dict:
    return read_json(SCANNER_DIR / "config" / "scan-policy.json", {})


def html_page(title: str, body: str, *, refresh: bool = False) -> bytes:
    refresh_tag = '<meta http-equiv="refresh" content="5">' if refresh else ""
    page = f"""<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {refresh_tag}
  <title>{html.escape(title)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #eef2f6;
      --panel: #ffffff;
      --panel-soft: #f8fafc;
      --line: #dde3eb;
      --line-strong: #b7c0cc;
      --text: #17202a;
      --muted: #667085;
      --brand: #17324d;
      --accent: #166534;
      --accent-soft: #dcfce7;
      --amber-soft: #fff7d6;
      --warn: #92400e;
      --danger: #991b1b;
      --danger-soft: #fee2e2;
      --info: #075985;
      --info-soft: #e0f2fe;
      --mark: #fff2a8;
      --mark2: #b8f2e6;
      --mark3: #ffd6a5;
      --code-bg: #111827;
      --code-text: #e5e7eb;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    a {{ color: #075985; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    header {{
      background: rgba(255,255,255,.94);
      color: var(--brand);
      border-bottom: 1px solid var(--line);
      position: sticky;
      top: 0;
      z-index: 5;
      backdrop-filter: blur(8px);
    }}
    header .bar, main {{ max-width: 1500px; margin: 0 auto; }}
    header .bar {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 13px 18px;
    }}
    .brand {{ display: inline-flex; align-items: center; gap: 10px; font-weight: 750; letter-spacing: 0; }}
    .brand::before {{
      content: "";
      width: 12px;
      height: 12px;
      border-radius: 3px;
      background: #0f766e;
      box-shadow: 0 0 0 4px #ccfbf1;
    }}
    .system-badge {{
      border: 1px solid var(--line);
      border-radius: 999px;
      color: #475467;
      background: #f8fafc;
      padding: 3px 10px;
      font-size: 12px;
      font-weight: 650;
    }}
    .toplinks a {{ color: #075985; margin-left: 14px; }}
    main {{ padding: 22px 18px; }}
    h1, h2 {{ margin: 0 0 12px; line-height: 1.22; letter-spacing: 0; }}
    h1 {{ font-size: 26px; color: #111827; }}
    h2 {{ font-size: 16px; color: #253044; }}
    .eyebrow {{
      color: #475467;
      font-size: 12px;
      font-weight: 750;
      letter-spacing: .04em;
      text-transform: uppercase;
      margin-bottom: 6px;
    }}
    .band {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 16px;
      min-width: 0;
      box-shadow: 0 1px 2px rgba(16,24,40,.04);
    }}
    .page-head {{
      padding: 20px;
      border-color: #cfd8e3;
    }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }}
    .metric {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px 13px;
      background: var(--panel-soft);
      min-height: 86px;
      position: relative;
      overflow: hidden;
    }}
    .metric::before {{
      content: "";
      position: absolute;
      left: 0;
      top: 0;
      right: 0;
      height: 3px;
      background: #64748b;
    }}
    .metric:nth-child(2)::before, .metric:nth-child(3)::before {{ background: #dc2626; }}
    .metric:nth-child(4)::before {{ background: #0f766e; }}
    .metric:nth-child(7)::before {{ background: #d97706; }}
    .metric:nth-child(8)::before {{ background: #166534; }}
    .metric b {{ display: block; font-size: 30px; line-height: 1.1; margin-bottom: 6px; }}
    .metric span {{ color: var(--muted); font-size: 13px; }}
    .tablewrap {{ width: 100%; overflow-x: auto; }}
    table {{ width: 100%; min-width: 720px; border-collapse: separate; border-spacing: 0; background: var(--panel); }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 10px 9px; vertical-align: top; }}
    th {{
      text-align: left;
      color: #475467;
      background: #f8fafc;
      position: sticky;
      top: 0;
      z-index: 1;
      font-size: 12px;
      font-weight: 750;
      text-transform: uppercase;
    }}
    tbody tr:nth-child(even) td {{ background: #fcfdff; }}
    tr:hover td {{ background: #f1f7ff; }}
    .path {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; }}
    .muted {{ color: var(--muted); overflow-wrap: anywhere; }}
    .pill {{
      display: inline-block;
      border: 1px solid var(--line-strong);
      border-radius: 999px;
      padding: 2px 9px;
      background: #fff;
      white-space: nowrap;
      font-size: 12px;
      font-weight: 650;
    }}
    .score-high {{ color: var(--danger); font-weight: 700; }}
    .score-mid {{ color: var(--warn); font-weight: 700; }}
    .score-low {{ color: var(--info); font-weight: 700; }}
    .status-pending {{ background: #f2f4f7; color: #344054; border-color: #d0d5dd; }}
    .status-reviewing {{ background: var(--info-soft); color: #075985; border-color: #7dd3fc; }}
    .status-confirmed {{ background: var(--danger-soft); color: #991b1b; border-color: #fca5a5; }}
    .status-benign {{ background: var(--accent-soft); color: #166534; border-color: #86efac; }}
    .status-remediated {{ background: #ede9fe; color: #5b21b6; border-color: #c4b5fd; }}
    .split {{ display: grid; grid-template-columns: 360px minmax(0, 1fr); gap: 14px; align-items: start; min-width: 0; }}
    .split > * {{ min-width: 0; }}
    .stack > * + * {{ margin-top: 10px; }}
    .stack > label {{ display: block; font-weight: 650; color: #344054; }}
    .stack select, .stack textarea {{ width: 100%; margin-top: 4px; }}
    input, select, textarea, button {{
      font: inherit;
      border: 1px solid var(--line-strong);
      border-radius: 7px;
      padding: 8px 10px;
      background: #fff;
    }}
    input:focus, select:focus, textarea:focus {{
      outline: 3px solid #bfdbfe;
      border-color: #2563eb;
    }}
    textarea {{ width: 100%; min-height: 120px; resize: vertical; }}
    button, .button {{
      cursor: pointer;
      background: #0f172a;
      color: #fff;
      border-color: #0f172a;
      display: inline-block;
      font-weight: 700;
    }}
    button:hover, .button:hover {{ background: #1f2937; text-decoration: none; }}
    button.secondary, .button.secondary {{ background: #fff; color: #0f172a; border-color: var(--line-strong); }}
    .filters {{ display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }}
    .codewrap {{
      background: var(--code-bg);
      color: var(--code-text);
      border-radius: 8px;
      overflow: auto;
      max-width: 100%;
      max-height: 72vh;
      border: 1px solid #020617;
    }}
    pre.code {{
      margin: 0;
      padding: 12px 0;
      min-width: 100%;
      font: 12px/1.55 ui-monospace, SFMono-Regular, Consolas, monospace;
      white-space: pre;
    }}
    .ln {{ display: inline-block; width: 58px; padding-right: 12px; text-align: right; color: #94a3b8; user-select: none; }}
    mark {{ color: #111827; padding: 0 1px; border-radius: 2px; }}
    mark.m0 {{ background: var(--mark); }}
    mark.m1 {{ background: var(--mark2); }}
    mark.m2 {{ background: var(--mark3); }}
    .rule-list {{ max-height: 40vh; overflow: auto; border-top: 1px solid var(--line); }}
    .rule-hit {{ border-bottom: 1px solid var(--line); padding: 10px 0; overflow-wrap: anywhere; }}
    .rule-hit code {{ background: #eef2f7; padding: 2px 5px; border-radius: 4px; color: #111827; }}
    details.details {{
      margin-top: 10px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #f8fafc;
      padding: 8px 10px;
    }}
    details.details summary {{
      cursor: pointer;
      color: #253044;
      font-weight: 700;
    }}
    .detail-text {{
      margin: 8px 0 0;
      max-height: 180px;
      overflow: auto;
      font-size: 12px;
    }}
    .notice {{ border-left: 4px solid #075985; background: var(--info-soft); padding: 10px 12px; border-radius: 6px; }}
    .warn {{ border-left: 4px solid #92400e; background: #fffbeb; padding: 10px 12px; border-radius: 6px; }}
    @media (max-width: 980px) {{
      .grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .split {{ grid-template-columns: 1fr; }}
      header .bar {{ align-items: flex-start; flex-direction: column; }}
      main {{ padding: 12px; }}
      h1 {{ font-size: 22px; }}
      .filters input {{ min-width: 0 !important; width: 100%; }}
      .pill {{ white-space: normal; overflow-wrap: anywhere; }}
    }}
  </style>
</head>
<body>
  <header><div class="bar"><div class="brand">Webshell Scan Review</div><div class="toplinks"><span class="system-badge">ATTT review</span></div></div></header>
  <main>{body}</main>
</body>
</html>"""
    return page.encode("utf-8")


def safe_int(value, default=0):
    try:
        if value in (None, ""):
            return default
        return int(float(str(value).strip()))
    except Exception:
        return default


def normalize_header(value: str) -> str:
    return re.sub(r"\s+", "_", str(value or "").strip().upper())


def parse_findings_file(filename: str, data: bytes) -> list[dict]:
    suffix = Path(filename or "").suffix.lower()
    if suffix in (".xlsx", ".xlsm"):
        if openpyxl is None:
            raise RuntimeError("Thiếu openpyxl nên chưa đọc được file Excel.")
        wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        ws = wb.active
        rows = ws.iter_rows(values_only=True)
        headers = [normalize_header(v) for v in next(rows, [])]
        result = []
        for row in rows:
            item = {}
            for idx, header in enumerate(headers):
                if not header or header.startswith("UNNAMED"):
                    continue
                item[header] = row[idx] if idx < len(row) else None
            if item.get("FILE"):
                result.append(item)
        return result

    text = data.decode("utf-8-sig", errors="replace")
    sample = text[:4096]
    dialect = csv.Sniffer().sniff(sample) if sample.strip() else csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    result = []
    for row in reader:
        item = {normalize_header(k): v for k, v in row.items() if k}
        if item.get("FILE"):
            result.append(item)
    return result


def parse_multipart(headers, body: bytes) -> dict[str, list[UploadedPart]]:
    content_type = headers.get("Content-Type", "")
    raw = b"Content-Type: " + content_type.encode("latin-1") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    parts: dict[str, list[UploadedPart]] = {}
    if not msg.is_multipart():
        return parts
    for part in msg.iter_parts():
        cd = part.get("Content-Disposition", "")
        if "form-data" not in cd:
            continue
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        parts.setdefault(name, []).append(
            UploadedPart(name=name, filename=filename, content_type=part.get_content_type(), data=payload)
        )
    return parts


def parse_post_parts(headers, body: bytes) -> dict[str, list[UploadedPart]]:
    content_type = headers.get("Content-Type", "")
    if content_type.lower().startswith("application/x-www-form-urlencoded"):
        parsed = urllib.parse.parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
        return {
            name: [
                UploadedPart(name=name, filename=None, content_type="text/plain", data=value.encode("utf-8"))
                for value in values
            ]
            for name, values in parsed.items()
        }
    return parse_multipart(headers, body)


def form_value(parts: dict[str, list[UploadedPart]], name: str, default: str = "") -> str:
    values = parts.get(name) or []
    if not values:
        return default
    return values[0].data.decode("utf-8", errors="replace").strip()


def file_part(parts: dict[str, list[UploadedPart]], name: str) -> UploadedPart | None:
    for part in parts.get(name) or []:
        if part.filename and part.data:
            return part
    return None


def safe_zip_extract(data: bytes, dest: Path) -> int:
    count = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            raw_name = info.filename.replace("\\", "/")
            pure = PurePosixPath(raw_name)
            if pure.is_absolute() or ".." in pure.parts:
                continue
            rel = Path(*[p for p in pure.parts if p and p not in (".",)])
            target = (dest / rel).resolve()
            if not str(target).startswith(str(dest.resolve())):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out, length=1024 * 1024)
            count += 1
    return count


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def norm_path_for_match(value: str) -> str:
    value = (value or "").replace("\\", "/")
    value = re.sub(r"^[A-Za-z]:", "", value)
    value = value.strip("/")
    return posixpath.normpath(value).lower()


def build_source_index(root: Path) -> tuple[dict[str, Path], dict[str, list[Path]], dict[str, Path]]:
    suffix_map: dict[str, Path] = {}
    basename_map: dict[str, list[Path]] = {}
    sha_map: dict[str, Path] = {}
    if not root.exists():
        return suffix_map, basename_map, sha_map
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        norm = norm_path_for_match(rel)
        suffix_map[norm] = path
        basename_map.setdefault(path.name.lower(), []).append(path)
        try:
            sha_map[file_sha256(path).lower()] = path
        except Exception:
            pass
    return suffix_map, basename_map, sha_map


def locate_source_file(file_path: str, sha256: str | None, source_root: Path) -> Path | None:
    suffix_map, basename_map, sha_map = build_source_index(source_root)
    sha = (sha256 or "").strip().lower()
    if sha and sha != "n/a" and sha in sha_map:
        return sha_map[sha]
    wanted = norm_path_for_match(file_path)
    for rel, path in suffix_map.items():
        if rel == wanted or wanted.endswith(rel) or rel.endswith(wanted):
            return path
    candidates = basename_map.get(Path(file_path.replace("\\", "/")).name.lower(), [])
    if len(candidates) == 1:
        return candidates[0]
    return None


def yara_externals(file_path: str, data: bytes) -> dict:
    name = Path(file_path.replace("\\", "/")).name
    ext = Path(name).suffix
    return {
        "filename": name,
        "filepath": file_path,
        "extension": ext,
        "filetype": "",
        "md5": hashlib.md5(data).hexdigest(),
        "owner": "dummy",
    }


_COMPILED_YARA = None
_YARA_STATUS = ""


def compile_yara_rules():
    global _COMPILED_YARA, _YARA_STATUS
    if _COMPILED_YARA is not None or _YARA_STATUS:
        return _COMPILED_YARA
    if yara is None:
        _YARA_STATUS = "Thiếu yara-python nên không chạy lại YARA được."
        return None

    policy_data = scanner_policy()
    rule_mode = str(policy_data.get("yara_rule_mode", "all")).lower()
    patterns = [str(p).lower() for p in policy_data.get("webshell_yara_file_patterns", [])]
    rule_dirs = [
        SCANNER_DIR / "libs" / "signature-base" / "custom",
        SCANNER_DIR / "libs" / "signature-base" / "yara",
        SCANNER_DIR / "libs" / "signature-base" / "iocs" / "yara",
    ]
    externals = {
        "filename": "",
        "filepath": "",
        "extension": "",
        "filetype": "",
        "md5": "",
        "owner": "dummy",
    }
    valid_sources: list[str] = []
    skipped = 0
    for rule_dir in rule_dirs:
        if not rule_dir.exists():
            continue
        for path in rule_dir.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in (".yar", ".yara"):
                continue
            if path.name.startswith((".", "~", "_")):
                continue
            rel = path.relative_to(SCANNER_DIR).as_posix().lower()
            if rule_mode in ("webshell-only", "webshell_only", "webshell"):
                if "/custom/" not in rel and not any(p in rel for p in patterns):
                    continue
            source = path.read_text(encoding="utf-8", errors="replace")
            if not source.strip():
                continue
            try:
                yara.compile(source=source, externals=externals)
                valid_sources.append(source)
            except Exception:
                skipped += 1
    if not valid_sources:
        _YARA_STATUS = "Không compile được YARA rule nào."
        return None
    try:
        _COMPILED_YARA = yara.compile(source="\n".join(valid_sources), externals=externals)
        _YARA_STATUS = f"YARA ready: {len(valid_sources)} file rule hợp lệ, bỏ qua {skipped} file lỗi."
    except Exception as exc:
        _YARA_STATUS = f"Lỗi compile YARA tổng: {exc}"
        _COMPILED_YARA = None
    return _COMPILED_YARA


def match_instances(match) -> list[tuple[int, str, bytes]]:
    out: list[tuple[int, str, bytes]] = []
    for item in getattr(match, "strings", []) or []:
        if hasattr(item, "instances"):
            ident = str(getattr(item, "identifier", ""))
            for inst in getattr(item, "instances", []) or []:
                offset = int(getattr(inst, "offset", 0))
                data = getattr(inst, "matched_data", b"")
                if isinstance(data, str):
                    data = data.encode("utf-8", errors="replace")
                out.append((offset, ident, bytes(data)))
        elif isinstance(item, tuple) and len(item) >= 3:
            offset, ident, data = item[:3]
            if isinstance(data, str):
                data = data.encode("utf-8", errors="replace")
            out.append((int(offset), str(ident), bytes(data)))
    return out


def write_layer(case_id: int, finding_id: int, layer_name: str, data: bytes) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", layer_name)[:80] or "layer"
    rel = Path("cases") / str(case_id) / "layers" / str(finding_id) / f"{safe_name}.bin"
    path = DATA_DIR / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return rel.as_posix()


def extract_evidence(conn: sqlite3.Connection, case_id: int, finding_id: int, file_path: str, local_file: Path) -> int:
    rules = compile_yara_rules()
    if rules is None:
        return 0
    data = local_file.read_bytes()
    policy_data = scanner_policy()
    ext = Path(file_path.replace("\\", "/")).suffix
    if iter_deobfuscated_layers and should_deobfuscate and should_deobfuscate(ext, file_path, policy_data):
        layers = list(iter_deobfuscated_layers(data, policy_data))
    else:
        layers = [("raw", data)]

    total = 0
    for layer_name, layer_data in layers:
        rel = write_layer(case_id, finding_id, layer_name, layer_data)
        conn.execute(
            "INSERT OR IGNORE INTO layers(finding_id, name, relpath, size, sha256) VALUES(?,?,?,?,?)",
            (finding_id, layer_name, rel, len(layer_data), hashlib.sha256(layer_data).hexdigest()),
        )
        try:
            matches = rules.match(
                data=layer_data,
                externals=yara_externals(file_path, layer_data),
                timeout=YARA_TIMEOUT_SECONDS,
            )
        except TypeError:
            matches = rules.match(data=layer_data, externals=yara_externals(file_path, layer_data))
        except Exception:
            continue
        for match in matches:
            meta = getattr(match, "meta", {}) or {}
            score = safe_int(meta.get("score"), 70)
            description = str(meta.get("description") or meta.get("cluster") or "not set")
            reference = str(meta.get("reference") or meta.get("viz_url") or "-")
            author = str(meta.get("author") or "-")
            instances = match_instances(match)
            if not instances:
                conn.execute(
                    """
                    INSERT INTO evidence(finding_id, layer_name, rule_name, score, description, reference, author)
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (finding_id, layer_name, match.rule, score, description, reference, author),
                )
                total += 1
            for offset, ident, matched in instances[:200]:
                end = offset + len(matched)
                text = matched[:240].decode("utf-8", errors="replace")
                conn.execute(
                    """
                    INSERT INTO evidence(
                        finding_id, layer_name, rule_name, string_id, start_offset, end_offset,
                        matched_text, score, description, reference, author
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (finding_id, layer_name, match.rule, ident, offset, end, text, score, description, reference, author),
                )
                total += 1
    return total


def _read_bundle_json(zf: zipfile.ZipFile, name: str, default):
    try:
        return json.loads(zf.read(name).decode("utf-8"))
    except KeyError:
        return default


def _safe_bundle_source_path(relpath: str) -> Path | None:
    raw = (relpath or "").replace("\\", "/")
    pure = PurePosixPath(raw)
    if pure.is_absolute() or ".." in pure.parts:
        return None
    if len(pure.parts) < 2 or pure.parts[0] != "sources":
        return None
    return Path(*[part for part in pure.parts if part and part != "."])


def _extract_bundle_member(
    zf: zipfile.ZipFile,
    relpath: str,
    source_root: Path,
    source_root_resolved: Path,
    data_root: Path,
) -> str | None:
    rel = _safe_bundle_source_path(relpath)
    if rel is None:
        return None
    try:
        data = zf.read(rel.as_posix())
    except KeyError:
        return None
    target = (source_root / rel).resolve()
    try:
        target.relative_to(source_root_resolved)
    except ValueError:
        return None
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return target.relative_to(data_root).as_posix()


def import_enc_case(title: str, enc_bundle: UploadedPart) -> tuple[int, str, int, int]:
    filename = enc_bundle.filename or "review.enc"
    if Path(filename).suffix.lower() != ".enc":
        raise RuntimeError("Chỉ chấp nhận file .enc được tạo bởi webshell-scan.")
    if decrypt_review_bundle_bytes is None or bundle_passphrase is None:
        raise RuntimeError("Thiếu module đọc .enc trong libs/review_bundle.py.")

    passphrase = bundle_passphrase(SCANNER_DIR, create_if_missing=False)
    zip_payload = decrypt_review_bundle_bytes(enc_bundle.data, passphrase)
    if not zipfile.is_zipfile(io.BytesIO(zip_payload)):
        raise RuntimeError("Payload .enc không chứa review bundle hợp lệ.")

    share_key = secrets.token_urlsafe(32)
    viewer_key = secrets.token_urlsafe(24)
    created = now_ts()
    with zipfile.ZipFile(io.BytesIO(zip_payload)) as zf, connect_db() as conn:
        manifest = _read_bundle_json(zf, "manifest.json", {})
        findings = _read_bundle_json(zf, "findings.json", [])
        gray_zone = _read_bundle_json(zf, "gray_zone.json", [])
        source_index = _read_bundle_json(zf, "sources/index.json", [])
        if manifest.get("schema") != "webshell-review-bundle-v1":
            raise RuntimeError("File .enc không đúng schema review bundle.")
        if not isinstance(findings, list):
            findings = []
        if not isinstance(gray_zone, list):
            gray_zone = []
        if not isinstance(source_index, list):
            source_index = []
        valid_rows = [row for row in findings + gray_zone if isinstance(row, dict) and (
            str(row.get("FILE") or row.get("file") or "").strip()
            and str(row.get("SHA256") or row.get("sha256") or "N/A").strip()
        )]
        valid_candidates = [item for item in source_index if isinstance(item, dict) and (
            str(item.get("candidate_id") or "").strip()
            and (str(item.get("file") or "").strip() or str(item.get("relpath") or "").strip()
                 or item.get("source_status") == "omitted")
        )]
        if not valid_rows and not valid_candidates:
            raise RuntimeError("File .enc không có finding hoặc candidate hợp lệ để import.")
        if not findings and not gray_zone and not valid_candidates:
            raise RuntimeError("File .enc không có candidate hợp lệ để import.")
        if not findings and not gray_zone:
            findings = [{
                "FILE": str(item.get("file") or item.get("candidate_id")),
                "SHA256": str(item.get("sha256") or "N/A"),
                "SCORE": item.get("score"),
                "TIME": item.get("time", ""),
                "DESCRIPTION": item.get("description", "candidate-only import"),
                "EXTENSION": item.get("extension") or Path(str(item.get("file") or "")).suffix,
                "candidate_id": str(item.get("candidate_id")),
            } for item in valid_candidates]
            if not findings:
                raise RuntimeError("File .enc không có candidate hợp lệ để import.")

        default_title = (
            title
            or Path(str(manifest.get("scan_path") or "")).name
            or str(manifest.get("out_file") or "")
            or f"Scan import {time.strftime('%Y-%m-%d %H:%M')}"
        )
        cur = conn.execute(
            "INSERT INTO cases(title, share_key, viewer_key, created_at, source_zip_name) VALUES(?,?,?,?,?)",
            (default_title, share_key, viewer_key, created, filename),
        )
        case_id = int(cur.lastrowid)
        data_root = DATA_DIR.resolve()
        case_dir = data_root / "cases" / str(case_id)
        source_root = case_dir / "source"
        source_root.mkdir(parents=True, exist_ok=True)
        source_root_resolved = source_root.resolve()

        source_by_file = {}
        source_by_sha = {}
        source_by_candidate = {}
        source_count = 0
        for item in source_index if isinstance(source_index, list) else []:
            if not isinstance(item, dict):
                continue
            meta = {
                "local_relpath": "",
                "snippet_only": bool(item.get("snippet_only")),
                "layers": [],
                "evidence": item.get("evidence") if isinstance(item.get("evidence"), list) else [],
                "candidate_id": str(item.get("candidate_id") or ""),
                "source_status": str(item.get("source_status") or "stored"),
                "source_reason": str(item.get("source_reason") or item.get("omitted_reason") or ""),
                "archive": item.get("archive") if isinstance(item.get("archive"), dict) else {},
            }
            layers = item.get("layers") if isinstance(item.get("layers"), list) else []
            for layer in layers:
                if not isinstance(layer, dict):
                    continue
                local_layer_rel = _extract_bundle_member(zf, str(layer.get("relpath") or ""), source_root, source_root_resolved, data_root)
                if local_layer_rel:
                    layer_meta = dict(layer)
                    layer_meta["local_relpath"] = local_layer_rel
                    meta["layers"].append(layer_meta)
                    if not meta["local_relpath"]:
                        meta["local_relpath"] = local_layer_rel
            if not layers:
                local_rel = _extract_bundle_member(zf, str(item.get("relpath") or ""), source_root, source_root_resolved, data_root)
                if local_rel:
                    meta["local_relpath"] = local_rel

            if meta["local_relpath"] or meta["layers"]:
                source_count += 1
            if meta["candidate_id"]:
                source_by_candidate[meta["candidate_id"]] = meta
            if item.get("file"):
                source_by_file[str(item["file"])] = meta
            sha = str(item.get("sha256") or "").lower()
            if sha and sha != "n/a":
                source_by_sha[sha] = meta

        imported = 0
        rows = list(findings) + [row for row in gray_zone if isinstance(row, dict)]
        seen = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            file_path = str(row.get("FILE") or row.get("file") or "").strip()
            if not file_path:
                continue
            sha256 = str(row.get("SHA256") or row.get("sha256") or "N/A").strip()
            candidate_id = str(row.get("candidate_id") or "")
            source_meta = source_by_candidate.get(candidate_id) or source_by_file.get(file_path) or source_by_sha.get(sha256.lower()) or {}
            dedupe_key = candidate_id or "%s:%s" % (file_path, sha256)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            local_rel = source_meta.get("local_relpath") if isinstance(source_meta, dict) else ""
            local_file = DATA_DIR / local_rel if local_rel else None
            bundle_layers = source_meta.get("layers", []) if isinstance(source_meta, dict) else []
            bundle_evidence = source_meta.get("evidence", []) if isinstance(source_meta, dict) else []
            cur = conn.execute(
                "INSERT INTO findings(case_id, file_path, sha256, score, scan_time, description, extension, local_relpath, has_source, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (case_id, file_path, sha256, safe_int(row.get("SCORE", row.get("score")), None), str(row.get("TIME", row.get("time", ""))), str(row.get("DESCRIPTION", row.get("description", ""))), str(row.get("EXTENSION", row.get("extension", Path(file_path).suffix))), local_rel, 1 if (local_file and local_file.exists()) or bundle_layers else 0, created),
            )
            finding_id = int(cur.lastrowid)
            if bundle_layers:
                stored_layer_names = set()
                for layer in bundle_layers:
                    name = str(layer.get("name") or "snippet")
                    rel = str(layer.get("local_relpath") or "")
                    path = DATA_DIR / rel
                    if not rel or not path.exists():
                        continue
                    stored_layer_names.add(name)
                    conn.execute(
                        "INSERT OR IGNORE INTO layers(finding_id, name, relpath, size, sha256) VALUES(?,?,?,?,?)",
                        (finding_id, name, rel, safe_int(layer.get("size"), path.stat().st_size), str(layer.get("sha256") or file_sha256(path))),
                    )
                for ev in bundle_evidence:
                    if not isinstance(ev, dict) or str(ev.get("layer_name") or "") not in stored_layer_names:
                        continue
                    conn.execute(
                        "INSERT INTO evidence(finding_id, layer_name, rule_name, string_id, start_offset, end_offset, matched_text, score, description, reference, author) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (finding_id, str(ev.get("layer_name") or ""), str(ev.get("rule_name") or ""), str(ev.get("string_id") or ""), safe_int(ev.get("start_offset"), None) if ev.get("start_offset") is not None else None, safe_int(ev.get("end_offset"), None) if ev.get("end_offset") is not None else None, str(ev.get("matched_text") or ""), safe_int(ev.get("score"), 70), str(ev.get("description") or ""), str(ev.get("reference") or "-"), str(ev.get("author") or "-")),
                    )
            elif local_file and local_file.exists():
                try:
                    extract_evidence(conn, case_id, finding_id, file_path, local_file)
                except Exception as exc:
                    conn.execute(
                        "INSERT INTO audit_log(case_id, finding_id, action, detail, created_at) VALUES(?,?,?,?,?)",
                        (case_id, finding_id, "evidence_error", str(exc), now_ts()),
                    )
            imported += 1

        conn.execute(
            "UPDATE cases SET finding_count=?, source_count=? WHERE id=?",
            (imported, source_count, case_id),
        )
        conn.execute(
            "INSERT INTO audit_log(case_id, action, detail, created_at) VALUES(?,?,?,?)",
            (case_id, "import_enc", "Imported %s findings, %s source files from %s" % (imported, source_count, filename), now_ts()),
        )

    return case_id, share_key, imported, source_count


def import_case(title: str, findings: UploadedPart, source_zip: UploadedPart | None) -> tuple[int, str, int, int]:
    rows = parse_findings_file(findings.filename or "findings.csv", findings.data)
    if not rows:
        raise RuntimeError("Không thấy dòng finding hợp lệ trong file kết quả.")

    share_key = secrets.token_urlsafe(32)
    viewer_key = secrets.token_urlsafe(24)
    created = now_ts()
    with connect_db() as conn:
        cur = conn.execute(
            "INSERT INTO cases(title, share_key, viewer_key, created_at, source_zip_name) VALUES(?,?,?,?,?)",
            (title or f"Scan import {time.strftime('%Y-%m-%d %H:%M')}", share_key, viewer_key, created,
             source_zip.filename if source_zip else None),
        )
        case_id = int(cur.lastrowid)
        case_dir = DATA_DIR / "cases" / str(case_id)
        source_root = case_dir / "source"
        source_count = 0
        if source_zip:
            source_root.mkdir(parents=True, exist_ok=True)
            source_count = safe_zip_extract(source_zip.data, source_root)

        imported = 0
        for row in rows:
            file_path = str(row.get("FILE") or "").strip()
            if not file_path:
                continue
            sha256 = str(row.get("SHA256") or "N/A").strip()
            score = safe_int(row.get("SCORE"), None)
            local_file = locate_source_file(file_path, sha256, source_root) if source_count else None
            local_rel = local_file.relative_to(DATA_DIR).as_posix() if local_file else None
            cur = conn.execute(
                """
                INSERT INTO findings(
                    case_id, file_path, sha256, score, scan_time, description, extension,
                    local_relpath, has_source, created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    case_id,
                    file_path,
                    sha256,
                    score,
                    str(row.get("TIME") or ""),
                    str(row.get("DESCRIPTION") or ""),
                    str(row.get("EXTENSION") or Path(file_path).suffix),
                    local_rel,
                    1 if local_file else 0,
                    created,
                ),
            )
            finding_id = int(cur.lastrowid)
            if local_file:
                try:
                    extract_evidence(conn, case_id, finding_id, file_path, local_file)
                except Exception as exc:
                    conn.execute(
                        "INSERT INTO audit_log(case_id, finding_id, action, detail, created_at) VALUES(?,?,?,?,?)",
                        (case_id, finding_id, "evidence_error", str(exc), now_ts()),
                    )
            imported += 1
        conn.execute(
            "UPDATE cases SET finding_count=?, source_count=? WHERE id=?",
            (imported, source_count, case_id),
        )
        conn.execute(
            "INSERT INTO audit_log(case_id, action, detail, created_at) VALUES(?,?,?,?)",
            (case_id, "import", f"Imported {imported} findings, {source_count} source files", now_ts()),
        )
    return case_id, share_key, imported, source_count


def query_one(sql: str, params=()):
    with connect_db() as conn:
        return conn.execute(sql, params).fetchone()


def query_all(sql: str, params=()):
    with connect_db() as conn:
        return conn.execute(sql, params).fetchall()


def score_class(score) -> str:
    score = safe_int(score, 0)
    if score >= 100:
        return "score-high"
    if score >= 40:
        return "score-mid"
    return "score-low"


def status_label(status: str) -> str:
    labels = {
        "pending": "Chờ đánh giá",
        "reviewing": "Đang xem",
        "confirmed": "Xác nhận webshell",
        "benign": "Loại trừ",
        "remediated": "Đã xử lý",
    }
    return labels.get(status, status)


def case_from_id(case_id: int):
    return query_one("SELECT * FROM cases WHERE id=?", (case_id,))


def case_from_key(key: str):
    return query_one("SELECT * FROM cases WHERE share_key=?", (key,))


def case_access_from_key(key: str):
    case = query_one("SELECT *, 'reviewer' AS access_role FROM cases WHERE share_key=?", (key,))
    if case:
        return case
    return query_one("SELECT *, 'viewer' AS access_role FROM cases WHERE viewer_key=?", (key,))


def create_session(case_id: int, role: str) -> str:
    token = secrets.token_urlsafe(32)
    created = now_ts()
    if role not in ("reviewer", "viewer"):
        role = "viewer"
    with connect_db() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (created,))
        conn.execute(
            "INSERT INTO sessions(token, case_id, role, created_at, expires_at) VALUES(?,?,?,?,?)",
            (token, case_id, role, created, created + SESSION_TTL_SECONDS),
        )
    return token


def create_admin_session() -> str:
    token = secrets.token_urlsafe(32)
    created = now_ts()
    with connect_db() as conn:
        conn.execute("DELETE FROM admin_sessions WHERE expires_at < ?", (created,))
        conn.execute(
            "INSERT INTO admin_sessions(token, created_at, expires_at) VALUES(?,?,?)",
            (token, created, created + SESSION_TTL_SECONDS),
        )
    return token


def parse_cookie(header_value: str | None) -> dict[str, str]:
    cookie = SimpleCookie()
    try:
        cookie.load(header_value or "")
    except Exception:
        return {}
    return {key: morsel.value for key, morsel in cookie.items()}


def session_case_id(headers) -> int | None:
    info = session_info(headers)
    return info[0] if info else None


def session_info(headers) -> tuple[int, str] | None:
    token = parse_cookie(headers.get("Cookie")).get(SESSION_COOKIE, "")
    if not token:
        return None
    now = now_ts()
    row = query_one("SELECT case_id, role FROM sessions WHERE token=? AND expires_at>=?", (token, now))
    if not row:
        return None
    return int(row["case_id"]), str(row["role"] or "viewer")


def is_admin_session(headers) -> bool:
    token = parse_cookie(headers.get("Cookie")).get(ADMIN_COOKIE, "")
    if not token:
        return False
    now = now_ts()
    return query_one("SELECT token FROM admin_sessions WHERE token=? AND expires_at>=?", (token, now)) is not None


def admin_login_page(message: str = "") -> bytes:
    notice = f"<div class=\"warn\">{html.escape(message)}</div>" if message else ""
    body = f"""
    <section class="band" style="max-width:560px;margin:42px auto;">
      <h1>Đăng nhập trang import</h1>
      {notice}
      <form method="post" action="/admin/login" class="stack">
        <label>Admin key<br><input name="admin_key" type="password" autocomplete="current-password" required style="width:100%"></label>
        <button type="submit">Vào trang admin</button>
      </form>
    </section>
    """
    return html_page("Admin login", body)


def access_page(case_id: int | None = None, message: str = "") -> bytes:
    hidden = f'<input type="hidden" name="case_id" value="{case_id}">' if case_id else ""
    notice = f"<div class=\"warn\">{html.escape(message)}</div>" if message else ""
    body = f"""
    <section class="band" style="max-width:560px;margin:42px auto;">
      <h1>Nhập mã truy cập báo cáo</h1>
      {notice}
      <form method="post" action="/access" class="stack">
        {hidden}
        <label>Mã truy cập<br><input name="access_key" type="password" autocomplete="current-password" required style="width:100%"></label>
        <button type="submit">Xem dashboard</button>
      </form>
    </section>
    """
    return html_page("Nhập mã truy cập", body)


def admin_page(base_url: str, message: str = "") -> bytes:
    cases = query_all("SELECT * FROM cases ORDER BY created_at DESC LIMIT 100")
    rows = []
    for case in cases:
        url = f"{base_url}/case/{case['id']}"
        rows.append(
            f"<tr><td><a href=\"/case/{case['id']}\">{html.escape(case['title'])}</a></td>"
            f"<td>{case['finding_count']}</td><td>{case['source_count']}</td>"
            f"<td class=\"path\"><a href=\"{url}\">{html.escape(url)}</a></td>"
            f"<td class=\"path\"><code>{html.escape(case['viewer_key'] or '')}</code></td>"
            f"<td class=\"path\"><code>{html.escape(case['share_key'])}</code></td></tr>"
        )
    notice = f"<div class=\"notice\">{html.escape(message)}</div>" if message else ""
    body = f"""
    <section class="band">
      <h1>Import kết quả scan</h1>
      {notice}
      <form method="post" action="/admin/import" enctype="multipart/form-data" class="stack">
        <label>Tên đợt rà quét<br><input name="title" style="width:100%" placeholder="VD: Đơn vị A - 2026-06-28"></label>
        <label>File kết quả .enc<br><input type="file" name="review_bundle" required accept=".enc"></label>
        <button type="submit">Import</button>
      </form>
    </section>
    <section class="band">
      <h2>Các đợt đã import</h2>
      <div class="tablewrap"><table><thead><tr><th>Tên</th><th>Findings</th><th>Source files</th><th>URL công khai</th><th>Mã lãnh đạo</th><th>Mã reviewer</th></tr></thead>
      <tbody>{''.join(rows) or '<tr><td colspan="6" class="muted">Chưa có dữ liệu.</td></tr>'}</tbody></table></div>
    </section>
    <section class="band">
      <h2>Ghi chú vận hành</h2>
      <div class="warn">Đầu vào chính thức là một file .enc do webshell-scan tạo sau khi quét. Bundle này đã bao gồm findings và source/evidence cần thiết để web dựng dashboard, xem raw/decode và highlight rule hit.</div>
    </section>
    """
    return html_page("Admin import", body)


def case_dashboard(case_id: int, query: dict[str, list[str]]) -> bytes:
    case = case_from_id(case_id)
    if not case:
        return html_page("Không tìm thấy", "<section class=\"band\">Báo cáo không tồn tại.</section>")
    status = (query.get("status") or [""])[0]
    q = (query.get("q") or [""])[0].strip()
    where = ["case_id=?"]
    params: list = [case["id"]]
    if status in VALID_STATUSES:
        where.append("status=?")
        params.append(status)
    if q:
        where.append("(file_path LIKE ? OR sha256 LIKE ? OR description LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like, like])
    findings = query_all(
        f"""
        SELECT f.*,
               (SELECT COUNT(*) FROM evidence e WHERE e.finding_id=f.id) AS evidence_count
        FROM findings f
        WHERE {' AND '.join(where)}
        ORDER BY score DESC, id ASC
        LIMIT 1000
        """,
        params,
    )
    counts = {row["status"]: row["c"] for row in query_all(
        "SELECT status, COUNT(*) AS c FROM findings WHERE case_id=? GROUP BY status", (case["id"],)
    )}
    evidence_total = query_one(
        "SELECT COUNT(*) AS c FROM evidence e JOIN findings f ON f.id=e.finding_id WHERE f.case_id=?",
        (case["id"],),
    )["c"]
    high_risk = query_one("SELECT COUNT(*) AS c FROM findings WHERE case_id=? AND score>=100", (case["id"],))["c"]
    missing_source = query_one("SELECT COUNT(*) AS c FROM findings WHERE case_id=? AND has_source=0", (case["id"],))["c"]
    reviewed = counts.get("confirmed", 0) + counts.get("benign", 0) + counts.get("remediated", 0)
    finding_count = int(case["finding_count"] or 0)
    reviewed_percent = int((reviewed / finding_count) * 100) if finding_count else 0
    metric_html = f"""
    <div class="grid">
      <div class="metric"><b>{case['finding_count']}</b><span>Finding</span></div>
      <div class="metric"><b>{high_risk}</b><span>Nguy cơ cao (score >= 100)</span></div>
      <div class="metric"><b>{counts.get('confirmed', 0)}</b><span>Đã xác nhận</span></div>
      <div class="metric"><b>{reviewed_percent}%</b><span>Tiến độ đánh giá</span></div>
      <div class="metric"><b>{case['source_count']}</b><span>File source đã upload</span></div>
      <div class="metric"><b>{evidence_total}</b><span>Evidence YARA/string</span></div>
      <div class="metric"><b>{missing_source}</b><span>Thiếu source để xem code</span></div>
      <div class="metric"><b>{counts.get('benign', 0)}</b><span>Đã loại trừ</span></div>
    </div>
    """
    filters = ["<a class=\"pill\" href=\"?\">Tất cả</a>"]
    for st in VALID_STATUSES:
        filters.append(f"<a class=\"pill status-{st}\" href=\"?status={st}\">{status_label(st)}: {counts.get(st, 0)}</a>")
    rows = []
    for item in findings:
        has_source_label = 'Có' if item['has_source'] else 'Thiếu'
        rows.append(
            "<tr>"
            f"<td><a href=\"/case/{case['id']}/finding/{item['id']}\">#{item['id']}</a></td>"
            f"<td class=\"{score_class(item['score'])}\">{html.escape(str(item['score'] or ''))}</td>"
            f"<td><span class=\"pill status-{item['status']}\">{status_label(item['status'])}</span></td>"
            f"<td class=\"path\">{html.escape(item['file_path'])}<br><span class=\"muted\">{html.escape(item['sha256'] or 'N/A')}</span></td>"
            f"<td>{item['evidence_count']}</td>"
            f"<td>{has_source_label}</td>"
            f"</tr>"
        )
    body = f"""
    <section class="band page-head">
      <div class="eyebrow">Tổng quan kết quả rà quét</div>
      <h1>Dashboard lãnh đạo: {html.escape(case['title'])}</h1>
      {metric_html}
    </section>
    <section class="band">
      <form method="get" class="filters">
        <input name="q" value="{html.escape(q)}" placeholder="Tìm path, hash, mô tả" style="min-width:280px">
        <button type="submit">Lọc</button>
        {''.join(filters)}
      </form>
    </section>
    <section class="band">
      <div class="tablewrap"><table><thead><tr><th>ID</th><th>Score</th><th>Trạng thái</th><th>File</th><th>Evidence</th><th>Source</th></tr></thead>
      <tbody>{''.join(rows) or '<tr><td colspan="6" class="muted">Không có finding phù hợp.</td></tr>'}</tbody></table></div>
    </section>
    """
    return html_page(case["title"], body)


def read_layer_bytes(finding_id: int, layer_name: str) -> tuple[bytes | None, str]:
    row = query_one("SELECT * FROM layers WHERE finding_id=? AND name=?", (finding_id, layer_name))
    if row:
        path = DATA_DIR / row["relpath"]
        if path.exists() and path.stat().st_size <= MAX_VIEW_BYTES:
            return path.read_bytes(), row["name"]
        return None, row["name"]
    finding = query_one("SELECT * FROM findings WHERE id=?", (finding_id,))
    if finding and finding["local_relpath"]:
        path = DATA_DIR / finding["local_relpath"]
        if path.exists() and path.stat().st_size <= MAX_VIEW_BYTES:
            return path.read_bytes(), "raw"
    return None, layer_name


def render_code(data: bytes, highlights: list[sqlite3.Row]) -> str:
    spans: list[tuple[int, int, int]] = []
    for idx, ev in enumerate(highlights):
        start = ev["start_offset"]
        end = ev["end_offset"]
        if start is None or end is None:
            continue
        start_i, end_i = int(start), int(end)
        if 0 <= start_i < end_i <= len(data):
            spans.append((start_i, end_i, idx % 3))
    spans.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    chunks = []
    cursor = 0
    for start, end, color in spans:
        if start < cursor:
            continue
        chunks.append(html.escape(data[cursor:start].decode("utf-8", errors="replace")))
        chunks.append(f"<mark class=\"m{color}\">")
        chunks.append(html.escape(data[start:end].decode("utf-8", errors="replace")))
        chunks.append("</mark>")
        cursor = end
    chunks.append(html.escape(data[cursor:].decode("utf-8", errors="replace")))
    rendered = "".join(chunks)
    lines = rendered.splitlines() or [""]
    numbered = []
    for idx, line in enumerate(lines, start=1):
        numbered.append(f"<span class=\"ln\">{idx}</span>{line}")
    return "\n".join(numbered)


def finding_detail(case_id: int, finding_id: int, query: dict[str, list[str]], role: str = "viewer") -> bytes:
    case = case_from_id(case_id)
    if not case:
        return html_page("Không tìm thấy", "<section class=\"band\">Báo cáo không tồn tại.</section>")
    finding = query_one("SELECT * FROM findings WHERE id=? AND case_id=?", (finding_id, case["id"]))
    if not finding:
        return html_page("Không tìm thấy", "<section class=\"band\">Finding không tồn tại.</section>")
    layers = query_all(
        """
        SELECT * FROM layers
        WHERE finding_id=?
        ORDER BY CASE
            WHEN name='raw' THEN 0
            WHEN name='raw_snippet' THEN 1
            WHEN name LIKE '%_snippet' THEN 2
            ELSE 3
        END, name
        """,
        (finding_id,),
    )
    selected_layer = (query.get("layer") or ["raw"])[0]
    if layers and selected_layer not in [row["name"] for row in layers]:
        selected_layer = layers[0]["name"]
    evidence = query_all(
        "SELECT * FROM evidence WHERE finding_id=? AND layer_name=? ORDER BY rule_name, start_offset",
        (finding_id, selected_layer),
    )
    all_evidence = query_all(
        "SELECT rule_name, layer_name, COUNT(*) AS c FROM evidence WHERE finding_id=? GROUP BY rule_name, layer_name ORDER BY rule_name",
        (finding_id,),
    )
    data, actual_layer = read_layer_bytes(finding_id, selected_layer)
    layer_links = []
    for layer in layers:
        active = " style=\"font-weight:700\"" if layer["name"] == selected_layer else ""
        layer_links.append(
            f"<a class=\"pill\"{active} href=\"?layer={urllib.parse.quote(layer['name'])}\">{html.escape(layer['name'])} ({layer['size']} bytes)</a>"
        )
    rule_rows = []
    for ev in evidence:
        matched = html.escape((ev["matched_text"] or "")[:180])
        offset = "" if ev["start_offset"] is None else f"@{ev['start_offset']}"
        rule_rows.append(
            f"<div class=\"rule-hit\"><b>{html.escape(ev['rule_name'])}</b> "
            f"<span class=\"muted\">{html.escape(ev['string_id'] or '')} {offset}</span><br>"
            f"<code>{matched}</code><br><span class=\"muted\">{html.escape(ev['description'] or '')}</span></div>"
        )
    if data is None:
        code_html = "<div class=\"warn\">Không có source/layer để hiển thị. Hãy import lại kèm ZIP source/quarantine hoặc tạo report evidence giàu dữ liệu từ scanner.</div>"
    else:
        code_html = f"<div class=\"codewrap\"><pre class=\"code\">{render_code(data, evidence)}</pre></div>"
    snippet_notice = ""
    if str(actual_layer).endswith("_snippet"):
        snippet_notice = (
            '<div class="notice">Layer này là snippet-only: hệ thống chỉ đóng gói các đoạn quanh rule hit '
            'để giữ file .enc gọn, không phải toàn bộ source.</div>'
        )
    evidence_summary = ", ".join(
        f"{html.escape(row['rule_name'])} [{html.escape(row['layer_name'])}: {row['c']}]" for row in all_evidence[:40]
    )
    description = str(finding["description"] or "")
    description_block = ""
    if description:
        description_block = f"""
        <details class="details">
          <summary>Mô tả scanner ({len(description)} ký tự)</summary>
          <p class="muted detail-text">{html.escape(description)}</p>
        </details>
        """
    evidence_block = ""
    if evidence_summary:
        evidence_block = f"""
        <details class="details">
          <summary>Tóm tắt rule hit ({len(all_evidence)} nhóm)</summary>
          <p class="muted detail-text">{evidence_summary}</p>
        </details>
        """
    if role == "reviewer":
        review_panel = f"""
        <form method="post" action="/case/{case['id']}/finding/{finding_id}/update" enctype="multipart/form-data" class="stack">
          <label>Trạng thái<br>
            <select name="status">
              {''.join(f'<option value="{st}" {"selected" if finding["status"] == st else ""}>{status_label(st)}</option>' for st in VALID_STATUSES)}
            </select>
          </label>
          <label>Ghi chú đánh giá<br><textarea name="reviewer_note">{html.escape(finding['reviewer_note'] or '')}</textarea></label>
          <button type="submit">Lưu đánh giá</button>
        </form>
        """
    else:
        review_panel = f"""
        <div class="notice">Bạn đang xem bằng mã lãnh đạo nên chỉ có quyền xem.</div>
        <div>
          <h2>Ghi chú đánh giá</h2>
          <p>{html.escape(finding['reviewer_note'] or 'Chưa có ghi chú.')}</p>
        </div>
        """
    body = f"""
    <section class="band page-head">
      <a href="/case/{case['id']}">← Quay lại dashboard</a>
      <div class="eyebrow">Chi tiết finding</div>
      <h1 class="path">{html.escape(finding['file_path'])}</h1>
      <div class="filters">
        <span class="pill {score_class(finding['score'])}">Score {html.escape(str(finding['score'] or ''))}</span>
        <span class="pill status-{finding['status']}">{status_label(finding['status'])}</span>
        <span class="pill">SHA256 {html.escape(finding['sha256'] or 'N/A')}</span>
      </div>
      {description_block}
      {evidence_block or '<p class="muted">Chưa có evidence chi tiết.</p>'}
    </section>
    <div class="split">
      <aside class="band stack">
        {review_panel}
        <div>
          <h2>Layer</h2>
          <div class="filters">{''.join(layer_links) or '<span class="muted">Chưa có layer.</span>'}</div>
        </div>
        <div>
          <h2>Rule/String hit</h2>
          <div class="rule-list">{''.join(rule_rows) or '<div class="muted">Không có hit trên layer này.</div>'}</div>
        </div>
      </aside>
      <section class="band">
        <h2>Raw/decode viewer: {html.escape(actual_layer)}</h2>
        {snippet_notice}
        {code_html}
      </section>
    </div>
    """
    return html_page(f"Finding #{finding_id}", body)


class ReviewHandler(BaseHTTPRequestHandler):
    server_version = "WebshellReview/1.0"

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline' 'self'; frame-ancestors 'none'")
        super().end_headers()

    def send_html(self, data: bytes, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location: str, cookie: str | None = None) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > MAX_UPLOAD_BYTES:
            raise RuntimeError("Upload quá lớn.")
        return self.rfile.read(length)

    def base_url(self) -> str:
        host = self.headers.get("Host") or f"{self.server.server_address[0]}:{self.server.server_address[1]}"
        return f"http://{host}"

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/":
            self.send_html(access_page())
            return
        if parsed.path == "/admin":
            if not is_admin_session(self.headers):
                self.send_html(admin_login_page())
                return
            self.send_html(admin_page(self.base_url()))
            return
        match = re.fullmatch(r"/case/(\d+)", parsed.path)
        if match:
            case_id = int(match.group(1))
            info = session_info(self.headers)
            if not info or info[0] != case_id:
                self.send_html(access_page(case_id))
                return
            self.send_html(case_dashboard(case_id, query))
            return
        match = re.fullmatch(r"/case/(\d+)/finding/(\d+)", parsed.path)
        if match:
            case_id = int(match.group(1))
            info = session_info(self.headers)
            if not info or info[0] != case_id:
                self.send_html(access_page(case_id))
                return
            self.send_html(finding_detail(case_id, int(match.group(2)), query, info[1]))
            return
        if re.fullmatch(r"/c/.+", parsed.path):
            self.send_html(access_page(message="Định dạng link chứa khóa trên URL đã được tắt. Vui lòng nhập mã truy cập để xem báo cáo."))
            return
        self.send_html(html_page("404", "<section class=\"band\">Không tìm thấy trang.</section>"), HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        try:
            body = self.read_body()
            parts = parse_post_parts(self.headers, body)
            if parsed.path == "/admin/login":
                key = form_value(parts, "admin_key")
                if key != get_admin_key():
                    self.send_html(admin_login_page("Admin key không hợp lệ."), HTTPStatus.FORBIDDEN)
                    return
                token = create_admin_session()
                cookie = (
                    f"{ADMIN_COOKIE}={token}; Path=/admin; Max-Age={SESSION_TTL_SECONDS}; "
                    "HttpOnly; SameSite=Strict"
                )
                self.redirect("/admin", cookie=cookie)
                return
            if parsed.path == "/access":
                access_key = form_value(parts, "access_key")
                requested_case_id = safe_int(form_value(parts, "case_id"), None)
                case = case_access_from_key(access_key)
                if not case or (requested_case_id and requested_case_id != int(case["id"])):
                    self.send_html(access_page(requested_case_id, "Mã truy cập không hợp lệ."), HTTPStatus.FORBIDDEN)
                    return
                token = create_session(int(case["id"]), str(case["access_role"]))
                cookie = (
                    f"{SESSION_COOKIE}={token}; Path=/; Max-Age={SESSION_TTL_SECONDS}; "
                    "HttpOnly; SameSite=Strict"
                )
                self.redirect(f"/case/{case['id']}", cookie=cookie)
                return
            if parsed.path == "/admin/import":
                if not is_admin_session(self.headers):
                    self.send_html(admin_login_page("Phiên admin không hợp lệ hoặc đã hết hạn."), HTTPStatus.FORBIDDEN)
                    return
                review_bundle = file_part(parts, "review_bundle")
                if not review_bundle:
                    raise RuntimeError("Thiếu file .enc.")
                case_id, share_key, imported, source_count = import_enc_case(form_value(parts, "title"), review_bundle)
                self.redirect("/admin")
                return
            match = re.fullmatch(r"/case/(\d+)/finding/(\d+)/update", parsed.path)
            if match:
                case_id, finding_id = int(match.group(1)), int(match.group(2))
                case = case_from_id(case_id)
                info = session_info(self.headers)
                if not case or not info or info[0] != case_id:
                    self.send_html(access_page(case_id, "Phiên truy cập không hợp lệ hoặc đã hết hạn."), HTTPStatus.FORBIDDEN)
                    return
                if info[1] != "reviewer":
                    self.send_html(html_page("403", "<section class=\"band\">Mã lãnh đạo chỉ có quyền xem, không được cập nhật đánh giá.</section>"), HTTPStatus.FORBIDDEN)
                    return
                status = form_value(parts, "status", "pending")
                if status not in VALID_STATUSES:
                    status = "pending"
                note = form_value(parts, "reviewer_note", "")
                with connect_db() as conn:
                    conn.execute(
                        "UPDATE findings SET status=?, reviewer_note=? WHERE id=? AND case_id=?",
                        (status, note, finding_id, case["id"]),
                    )
                    conn.execute(
                        "INSERT INTO audit_log(case_id, finding_id, action, detail, created_at) VALUES(?,?,?,?,?)",
                        (case["id"], finding_id, "review_update", status, now_ts()),
                    )
                self.redirect(f"/case/{case['id']}/finding/{finding_id}")
                return
            self.send_html(html_page("404", "<section class=\"band\">Không tìm thấy endpoint.</section>"), HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self.send_html(
                html_page("Lỗi", f"<section class=\"band\"><h1>Lỗi xử lý</h1><div class=\"warn\">{html.escape(str(exc))}</div></section>"),
                HTTPStatus.BAD_REQUEST,
            )

    def log_message(self, fmt, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.log_date_time_string(), fmt % args))


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

    parser = argparse.ArgumentParser(description="Web review portal for webshell scan findings")
    parser.add_argument("--host", default="127.0.0.1", help="Host bind, default 127.0.0.1")
    parser.add_argument("--port", type=int, default=8088, help="Port, default 8088")
    args = parser.parse_args(argv)

    ensure_dirs()
    init_db()
    compile_yara_rules()
    admin_url = f"http://{args.host}:{args.port}/admin"
    print("Webshell Scan Review")
    print(f"Admin URL: {admin_url}")
    print(f"YARA: {_YARA_STATUS or 'not initialized'}")
    server = ThreadingHTTPServer((args.host, args.port), ReviewHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
