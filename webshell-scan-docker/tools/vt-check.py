#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vt-check.py — Tra VirusTotal tự động, cập nhật SSDeep DB, xuất báo cáo CSV
============================================================================

Cách dùng:
  python3 tools/vt-check.py -r logs/          # Chế độ 1: từ báo cáo scan
  python3 tools/vt-check.py -p /var/www/html  # Chế độ 2: từ thư mục file

Tính năng:
  - Selenium tự động cào kết quả VT (fallback thủ công nếu không có driver)
  - Malicious → tự động thêm SSDeep (bỏ qua nếu đã có trong DB)
  - Tự lưu CSV sau mỗi entry, không mất dữ liệu khi bị ngắt

Yêu cầu:
    pip install selenium pandas openpyxl
    apt install chromium-driver        # hoặc firefox-geckodriver
"""

import argparse
import csv
import glob as glob_mod
import hashlib
import os
import re
import sys
import time
import webbrowser
from datetime import datetime

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP_ROOT)

try:
    import pandas as pd
    _PANDAS_OK = True
except ImportError:
    _PANDAS_OK = False

try:
    from libs.ssdeep_db import append_from_file, get_ssdeep_db_path
except ImportError as exc:
    print(f"[ERROR] Không import được libs: {exc}")
    sys.exit(1)

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.common.exceptions import WebDriverException
    _SELENIUM_OK = True
except ImportError:
    _SELENIUM_OK = False

# ---------------------------------------------------------------------------
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
VT_BASE = "https://www.virustotal.com/gui/file/{sha256}"
MAX_FILE_BYTES = 50 * 1024 * 1024  # 50 MB

DEFAULT_EXTS = {
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8",
    ".phar", ".pht", ".phtm", ".inc", ".module", ".theme", ".tpl",
    ".twig",
    ".asp", ".aspx", ".ashx", ".asmx", ".asa", ".cer", ".cdx",
    ".ascx", ".asax", ".svc", ".master", ".config",
    ".jsp", ".jspx", ".jspf", ".tag", ".tld",
    ".cfm", ".cfml", ".cfc",
    ".cgi", ".pl", ".py", ".rb", ".sh", ".bash", ".ps1", ".bat",
    ".cmd", ".vbs",
    ".war", ".jar",
}

CSV_COLUMNS = [
    "file_path", "sha256", "score",
    "virustotal_url", "vt_detections", "vt_verdict",
    "verdict", "ssdeep_added", "ssdeep_message",
    "quarantine_path",
    "source", "checked_at",
]

# File cache DB — lưu kết quả VT đã tra để không tra lại
VT_CACHE_PATH = os.path.join(APP_ROOT, "tools", "vt_cache.json")


# ---------------------------------------------------------------------------
# Cache DB
# ---------------------------------------------------------------------------

def _load_cache(path: str) -> dict:
    """Đọc cache từ JSON. Key = sha256, value = dict kết quả."""
    import json
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save_cache(cache: dict, path: str):
    """Ghi cache ra JSON."""
    import json
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"  [WARN] Không ghi được cache: {e}")


def cache_get(cache: dict, sha256: str):
    """Trả về entry cache nếu có, None nếu chưa tra."""
    return cache.get(sha256.lower())


def cache_put(cache: dict, sha256: str, verdict: str,
              vt_detections: str, vt_verdict: str, path: str):
    """Lưu kết quả vào cache và ghi file ngay."""
    cache[sha256.lower()] = {
        "verdict":       verdict,
        "vt_detections": vt_detections,
        "vt_verdict":    vt_verdict,
        "checked_at":    datetime.now().isoformat(),
    }
    _save_cache(cache, path)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256_file(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def vt_url(sha256: str) -> str:
    if not sha256 or not SHA256_RE.match(sha256):
        return "N/A"
    return VT_BASE.format(sha256=sha256)


def print_sep(char="=", n=72):
    print(char * n)


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------

def quarantine_file(src: str, qdir: str, sha256: str) -> str:
    """
    Di chuyển file vào thư mục quarantine.
    - Trùng tên + trùng hash  → ghi đè (xóa cũ, move mới)
    - Trùng tên   + khác hash → đổi tên thêm _<sha256[:8]>.<ext>
    - Chưa có     → move thẳng
    Trả về đường dẫn đích hoặc '' nếu lỗi.
    """
    if not src or not os.path.isfile(src):
        return ""
    os.makedirs(qdir, exist_ok=True)

    fname = os.path.basename(src)
    dst = os.path.join(qdir, fname)

    # Kiểm tra xung đột
    if os.path.exists(dst):
        dst_sha = sha256_file(dst)
        if dst_sha == sha256:
            # Trùng tên + trùng hash → ghi đè
            try:
                os.remove(dst)
            except Exception:
                pass
        else:
            # Trùng tên + khác hash → đổi tên
            name, ext = os.path.splitext(fname)
            fname = f"{name}_{sha256[:8]}{ext}"
            dst = os.path.join(qdir, fname)
            # Nếu tên mới vẫn tồn tại và cùng hash → ghi đè
            if os.path.exists(dst) and sha256_file(dst) == sha256:
                try:
                    os.remove(dst)
                except Exception:
                    pass

    try:
        import shutil
        shutil.move(src, dst)
        return dst
    except Exception as e:
        print(f"  [WARN] Không quarantine được: {e}")
        return ""


# ---------------------------------------------------------------------------
# Thu thập entries — Chế độ 1: từ báo cáo
# ---------------------------------------------------------------------------

def collect_from_report(paths: list, glob_pattern: str,
                        min_score=None, max_score=None) -> list:
    if not _PANDAS_OK:
        print("[ERROR] Cần cài: pip install pandas openpyxl")
        sys.exit(1)

    file_list = []
    for p in paths:
        if os.path.isdir(p):
            file_list.extend(
                glob_mod.glob(
                    os.path.join(p, "**", glob_pattern or "*.xlsx"),
                    recursive=True,
                )
            )
        else:
            file_list.append(p)

    entries, seen = [], set()
    for fpath in sorted(file_list):
        ext = fpath.lower()
        try:
            if ext.endswith(".xlsx") or ext.endswith(".xls"):
                rows = _parse_excel(fpath, min_score, max_score)
            elif ext.endswith(".csv"):
                rows = _parse_csv(fpath, min_score, max_score)
            elif ext.endswith(".log"):
                rows = _parse_log(fpath)
            else:
                continue
        except Exception as e:
            print(f"[WARN] Không đọc được {fpath}: {e}")
            continue
        for row in rows:
            sha = row["sha256"].lower().strip()
            if not SHA256_RE.match(sha) or sha in seen:
                continue
            seen.add(sha)
            row["sha256"] = sha
            row["source"] = os.path.basename(fpath)
            entries.append(row)

    print(f"[INFO] Chế độ -r: {len(entries)} SHA256 từ báo cáo.")
    return entries


def _parse_excel(path, min_score=None, max_score=None):
    df = pd.read_excel(path, dtype=str)
    df.columns = [str(c).upper().strip() for c in df.columns]
    if "SHA256" not in df.columns:
        return []
    rows = []
    for _, row in df.iterrows():
        sha = str(row.get("SHA256", "")).strip()
        fp  = str(row.get("FILE", "")).strip()
        sc  = row.get("SCORE", "")
        try:
            score = int(float(sc)) if str(sc) not in ("", "nan", "None") else None
        except (ValueError, TypeError):
            score = None
        if min_score is not None and score is not None and score < min_score:
            continue
        if max_score is not None and score is not None and score > max_score:
            continue
        rows.append({"sha256": sha, "file_path": fp, "score": score})
    return rows


def _parse_csv(path, min_score=None, max_score=None):
    rows = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            norm = {k.upper().strip(): v for k, v in row.items()}
            sha  = norm.get("SHA256", "").strip()
            fp   = norm.get("FILE", "").strip()
            sc   = norm.get("SCORE", "")
            try:
                score = int(float(sc)) if sc else None
            except (ValueError, TypeError):
                score = None
            if min_score is not None and score is not None and score < min_score:
                continue
            if max_score is not None and score is not None and score > max_score:
                continue
            rows.append({"sha256": sha, "file_path": fp, "score": score})
    return rows


def _parse_log(path):
    rows, current = [], ""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if "FILE:" in line:
                current = line.split("FILE:", 1)[-1].strip()
            m = re.search(r"SHA256[:\s]+([a-fA-F0-9]{64})", line)
            if m:
                rows.append({"sha256": m.group(1).lower(),
                             "file_path": current, "score": None})
    return rows


# ---------------------------------------------------------------------------
# Thu thập entries — Chế độ 2: từ thư mục
# ---------------------------------------------------------------------------

def collect_from_dir(dirs: list, extensions: set = None,
                     recursive: bool = True) -> list:
    exts = extensions or DEFAULT_EXTS
    entries, seen = [], set()
    for base in dirs:
        if not os.path.isdir(base):
            print(f"[WARN] Không phải thư mục: {base}")
            continue
        print(f"[INFO] Quét: {base}")
        walker = os.walk(base) if recursive else [(base, [], os.listdir(base))]
        for root, _, files in walker:
            for fname in files:
                if exts and os.path.splitext(fname)[1].lower() not in exts:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    sz = os.path.getsize(fpath)
                    if sz == 0 or sz > MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                sha = sha256_file(fpath)
                if not sha or sha in seen:
                    continue
                seen.add(sha)
                entries.append({"sha256": sha, "file_path": fpath,
                                 "score": None, "source": base})
    print(f"[INFO] Chế độ -p: {len(entries)} file duy nhất.")
    return entries


# ---------------------------------------------------------------------------
# Selenium scraper
# ---------------------------------------------------------------------------

class VTScraper:
    def __init__(self, headless: bool = False, browser: str = "chrome",
                 no_wait: bool = False):
        self.driver = None
        self.no_wait = no_wait          # True = không delay phòng ngừa
        self._last_request_time = 0
        self._start(headless, browser)

    def _start(self, headless, browser):
        if not _SELENIUM_OK:
            return
        try:
            if browser == "firefox":
                from selenium.webdriver.firefox.options import Options
                opts = Options()
                if headless:
                    opts.add_argument("--headless")
                self.driver = webdriver.Firefox(options=opts)
            else:
                from selenium.webdriver.chrome.options import Options
                opts = Options()
                if headless:
                    opts.add_argument("--headless=new")
                opts.add_argument("--no-sandbox")
                opts.add_argument("--disable-dev-shm-usage")
                opts.add_argument("--disable-gpu")
                opts.add_argument("--window-size=1280,900")
                opts.add_argument(
                    "user-agent=Mozilla/5.0 (X11; Linux x86_64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                )
                self.driver = webdriver.Chrome(options=opts)
            print(f"[INFO] Selenium ({browser}) sẵn sàng.")
        except Exception as e:
            print(f"[WARN] Không khởi động Selenium: {e}")
            self.driver = None

    def fetch(self, sha256: str, wait_sec: int = 15) -> dict:
        """Cào trang VT. Poll mỗi 0.5s, có kết quả là thoát ngay, không đợi hết wait_sec."""
        result = {"ratio": "", "detections": None, "total": None,
                  "vt_verdict": "", "raw_text": ""}
        if not self.driver:
            return result

        # JS đệ quy xuyên Shadow DOM (VT dùng Polymer web components)
        js = """
            function dig(el) {
                var t = '';
                try {
                    if (el.shadowRoot) t += dig(el.shadowRoot);
                    var kids = el.children || [];
                    for (var i = 0; i < kids.length; i++) t += dig(kids[i]);
                    if (!kids.length && el.textContent) t += ' ' + el.textContent;
                } catch(e) {}
                return t;
            }
            return dig(document.body).substring(0, 10000);
        """

        patterns = [
            r"(\d+)\s*/\s*(\d+)\s+(?:security\s+vendors?|engines?|scanners?)",
            r"[Dd]etected\s+by\s+(\d+)\s+out\s+of\s+(\d+)",
            r"\b(\d{1,3})\s*/\s*(\d{2,3})\b",
        ]

        def _try_parse(text: str) -> dict:
            # Kiểm tra "Item not found" trước
            if re.search(r"item\s+not\s+found", text, re.IGNORECASE):
                return {"vt_verdict": "not_found", "ratio": "", "raw_text": text[:200]}

            for pat in patterns:
                m = re.search(pat, text)
                if m:
                    det, tot = int(m.group(1)), int(m.group(2))
                    if 0 <= det <= tot and 10 < tot <= 120:
                        return {
                            "detections": det, "total": tot,
                            "ratio": f"{det}/{tot}",
                            "vt_verdict": "malicious" if det > 0 else "clean",
                            "raw_text": text[:200].replace("\n", " ").strip(),
                        }
            return {}

        # Delay tối thiểu giữa các request để tránh rate limit
        # VT free ~4 req/phút = 15s/req. Bỏ qua nếu --no-wait
        if not self.no_wait:
            elapsed_since_last = time.time() - self._last_request_time
            min_delay = 16
            if elapsed_since_last < min_delay:
                wait_gap = min_delay - elapsed_since_last
                print(f"  [Rate limit] Chờ {wait_gap:.0f}s...", end=" ", flush=True)
                time.sleep(wait_gap)
                print("xong.")
        self._last_request_time = time.time()

        try:
            self.driver.get(vt_url(sha256))

            deadline = time.time() + wait_sec
            poll_interval = 0.5
            rate_limited = False

            while time.time() < deadline:
                time.sleep(poll_interval)
                try:
                    deep = self.driver.execute_script(js) or ""
                    body = ""
                    try:
                        body = self.driver.find_element(By.TAG_NAME, "body").text or ""
                    except Exception:
                        pass
                    text = deep + " " + body

                    # Detect rate limit — nếu bị thì chờ và retry
                    if re.search(r"too\s+many\s+requests", text, re.IGNORECASE):
                        if not rate_limited:
                            rate_limited = True
                            print(f"\n  ⏳ VT: Too Many Requests — chờ 10 phút rồi thử lại...")
                            for remaining in range(600, 0, -10):
                                print(f"\r  ⏳ Còn {remaining}s...", end="", flush=True)
                                time.sleep(10)
                            print(f"\r  ⏳ Hết chờ, thử lại...          ")
                        self.driver.get(vt_url(sha256))
                        self._last_request_time = time.time()
                        deadline = time.time() + wait_sec  # reset deadline
                        rate_limited = False  # reset để có thể detect lần tiếp
                        continue

                    parsed = _try_parse(text)
                    if parsed:
                        result.update(parsed)
                        return result  # có kết quả → thoát ngay
                except WebDriverException:
                    break  # driver bị đóng

            # Hết thời gian, lưu raw text để debug
            try:
                deep = self.driver.execute_script(js) or ""
                result["raw_text"] = deep[:200].replace("\n", " ").strip()
            except Exception:
                pass

        except WebDriverException as e:
            print(f"  [WARN] Selenium: {e}")

        return result

    def close(self):
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None


# ---------------------------------------------------------------------------
# Xử lý từng entry
# ---------------------------------------------------------------------------

def run(entries: list, args, scraper) -> tuple:
    ssdeep_db = get_ssdeep_db_path(APP_ROOT)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(APP_ROOT, "logs")
    os.makedirs(out_dir, exist_ok=True)
    csv_path = args.output or os.path.join(out_dir, f"vt_report_{stamp}.csv")

    # Load cache DB
    cache_path = VT_CACHE_PATH
    cache = _load_cache(cache_path)
    cache_hits = 0

    results = []
    total = len(entries)
    has_selenium = scraper and scraper.driver

    mode = "Selenium tự động" if has_selenium else "thủ công (mở browser)"
    wait_mode = "⚡ no-wait (nhanh, tự retry 10 phút nếu bị rate limit)" if getattr(args, "no_wait", False) else "🐢 có delay 16s/req (ổn định)"
    print(f"\n[INFO] {total} entries | cào VT: {mode} | {wait_mode}")
    print(f"[INFO] Cache DB: {cache_path} ({len(cache)} entries đã tra)")
    if args.quarantine:
        print(f"[INFO] Quarantine → {args.quarantine}")
    print("[INFO] Verdict: m=malicious  c=clean  s=skip  q=quit\n")

    for idx, entry in enumerate(entries, 1):
        sha       = entry["sha256"]
        file_path = entry.get("file_path", "")
        score     = entry.get("score")
        source    = entry.get("source", "")
        url       = vt_url(sha)

        print_sep()
        print(f"[{idx}/{total}]  {file_path or sha}")
        if score is not None:
            print(f"  SCORE  : {score}")
        print(f"  SHA256 : {sha}")
        print(f"  URL    : {url}")

        # --- Kiểm tra cache — nếu đã tra rồi thì dùng lại ---
        cached = cache_get(cache, sha)
        if cached:
            cache_hits += 1
            verdict      = cached["verdict"]
            vt_detections = cached.get("vt_detections", "")
            vt            = {"vt_verdict": cached.get("vt_verdict", ""),
                             "ratio": vt_detections}
            checked_at_str = cached.get("checked_at", "")
            print(f"  ⚡ Cache hit (đã tra {checked_at_str[:10]}): "
                  f"{verdict} {vt_detections}")

            # Vẫn thực hiện SSDeep / quarantine nếu malicious
            ssdeep_added, ssdeep_msg = False, ""
            if verdict == "malicious" and file_path and os.path.isfile(file_path):
                ok, msg = append_from_file(
                    file_path, ssdeep_db,
                    source=vt_detections or "cache",
                    max_bytes=MAX_FILE_BYTES,
                )
                ssdeep_added, ssdeep_msg = ok, msg
                print(f"  [SSDeep] {'✅ đã thêm' if ok else '⏭  ' + msg}")

            quarantine_path = ""
            if verdict == "malicious" and args.quarantine and file_path and os.path.isfile(file_path):
                quarantine_path = quarantine_file(file_path, args.quarantine, sha)
                if quarantine_path:
                    print(f"  [Quarantine] ✅ → {quarantine_path}")

            results.append({
                "file_path":       file_path,
                "sha256":          sha,
                "score":           "" if score is None else score,
                "virustotal_url":  url,
                "vt_detections":   vt_detections,
                "vt_verdict":      vt["vt_verdict"],
                "verdict":         verdict,
                "ssdeep_added":    ssdeep_added,
                "ssdeep_message":  ssdeep_msg,
                "quarantine_path": quarantine_path,
                "source":          source,
                "checked_at":      checked_at_str,
            })
            _save_csv(results, csv_path)
            continue  # Bỏ qua toàn bộ phần cào VT bên dưới

        # --- Cào VT ---
        vt = {}
        if has_selenium:
            print(f"  [VT] Đang tải...", end=" ", flush=True)
            t0 = time.time()
            vt = scraper.fetch(sha, wait_sec=args.wait)
            elapsed = time.time() - t0
            if vt.get("ratio"):
                icon = "🔴" if vt["detections"] > 0 else "🟢"
                print(f"({elapsed:.1f}s) {icon} {vt['ratio']} → {vt['vt_verdict']}")
            else:
                print(f"({elapsed:.1f}s) không đọc được kết quả")
                if vt.get("raw_text"):
                    print(f"       raw: {vt['raw_text'][:100]}")
        else:
            # Không có Selenium — mở browser thường
            webbrowser.open(url)
            print("  [VT] Đã mở trình duyệt.")

        # --- Verdict --- 
        # Nếu Selenium đã cào được kết quả rõ ràng → tự động, không hỏi
        auto_verdict = vt.get("vt_verdict", "")
        if auto_verdict == "malicious":
            verdict = "malicious"
            print(f"  ✅ Tự động chọn: Malicious — mã độc")
        elif auto_verdict == "clean":
            verdict = "clean"
            print(f"  ✅ Tự động chọn: Clean — sạch")
        elif auto_verdict == "not_found":
            verdict = "unknown"
            print(f"  ℹ️  Tự động chọn: Unknown — file chưa có trên VirusTotal")
        else:
            # Không cào được → hỏi thủ công
            print("  [?] Không đọc được kết quả VT (file chưa có / cần đăng nhập / timeout)")
            print("  Chọn một trong các option:")
            print("    m  malicious  — xác nhận là mã độc (thêm SSDeep + quarantine)")
            print("    c  clean      — file sạch, bỏ qua")
            print("    u  unknown    — chưa có trên VirusTotal, bỏ qua")
            print("    s  skip       — bỏ qua lần này, không ghi kết quả")
            print("    q  quit       — dừng toàn bộ chương trình")
            while True:
                raw = input("  Verdict [m/c/u/s/q]: ").strip().lower()
                if raw in ("m", "malicious"):         verdict = "malicious"; break
                if raw in ("c", "clean"):             verdict = "clean";     break
                if raw in ("u", "unknown", "n/a"):    verdict = "unknown";   break
                if raw in ("s", "skip", ""):          verdict = "skip";      break
                if raw in ("q", "quit"):              verdict = "quit";      break
                print("  Không hợp lệ. Nhập m, c, u, s hoặc q.")

        # --- Tỷ lệ: dùng từ Selenium, chỉ hỏi nếu malicious thủ công mà chưa có ---
        vt_detections = vt.get("ratio", "")
        if verdict == "malicious" and not vt_detections:
            r = input("  Tỷ lệ VT (vd. 15/72), Enter bỏ qua: ").strip()
            m = re.match(r"(\d+)\s*/\s*(\d+)", r)
            vt_detections = f"{m.group(1)}/{m.group(2)}" if m else "manual"

        # --- Tự động thêm SSDeep nếu malicious ---
        ssdeep_added, ssdeep_msg = False, ""
        if verdict == "malicious" and file_path and os.path.isfile(file_path):
            ok, msg = append_from_file(
                file_path, ssdeep_db,
                source=vt_detections or "manual",
                max_bytes=MAX_FILE_BYTES,
            )
            ssdeep_added, ssdeep_msg = ok, msg
            print(f"  [SSDeep] {'✅ đã thêm' if ok else '⏭  ' + msg}")

        # --- Quarantine nếu bật -q ---
        quarantine_path = ""
        if verdict == "malicious" and args.quarantine and file_path and os.path.isfile(file_path):
            quarantine_path = quarantine_file(file_path, args.quarantine, sha)
            if quarantine_path:
                print(f"  [Quarantine] ✅ → {quarantine_path}")
            else:
                print(f"  [Quarantine] ⚠️  Không di chuyển được.")

        # --- Lưu vào cache DB ---
        if verdict not in ("skip", "quit"):
            cache_put(cache, sha, verdict, vt_detections,
                      vt.get("vt_verdict", ""), cache_path)

        results.append({
            "file_path":    file_path,
            "sha256":       sha,
            "score":        "" if score is None else score,
            "virustotal_url": url,
            "vt_detections": vt_detections,
            "vt_verdict":   vt.get("vt_verdict", ""),
            "verdict":      verdict,
            "ssdeep_added": ssdeep_added,
            "ssdeep_message": ssdeep_msg,
            "quarantine_path": quarantine_path,
            "source":       source,
            "checked_at":   datetime.now().isoformat(),
        })
        _save_csv(results, csv_path)   # lưu ngay sau mỗi entry

        if verdict == "quit":
            print("\n[INFO] Dừng theo yêu cầu.")
            break

    print(f"\n[INFO] Cache hits: {cache_hits}/{total} (bỏ qua, đã tra trước đó)")
    return results, csv_path


def _save_csv(rows: list, path: str):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def summary(rows: list, csv_path: str):
    print_sep()
    print("TÓM TẮT")
    print_sep()
    print(f"  Tổng          : {len(rows)}")
    print(f"  Malicious     : {sum(1 for r in rows if r['verdict']=='malicious')}")
    print(f"  Clean         : {sum(1 for r in rows if r['verdict']=='clean')}")
    print(f"  Unknown/N/A   : {sum(1 for r in rows if r['verdict']=='unknown')}")
    print(f"  Skip          : {sum(1 for r in rows if r['verdict']=='skip')}")
    print(f"  SSDeep added  : {sum(1 for r in rows if r['ssdeep_added'])}")
    q = sum(1 for r in rows if r.get("quarantine_path"))
    if q:
        print(f"  Quarantined   : {q}")
    print(f"  Báo cáo CSV   : {csv_path}")
    print_sep()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        prog="vt-check.py",
        description="Tra VirusTotal tự động, cập nhật SSDeep DB, xuất báo cáo CSV",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  # Chế độ có delay (ổn định, ít bị rate limit)
  python3 tools/vt-check.py -r logs/
  python3 tools/vt-check.py -r logs/ --min-score 40
  python3 tools/vt-check.py -p /var/www/html -q /quarantine

  # Chế độ không delay (nhanh hơn, tự retry 60s khi bị rate limit)
  python3 tools/vt-check.py -p /var/www/html --no-wait -q /quarantine
  python3 tools/vt-check.py -r logs/ --no-wait --headless

  # Các option thường dùng
  python3 tools/vt-check.py -p /var/www --ext php jsp --headless --no-wait
  python3 tools/vt-check.py -p /var/www --no-recursive --recheck
        """,
    )

    # Nguồn (bắt buộc chọn 1 trong 2)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("-r", "--from-report", nargs="+", metavar="FILE_OR_DIR",
                     help="Chế độ 1: file CSV/XLSX/log hoặc thư mục báo cáo webshell-scan")
    src.add_argument("-p", "--from-dir",    nargs="+", metavar="DIR",
                     help="Chế độ 2: thư mục chứa file nghi ngờ (tính SHA256 từ file)")

    # Tùy chọn chế độ 1
    p.add_argument("--glob",      default="*.xlsx",
                   help="Glob đệ quy khi -r là thư mục (mặc định: *.xlsx)")
    p.add_argument("--min-score", type=int, default=None,
                   help="Chỉ lấy entry có score >= N")
    p.add_argument("--max-score", type=int, default=None,
                   help="Chỉ lấy entry có score <= N")

    # Tùy chọn chế độ 2
    p.add_argument("--ext", nargs="+", metavar="EXT",
                   help="Extension cần quét (vd: php jsp asp). "
                        "Mặc định: php phtml asp aspx jsp cgi pl py war jar")
    p.add_argument("--no-recursive", action="store_true",
                   help="Không quét đệ quy thư mục con")

    # Selenium
    p.add_argument("--headless", action="store_true",
                   help="Selenium headless — không hiện cửa sổ (dùng trên server)")
    p.add_argument("--browser",  default="chrome", choices=["chrome", "firefox"],
                   help="Trình duyệt Selenium (mặc định: chrome)")
    p.add_argument("--wait",     type=int, default=15,
                   help="Giây chờ tối đa trang VT render (mặc định: 15)")
    p.add_argument("--no-wait",  action="store_true",
                   help="Không delay giữa các request (nhanh hơn, có thể bị rate limit → tự retry 10 phút)")

    # Output & quarantine
    p.add_argument("-o", "--output",     default=None,
                   help="File CSV kết quả (mặc định: logs/vt_report_<ts>.csv)")
    p.add_argument("-q", "--quarantine", nargs="?",
                   const=os.path.join(APP_ROOT, "quarantine"),
                   default=None, metavar="DIR",
                   help="Di chuyển file malicious vào thư mục quarantine. "
                        "Dùng -q không tham số → mặc định: <project>/quarantine. "
                        "Trùng tên+hash → ghi đè; trùng tên+khác hash → đổi tên thêm _<sha8>")
    p.add_argument("--limit", type=int, default=0,
                   help="Giới hạn số entry (0 = không giới hạn)")
    p.add_argument("--recheck", action="store_true",
                   help="Bỏ qua cache, tra lại VT cho tất cả entries")

    args = p.parse_args()

    # --recheck: xóa cache trước khi chạy
    if getattr(args, "recheck", False):
        cache_path = VT_CACHE_PATH
        if os.path.isfile(cache_path):
            os.remove(cache_path)
            print(f"[INFO] --recheck: đã xóa cache {cache_path}")

    # --- Thu thập entries ---
    if args.from_report:
        entries = collect_from_report(
            args.from_report, args.glob, args.min_score, args.max_score)
    else:
        exts = None
        if args.ext:
            exts = {("." + e.lstrip(".")).lower() for e in args.ext}
        entries = collect_from_dir(
            args.from_dir,
            extensions=exts,
            recursive=not args.no_recursive,
        )

    if not entries:
        print("[INFO] Không có entry nào.")
        sys.exit(0)

    if args.limit > 0:
        entries = entries[:args.limit]
        print(f"[INFO] --limit: xử lý {len(entries)} entries.")

    # --- Khởi động Selenium (luôn thử) ---
    scraper = None
    if not _SELENIUM_OK:
        print("[WARN] Selenium chưa cài → fallback thủ công.")
        print("[WARN] Cài: pip install selenium && apt install chromium-driver")
    else:
        scraper = VTScraper(headless=args.headless, browser=args.browser,
                            no_wait=args.no_wait)
        if not scraper.driver:
            print("[WARN] Không khởi động được driver → fallback thủ công.")
            scraper = None

    # --- Chạy ---
    try:
        results, csv_path = run(entries, args, scraper)
    finally:
        if scraper:
            scraper.close()

    summary(results, csv_path)


if __name__ == "__main__":
    main()
