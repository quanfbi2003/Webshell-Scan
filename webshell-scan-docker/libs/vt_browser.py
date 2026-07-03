# -*- coding: utf-8 -*-
"""
Tra VirusTotal qua trình duyệt (GUI) — không dùng API.
Người dùng xem detections/total trên web rồi nhập verdict thủ công.
"""

import re
import webbrowser

from libs.helpers import virustotal_file_url

VT_RATIO_RE = re.compile(r"^\s*(\d+)\s*/\s*(\d+)\s*$")


def open_vt_page(sha256):
    url = virustotal_file_url(sha256)
    if url and url != "N/A":
        webbrowser.open(url)
    return url


def normalize_vt_ratio(text):
    """Chuẩn hóa chuỗi dạng 15/72 từ người dùng."""
    if not text:
        return None
    m = VT_RATIO_RE.match(text.strip())
    if not m:
        return None
    return "%s/%s" % (m.group(1), m.group(2))


def prompt_browser_verdict(sha256, file_path, score=None, open_browser=True, index=None, total=None):
    """
    Mở VT trên trình duyệt, hỏi verdict.
    Trả về dict: verdict (malicious|clean|skip|quit), vt_result, url
    """
    url = virustotal_file_url(sha256)
    header = "\n" + "=" * 72
    if index is not None and total is not None:
        header += "\n[%s/%s]" % (index, total)
    print(header)
    print("SHA256: %s" % sha256)
    print("FILE:   %s" % file_path)
    if score is not None:
        print("SCORE:  %s" % score)
    print("URL:    %s" % url)
    print("Mở trang VirusTotal, xem cột detections (vd. 15/72).")
    if open_browser:
        open_vt_page(sha256)

    while True:
        choice = input("[m]alicious / [c]lean / [s]kip / [q]uit: ").strip().lower()
        if choice in ("m", "malicious", "y", "yes"):
            verdict = "malicious"
            break
        if choice in ("c", "clean", "n", "no"):
            return {"verdict": "clean", "vt_result": "clean", "url": url}
        if choice in ("s", "skip", ""):
            return {"verdict": "skip", "vt_result": "skip", "url": url}
        if choice in ("q", "quit"):
            return {"verdict": "quit", "vt_result": "", "url": url}
        print("Chọn m, c, s hoặc q.")

    ratio_text = input(
        "Kết quả VT trên trang (vd. 15/72 — detections/total), Enter nếu bỏ qua: "
    ).strip()
    ratio = normalize_vt_ratio(ratio_text)
    if ratio:
        vt_result = "%s malicious" % ratio
    else:
        vt_result = "malicious"
    return {"verdict": verdict, "vt_result": vt_result, "url": url, "vt_ratio": ratio}
