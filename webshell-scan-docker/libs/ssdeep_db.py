# -*- coding: utf-8 -*-
"""Quản lý known_webshells.ssdeep — thêm mẫu và nạp lại cho scanner."""

import os
import re
import threading

try:
    import pyssdeep
except ImportError:
    pyssdeep = None

try:
    import tlsh
except ImportError:
    tlsh = None

_db_lock = threading.Lock()
DEFAULT_REL = os.path.join("libs", "signature-base", "custom", "known_webshells.ssdeep")
HEADER = "ssdeep,1.1--blocksize:hash:hash,filename"


def get_ssdeep_db_path(app_path):
    return os.path.join(app_path, "libs", "signature-base", "custom", "known_webshells.ssdeep")


def compute_ssdeep(data):
    if pyssdeep is None:
        return None
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    if not data:
        return None
    return pyssdeep.get_hash_buffer(data, len(data))


def compute_tlsh(data):
    """Optional local TLSH support; returns None when python-tlsh is unavailable."""
    if tlsh is None:
        return None
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    if not data or len(data) < 50:
        return None
    try:
        digest = tlsh.hash(data)
        if digest and digest != "TNULL":
            return digest
    except Exception:
        return None
    return None


def normalize_source_for_similarity(data, extension=""):
    if not data:
        return data
    if isinstance(data, str):
        text = data
    else:
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return data

    ext = (extension or "").lower()
    source_exts = {
        ".php", ".phtml", ".php5", ".php7", ".phar", ".inc",
        ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".asmx", ".js",
    }
    if ext and ext not in source_exts:
        return data
    if "\x00" in text[:4096]:
        return data

    text = re.sub(r"<!--.*?-->", " ", text, flags=re.DOTALL)
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    text = re.sub(r"(?m)^\s*(?:#|//).*$", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return data
    return text.encode("utf-8", errors="replace")


def _read_lines(ssdeep_file):
    if not os.path.isfile(ssdeep_file):
        return []
    with open(ssdeep_file, "r", encoding="utf-8", errors="replace") as handle:
        return [line.rstrip("\n") for line in handle if line.strip()]


def append_entry(ssdeep_file, digest, label, source=""):
    """
    Thêm một dòng SSDeep nếu chưa có. Trả về (added: bool, message: str).
    """
    if not digest or ":" not in digest:
        return False, "invalid ssdeep digest"
    if pyssdeep is None:
        return False, "pyssdeep not installed"

    label = (label or "unknown").replace('"', "'")
    if source:
        label = "%s|vt:%s" % (label, source)[:200]

    entry = '%s,"%s"' % (digest.strip(), label)

    with _db_lock:
        lines = _read_lines(ssdeep_file)
        if not lines or not lines[0].startswith("ssdeep,"):
            lines = [HEADER]
        existing = set(lines[1:])
        if entry in existing:
            return False, "already in database"
        lines.append(entry)
        os.makedirs(os.path.dirname(ssdeep_file), exist_ok=True)
        with open(ssdeep_file, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    return True, "added"


def append_from_file(file_path, ssdeep_file, source="", max_bytes=None):
    if not os.path.isfile(file_path):
        return False, "file not found: %s" % file_path
    try:
        size = os.path.getsize(file_path)
        if max_bytes is not None and size > max_bytes:
            return False, "file too large (%s bytes)" % size
        with open(file_path, "rb") as handle:
            data = handle.read()
    except Exception as exc:
        return False, str(exc)
    digest = compute_ssdeep(data)
    if not digest:
        return False, "cannot compute ssdeep"
    label = os.path.basename(file_path)
    added, msg = append_entry(ssdeep_file, digest, label, source=source)

    messages = ["raw:%s" % msg]
    normalized = normalize_source_for_similarity(data, os.path.splitext(file_path)[1].lower())
    if normalized and normalized != data:
        normalized_digest = compute_ssdeep(normalized)
        if normalized_digest and normalized_digest != digest:
            norm_added, norm_msg = append_entry(
                ssdeep_file, normalized_digest, "normalized:%s" % label, source=source)
            added = added or norm_added
            messages.append("normalized:%s" % norm_msg)

    tlsh_digest = compute_tlsh(data)
    if tlsh_digest:
        messages.append("tlsh:%s" % tlsh_digest[:24])

    return added, "; ".join(messages)


def parse_entries(ssdeep_file):
    """Trả về list (digest, filename) giống Scanner.initialize_ssdeep_signatures."""
    entries = []
    for line in _read_lines(ssdeep_file):
        if not line or line.startswith("#") or line.startswith("ssdeep,"):
            continue
        if "," not in line:
            continue
        parts = line.split(",", 1)
        if len(parts) != 2:
            continue
        digest = parts[0].strip()
        filename = parts[1].strip().strip('"').strip("'")
        if ":" in digest:
            entries.append((digest, filename))
    return entries
