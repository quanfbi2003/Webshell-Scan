# -*- coding: utf-8 -*-
"""Encrypted review bundle shared by scanner and review web.

The .enc artifact is a self-contained encrypted ZIP payload. It is intended to
carry enough local evidence for the review web without asking operators to
upload separate reports and source archives.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import posixpath
import re
import secrets
import struct
import time
import zipfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from libs.evidence import canonical_candidate_id

try:
    from libs.deobfuscate import iter_deobfuscated_layers, should_deobfuscate
except Exception:  # pragma: no cover - review bundle can still carry raw files
    iter_deobfuscated_layers = None
    should_deobfuscate = None


MAGIC = b"WSRENC1\n"
SCHEMA = "webshell-review-bundle-v1"
DEFAULT_ITERATIONS = 390000
DEFAULT_SOURCE_LIMIT_BYTES = 512 * 1024
DEFAULT_TOTAL_SOURCE_LIMIT_BYTES = 100 * 1024 * 1024
DEFAULT_SNIPPET_CONTEXT_BYTES = 8 * 1024
DEFAULT_SNIPPET_MAX_BYTES = 64 * 1024
DEFAULT_SNIPPET_SCAN_LIMIT_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_SNIPPETS_PER_LAYER = 24
DEFAULT_YARA_TIMEOUT_SECONDS = 20
KEY_ENV = "WEBSHELL_REVIEW_BUNDLE_KEY"
KEY_FILE = "review-bundle.key"


class ReviewBundleError(RuntimeError):
    pass


def bundle_passphrase(app_path: str | os.PathLike, create_if_missing: bool = False) -> str:
    env_value = os.environ.get(KEY_ENV, "").strip()
    if env_value:
        return env_value

    key_path = Path(app_path) / "config" / KEY_FILE
    if key_path.exists():
        return key_path.read_text(encoding="utf-8").strip()

    if not create_if_missing:
        raise ReviewBundleError(
            "Không tìm thấy khóa giải mã .enc. Đặt biến môi trường %s hoặc copy %s từ máy tạo bundle."
            % (KEY_ENV, key_path)
        )

    key_path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_urlsafe(48)
    key_path.write_text(value + "\n", encoding="utf-8")
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass
    return value


def _derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    if not passphrase:
        raise ReviewBundleError("Khóa .enc rỗng.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_review_bundle_bytes(zip_payload: bytes, passphrase: str) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(passphrase, salt, DEFAULT_ITERATIONS)
    header = {
        "schema": SCHEMA,
        "alg": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": DEFAULT_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "payload": "zip",
    }
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, zip_payload, MAGIC)
    return MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + ciphertext


def decrypt_review_bundle_bytes(enc_payload: bytes, passphrase: str) -> bytes:
    if not enc_payload.startswith(MAGIC) or len(enc_payload) < len(MAGIC) + 4:
        raise ReviewBundleError("File không đúng định dạng webshell review .enc.")
    offset = len(MAGIC)
    header_size = struct.unpack(">I", enc_payload[offset:offset + 4])[0]
    offset += 4
    if header_size <= 0 or header_size > 65536:
        raise ReviewBundleError("Header .enc không hợp lệ.")
    header = json.loads(enc_payload[offset:offset + header_size].decode("utf-8"))
    offset += header_size
    if header.get("schema") != SCHEMA:
        raise ReviewBundleError("Schema .enc không được hỗ trợ: %s" % header.get("schema"))
    salt = base64.b64decode(header["salt"])
    nonce = base64.b64decode(header["nonce"])
    iterations = int(header.get("iterations", DEFAULT_ITERATIONS))
    key = _derive_key(passphrase, salt, iterations)
    try:
        return AESGCM(key).decrypt(nonce, enc_payload[offset:], MAGIC)
    except Exception as exc:
        raise ReviewBundleError("Không giải mã được .enc. Kiểm tra khóa bundle hoặc file bị hỏng.") from exc


def report_rows(report: dict, columns: list[str]) -> list[dict]:
    if not report:
        return []
    size = max((len(report.get(col, [])) for col in columns), default=0)
    rows = []
    for idx in range(size):
        row = {}
        for col in columns:
            values = report.get(col, [])
            row[col] = values[idx] if idx < len(values) else ""
        rows.append(row)
    return rows


def _safe_name(value: str, fallback: str = "file") -> str:
    value = os.path.basename((value or "").replace("\\", "/")) or fallback
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return value[:120] or fallback


def _clean_report_path(path: str) -> str:
    return (path or "").split(" [ARCHIVE:", 1)[0].strip()


def _source_relpath(file_path: str, sha256_value: str) -> str:
    name = _safe_name(file_path)
    sha = re.sub(r"[^A-Fa-f0-9]+", "", sha256_value or "")
    prefix = sha.lower()[:16] if sha else hashlib.sha256(file_path.encode("utf-8", errors="replace")).hexdigest()[:16]
    return posixpath.join("sources", "files", "%s_%s" % (prefix, name))


def _safe_layer_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value or "raw").strip("._")
    return value[:80] or "raw"


def _snippet_relpath(file_path: str, sha256_value: str, layer_name: str) -> str:
    name = _safe_name(file_path)
    layer = _safe_layer_name(layer_name)
    sha = re.sub(r"[^A-Fa-f0-9]+", "", sha256_value or "")
    prefix = sha.lower()[:16] if sha else hashlib.sha256(file_path.encode("utf-8", errors="replace")).hexdigest()[:16]
    return posixpath.join("sources", "snippets", "%s_%s_%s.txt" % (prefix, layer, name))


def _match_instances(match) -> list[tuple[int, str, bytes]]:
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


def _rule_meta(match) -> dict[str, Any]:
    meta = getattr(match, "meta", {}) or {}
    description = str(meta.get("description") or meta.get("cluster") or "not set")
    return {
        "rule_name": str(getattr(match, "rule", "")),
        "score": _safe_int(meta.get("score"), 70),
        "description": description,
        "reference": str(meta.get("reference") or meta.get("viz_url") or "-"),
        "author": str(meta.get("author") or "-"),
    }


def _safe_int(value, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _yara_externals(file_path: str, data: bytes) -> dict[str, str]:
    clean_path = str(file_path or "")
    return {
        "filename": os.path.basename(clean_path.replace("\\", "/")),
        "filepath": clean_path,
        "extension": Path(clean_path.replace("\\", "/")).suffix,
        "filetype": "",
        "md5": hashlib.md5(data).hexdigest(),
        "owner": "dummy",
    }


def _iter_layers(data: bytes, file_path: str, scan_policy: dict | None) -> list[tuple[str, bytes]]:
    ext = Path(str(file_path).replace("\\", "/")).suffix
    if iter_deobfuscated_layers and should_deobfuscate:
        try:
            if should_deobfuscate(ext, file_path, scan_policy or {}):
                return list(iter_deobfuscated_layers(data, scan_policy or {}))
        except Exception:
            pass
    return [("raw", data)]


def _line_window(data: bytes, start: int, end: int, context_bytes: int, max_bytes: int) -> tuple[int, int]:
    left = max(0, start - context_bytes)
    right = min(len(data), end + context_bytes)
    newline_left = data.rfind(b"\n", 0, left)
    if newline_left >= 0:
        left = newline_left + 1
    newline_right = data.find(b"\n", right)
    if newline_right >= 0:
        right = newline_right + 1
    if right - left > max_bytes:
        half = max(0, (max_bytes - (end - start)) // 2)
        left = max(0, start - half)
        right = min(len(data), left + max_bytes)
        if end > right:
            right = min(len(data), end + half)
            left = max(0, right - max_bytes)
    return left, right


def _merge_windows(windows: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(windows):
        if not merged or start > merged[-1][1] + 256:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged


def _build_layer_snippet(
    *,
    layer_name: str,
    layer_data: bytes,
    file_path: str,
    sha256_value: str,
    matches: list[Any],
    context_bytes: int,
    max_snippet_bytes: int,
    max_snippets: int,
) -> tuple[dict | None, bytes, list[dict]]:
    hits: list[dict] = []
    windows: list[tuple[int, int]] = []
    seen = set()

    for match in matches:
        meta = _rule_meta(match)
        instances = _match_instances(match)
        if not instances:
            windows.append((0, min(len(layer_data), max_snippet_bytes)))
            hits.append({
                **meta,
                "layer_name": "%s_snippet" % layer_name,
                "string_id": "",
                "start_offset": None,
                "end_offset": None,
                "matched_text": "",
                "original_start_offset": None,
                "original_end_offset": None,
            })
            continue
        for offset, ident, matched in instances:
            key = (meta["rule_name"], ident, offset)
            if key in seen:
                continue
            seen.add(key)
            end = min(len(layer_data), offset + len(matched))
            windows.append(_line_window(layer_data, offset, end, context_bytes, max_snippet_bytes))
            hits.append({
                **meta,
                "layer_name": "%s_snippet" % layer_name,
                "string_id": ident,
                "start_offset": offset,
                "end_offset": end,
                "matched_text": matched[:240].decode("utf-8", errors="replace"),
                "original_start_offset": offset,
                "original_end_offset": end,
            })

    windows = _merge_windows(windows)[:max_snippets]
    if not windows:
        return None, b"", []

    parts: list[bytes] = []
    evidence: list[dict] = []
    snippet_name = "%s_snippet" % layer_name
    for idx, (start, end) in enumerate(windows, start=1):
        header = (
            "\n/* --- snippet %s: layer=%s original_offsets=%s-%s --- */\n"
            % (idx, layer_name, start, end)
        ).encode("utf-8")
        snippet_start = sum(len(part) for part in parts) + len(header)
        parts.append(header)
        parts.append(layer_data[start:end])
        if not parts[-1].endswith(b"\n"):
            parts.append(b"\n")
        for hit in hits:
            hit_start = hit.get("original_start_offset")
            hit_end = hit.get("original_end_offset")
            if hit_start is None or hit_end is None:
                if idx == 1 and hit["rule_name"]:
                    evidence.append(hit)
                continue
            if start <= int(hit_start) < int(hit_end) <= end:
                local_hit = dict(hit)
                local_hit["start_offset"] = snippet_start + int(hit_start) - start
                local_hit["end_offset"] = snippet_start + int(hit_end) - start
                evidence.append(local_hit)

    snippet_data = b"".join(parts)
    relpath = _snippet_relpath(file_path, sha256_value, snippet_name)
    meta = {
        "name": snippet_name,
        "relpath": relpath,
        "size": len(snippet_data),
        "sha256": hashlib.sha256(snippet_data).hexdigest(),
        "original_size": len(layer_data),
        "snippet_only": True,
    }
    return meta, snippet_data, evidence


def _build_snippet_layers(
    *,
    source_data: bytes,
    source_path: str,
    report_path: str,
    sha256_value: str,
    yara_rules,
    scan_policy: dict | None,
    context_bytes: int,
    max_snippet_bytes: int,
    max_snippets_per_layer: int,
    yara_timeout_seconds: int,
) -> tuple[list[tuple[dict, bytes]], list[dict], str]:
    if not yara_rules:
        return [], [], "snippet_yara_unavailable"

    rulesets = yara_rules if isinstance(yara_rules, (list, tuple)) else [yara_rules]
    stored_layers: list[tuple[dict, bytes]] = []
    evidence: list[dict] = []
    matched_any = False
    for layer_name, layer_data in _iter_layers(source_data, report_path or source_path, scan_policy):
        layer_matches = []
        for rules in rulesets:
            try:
                try:
                    matches = rules.match(
                        data=layer_data,
                        externals=_yara_externals(report_path or source_path, layer_data),
                        timeout=max(1, int(yara_timeout_seconds)),
                    )
                except TypeError:
                    matches = rules.match(
                        data=layer_data,
                        externals=_yara_externals(report_path or source_path, layer_data),
                    )
            except Exception:
                continue
            if matches:
                matched_any = True
                layer_matches.extend(matches)
        if not layer_matches:
            continue
        meta, data, layer_evidence = _build_layer_snippet(
            layer_name=layer_name,
            layer_data=layer_data,
            file_path=source_path,
            sha256_value=sha256_value,
            matches=layer_matches,
            context_bytes=context_bytes,
            max_snippet_bytes=max_snippet_bytes,
            max_snippets=max_snippets_per_layer,
        )
        if meta and data:
            stored_layers.append((meta, data))
            evidence.extend(layer_evidence)

    if not stored_layers and matched_any:
        return [], [], "snippet_no_string_offsets"
    if not stored_layers:
        return [], [], "snippet_no_yara_match"
    return stored_layers, evidence, ""


def _benchmark_records(benchmark_report):
    if not isinstance(benchmark_report, dict):
        return []
    for key in ("records", "results"):
        records = benchmark_report.get(key)
        if isinstance(records, list):
            return [item for item in records if isinstance(item, dict)]
    return []


def _archive_member_path(report_path: str) -> str:
    raw = str(report_path or '').replace('\\', '/')
    raw = re.sub(r'\s*\(in archive:.*?\)', '', raw, flags=re.IGNORECASE)
    raw = raw.split(' [ARCHIVE:', 1)[0].strip()
    match = re.search(r'/[^/]+_[0-9a-fA-F]{32}_extracted/(.+)$', raw)
    return match.group(1) if match else (raw.rsplit('/', 1)[-1] if raw else '')


def _report_archive_chain(report_path):
    match = re.search(r'\(in archive:\s*(.*?)\)', str(report_path or ''), flags=re.IGNORECASE)
    if not match:
        return ()
    return tuple(item.strip() for item in match.group(1).split(' -> ') if item.strip())


def _candidate_id(row, sha256, archive_path, member_path, benchmark_report):
    records = _benchmark_records(benchmark_report)
    row_path = str(row.get('FILE') or '')
    sha256_lower = str(sha256 or '').lower()
    benchmark = None
    row_candidate_id = str(row.get('candidate_id') or '')
    if row_candidate_id:
        benchmark = next(
            (item for item in records if str(item.get('candidate_id') or '') == row_candidate_id),
            None,
        )
    if benchmark is None and archive_path:
        chain_hint = _report_archive_chain(row_path)
        archive_records = [
            item for item in records
            if item.get('member_path')
            and str(item.get('member_sha256') or item.get('sha256') or '').lower() == sha256_lower
        ]
        if member_path:
            archive_records = [item for item in archive_records if item.get('member_path') == member_path]
        if chain_hint:
            hinted = [item for item in archive_records if tuple(item.get('archive_chain') or ()) == chain_hint]
            archive_records = hinted or archive_records
        benchmark = archive_records[0] if archive_records else None
    if benchmark is None:
        benchmark = next(
            (item for item in records if not item.get('member_path')
             and str(item.get('path') or '') == row_path
             and str(item.get('sha256') or '').lower() == sha256_lower),
            None,
        )
    if benchmark and benchmark.get('candidate_id'):
        return str(benchmark['candidate_id']), benchmark
    return canonical_candidate_id(
        'scanner', sha256, 'archive-member' if archive_path else _clean_report_path(row_path),
        archive_chain=(_report_archive_chain(row_path) or ((os.path.basename(archive_path),) if archive_path else ())),
        member_path=member_path or None, member_sha256=sha256 if member_path else None,
    ), benchmark

def _durable_member_path(report_path):
    member = _archive_member_path(report_path)
    if re.search(r'_[0-9a-fA-F]{32}_extracted/', member):
        return ''
    return member


def _read_archive_member(archive_path, archive_chain, member_path):
    if not archive_path or not member_path or not os.path.isfile(archive_path):
        return None
    try:
        current = Path(archive_path).read_bytes()
        chain = tuple(archive_chain or ())
        for nested_name in chain[1:]:
            with zipfile.ZipFile(io.BytesIO(current)) as archive:
                names = archive.namelist()
                name = next((item for item in names if item == nested_name), None)
                if name is None:
                    name = next((item for item in names if os.path.basename(item) == os.path.basename(nested_name)), None)
                if name is None:
                    return None
                current = archive.read(name)
        with zipfile.ZipFile(io.BytesIO(current)) as archive:
            try:
                return archive.read(member_path)
            except KeyError:
                name = next((item for item in archive.namelist() if item.endswith('/' + member_path)), None)
                return archive.read(name) if name else None
    except Exception:
        return None


def build_review_zip(
    *,
    findings_report: dict,
    findings_columns: list[str],
    all_files_report: dict,
    all_files_columns: list[str],
    gray_zone_report: dict,
    gray_zone_columns: list[str],
    scan_path: str,
    out_file: str,
    scanner_version: str,
    source_limit_bytes: int = DEFAULT_SOURCE_LIMIT_BYTES,
    total_source_limit_bytes: int = DEFAULT_TOTAL_SOURCE_LIMIT_BYTES,
    snippet_context_bytes: int = DEFAULT_SNIPPET_CONTEXT_BYTES,
    snippet_max_bytes: int = DEFAULT_SNIPPET_MAX_BYTES,
    snippet_scan_limit_bytes: int = DEFAULT_SNIPPET_SCAN_LIMIT_BYTES,
    max_snippets_per_layer: int = DEFAULT_MAX_SNIPPETS_PER_LAYER,
    yara_rules=None,
    scan_policy: dict | None = None,
    yara_timeout_seconds: int = DEFAULT_YARA_TIMEOUT_SECONDS,
    benchmark_report: dict | None = None,
) -> tuple[bytes, dict]:
    findings = report_rows(findings_report, findings_columns)
    all_files = report_rows(all_files_report, all_files_columns)
    gray_zone = report_rows(gray_zone_report, gray_zone_columns)
    candidates = []
    seen_ids = set()
    for row, candidate_kind in [(item, "finding") for item in findings] + [(item, "gray") for item in gray_zone]:
        report_path = str(row.get("FILE") or "")
        clean_path = _clean_report_path(report_path)
        sha256 = str(row.get("SHA256") or "N/A")
        parts = report_path.split(" [ARCHIVE:", 1)
        archive_path = parts[1].rstrip("]").strip() if len(parts) == 2 else ""
        member_path = _archive_member_path(clean_path) if archive_path else ""
        if not member_path and archive_path and len(parts) == 2:
            member_path = clean_path.replace("\\", "/").rsplit("/", 1)[-1]
        candidate_id, benchmark = _candidate_id(
            row, sha256, archive_path, member_path, benchmark_report,
        )
        if benchmark:
            member_path = str(benchmark.get("member_path") or member_path or "")
            sha256 = str(
                benchmark.get("member_sha256") or benchmark.get("sha256") or sha256
            )
        if archive_path and not benchmark and len(_report_archive_chain(report_path)) > 1:
            member_path = ""
        if candidate_id in seen_ids:
            continue
        seen_ids.add(candidate_id)
        candidates.append((
            row, candidate_kind, report_path, clean_path, sha256, candidate_id,
            archive_path, member_path, benchmark,
        ))
    source_index = []
    source_count = 0
    full_source_count = 0
    snippet_source_count = 0
    omitted_count = 0
    stored_source_bytes = 0

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for row, candidate_kind, report_path, source_path, sha256_value, candidate_id, archive_path, member_path, benchmark in candidates:
            durable_file = member_path or (
                _clean_report_path(report_path) if not archive_path else ""
            )
            entry = {
                "candidate_id": candidate_id,
                "candidate_kind": candidate_kind,
                "file": durable_file,
                "sha256": sha256_value,
                "relpath": "",
                "size": 0,
                "stored_size": 0,
                "storage": "omitted",
                "snippet_only": False,
                "layers": [],
                "evidence": [],
                "omitted_reason": "",
                "source_status": "omitted",
                "source_reason": "",
            }
            if archive_path or member_path:
                entry["archive"] = {
                    "archive_path": "",
                    "archive_sha256": (benchmark or {}).get("archive_sha256"),
                    "archive_chain": list((benchmark or {}).get("archive_chain") or _report_archive_chain(report_path)),
                    "member_path": member_path,
                    "member_sha256": (benchmark or {}).get("member_sha256") or (sha256_value if member_path else None),
                }
            archive_data = _read_archive_member(
                archive_path,
                (benchmark or {}).get("archive_chain") or _report_archive_chain(report_path),
                member_path,
            )
            if archive_data is not None:
                source_path = member_path
            if not source_path or (archive_data is None and not os.path.isfile(source_path)):
                entry["omitted_reason"] = entry["source_reason"] = "source_not_found"
                omitted_count += 1
            else:
                try:
                    size = len(archive_data) if archive_data is not None else os.path.getsize(source_path)
                    entry["size"] = size
                    if size <= source_limit_bytes and stored_source_bytes + size <= total_source_limit_bytes:
                        relpath = _source_relpath(source_path, entry["sha256"])
                        if archive_data is not None:
                            zf.writestr(relpath, archive_data)
                        else:
                            zf.write(source_path, relpath)
                        entry["relpath"] = relpath
                        entry["stored_size"] = size
                        entry["storage"] = "full"
                        entry["source_status"] = "stored"
                        entry["source_reason"] = "full_source"
                        source_count += 1
                        full_source_count += 1
                        stored_source_bytes += size
                    else:
                        if size > snippet_scan_limit_bytes:
                            entry["omitted_reason"] = entry["source_reason"] = "member_budget_exceeded"
                            omitted_count += 1
                        else:
                            data = archive_data if archive_data is not None else Path(source_path).read_bytes()
                            snippet_layers, evidence, snippet_error = _build_snippet_layers(
                                source_data=data,
                                source_path=source_path,
                                report_path=report_path,
                                sha256_value=entry["sha256"],
                                yara_rules=yara_rules,
                                scan_policy=scan_policy,
                                context_bytes=snippet_context_bytes,
                                max_snippet_bytes=snippet_max_bytes,
                                max_snippets_per_layer=max_snippets_per_layer,
                                yara_timeout_seconds=yara_timeout_seconds,
                            )
                            stored_layers = []
                            stored_layer_names = set()
                            for layer_meta, layer_data in snippet_layers:
                                if stored_source_bytes + len(layer_data) > total_source_limit_bytes:
                                    continue
                                zf.writestr(layer_meta["relpath"], layer_data)
                                stored_source_bytes += len(layer_data)
                                entry["stored_size"] += len(layer_data)
                                stored_layers.append(layer_meta)
                                stored_layer_names.add(layer_meta["name"])
                            if stored_layers:
                                entry["storage"] = "snippet"
                                entry["source_status"] = "stored"
                                entry["source_reason"] = "snippet_source"
                                entry["snippet_only"] = True
                                entry["relpath"] = stored_layers[0]["relpath"]
                                entry["layers"] = stored_layers
                                entry["evidence"] = [
                                    ev for ev in evidence
                                    if ev.get("layer_name") in stored_layer_names
                                ][:200]
                                entry["omitted_reason"] = (
                                    "source_too_large_snippet_only"
                                    if size > source_limit_bytes
                                    else "source_total_limit_snippet_only"
                                )
                                source_count += 1
                                snippet_source_count += 1
                            else:
                                entry["omitted_reason"] = snippet_error or "source_total_limit_reached"
                                entry["source_reason"] = entry["omitted_reason"]
                                omitted_count += 1
                except Exception as exc:
                    entry["omitted_reason"] = entry["source_reason"] = "source_read_error"
                    omitted_count += 1
            source_index.append(entry)

        manifest = {
            "schema": SCHEMA,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "scanner_version": scanner_version,
            "scan_path": scan_path,
            "out_file": out_file,
            "counts": {
                "findings": len(findings),
                "all_files": len(all_files),
                "gray_zone": len(gray_zone),
                "candidates": len(candidates),
                "sources": source_count,
                "sources_full": full_source_count,
                "sources_snippet": snippet_source_count,
                "sources_omitted": omitted_count,
                "stored_source_bytes": stored_source_bytes,
            },
            "source_limit_bytes": source_limit_bytes,
            "total_source_limit_bytes": total_source_limit_bytes,
            "snippet_context_bytes": snippet_context_bytes,
            "snippet_max_bytes": snippet_max_bytes,
            "max_snippets_per_layer": max_snippets_per_layer,
        }
        zf.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        zf.writestr("findings.json", json.dumps(findings, ensure_ascii=False, indent=2))
        zf.writestr("all_files.json", json.dumps(all_files, ensure_ascii=False, indent=2))
        zf.writestr("gray_zone.json", json.dumps(gray_zone, ensure_ascii=False, indent=2))
        zf.writestr("sources/index.json", json.dumps(source_index, ensure_ascii=False, indent=2))
        if benchmark_report is not None:
            zf.writestr("benchmark.json", json.dumps(benchmark_report, ensure_ascii=False, indent=2))

    return buffer.getvalue(), {
        "findings": len(findings),
        "sources": source_count,
        "sources_full": full_source_count,
        "sources_snippet": snippet_source_count,
        "sources_omitted": omitted_count,
        "stored_source_bytes": stored_source_bytes,
        "gray_zone": len(gray_zone),
        "candidates": len(candidates),
    }


def write_review_bundle(output_path: str | os.PathLike, zip_payload: bytes, passphrase: str) -> str:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(encrypt_review_bundle_bytes(zip_payload, passphrase))
    return str(output_path)
