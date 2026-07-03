# -*- coding: utf-8 -*-
"""Static deobfuscation layers for rescanning (no code execution)."""

import base64
import binascii
import codecs
import re
import struct
import urllib.parse
import zlib

_RE_BASE64_DECODE = re.compile(
    rb'base64_decode\s*\(\s*[\'"]([A-Za-z0-9+/=\s]{16,})[\'"]\s*\)',
    re.IGNORECASE,
)
_RE_B64_BLOB = re.compile(rb'[\'"]([A-Za-z0-9+/]{64,}={0,2})[\'"]')
_RE_B64_LONG = re.compile(rb'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{256,}={0,2})(?![A-Za-z0-9+/])')
_RE_GZINFLATE = re.compile(
    rb'gzinflate\s*\(\s*base64_decode\s*\(\s*[\'"]([A-Za-z0-9+/=\s]+)[\'"]\s*\)\s*\)',
    re.IGNORECASE,
)
_RE_GZUNCOMPRESS = re.compile(
    rb'gzuncompress\s*\(\s*base64_decode\s*\(\s*[\'"]([A-Za-z0-9+/=\s]+)[\'"]\s*\)\s*\)',
    re.IGNORECASE,
)
_RE_GZDECODE = re.compile(
    rb'gzdecode\s*\(\s*base64_decode\s*\(\s*[\'"]([A-Za-z0-9+/=\s]+)[\'"]\s*\)\s*\)',
    re.IGNORECASE,
)
_RE_STR_ROT13 = re.compile(
    rb'str_rot13\s*\(\s*[\'"](.{16,}?)[\'"]\s*\)',
    re.IGNORECASE,
)
_RE_STRREV = re.compile(rb'strrev\s*\(\s*([\'"])(.{4,}?)\1\s*\)', re.IGNORECASE | re.DOTALL)
_RE_URLDECODE = re.compile(
    rb'(?:raw)?urldecode\s*\(\s*([\'"])(.{8,}?)\1\s*\)',
    re.IGNORECASE | re.DOTALL,
)
_RE_CHR_CHAIN = re.compile(rb'(?:chr\s*\(\s*\d+\s*\)\s*\.?\s*){8,}', re.IGNORECASE)
_RE_QUOTED = re.compile(rb'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.DOTALL)
_RE_CONCAT_STRINGS = re.compile(
    rb'(?:(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')\s*\.\s*){1,}'
    rb'(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')',
    re.DOTALL,
)
_RE_ESCAPED_STRING = re.compile(
    rb'([\'"])(?=[^\'"]*(?:\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}))(.*?)\1',
    re.DOTALL,
)
_RE_XOR_STRINGS = re.compile(
    rb'([\'"])(.{2,}?)\1\s*\^\s*([\'"])(.{2,}?)\3',
    re.DOTALL,
)
_RE_PACK_HEX = re.compile(
    rb'pack\s*\(\s*[\'"]H\*[\'"]\s*,\s*([\'"])([0-9a-fA-F\s]{8,})\1\s*\)',
    re.IGNORECASE,
)
_RE_PACK_CHARS = re.compile(
    rb'pack\s*\(\s*[\'"]C\*[\'"]\s*,\s*([0-9,\s]{8,})\)',
    re.IGNORECASE,
)
_RE_UNICODE_ESCAPE_RUN = re.compile(rb'(?:\\u[0-9a-fA-F]{4}){3,}')


def _safe_decode_b64(payload):
    try:
        cleaned = re.sub(rb'\s+', b'', payload)
        return base64.b64decode(cleaned, validate=False)
    except Exception:
        return None


def _try_zlib(data):
    for wbits in (-15, zlib.MAX_WBITS):
        try:
            return zlib.decompress(data, wbits)
        except Exception:
            continue
    return None


def _try_gzip(data):
    try:
        return zlib.decompress(data, zlib.MAX_WBITS | 16)
    except Exception:
        return None


def _decode_php_string(raw):
    if not raw or len(raw) < 2:
        return None
    quote = raw[:1]
    if quote not in (b"'", b'"') or raw[-1:] != quote:
        return None
    body = raw[1:-1]

    def repl_hex(match):
        try:
            return bytes([int(match.group(1), 16)])
        except Exception:
            return match.group(0)

    def repl_oct(match):
        try:
            return bytes([int(match.group(1), 8) & 0xff])
        except Exception:
            return match.group(0)

    body = re.sub(rb'\\x([0-9a-fA-F]{2})', repl_hex, body)
    body = re.sub(rb'\\([0-7]{1,3})', repl_oct, body)
    body = body.replace(rb'\"', b'"').replace(rb"\'", b"'").replace(rb'\\n', b"\n")
    body = body.replace(rb'\\r', b"\r").replace(rb'\\t', b"\t").replace(rb'\\\\', b"\\")
    return body


def _decode_concat_expr(expr):
    parts = []
    for item in _RE_QUOTED.finditer(expr):
        decoded = _decode_php_string(item.group(0))
        if decoded is None:
            return None
        parts.append(decoded)
    if len(parts) < 2:
        return None
    return b"".join(parts)


def _decode_xor_strings(left, right):
    left_decoded = _decode_php_string(left)
    right_decoded = _decode_php_string(right)
    if not left_decoded or not right_decoded:
        return None
    size = min(len(left_decoded), len(right_decoded))
    if size == 0:
        return None
    return bytes(left_decoded[i] ^ right_decoded[i % len(right_decoded)] for i in range(len(left_decoded)))


def _decode_pack_chars(payload):
    try:
        values = [int(p.strip()) for p in payload.split(b",") if p.strip()]
        if len(values) < 3:
            return None
        return bytes(v & 0xff for v in values)
    except Exception:
        return None


def _decode_unicode_escape_run(payload):
    try:
        text = payload.decode("ascii", errors="strict")
        return codecs.decode(text, "unicode_escape").encode("utf-8", errors="replace")
    except Exception:
        return None


def _looks_textual(data):
    if not data:
        return False
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data) >= 0.65


def _decode_chr_chain(match):
    parts = re.findall(rb'chr\s*\(\s*(\d+)\s*\)', match.group(0), re.IGNORECASE)
    if not parts:
        return None
    try:
        return bytes(int(p) for p in parts)
    except Exception:
        return None


def _add_layer(layers, seen, name, data, max_output):
    if not data or len(data) > max_output:
        return
    # Use a lightweight hash fingerprint instead of storing raw bytes in the seen-set
    import hashlib
    key = (name, hashlib.md5(data[:4096]).digest(), len(data))
    if key in seen:
        return
    seen.add(key)
    layers.append((name, data))


def _iter_java_utf8_constants(data):
    if not data.startswith(b"\xca\xfe\xba\xbe") or len(data) < 10:
        return

    def read_u2(offset):
        return struct.unpack(">H", data[offset:offset + 2])[0], offset + 2

    try:
        cp_count, offset = read_u2(8)
        index = 1
        while index < cp_count and offset < len(data):
            tag = data[offset]
            offset += 1
            if tag == 1:
                size, offset = read_u2(offset)
                raw = data[offset:offset + size]
                offset += size
                yield raw
            elif tag in (3, 4):
                offset += 4
            elif tag in (5, 6):
                offset += 8
                index += 1
            elif tag in (7, 8, 16, 19, 20):
                offset += 2
            elif tag in (9, 10, 11, 12, 18):
                offset += 4
            elif tag == 15:
                offset += 3
            else:
                return
            index += 1
    except Exception:
        return


def iter_deobfuscated_layers(file_data, policy=None):
    """
    Yield (layer_name, bytes) including raw content first.
    """
    if not file_data:
        return

    policy = policy or {}
    max_depth = int(policy.get("deobfuscate_max_depth", 3))
    max_output = int(policy.get("deobfuscate_max_output_bytes", 2 * 1024 * 1024))
    max_file = int(policy.get("deobfuscate_max_file_bytes", 5 * 1024 * 1024))

    if len(file_data) > max_file:
        yield ("raw", file_data)
        return

    yield ("raw", file_data)

    if not policy.get("deobfuscate_enabled", True):
        return

    seen = set()
    layers = []
    queue = [("raw", file_data)]
    depth = 0

    while queue and depth < max_depth:
        depth += 1
        next_queue = []
        for _parent_name, content in queue:
            if not content:
                continue

            for match in _RE_BASE64_DECODE.finditer(content):
                decoded = _safe_decode_b64(match.group(1))
                if decoded:
                    _add_layer(layers, seen, "base64_decode", decoded, max_output)
                    next_queue.append(("base64_decode", decoded))

            if len(layers) < max_depth * 4:
                for match in _RE_B64_BLOB.finditer(content):
                    decoded = _safe_decode_b64(match.group(1))
                    if decoded and len(decoded) >= 32:
                        _add_layer(layers, seen, "base64_blob", decoded, max_output)
                        next_queue.append(("base64_blob", decoded))

            if len(layers) < max_depth * 6:
                for match in _RE_B64_LONG.finditer(content):
                    decoded = _safe_decode_b64(match.group(1))
                    if decoded and decoded.startswith(b"\xca\xfe\xba\xbe"):
                        _add_layer(layers, seen, "base64_java_class", decoded, max_output)
                        next_queue.append(("base64_java_class", decoded))

            if content.startswith(b"\xca\xfe\xba\xbe") and len(layers) < max_depth * 8:
                constants = list(_iter_java_utf8_constants(content))
                textual_constants = [
                    c for c in constants
                    if 4 <= len(c) <= 2048 and _looks_textual(c)
                ]
                if textual_constants:
                    joined = b"\n".join(textual_constants[:512])
                    _add_layer(layers, seen, "java_constant_pool_strings", joined, max_output)
                    next_queue.append(("java_constant_pool_strings", joined))
                for constant in constants:
                    if len(constant) < 256:
                        continue
                    decoded = _safe_decode_b64(constant)
                    if decoded and decoded.startswith(b"\xca\xfe\xba\xbe"):
                        _add_layer(layers, seen, "java_constant_base64_class", decoded, max_output)
                        next_queue.append(("java_constant_base64_class", decoded))

            for match in _RE_GZINFLATE.finditer(content):
                decoded = _safe_decode_b64(match.group(1))
                inflated = _try_zlib(decoded) if decoded else None
                if inflated:
                    _add_layer(layers, seen, "gzinflate_b64", inflated, max_output)
                    next_queue.append(("gzinflate_b64", inflated))

            for match in _RE_GZUNCOMPRESS.finditer(content):
                decoded = _safe_decode_b64(match.group(1))
                inflated = _try_zlib(decoded) if decoded else None
                if inflated:
                    _add_layer(layers, seen, "gzuncompress_b64", inflated, max_output)
                    next_queue.append(("gzuncompress_b64", inflated))

            for match in _RE_GZDECODE.finditer(content):
                decoded = _safe_decode_b64(match.group(1))
                inflated = _try_gzip(decoded) if decoded else None
                if inflated:
                    _add_layer(layers, seen, "gzdecode_b64", inflated, max_output)
                    next_queue.append(("gzdecode_b64", inflated))

            for match in _RE_STR_ROT13.finditer(content):
                try:
                    rotated = codecs.decode(match.group(1).decode("latin-1", errors="replace"), "rot_13")
                    _add_layer(layers, seen, "str_rot13", rotated.encode("utf-8", errors="replace"), max_output)
                    next_queue.append(("str_rot13", rotated.encode("utf-8", errors="replace")))
                except Exception:
                    pass

            for match in _RE_STRREV.finditer(content):
                decoded = match.group(2)[::-1]
                _add_layer(layers, seen, "strrev", decoded, max_output)
                next_queue.append(("strrev", decoded))

            for match in _RE_URLDECODE.finditer(content):
                try:
                    decoded = urllib.parse.unquote_to_bytes(match.group(2).decode("latin-1", errors="replace"))
                    if decoded:
                        _add_layer(layers, seen, "urldecode", decoded, max_output)
                        next_queue.append(("urldecode", decoded))
                except Exception:
                    pass

            for match in _RE_CHR_CHAIN.finditer(content):
                decoded = _decode_chr_chain(match)
                if decoded:
                    _add_layer(layers, seen, "chr_chain", decoded, max_output)
                    next_queue.append(("chr_chain", decoded))

            for match in _RE_CONCAT_STRINGS.finditer(content):
                decoded = _decode_concat_expr(match.group(0))
                if decoded and len(decoded) >= 4:
                    _add_layer(layers, seen, "php_concat_strings", decoded, max_output)
                    next_queue.append(("php_concat_strings", decoded))

            for match in _RE_ESCAPED_STRING.finditer(content):
                decoded = _decode_php_string(match.group(0))
                if decoded and decoded != match.group(2):
                    _add_layer(layers, seen, "php_escaped_string", decoded, max_output)
                    next_queue.append(("php_escaped_string", decoded))

            for match in _RE_XOR_STRINGS.finditer(content):
                decoded = _decode_xor_strings(match.group(1) + match.group(2) + match.group(1),
                                              match.group(3) + match.group(4) + match.group(3))
                if decoded and _looks_textual(decoded):
                    _add_layer(layers, seen, "php_xor_strings", decoded, max_output)
                    next_queue.append(("php_xor_strings", decoded))

            for match in _RE_PACK_HEX.finditer(content):
                try:
                    decoded = binascii.unhexlify(re.sub(rb'\s+', b'', match.group(2)))
                    if decoded:
                        _add_layer(layers, seen, "php_pack_hex", decoded, max_output)
                        next_queue.append(("php_pack_hex", decoded))
                except Exception:
                    pass

            for match in _RE_PACK_CHARS.finditer(content):
                decoded = _decode_pack_chars(match.group(1))
                if decoded:
                    _add_layer(layers, seen, "php_pack_chars", decoded, max_output)
                    next_queue.append(("php_pack_chars", decoded))

            for match in _RE_UNICODE_ESCAPE_RUN.finditer(content):
                decoded = _decode_unicode_escape_run(match.group(0))
                if decoded and _looks_textual(decoded):
                    _add_layer(layers, seen, "unicode_escape", decoded, max_output)
                    next_queue.append(("unicode_escape", decoded))

        queue = next_queue[:8]

    for name, data in layers:
        yield (name, data)


def should_deobfuscate(extension, file_path, policy):
    if not policy.get("deobfuscate_enabled", True):
        return False
    ext = (extension or "").lower()
    allowed = policy.get("deobfuscate_extensions") or []
    if ext in allowed or ext.lstrip(".") in [a.lstrip(".") for a in allowed]:
        return True
    path_lower = (file_path or "").lower()
    return any(
        p in path_lower
        for p in (policy.get("upload_path_patterns") or [])
    )
