import base64
import hashlib
import struct
import pathlib
import re


SRC = pathlib.Path(r"E:\Quarantine\File_test\webshell\jsp\2021052101.jsp")
OUT = pathlib.Path(r"E:\Downloads\Tools-Linux\Webshell-Scan\decoded_2021052101.class")

text = SRC.read_text(errors="replace")
match = re.search(r'clzBytecodeBase64Str\s*=\s*"([^"]+)"', text)
if not match:
    raise SystemExit("Base64 bytecode string not found")

data = base64.b64decode(match.group(1))
OUT.write_bytes(data)

print(f"jsp_sha256={hashlib.sha256(SRC.read_bytes()).hexdigest()}")
print(f"decoded_class={OUT}")
print(f"decoded_bytes={len(data)}")
print(f"class_sha256={hashlib.sha256(data).hexdigest()}")
print(f"magic={data[:4].hex()}")
print("strings:")
for item in re.findall(rb"[ -~]{4,}", data):
    print(item.decode("latin1", errors="replace"))


def read_u1(buf, off):
    return buf[off], off + 1


def read_u2(buf, off):
    return struct.unpack(">H", buf[off:off + 2])[0], off + 2


def read_u4(buf, off):
    return struct.unpack(">I", buf[off:off + 4])[0], off + 4


def decode_modified_utf8(raw):
    out = []
    i = 0
    while i < len(raw):
        b = raw[i]
        if b >> 7 == 0:
            out.append(chr(b))
            i += 1
        elif (b & 0xE0) == 0xC0:
            b2 = raw[i + 1]
            out.append(chr(((b & 0x1F) << 6) | (b2 & 0x3F)))
            i += 2
        else:
            b2 = raw[i + 1]
            b3 = raw[i + 2]
            out.append(chr(((b & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F)))
            i += 3
    return "".join(out)


def parse_constant_pool(buf):
    off = 8
    cp_count, off = read_u2(buf, off)
    cp = [None] * cp_count
    i = 1
    while i < cp_count:
        tag, off = read_u1(buf, off)
        if tag == 1:
            size, off = read_u2(buf, off)
            cp[i] = ("Utf8", decode_modified_utf8(buf[off:off + size]))
            off += size
        elif tag in (3, 4):
            _, off = read_u4(buf, off)
            cp[i] = ("Num", None)
        elif tag in (5, 6):
            _, off = read_u4(buf, off)
            _, off = read_u4(buf, off)
            cp[i] = ("Num2", None)
            i += 1
        elif tag in (7, 8, 16, 19, 20):
            idx, off = read_u2(buf, off)
            cp[i] = ("Ref", idx)
        elif tag in (9, 10, 11, 12, 18):
            a, off = read_u2(buf, off)
            b, off = read_u2(buf, off)
            cp[i] = ("Ref2", (a, b))
        elif tag == 15:
            _, off = read_u1(buf, off)
            _, off = read_u2(buf, off)
            cp[i] = ("MethodHandle", None)
        else:
            raise ValueError(f"Unsupported cp tag {tag} at {i}")
        i += 1
    return cp


def decrypt_segments(s, first_len, key=None):
    key = key or [64, 67, 119, 41, 81, 87, 66]
    result = []
    pos = -1
    seg_len = first_len
    while True:
        pos += 1
        part = s[pos:pos + seg_len]
        result.append("".join(chr(ord(ch) ^ key[i % len(key)]) for i, ch in enumerate(part)))
        pos += seg_len
        if pos >= len(s):
            break
        seg_len = ord(s[pos])
    return result


cp = parse_constant_pool(data)
string_values = []
for entry in cp:
    if entry and entry[0] == "Ref":
        idx = entry[1]
        if idx < len(cp) and cp[idx] and cp[idx][0] == "Utf8":
            string_values.append(cp[idx][1])

print("decrypted_string_array:")
decoded = []
for s in string_values:
    if len(s) > 1000:
        first = 24 if not decoded else 21
        decoded.extend(decrypt_segments(s, first))
for i, value in enumerate(decoded[:80]):
    print(f"{i}: {value}")

if len(decoded) > 11 and re.fullmatch(r"[A-Za-z0-9+/=]+", decoded[11]):
    nested = base64.b64decode(decoded[11])
    nested_out = pathlib.Path(r"E:\Downloads\Tools-Linux\Webshell-Scan\decoded_2021052101_nested.class")
    nested_out.write_bytes(nested)
    print(f"nested_class={nested_out}")
    print(f"nested_bytes={len(nested)}")
    print(f"nested_sha256={hashlib.sha256(nested).hexdigest()}")
    print(f"nested_magic={nested[:4].hex()}")
    nested_cp = parse_constant_pool(nested)
    nested_string_values = []
    for entry in nested_cp:
        if entry and entry[0] == "Ref":
            idx = entry[1]
            if idx < len(nested_cp) and nested_cp[idx] and nested_cp[idx][0] == "Utf8":
                nested_string_values.append(nested_cp[idx][1])
    print("nested_plain_strings:")
    for item in re.findall(rb"[ -~]{4,}", nested):
        print(item.decode("latin1", errors="replace"))
    print("nested_decrypted_string_array:")
    nested_decoded = []
    first_lengths = [6, 21]
    for s in nested_string_values:
        if len(s) > 20:
            first = first_lengths[min(len(nested_decoded) > 0, 1)]
            try:
                nested_decoded.extend(decrypt_segments(s, first, [105, 20, 25, 17, 21, 39, 22]))
            except Exception:
                pass
    for i, value in enumerate(nested_decoded[:80]):
        print(f"{i}: {value}")
