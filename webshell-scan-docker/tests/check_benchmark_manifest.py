"""Small manifest validation checks for the benchmark helpers."""

import hashlib
import json
import os
import tempfile

from libs.benchmark import load_cases


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, "tests", "fixtures", "benchmark", "cases.jsonl")
EXPECTED_IDS = {
    "benign_aspx_page",
    "benign_wordpress_style_upload",
    "clean_hello",
    "obfusc_base64",
    "obfusc_gzinflate",
    "obfusc_pack",
    "obfusc_strrev",
    "obfusc_urldecode",
    "source_sink_aspx",
    "source_sink_jsp",
    "source_sink_php",
}


def _write_rows(rows):
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
    try:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
        return handle.name
    finally:
        handle.close()


def _read_rows():
    with open(MANIFEST, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def main():
    cases = load_cases(MANIFEST, ROOT)
    assert len(cases) == 11
    assert {case["id"] for case in cases} == EXPECTED_IDS
    assert all(case["archive"] is False for case in cases)

    rows = _read_rows()
    duplicate_path = _write_rows(rows + [rows[0]])
    try:
        try:
            load_cases(duplicate_path, ROOT)
        except ValueError as exc:
            assert "duplicate" in str(exc).lower()
        else:
            raise AssertionError("duplicate IDs were accepted")
    finally:
        os.unlink(duplicate_path)

    invalid_label = dict(rows[0], label="unknown")
    invalid_label_path = _write_rows([invalid_label])
    try:
        try:
            load_cases(invalid_label_path, ROOT)
        except ValueError as exc:
            assert "label" in str(exc).lower()
        else:
            raise AssertionError("invalid label was accepted")
    finally:
        os.unlink(invalid_label_path)

    bad_hash = dict(rows[0], sha256="0" * 64)
    bad_hash_path = _write_rows([bad_hash])
    try:
        try:
            load_cases(bad_hash_path, ROOT)
        except ValueError as exc:
            assert "sha" in str(exc).lower()
        else:
            raise AssertionError("SHA-256 mismatch was accepted")
    finally:
        os.unlink(bad_hash_path)

    missing = rows[:-1]
    missing_path = _write_rows(missing)
    try:
        loaded_ids = {case["id"] for case in load_cases(missing_path, ROOT)}
        assert EXPECTED_IDS - loaded_ids == {rows[-1]["id"]}
    finally:
        os.unlink(missing_path)

    sample = os.path.join(ROOT, rows[0]["path"])
    with open(sample, "rb") as handle:
        assert hashlib.sha256(handle.read()).hexdigest() == rows[0]["sha256"]
    print("benchmark manifest checks passed")


if __name__ == "__main__":
    main()
