import io
import json
import tempfile
import zipfile
from pathlib import Path

import importlib.util

from libs.review_bundle import build_review_zip, encrypt_review_bundle_bytes, decrypt_review_bundle_bytes

_app_spec = importlib.util.spec_from_file_location("review_web_app", Path(__file__).parents[1] / "review-web" / "app.py")
review_web_app = importlib.util.module_from_spec(_app_spec)
import sys
sys.modules["review_web_app"] = review_web_app
_app_spec.loader.exec_module(review_web_app)
import_enc_case = review_web_app.import_enc_case
UploadedPart = review_web_app.UploadedPart
review_web_app.bundle_passphrase = lambda *args, **kwargs: "local-test-key"


FINDING_COLUMNS = ["FILE", "SHA256", "SCORE", "TIME", "DESCRIPTION", "EXTENSION"]
GRAY_COLUMNS = FINDING_COLUMNS + ["VIRUSTOTAL_URL", "VT_CHECKED", "VT_RESULT"]
ALL_COLUMNS = ["FILE", "SHA256", "TIME_CREATED", "TIME_MODIFIED", "TIME_ACCESSED", "EXTENSION"]


def rows(columns, values):
    return {column: [values.get(column, "")] for column in columns if column in values}


def build(**kwargs):
    return build_review_zip(
        findings_report=kwargs.get("findings_report", {}),
        findings_columns=FINDING_COLUMNS,
        all_files_report=kwargs.get("all_files_report", {}),
        all_files_columns=ALL_COLUMNS,
        gray_zone_report=kwargs.get("gray_zone_report", {}),
        gray_zone_columns=GRAY_COLUMNS,
        scan_path=kwargs.get("scan_path", "/scan"),
        out_file="report",
        scanner_version="test",
        **{key: value for key, value in kwargs.items() if key in {
            "benchmark_report", "source_limit_bytes", "total_source_limit_bytes",
        }},
    )


def main():
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "gray.php"
        source.write_text("<?php echo $_GET['x'];", encoding="utf-8")
        gray = rows(GRAY_COLUMNS, {
            "FILE": str(source), "SHA256": "a" * 64, "SCORE": 30,
            "DESCRIPTION": "gray", "EXTENSION": ".php",
        })
        benchmark = {
            "records": [
                {"path": str(source), "sha256": "a" * 64, "candidate_id": "candidate-a",
                 "archive_sha256": None, "archive_chain": [], "member_path": None,
                 "member_sha256": None},
            ]
        }
        payload, stats = build(gray_zone_report=gray, benchmark_report=benchmark)
        with zipfile.ZipFile(io.BytesIO(payload)) as bundle:
            names = set(bundle.namelist())
            assert "benchmark.json" in names
            manifest = json.loads(bundle.read("manifest.json"))
            index = json.loads(bundle.read("sources/index.json"))
            assert manifest["schema"] == "webshell-review-bundle-v1"
            assert manifest["counts"]["findings"] == 0
            assert len(index) == 1
            assert index[0]["candidate_id"] == "candidate-a"
            assert index[0]["source_status"] == "stored"
            entry = index[0]
            assert entry.get("relpath", ""), "source should have a stored relpath"
            assert not entry.get("archive", {}).get("archive_path", ""), "non-archive must not have archive_path"
        encrypted = encrypt_review_bundle_bytes(payload, "local-test-key")
        assert decrypt_review_bundle_bytes(encrypted, "local-test-key") == payload

        source_two = Path(tmp) / "second.php"
        source_two.write_text("<?php echo 2;", encoding="utf-8")
        rows_two = rows(GRAY_COLUMNS, {
            "FILE": str(source_two), "SHA256": "c" * 64, "SCORE": 31,
            "DESCRIPTION": "second", "EXTENSION": ".php",
        })
        multi = {"records": [
            {"path": str(source), "sha256": "a" * 64, "candidate_id": "candidate-a"},
            {"path": str(source_two), "sha256": "c" * 64, "candidate_id": "candidate-b"},
        ]}
        finding_two = rows(FINDING_COLUMNS, {
            "FILE": str(source), "SHA256": "a" * 64, "SCORE": 91,
            "DESCRIPTION": "first", "EXTENSION": ".php",
        })
        payload, _ = build(findings_report=finding_two, gray_zone_report=rows_two, benchmark_report=multi)
        with zipfile.ZipFile(io.BytesIO(payload)) as bundle:
            ids = [item["candidate_id"] for item in json.loads(bundle.read("sources/index.json"))]
            assert ids == ["candidate-a", "candidate-b"]

        candidate_only = {
            "schema": "webshell-review-bundle-v1",
            "source_index": [{"candidate_id": "candidate-only", "file": "candidate.php",
                              "sha256": "d" * 64, "source_status": "omitted"}],
        }
        payload, _ = build(gray_zone_report={}, benchmark_report={"records": []})
        with zipfile.ZipFile(io.BytesIO(payload)) as original:
            entries = {name: original.read(name) for name in original.namelist()}
        entries["sources/index.json"] = json.dumps(candidate_only["source_index"]).encode("utf-8")
        entries["findings.json"] = b"[]"
        entries["gray_zone.json"] = b"[]"
        rewritten = io.BytesIO()
        with zipfile.ZipFile(rewritten, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for name, data in entries.items():
                bundle.writestr(name, data)
        encrypted = encrypt_review_bundle_bytes(rewritten.getvalue(), "local-test-key")

        original_data, original_db = review_web_app.DATA_DIR, review_web_app.DB_PATH
        review_web_app.DATA_DIR = Path(tmp) / "data"
        review_web_app.DB_PATH = review_web_app.DATA_DIR / "review.db"
        review_web_app.CONFIG_PATH = review_web_app.DATA_DIR / "config.json"
        review_web_app.ensure_dirs()
        review_web_app.init_db()
        try:
            case_id, _, imported, _ = import_enc_case("candidate-only", UploadedPart("review", "case.enc", "", encrypted))
            assert case_id > 0 and imported == 1
        finally:
            review_web_app.DATA_DIR, review_web_app.DB_PATH = original_data, original_db
            review_web_app.CONFIG_PATH = original_data / "config.json"

        malformed = encrypt_review_bundle_bytes(build(gray_zone_report={}, benchmark_report=None)[0], "local-test-key")
        review_web_app.DATA_DIR = Path(tmp) / "bad-data"
        review_web_app.DB_PATH = review_web_app.DATA_DIR / "review.db"
        review_web_app.CONFIG_PATH = review_web_app.DATA_DIR / "config.json"
        review_web_app.ensure_dirs()
        review_web_app.init_db()
        try:
            try:
                import_enc_case("bad", UploadedPart("review", "bad.enc", "", malformed))
            except RuntimeError:
                pass
            else:
                raise AssertionError("malformed/empty candidate-only bundle was accepted")
        finally:
            review_web_app.DATA_DIR, review_web_app.DB_PATH = original_data, original_db
            review_web_app.CONFIG_PATH = original_data / "config.json"

    print("check_review_bundle_compat: ok")


if __name__ == "__main__":
    main()
