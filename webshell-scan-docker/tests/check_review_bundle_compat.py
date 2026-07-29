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
        payload, stats = build(gray_zone_report=gray, benchmark_report={"run_id": "run-1"})
        with zipfile.ZipFile(io.BytesIO(payload)) as bundle:
            names = set(bundle.namelist())
            assert "benchmark.json" in names
            manifest = json.loads(bundle.read("manifest.json"))
            index = json.loads(bundle.read("sources/index.json"))
            assert manifest["schema"] == "webshell-review-bundle-v1"
            assert manifest["counts"]["findings"] == 0
            assert len(index) == 1
            assert index[0]["candidate_id"]
            assert index[0]["source_status"] == "stored"
        encrypted = encrypt_review_bundle_bytes(payload, "local-test-key")
        assert decrypt_review_bundle_bytes(encrypted, "local-test-key") == payload

    print("check_review_bundle_compat: ok")


if __name__ == "__main__":
    main()
