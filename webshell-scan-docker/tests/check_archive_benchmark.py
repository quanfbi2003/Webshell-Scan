import io
import json
import tempfile
import zipfile
from pathlib import Path

from libs.review_bundle import build_review_zip

COLUMNS = ["FILE", "SHA256", "SCORE", "TIME", "DESCRIPTION", "EXTENSION"]


def report(path, sha):
    return {column: [value] for column, value in {
        "FILE": path, "SHA256": sha, "SCORE": 90, "TIME": "now",
        "DESCRIPTION": "archive candidate", "EXTENSION": ".php",
    }.items()}


def make_bundle(path, **kwargs):
    return build_review_zip(
        findings_report={}, findings_columns=COLUMNS,
        all_files_report={}, all_files_columns=COLUMNS,
        gray_zone_report=report(path, "b" * 64), gray_zone_columns=COLUMNS,
        scan_path="/scan", out_file="report", scanner_version="test", **kwargs,
    )


def read_entry(payload):
    with zipfile.ZipFile(io.BytesIO(payload)) as bundle:
        return json.loads(bundle.read("sources/index.json"))[0], bundle.namelist()


def main():
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "sample.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("archive-member.php", b"<?php echo 'member'; ?>")
        report_path = "archive-member.php [ARCHIVE: %s]" % archive

        entry, names = read_entry(make_bundle(report_path, source_limit_bytes=1, total_source_limit_bytes=1024)[0])
        assert entry["source_status"] == "omitted"
        assert entry["source_reason"]
        assert str(Path(tmp)) not in json.dumps(entry)
        assert not any(str(Path(tmp)) in name for name in names)

        entry, names = read_entry(make_bundle(report_path, source_limit_bytes=1024, total_source_limit_bytes=1024)[0])
        assert entry["source_status"] == "stored"
        assert entry["archive"]["member_path"] == "archive-member.php"
        assert entry["archive"]["member_sha256"] == "b" * 64

    print("check_archive_benchmark: ok")


if __name__ == "__main__":
    main()
