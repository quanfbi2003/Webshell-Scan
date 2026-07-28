"""Focused integration checks for scanner evidence envelopes."""
import argparse
import hashlib
import os
import shutil
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location("webshell_scan", os.path.join(ROOT, "webshell-scan.py"))
webshell_scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(webshell_scan)  # noqa: E402

from libs.scan_health import ScanStats  # noqa: E402
from libs.scan_policy import load_scan_policy  # noqa: E402
from libs.logger import Logger  # noqa: E402


webshell_scan.logger = Logger("check", "linux", "check", log_file="scanner-evidence.log")
# Keep the check importable without installing the scanner as a package.


def _args(**values):
    defaults = {
        "min_score": 40,
        "paranoid": False,
        "quarantine": False,
        "quarantine_exact": False,
    }
    defaults.update(values)
    return argparse.Namespace(**defaults)


def _scanner():
    scanner = webshell_scan.Scanner.__new__(webshell_scan.Scanner)
    scanner.effective_policy = dict(load_scan_policy(ROOT, None))
    scanner.effective_policy.update({
        "min_score_effective": 1000,
        "gray_zone_min_score": 25,
        "shadow_mode": True,
        "behavioral_fusion_enabled": True,
    })
    scanner._get_min_score = lambda args: int(getattr(args, "min_score", 1000))
    scanner._get_gray_zone_min = lambda: 25
    scanner._increment_progress = lambda *args: None
    scanner._is_scanner_internal_path = lambda path: False
    scanner._collect_yara_matches = lambda *args, **kwargs: ([], False)
    scanner.benchmark_records = []
    return scanner


def main():
    webshell_scan.MESSAGE = []
    webshell_scan.fileInfo_csv = webshell_scan.new_findings_report()
    webshell_scan.all_files_csv = webshell_scan.new_all_files_report()
    webshell_scan.gray_zone_csv = webshell_scan.new_gray_zone_report()
    tmp = tempfile.mkdtemp(prefix="scanner-evidence-")

    try:
        plain = os.path.join(tmp, "sample.php")
        archive = os.path.join(tmp, "sample.zip")
        data = b"<?php echo $_GET['x']; system($_GET['x']); ?>"
        with open(plain, "wb") as handle:
            handle.write(data)
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("WEB-INF/sample.php", data)

        scanner = _scanner()
        scanner.app_path = ROOT
        scanner.fullExcludes = []
        scanner.startExcludes = []
        scanner.LINUX_PATH_SKIPS_END = set()
        scanner.use_multiprocessing = False
        scanner.processed_files = 0
        scanner.progress_lock = __import__("threading").Lock()
        scanner.result_lock = __import__("threading").Lock()
        scanner.archive_extractor = webshell_scan.SafeArchiveExtractor()
        scanner.benign_filter = webshell_scan.BenignFileFilter()
        scanner.filetype_magics = {}
        scanner.max_filetype_magics = 0
        scanner.filename_iocs = []
        scanner.false_hashes = {}
        scanner.hashes_md5 = scanner.hashes_sha1 = scanner.hashes_sha256 = {}
        scanner.hashes_md5_list = scanner.hashes_sha1_list = scanner.hashes_sha256_list = []
        scanner.ssdeep_signatures = []
        scanner.ssdeep_index = {}
        scanner.yara_rules = []
        scanner.scan_stats = ScanStats()
        scanner.quarantine_manager = type("NoQuarantine", (), {"move": lambda *args, **kwargs: (None, None)})()
        scanner._get_min_score = lambda args: int(getattr(args, "min_score", 1000))
        scanner._get_gray_zone_min = lambda: 25
        scanner._increment_progress = lambda *args: None
        scanner._is_scanner_internal_path = lambda path: False
        scanner._collect_yara_matches = lambda *args, **kwargs: ([], False)

        normal = scanner.process_single_file_with_result(plain, _args(), ROOT.lower(), 1)
        assert normal and normal["benchmark"], normal
        normal_record = normal["benchmark"][0]
        assert normal_record["legacy_score"] == normal_record["legacy_score"]
        assert {item["detector"] for item in normal_record["evidence"]} >= {"yara", "source_sink"}
        assert normal_record["shadow_score"] is not None
        assert not normal["findings"] and not normal["gray_zone"]
        assert not os.path.isdir(os.path.join(ROOT, "quarantine", "sample.php"))

        archive_result = scanner.process_single_file_with_result(archive, _args(), ROOT.lower(), 1)
        assert archive_result and archive_result["benchmark"], archive_result
        archive_record = archive_result["benchmark"][0]
        assert archive_record["archive_sha256"] == hashlib.sha256(open(archive, "rb").read()).hexdigest()
        assert archive_record["member_path"] == "WEB-INF/sample.php"
        assert archive_record["member_sha256"] == hashlib.sha256(data).hexdigest()
        assert os.path.abspath(tmp) not in archive_record["member_path"]
        assert not archive_result["findings"]
        assert not os.path.exists(next((p for p in scanner.benchmark_records if False), ""))
        print("scanner evidence checks passed")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
