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
        assert normal_record["legacy_score"] == 167
        assert {item["detector"] for item in normal_record["evidence"]} >= {"yara", "source_sink"}

        original_ast_df = webshell_scan.ast_df_heuristic
        webshell_scan.ast_df_heuristic = lambda *args, **kwargs: (0, "model_incompatible")
        try:
            incompatible_result = scanner.process_single_file_with_result(
                plain, _args(), ROOT.lower(), 1)
        finally:
            webshell_scan.ast_df_heuristic = original_ast_df
        incompatible_record = incompatible_result["benchmark"][0]
        incompatible_ast = next(item for item in incompatible_record["evidence"]
                                if item["detector"] == "ast_df")
        assert incompatible_result["terminal_status"] == "completed"
        assert incompatible_record["status"] == "model_incompatible"
        assert incompatible_record["coverage"] == "partial"
        assert incompatible_record["legacy_decision"] != "report_threshold_met"
        assert incompatible_ast["reason"] == "model_incompatible"
        assert incompatible_ast["status"] == "model_incompatible"
        assert incompatible_ast["truncated"] is True

        incompatible = scanner._build_evidence_records({}, ["model_incompatible"])
        ast_record = next(item for item in incompatible if item["detector"] == "ast_df")
        assert ast_record["status"] == "model_incompatible"
        assert ast_record["coverage"] == "partial"
        assert ast_record["truncated"] is True

        def yara_error(*args, **kwargs):
            raise RuntimeError("broken yara")

        scanner._collect_yara_matches = yara_error
        yara_error_result = scanner.process_single_file_with_result(plain, _args(), ROOT.lower(), 1)
        assert yara_error_result["terminal_status"] == "error"
        assert yara_error_result["benchmark"][0]["status"] == "error"
        assert yara_error_result["benchmark"][0]["coverage"] == "partial"

        def read_error(*args, **kwargs):
            raise OSError("read denied")

        scanner._collect_yara_matches = lambda *args, **kwargs: ([], False)
        scanner.get_file_data = read_error
        read_error_result = scanner.process_single_file_with_result(plain, _args(), ROOT.lower(), 1)
        assert read_error_result["terminal_status"] == "error"
        assert read_error_result["benchmark"][0]["status"] == "error"
        assert read_error_result["benchmark"][0]["coverage"] == "partial"

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
        scanner.scan_path(plain, _args(threads=1))
        assert len(scanner.benchmark_records) == 1
        assert scanner.benchmark_records[0]["path"] == plain

        previous_platform = webshell_scan.os_platform
        try:
            webshell_scan.os_platform = "windows"
            scanner.scan_path(plain, _args(threads=2))
            assert len(scanner.benchmark_records) == 1
            assert scanner.benchmark_records[0]["path"] == plain
        finally:
            webshell_scan.os_platform = previous_platform

        original_internal = scanner._process_single_file_internal
        scanner._process_single_file_internal = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("worker failure"))
        internal_error = scanner.process_single_file_with_result(plain, _args(), ROOT.lower(), 1)
        scanner._process_single_file_internal = original_internal
        scanner.get_file_data = webshell_scan.Scanner.get_file_data

        scanner.terminal_counts = {"completed": 0, "skipped": 0, "unsupported": 0, "errors": 0}
        scanner._record_terminal_status(internal_error)
        assert scanner._assert_terminal_accounting(1, scanner.terminal_counts)["errors"] == 1
        try:
            scanner._assert_terminal_accounting(1, {"completed": 1, "skipped": 1, "unsupported": 0, "errors": 0})
        except AssertionError:
            pass
        else:
            raise AssertionError("terminal accounting accepted missing/extra result")

        scanner._process_single_file_internal = original_internal
        scanner.get_file_data = webshell_scan.Scanner.get_file_data
        scanner._collect_yara_matches = lambda *args, **kwargs: ([], False)

        archive_result = scanner.process_single_file_with_result(archive, _args(), ROOT.lower(), 1)
        assert archive_result and archive_result["benchmark"], archive_result
        archive_record = archive_result["benchmark"][0]
        assert archive_record["archive_sha256"] == hashlib.sha256(open(archive, "rb").read()).hexdigest()
        assert archive_record["member_path"] == "WEB-INF/sample.php"
        assert archive_record["member_sha256"] == hashlib.sha256(data).hexdigest()
        assert archive_record["member_extension"] == ".php"
        assert archive_record["archive_chain"] == ("sample.zip",)
        assert os.path.abspath(tmp) not in archive_record["member_path"]
        assert "_extracted" not in archive_record["path"]
        assert not archive_result["findings"]
        assert archive_record["candidate_id"]

        archive_copy_dir = os.path.join(tmp, "other-extraction-root")
        os.makedirs(archive_copy_dir)
        archive_copy = os.path.join(archive_copy_dir, "sample.zip")
        shutil.copy2(archive, archive_copy)
        archive_copy_result = scanner.process_single_file_with_result(
            archive_copy, _args(), ROOT.lower(), 1)
        assert archive_copy_result["benchmark"][0]["candidate_id"] == archive_record["candidate_id"]

        original_ast_df = webshell_scan.ast_df_heuristic
        webshell_scan.ast_df_heuristic = lambda *args, **kwargs: (0, "model_incompatible")
        try:
            archive_incompatible = scanner.process_single_file_with_result(
                archive, _args(), ROOT.lower(), 1)
        finally:
            webshell_scan.ast_df_heuristic = original_ast_df
        archive_incompatible_record = archive_incompatible["benchmark"][0]
        assert archive_incompatible_record["status"] == "model_incompatible"
        assert archive_incompatible_record["coverage"] == "partial"
        assert archive_incompatible_record["truncated"] is True

        legacy_result = scanner.process_single_file_with_result(plain, _args(), ROOT.lower(), 1)
        assert legacy_result["benchmark"][0]["legacy_score"] == normal_record["legacy_score"]
        assert legacy_result["findings"] == normal["findings"]
        assert legacy_result["gray_zone"] == normal["gray_zone"]
        assert not legacy_result["findings"]
        assert not legacy_result["gray_zone"]
        assert not os.path.exists(os.path.join(ROOT, "quarantine", "sample.php"))

        original_ast_df = webshell_scan.ast_df_heuristic
        webshell_scan.ast_df_heuristic = lambda *args, **kwargs: (0, "model_incompatible")
        try:
            archive_incompatible_again = scanner.process_single_file_with_result(
                archive, _args(), ROOT.lower(), 1)
        finally:
            webshell_scan.ast_df_heuristic = original_ast_df
        archive_incompatible_record = archive_incompatible_again["benchmark"][0]
        assert archive_incompatible_record["legacy_decision"] != "report_threshold_met"
        assert any(item["reason"] == "model_incompatible" for item in archive_incompatible_record["evidence"])

        original_get_file_data = scanner.get_file_data
        def member_read_error(path):
            if str(path).endswith("sample.php"):
                raise OSError("member read denied")
            return original_get_file_data(path)
        scanner.get_file_data = member_read_error
        try:
            archive_read_error = scanner.process_single_file_with_result(
                archive, _args(), ROOT.lower(), 1)
        finally:
            scanner.get_file_data = original_get_file_data
        assert archive_read_error["terminal_status"] == "error"
        assert archive_read_error["benchmark"]
        assert any(record["status"] == "error" for record in archive_read_error["benchmark"])

        empty_archive = os.path.join(tmp, "empty.zip")
        with zipfile.ZipFile(empty_archive, "w"):
            pass
        empty_result = scanner.process_single_file_with_result(empty_archive, _args(), ROOT.lower(), 1)
        assert empty_result["terminal_status"] == "error"
        assert empty_result["benchmark"]
        assert empty_result["benchmark"][0]["status"] == "error"
        print("scanner evidence checks passed")
        assert normal_record["shadow_score"] is not None
        assert not normal["findings"] and not normal["gray_zone"]
        assert not os.path.isdir(os.path.join(ROOT, "quarantine", "sample.php"))
        assert normal_record["shadow_score"] is not None
        assert not normal["findings"] and not normal["gray_zone"]
        assert not os.path.isdir(os.path.join(ROOT, "quarantine", "sample.php"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
