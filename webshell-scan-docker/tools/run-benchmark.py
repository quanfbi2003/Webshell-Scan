#!/usr/bin/env python3
"""Run the local scanner against a fail-closed benchmark manifest."""

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import time
import uuid

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if APP_ROOT not in sys.path:
    sys.path.insert(0, APP_ROOT)

from libs.benchmark import compute_metrics, load_cases, record_result


_FINDINGS_COLUMNS = ["FILE", "SHA256", "SCORE", "TIME", "DESCRIPTION", "EXTENSION"]
_ALL_FILES_COLUMNS = ["FILE", "SHA256", "TIME_CREATED", "TIME_MODIFIED", "TIME_ACCESSED", "EXTENSION"]
_GRAY_ZONE_COLUMNS = [
    "FILE", "SHA256", "SCORE", "TIME", "DESCRIPTION", "EXTENSION",
    "VIRUSTOTAL_URL", "VT_CHECKED", "VT_RESULT",
]
_TERMINAL = {"completed", "skipped", "unsupported", "error"}


def _load_scanner_module(app_root):
    path = os.path.join(app_root, "webshell-scan.py")
    spec = importlib.util.spec_from_file_location("webshell_scan_benchmark", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.logger = module.Logger("benchmark", module.os_platform, "benchmark", log_file="benchmark.log")
    module.MESSAGE = []
    module.fileInfo_csv = module.new_findings_report()
    module.all_files_csv = module.new_all_files_report()
    module.gray_zone_csv = module.new_gray_zone_report()
    return module


def legacy_report_columns():
    return {
        "findings": list(_FINDINGS_COLUMNS),
        "all_files": list(_ALL_FILES_COLUMNS),
        "gray_zone": list(_GRAY_ZONE_COLUMNS),
    }


def _args(worker_count):
    return type("BenchmarkArgs", (), {
        "min_score": None,
        "paranoid": False,
        "quarantine": False,
        "quarantine_exact": False,
        "threads": worker_count,
        "no_ssdeep": False,
        "vt_ssdeep": False,
        "no_review_bundle": True,
    })()


def _case_path(root, case):
    root = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(root, case["path"]))
    if os.path.commonpath((root, candidate)) != root:
        raise ValueError("case path escapes root: %s" % case["path"])
    return candidate


def _status_and_prediction(record):
    status = record.get("status", "error")
    score = record.get("legacy_score")
    if status in {"error", "model_incompatible", "manual_review"}:
        return status, None, score
    if record.get("legacy_decision") == "report_threshold_met":
        return "detected", "webshell", score
    if status == "clean" and not record.get("evidence_groups"):
        return status, "benign", score
    return "gray_zone", None, score


def _normalize_selected(selected, result, case):
    status, predicted, score = _status_and_prediction(selected)
    row = record_result(case, status, predicted, score)
    row.update(selected)
    row["id"] = case["id"]
    row["label"] = case["label"]
    row["status"] = status
    row["predicted"] = predicted
    row["score"] = score
    row["terminal_status"] = result.get("terminal_status", "error")
    return row


def _archive_rows(records, case, result):
    if not case.get("archive"):
        return []
    return [_normalize_selected(record, result, case) for record in records]



def _select_rows(records, result, case):
    normal = [row for row in records if row.get("member_path") is None]
    if normal:
        return [_normalize_selected(normal[0], result, case)]
    archive = _archive_rows(records, case, result)
    if archive:
        return archive
    return [record_result(case, result.get("terminal_status", "error"), None, None,
                          sha256="N/A", evidence_groups=[])]



def run_case(scanner, case):
    """Scan one manifest case without quarantine and return one result row."""
    path = _case_path(scanner._benchmark_root, case)
    result = scanner.process_single_file_with_result(
        path, scanner._benchmark_args, scanner._benchmark_root.lower(), 1,
    )
    rows = _select_rows(result.get("benchmark", []), result, case)
    if not rows:
        raise ValueError("no benchmark record for case %s" % case["id"])
    return rows[0]


def _resolve_benchmark_root(root):
    root = os.path.realpath(root)
    if os.path.isdir(os.path.join(root, "tests", "samples")):
        return root
    nested = os.path.join(root, "webshell-scan-docker")
    if os.path.isdir(os.path.join(nested, "tests", "samples")):
        return nested
    return root


def run_manifest(manifest_path, root, worker_count=1):
    """Validate and scan all cases exactly once, failing closed on ID loss."""
    root = _resolve_benchmark_root(root)
    cases = load_cases(manifest_path, root)
    scanner_module = _load_scanner_module(root)
    scanner = scanner_module.Scanner()
    scanner._benchmark_root = root
    scanner._benchmark_args = _args(worker_count)
    scanner.apply_runtime_policy(scanner._benchmark_args)
    rows = [run_case(scanner, case) for case in cases]
    expected = [case["id"] for case in cases]
    actual = [row.get("id") for row in rows]
    if len(actual) != len(set(actual)) or set(actual) != set(expected) or len(actual) != len(expected):
        raise ValueError("benchmark result IDs missing or duplicated")
    if any(row.get("terminal_status") not in _TERMINAL for row in rows):
        raise ValueError("benchmark result has non-terminal status")
    return rows


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_report_schema(run):
    if not isinstance(run, dict) or not isinstance(run.get("run_id"), str) or not run["run_id"]:
        raise ValueError("report requires run_id")
    if not isinstance(run.get("results"), list):
        raise ValueError("report requires results")
    ids = []
    required = {"id", "legacy_score", "shadow_score", "status", "evidence_groups", "sha256"}
    for row in run["results"]:
        if not required.issubset(row):
            raise ValueError("benchmark result missing required fields")
        ids.append(row["id"])
        if not isinstance(row["evidence_groups"], list):
            raise ValueError("evidence_groups must be a list")
        digest = row["sha256"]
        if digest != "N/A" and (not isinstance(digest, str) or len(digest) != 64):
            raise ValueError("sha256 must be a SHA-256 digest or N/A")
        archive_digest = row.get("archive_sha256")
        member_path = row.get("member_path")
        member_digest = row.get("member_sha256")
        if archive_digest is not None and (not isinstance(archive_digest, str) or len(archive_digest) != 64):
            raise ValueError("archive_sha256 must be a SHA-256 digest")
        if member_path is not None and (not isinstance(member_digest, str) or len(member_digest) != 64):
            raise ValueError("archive member requires member_sha256")
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate benchmark IDs")
    return True


def write_benchmark_report(path, run):
    validate_report_schema(run)
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(run, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _build_report(rows, manifest_path, root, worker_count):
    return {
        "schema": "webshell-benchmark-v1",
        "run_id": str(uuid.uuid4()),
        "manifest": os.path.relpath(manifest_path, root).replace(os.sep, "/"),
        "root": root,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "worker_count": int(worker_count),
        "quarantine": False,
        "results": rows,
        "metrics": compute_metrics(rows),
        "unknown": [row for row in rows if row.get("status") not in {"detected", "clean"}],
        "terminal": {status: sum(row.get("terminal_status") == status for row in rows)
                      for status in sorted(_TERMINAL)},
        "manifest_sha256": _sha256_file(manifest_path),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--output", required=True)
    parser.add_argument("--shadow-only", action="store_true")
    args = parser.parse_args(argv)
    if args.workers < 1:
        parser.error("--workers must be >= 1")
    root = _resolve_benchmark_root(args.root)
    rows = run_manifest(args.manifest, root, args.workers)
    report = _build_report(rows, args.manifest, root, args.workers)
    write_benchmark_report(args.output, report)
    print(json.dumps(report["metrics"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
