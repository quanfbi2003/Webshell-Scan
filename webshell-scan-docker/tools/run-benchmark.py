#!/usr/bin/env python3
"""Run the local scanner against a fail-closed benchmark manifest."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
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
_HEX_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_UNKNOWN_TERMINAL = {"skipped", "unsupported", "error"}


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


def _provenance(shadow_only=False, policy=None):
    policy = policy or {}
    return {
        "source": "scanner",
        "field": "shadow_score",
        "decision": "shadow_decision" if shadow_only else "legacy_decision",
        "mode": "shadow" if shadow_only else "legacy",
        "shadow_mode": policy.get("shadow_mode"),
        "behavioral_fusion_enabled": policy.get("behavioral_fusion_enabled"),
        "requested_shadow_only": bool(shadow_only),
    }


def _case_member_extension(case):
    member_path = case.get("member_path") or case.get("path", "")
    return os.path.splitext(member_path)[1].lower()


def _unknown_row(case, terminal_status, error=None, shadow_only=False, policy=None):
    archive = bool(case.get("archive"))
    row = record_result(
        case, "unknown", None, None,
        legacy_score=None,
        shadow_score=None,
        evidence_groups=[],
        sha256="N/A",
        archive_sha256=case.get("sha256") if archive else None,
        member_path=case.get("member_path") if archive else None,
        member_sha256=case.get("member_sha256") if archive else None,
        member_extension=_case_member_extension(case),
    )
    row["terminal_status"] = terminal_status
    row["shadow_provenance"] = _provenance(shadow_only, policy)
    if error:
        row["error"] = str(error)
    return row


def _status_and_prediction(record, terminal_status, shadow_only=False):
    if terminal_status in _UNKNOWN_TERMINAL:
        return "unknown", None, None
    status = record.get("status", "error")
    if status in {"error", "model_incompatible", "manual_review"}:
        return "unknown", None, None
    score_field = "shadow_score" if shadow_only else "legacy_score"
    decision_field = "shadow_decision" if shadow_only else "legacy_decision"
    score = record.get(score_field)
    if record.get(decision_field) == "report_threshold_met":
        return "detected", "webshell", score
    if status == "clean" and not record.get("evidence_groups"):
        return "clean", "benign", score
    return "unknown", None, None


def _normalize_selected(selected, result, case, shadow_only=False, policy=None):
    terminal_status = result.get("terminal_status", "error")
    status, predicted, score = _status_and_prediction(
        selected, terminal_status, shadow_only=shadow_only,
    )
    row = record_result(case, status, predicted, score)
    row.update(selected)
    row.update({
        "id": case["id"],
        "label": case["label"],
        "status": status,
        "predicted": predicted,
        "score": score,
        "legacy_score": selected.get("legacy_score") if status != "unknown" else None,
        "shadow_score": selected.get("shadow_score") if status != "unknown" else None,
        "terminal_status": terminal_status,
        "shadow_provenance": _provenance(shadow_only, policy),
    })
    if status == "unknown":
        row["score"] = None
        row.setdefault("member_extension", _case_member_extension(case))
    if case.get("archive"):
        row.setdefault("member_extension", _case_member_extension(case))
    return row


def _archive_rows(records, result, case, shadow_only=False, policy=None):
    expected_archive_sha = str(case.get("sha256", "")).lower()
    expected_path = case.get("member_path")
    expected_sha = str(case.get("member_sha256", "")).lower()
    matches = [
        record for record in records
        if str(record.get("archive_sha256", "")).lower() == expected_archive_sha
        and record.get("member_path") == expected_path
        and str(record.get("member_sha256", "")).lower() == expected_sha
    ]
    if len(matches) > 1:
        raise ValueError(
            "archive case %s has duplicate member %s with SHA-256 %s"
            % (case["id"], expected_path, expected_sha)
        )
    if not matches:
        return [_unknown_row(
            case, result.get("terminal_status", "error"), result.get("error"),
            shadow_only, policy,
        )]
    return [_normalize_selected(
        matches[0], result, case, shadow_only=shadow_only, policy=policy,
    )]


def _select_rows(records, result, case, shadow_only=False, policy=None):
    if case.get("archive"):
        return _archive_rows(
            records, result, case, shadow_only=shadow_only, policy=policy,
        )
    normal = [row for row in records if row.get("member_path") is None]
    if len(normal) == 1:
        return [_normalize_selected(
            normal[0], result, case, shadow_only=shadow_only, policy=policy,
        )]
    if not normal:
        return [_unknown_row(
            case, result.get("terminal_status", "error"), result.get("error"),
            shadow_only, policy,
        )]
    raise ValueError("multiple normal benchmark records for case %s" % case["id"])


def run_case(scanner, case, shadow_only=False, policy=None):
    """Scan one manifest case without quarantine and return one result row."""
    path = _case_path(scanner._benchmark_root, case)
    result = scanner.process_single_file_with_result(
        path, scanner._benchmark_args, scanner._benchmark_root.lower(), 1,
    )
    rows = _select_rows(
        result.get("benchmark", []), result, case,
        shadow_only=shadow_only, policy=scanner.effective_policy,
    )
    if len(rows) != 1:
        raise ValueError("expected one benchmark record for case %s" % case["id"])
    return rows[0]


def _resolve_benchmark_root(root):
    root = os.path.realpath(root)
    if os.path.isdir(os.path.join(root, "tests", "samples")):
        return root
    nested = os.path.join(root, "webshell-scan-docker")
    if os.path.isdir(os.path.join(nested, "tests", "samples")):
        return nested
    return root


def run_manifest(manifest_path, root, worker_count=1, shadow_only=False):
    """Validate and scan all cases exactly once, failing closed on ID loss."""
    root = _resolve_benchmark_root(root)
    cases = load_cases(manifest_path, root)
    scanner_module = _load_scanner_module(root)
    scanner = scanner_module.Scanner()
    scanner._benchmark_root = root
    scanner._benchmark_args = _args(worker_count)
    scanner.apply_runtime_policy(scanner._benchmark_args)
    rows = [run_case(
        scanner, case, shadow_only=shadow_only, policy=scanner.effective_policy,
    ) for case in cases]
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


def _validate_sha256(value, field, allow_na=False):
    if allow_na and value == "N/A":
        return
    if not isinstance(value, str) or not _HEX_SHA256.fullmatch(value):
        raise ValueError("%s must be a 64-character hexadecimal digest" % field)


def _validate_archive_row(row):
    archive_sha = row.get("archive_sha256")
    member_path = row.get("member_path")
    member_sha = row.get("member_sha256")
    if member_path is None and member_sha is None and archive_sha is None:
        return
    if not isinstance(member_path, str) or not member_path:
        raise ValueError("archive metadata requires member_path")
    if "member_extension" not in row or not isinstance(row["member_extension"], str):
        raise ValueError("archive metadata requires member_extension")
    expected_extension = os.path.splitext(member_path)[1].lower()
    if expected_extension and row["member_extension"].lower() != expected_extension:
        raise ValueError("member_extension does not match member_path")
    _validate_sha256(archive_sha, "archive_sha256")
    _validate_sha256(member_sha, "member_sha256")


def _validate_shadow_provenance(value):
    required = {"source", "field", "decision", "mode", "shadow_mode",
                "behavioral_fusion_enabled", "requested_shadow_only"}
    if not isinstance(value, dict) or not required.issubset(value):
        raise ValueError("shadow_provenance is incomplete")
    if value.get("source") != "scanner":
        raise ValueError("shadow_provenance must identify the scanner")
    if value.get("field") != "shadow_score":
        raise ValueError("shadow_provenance must identify shadow_score")
    for field in ("shadow_mode", "behavioral_fusion_enabled", "requested_shadow_only"):
        if type(value.get(field)) is not bool:
            raise ValueError("shadow_provenance.%s must be boolean" % field)
    shadow_only = value["requested_shadow_only"]
    if value.get("decision") != ("shadow_decision" if shadow_only else "legacy_decision"):
        raise ValueError("shadow_provenance decision does not match requested mode")
    if value.get("mode") != ("shadow" if shadow_only else "legacy"):
        raise ValueError("shadow_provenance mode does not match requested mode")


def validate_report_schema(run):
    if not isinstance(run, dict) or not isinstance(run.get("run_id"), str) or not run["run_id"]:
        raise ValueError("report requires run_id")
    if not isinstance(run.get("results"), list):
        raise ValueError("report requires results")
    if type(run.get("shadow_only")) is not bool:
        raise ValueError("report requires shadow_only boolean")
    _validate_shadow_provenance(run.get("shadow_provenance"))
    if run["shadow_provenance"]["requested_shadow_only"] != run["shadow_only"]:
        raise ValueError("report provenance does not match shadow_only")
    ids = []
    required = {
        "id", "legacy_score", "shadow_score", "status", "terminal_status",
        "evidence_groups", "sha256", "shadow_provenance",
    }
    for row in run["results"]:
        if not isinstance(row, dict) or not required.issubset(row):
            raise ValueError("benchmark result missing required fields")
        ids.append(row["id"])
        if row["terminal_status"] not in _TERMINAL:
            raise ValueError("benchmark result has non-terminal status")
        if row["status"] == "unknown":
            if row["legacy_score"] is not None or row["shadow_score"] is not None:
                raise ValueError("unknown result scores must be null")
            if not isinstance(row.get("member_extension"), str):
                raise ValueError("unknown result requires member_extension")
        if not isinstance(row["evidence_groups"], list):
            raise ValueError("evidence_groups must be a list")
        _validate_sha256(row["sha256"], "sha256", allow_na=True)
        _validate_archive_row(row)
        _validate_shadow_provenance(row["shadow_provenance"])
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


def _build_report(rows, manifest_path, root, worker_count, shadow_only=False, policy=None):
    return {
        "schema": "webshell-benchmark-v1",
        "run_id": str(uuid.uuid4()),
        "manifest": os.path.relpath(manifest_path, root).replace(os.sep, "/"),
        "root": root,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "worker_count": int(worker_count),
        "quarantine": False,
        "shadow_only": bool(shadow_only),
        "shadow_provenance": _provenance(shadow_only, policy),
        "results": rows,
        "metrics": compute_metrics(rows),
        "unknown": [row for row in rows if row.get("status") == "unknown"],
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
    parser.add_argument("--shadow-only", action="store_true",
                        help="classify using shadow_score/shadow_decision while retaining legacy fields")
    args = parser.parse_args(argv)
    if args.workers < 1:
        parser.error("--workers must be >= 1")
    root = _resolve_benchmark_root(args.root)
    manifest = os.path.realpath(args.manifest)
    rows = run_manifest(manifest, root, args.workers, shadow_only=args.shadow_only)
    policy = {
        "shadow_mode": rows[0]["shadow_provenance"]["shadow_mode"],
        "behavioral_fusion_enabled": rows[0]["shadow_provenance"]["behavioral_fusion_enabled"],
    }
    report = _build_report(
        rows, manifest, root, args.workers, shadow_only=args.shadow_only,
        policy=policy,
    )
    write_benchmark_report(args.output, report)
    print(json.dumps(report["metrics"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
