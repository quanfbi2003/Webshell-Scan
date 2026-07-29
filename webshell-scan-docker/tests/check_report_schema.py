#!/usr/bin/env python3
"""Fail-closed checks for benchmark and legacy report schemas."""

import importlib.util
import json
import os
import tempfile


APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_runner():
    path = os.path.join(APP_ROOT, "tools", "run-benchmark.py")
    spec = importlib.util.spec_from_file_location("run_benchmark", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    runner = _load_runner()
    expected_columns = {
        "findings": ["FILE", "SHA256", "SCORE", "TIME", "DESCRIPTION", "EXTENSION"],
        "all_files": ["FILE", "SHA256", "TIME_CREATED", "TIME_MODIFIED", "TIME_ACCESSED", "EXTENSION"],
        "gray_zone": [
            "FILE", "SHA256", "SCORE", "TIME", "DESCRIPTION", "EXTENSION",
            "VIRUSTOTAL_URL", "VT_CHECKED", "VT_RESULT",
        ],
    }
    assert runner.legacy_report_columns() == expected_columns

    report = {
        "schema": "webshell-benchmark-v1",
        "run_id": "run-test",
        "results": [{
            "id": "sample",
            "legacy_score": 90,
            "shadow_score": 70,
            "status": "detected",
            "terminal_status": "completed",
            "evidence_groups": ["source_sink"],
            "sha256": "a" * 64,
            "archive_sha256": None,
            "member_path": None,
            "member_sha256": None,
            "shadow_provenance": {"source": "scanner", "field": "shadow_score"},
        }],
    }
    with tempfile.TemporaryDirectory() as temp_dir:
        path = os.path.join(temp_dir, "benchmark.json")
        runner.write_benchmark_report(path, report)
        with open(path, encoding="utf-8") as handle:
            loaded = json.load(handle)
        runner.validate_report_schema(loaded)

        archive = dict(report)
        archive["results"] = [dict(report["results"][0], archive_sha256="b" * 64,
                                   member_path="nested/shell.php", member_sha256="c" * 64)]
        runner.validate_report_schema(archive)

    for missing in (
        "run_id", "legacy_score", "shadow_score", "status", "terminal_status",
        "evidence_groups", "sha256", "shadow_provenance",
    ):
        invalid = json.loads(json.dumps(report))
        if missing == "run_id":
            del invalid[missing]
        else:
            del invalid["results"][0][missing]
        try:
            runner.validate_report_schema(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("schema accepted missing %s" % missing)

    for field in ("sha256", "archive_sha256", "member_sha256"):
        invalid = json.loads(json.dumps(report))
        invalid["results"][0][field] = "g" * 64
        if field != "sha256":
            invalid["results"][0]["archive_sha256"] = "b" * 64
            invalid["results"][0]["member_path"] = "nested/shell.php"
            invalid["results"][0]["member_sha256"] = "c" * 64
            invalid["results"][0][field] = "g" * 64
        try:
            runner.validate_report_schema(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("schema accepted non-hex %s" % field)

    invalid_archive = json.loads(json.dumps(report))
    invalid_archive["results"][0]["member_path"] = "nested/shell.php"
    invalid_archive["results"][0]["member_sha256"] = "c" * 64
    try:
        runner.validate_report_schema(invalid_archive)
    except ValueError:
        pass
    else:
        raise AssertionError("schema accepted archive member without archive_sha256")

    case = {"id": "skip", "label": "benign", "archive": False}
    skipped = runner._select_rows([], {"terminal_status": "skipped"}, case)[0]
    assert skipped["status"] == "unknown"
    assert skipped["terminal_status"] == "skipped"
    assert skipped["legacy_score"] is None
    assert skipped["shadow_score"] is None

    archive_case = {
        "id": "archive", "label": "webshell", "archive": True,
        "sha256": "a" * 64, "member_path": "nested/shell.php",
        "member_sha256": "c" * 64,
    }
    archive_records = [
        dict(report["results"][0], archive_sha256="b" * 64,
             member_path="other.php", member_sha256="d" * 64),
        dict(report["results"][0], archive_sha256="b" * 64,
             member_path="nested/shell.php", member_sha256="c" * 64),
    ]
    selected = runner._select_rows(archive_records, {"terminal_status": "completed"}, archive_case)
    assert len(selected) == 1
    assert selected[0]["member_path"] == "nested/shell.php"
    assert selected[0]["member_sha256"] == "c" * 64

    shadow_record = dict(report["results"][0], legacy_decision="below_report_threshold",
                         shadow_decision="report_threshold_met")
    shadow = runner._normalize_selected(
        shadow_record, {"terminal_status": "completed"}, case, shadow_only=True,
    )
    assert shadow["status"] == "detected"
    assert shadow["predicted"] == "webshell"
    assert shadow["score"] == shadow["shadow_score"]
    assert shadow["shadow_provenance"]["source"] == "scanner"

    print("report schema checks passed")


if __name__ == "__main__":
    main()
