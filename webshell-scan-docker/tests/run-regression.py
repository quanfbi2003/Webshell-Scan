#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run focused checks plus direct YARA/deobfuscation regression assertions."""

import argparse
import json
import os
import subprocess
import sys

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if APP_ROOT not in sys.path:
    sys.path.insert(0, APP_ROOT)

import yara
from libs.benchmark import load_cases
from libs.deobfuscate import iter_deobfuscated_layers
from libs.heuristics import source_sink_heuristic
from libs.scan_policy import load_scan_policy

SAMPLES = os.path.join(APP_ROOT, "tests", "samples")
MANIFEST = os.path.join(APP_ROOT, "tests", "fixtures", "benchmark", "cases.jsonl")
CUSTOM_YARA = os.path.join(APP_ROOT, "libs", "signature-base", "custom")

# These are the direct custom-rule expectations; broad scanner YARA is covered by evidence checks.
EXPECTED = {
    "benign_": {"source_sink": False, "yara": False},
    "clean_": {"source_sink": False, "yara": False},
    "obfusc_base64.php": {"deobfuscate": True, "yara": True},
    "obfusc_gzinflate.php": {"deobfuscate": True, "yara": True},
    "obfusc_pack.php": {"deobfuscate": True, "yara": False},
    "obfusc_strrev.php": {"deobfuscate": True, "yara": False},
    "obfusc_urldecode.php": {"deobfuscate": True, "yara": False},
    "source_sink_": {"source_sink": True},
}

FOCUSED_CHECKS = (
    "check_evidence.py",
    "check_benchmark_manifest.py",
    "check_benchmark_metrics.py",
    "check_policy_validation.py",
    "check_model_metadata.py",
    "check_scanner_evidence.py",
    "check_report_schema.py",
    "check_fp_guard.py",
    "check_scan_policy_defaults.py",
    "check_ast_df.py",
)


def compile_custom_rules():
    filepaths = {}
    for name in sorted(os.listdir(CUSTOM_YARA)):
        if name.endswith((".yar", ".yara")):
            namespace = "custom_%d" % len(filepaths)
            filepaths[namespace] = os.path.join(CUSTOM_YARA, name)
    return yara.compile(filepaths=filepaths)


def _run_focused_checks():
    env = os.environ.copy()
    env["PYTHONPATH"] = APP_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    failures = []
    outputs = []
    for name in FOCUSED_CHECKS:
        path = os.path.join(APP_ROOT, "tests", name)
        completed = subprocess.run(
            [sys.executable, path], cwd=APP_ROOT, env=env,
            text=True, capture_output=True,
        )
        output = (completed.stdout + completed.stderr).strip()
        outputs.append("[%s]\n%s" % (name, output or "(no output)"))
        if completed.returncode:
            failures.append("%s exited %s" % (name, completed.returncode))
    return failures, outputs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=MANIFEST)
    args = parser.parse_args(argv)

    try:
        cases = load_cases(args.manifest, APP_ROOT)
    except Exception as exc:
        print("manifest check failed: %s" % exc)
        return 1
    manifest_paths = {os.path.basename(case["path"]) for case in cases}
    policy = load_scan_policy(APP_ROOT)
    compiled = compile_custom_rules()
    failures = []
    print("Regression samples in %s\n" % SAMPLES)
    for fname in sorted(os.listdir(SAMPLES)):
        path = os.path.join(SAMPLES, fname)
        if not os.path.isfile(path):
            continue
        if fname not in manifest_paths:
            failures.append("unrecognized sample not in manifest: %s" % fname)
        checks = None
        for key, expected in EXPECTED.items():
            if fname == key or fname.startswith(key):
                checks = expected
                break
        if checks is None:
            failures.append("unrecognized sample prefix: %s" % fname)
            continue

        with open(path, "rb") as handle:
            data = handle.read()
        ext = os.path.splitext(fname)[1].lower()
        externals = {
            "filename": fname, "filepath": path, "extension": ext,
            "filetype": "UNKNOWN", "md5": "-", "owner": "dummy",
        }
        hits = []
        layers = list(iter_deobfuscated_layers(data, policy))
        for layer_name, layer_data in layers:
            matches = compiled.match(data=layer_data, externals=externals)
            for match in matches:
                hits.append("%s:%s" % (layer_name, match.rule))
        ss_score, ss_reason = source_sink_heuristic(data, ext, path, policy)
        status = "MATCH" if hits else "clean"
        print("%-32s %-7s layers=%-2s source_sink=%-3s %s" % (
            fname, status, len(layers), ss_score, hits))

        if checks.get("source_sink") is True and not ss_score:
            failures.append("%s expected source_sink hit" % fname)
        if checks.get("source_sink") is False and ss_score:
            failures.append("%s unexpected source_sink hit: %s" % (fname, ss_reason))
        if checks.get("yara") is True and not hits:
            failures.append("%s expected positive YARA hit" % fname)
        if checks.get("yara") is False and hits:
            failures.append("%s unexpected YARA hit: %s" % (fname, hits))
        if checks.get("deobfuscate") is True and len(layers) < 2:
            failures.append("%s expected deobfuscated layer" % fname)

    check_failures, outputs = _run_focused_checks()
    for output in outputs:
        print("\n" + output)
    failures.extend(check_failures)
    if failures:
        print("\nFAIL")
        for item in failures:
            print(" - %s" % item)
        return 1
    print("\nPASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
